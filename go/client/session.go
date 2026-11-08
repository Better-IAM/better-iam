package client

// Port of packages/client/src/session.ts: framework-agnostic session state.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// SessionClient is the minimum client surface the session store needs; SessionClientOf adapts a *Client.
type SessionClient[Session any] interface {
	GetSession(ctx context.Context) (Session, error)
	SignOut(ctx context.Context) error
}

// SessionStatus is the state of a SessionStore.
type SessionStatus string

const (
	SessionLoading         SessionStatus = "loading"
	SessionAuthenticated   SessionStatus = "authenticated"
	SessionUnauthenticated SessionStatus = "unauthenticated"
	SessionError           SessionStatus = "error"
)

// SessionSnapshot is the store's current state.
type SessionSnapshot[Session any] struct {
	Status SessionStatus
	// Session is the current identity and session, or nil when signed out.
	Session *Session
	// Error is the last transport or authentication error. Unauthenticated states keep the server's error so its
	// code can be shown.
	Error error
	// UpdatedAt is when the snapshot was published, in milliseconds since the epoch (0 while loading).
	UpdatedAt int64
}

// SessionStoreOptions configure NewSessionStore.
type SessionStoreOptions[Session any] struct {
	// HasInitial starts the store from Initial instead of "loading": a nil Initial is signed out.
	HasInitial bool
	Initial    *Session
}

// SessionStore is framework-agnostic session state; UI bindings subscribe to it, and it can drive scripts too.
type SessionStore[Session any] struct {
	client    SessionClient[Session]
	mu        sync.Mutex
	snapshot  SessionSnapshot[Session]
	listeners map[int]func()
	order     []int
	nextID    int
	inflight  chan struct{}
}

// IsUnauthenticated reports whether an error is the server refusing missing, expired, or step-up-required
// credentials (status 401 or 403); anything else is a transport failure. It also recognizes the server's own
// *core.IamError, for server-side code that calls the server in process.
func IsUnauthenticated(err error) bool {
	var clientError *IamClientError
	if errors.As(err, &clientError) {
		return clientError.Status == 401 || clientError.Status == 403
	}
	var serverError *core.IamError
	if errors.As(err, &serverError) {
		return serverError.Status == 401 || serverError.Status == 403
	}
	return false
}

// NewSessionStore creates a session store over a session client (createSessionStore).
func NewSessionStore[Session any](client SessionClient[Session], options SessionStoreOptions[Session]) *SessionStore[Session] {
	store := &SessionStore[Session]{client: client, listeners: map[int]func(){}}
	if !options.HasInitial {
		store.snapshot = SessionSnapshot[Session]{Status: SessionLoading}
	} else {
		status := SessionAuthenticated
		if options.Initial == nil {
			status = SessionUnauthenticated
		}
		store.snapshot = SessionSnapshot[Session]{Status: status, Session: options.Initial, UpdatedAt: time.Now().UnixMilli()}
	}
	return store
}

// NewClientSessionStore creates a session store over a typed client.
func NewClientSessionStore(c *Client, options SessionStoreOptions[apitypes.AuthGetSessionOutput]) *SessionStore[apitypes.AuthGetSessionOutput] {
	return NewSessionStore[apitypes.AuthGetSessionOutput](SessionClientOf(c), options)
}

// SessionClientOf adapts a typed client to SessionClient (auth.getSession and auth.signOut).
func SessionClientOf(c *Client) SessionClient[apitypes.AuthGetSessionOutput] { return clientSession{c} }

type clientSession struct{ c *Client }

func (s clientSession) GetSession(ctx context.Context) (apitypes.AuthGetSessionOutput, error) {
	return s.c.Auth.GetSession(ctx)
}

func (s clientSession) SignOut(ctx context.Context) error {
	_, err := s.c.Auth.SignOut(ctx)
	return err
}

// Snapshot returns the current state.
func (s *SessionStore[Session]) Snapshot() SessionSnapshot[Session] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}

// Subscribe calls listener after every change; the returned function unsubscribes.
func (s *SessionStore[Session]) Subscribe(listener func()) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID
	s.nextID++
	s.listeners[id] = listener
	s.order = append(s.order, id)
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.listeners[id]; !ok {
			return
		}
		delete(s.listeners, id)
		for index, other := range s.order {
			if other == id {
				s.order = append(s.order[:index:index], s.order[index+1:]...)
				break
			}
		}
	}
}

func (s *SessionStore[Session]) publish(next SessionSnapshot[Session]) {
	s.mu.Lock()
	s.snapshot = next
	listeners := make([]func(), 0, len(s.order))
	for _, id := range s.order {
		listeners = append(listeners, s.listeners[id])
	}
	s.mu.Unlock()
	for _, listener := range listeners {
		listener()
	}
}

// Refresh reloads the session from the server. Concurrent calls share one request, which runs to completion even
// when the context of the call that started it is cancelled (it keeps that context's values).
func (s *SessionStore[Session]) Refresh(ctx context.Context) SessionSnapshot[Session] {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.inflight != nil {
		done := s.inflight
		s.mu.Unlock()
		<-done
		return s.Snapshot()
	}
	done := make(chan struct{})
	s.inflight = done
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight = nil
		s.mu.Unlock()
		close(done)
	}()
	session, err := s.getSession(context.WithoutCancel(ctx))
	if err == nil {
		s.publish(SessionSnapshot[Session]{Status: SessionAuthenticated, Session: &session, UpdatedAt: time.Now().UnixMilli()})
	} else {
		next := SessionSnapshot[Session]{Status: SessionError, Session: s.Snapshot().Session, Error: err, UpdatedAt: time.Now().UnixMilli()}
		if IsUnauthenticated(err) {
			next.Status, next.Session = SessionUnauthenticated, nil
		}
		s.publish(next)
	}
	return s.Snapshot()
}

// getSession calls the client, turning a panic into an error as a rejected promise would be.
func (s *SessionStore[Session]) getSession(ctx context.Context) (session Session, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(error); ok {
				err = failure
			} else {
				err = fmt.Errorf("%v", recovered)
			}
		}
	}()
	return s.client.GetSession(ctx)
}

// SignOut signs out on the server, then clears the local session even if the server call failed; the server's
// error is returned.
func (s *SessionStore[Session]) SignOut(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	defer s.publish(SessionSnapshot[Session]{Status: SessionUnauthenticated, UpdatedAt: time.Now().UnixMilli()})
	return s.client.SignOut(ctx)
}

// Set replaces the local session, for example right after a sign-in response; nil signs out locally.
func (s *SessionStore[Session]) Set(session *Session) {
	status := SessionAuthenticated
	if session == nil {
		status = SessionUnauthenticated
	}
	s.publish(SessionSnapshot[Session]{Status: status, Session: session, UpdatedAt: time.Now().UnixMilli()})
}
