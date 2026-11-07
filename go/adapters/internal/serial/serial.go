// Package serial holds the per-database locks of the SQLite and libSQL adapters: operations serialize per canonical
// database path in this process, and a call chain (a context) that already holds a database's lock through one
// adapter instance fails with DATABASE_IN_USE instead of waiting on itself through another instance (for example
// when copying a database onto itself).
package serial

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Better-IAM/better-iam/go/core"
)

type held struct {
	mutex  *Mutex
	active atomic.Bool
}

// Registry maps canonical database paths to locks. Each adapter has its own registry (and its own held-lock chain),
// as the TypeScript adapters do.
type Registry struct {
	mu      sync.Mutex
	mutexes map[string]*Mutex
	key     *int
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{mutexes: map[string]*Mutex{}, key: new(int)} }

// Mutex serializes operations on one database. It is not reentrant: a chain holding it fails with DATABASE_IN_USE.
type Mutex struct {
	registry *Registry
	slot     chan struct{}
}

// New returns a lock no other instance shares (for in-memory databases).
func (r *Registry) New() *Mutex { return &Mutex{registry: r, slot: make(chan struct{}, 1)} }

// For returns the lock of a canonical path, creating it on first use.
func (r *Registry) For(canonical string) *Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mutex, ok := r.mutexes[canonical]; ok {
		return mutex
	}
	mutex := r.New()
	r.mutexes[canonical] = mutex
	return mutex
}

func (r *Registry) chain(ctx context.Context) []*held {
	chain, _ := ctx.Value(r.key).([]*held)
	return chain
}

// Run runs operation while holding the lock; the operation's context records that this chain holds it.
func (m *Mutex) Run(ctx context.Context, operation func(ctx context.Context) error) error {
	chain := m.registry.chain(ctx)
	for _, entry := range chain {
		if entry.mutex == m && entry.active.Load() {
			return core.NewIamError("DATABASE_IN_USE", "This call chain already holds this database through another adapter instance", 409)
		}
	}
	select {
	case m.slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	entry := &held{mutex: m}
	entry.active.Store(true)
	defer func() {
		entry.active.Store(false)
		<-m.slot
	}()
	next := append(append([]*held(nil), chain...), entry)
	return operation(context.WithValue(ctx, m.registry.key, next))
}

// CanonicalPath is the absolute, symlink- and short-name-resolved path of a database file (lower-cased on Windows),
// so every spelling of a file shares one lock.
func CanonicalPath(filename string) string {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		absolute = filename
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	} else if dir, err := filepath.EvalSymlinks(filepath.Dir(absolute)); err == nil {
		absolute = filepath.Join(dir, filepath.Base(absolute))
	}
	absolute = longPath(absolute)
	if runtime.GOOS == "windows" {
		absolute = strings.ToLower(absolute)
	}
	return absolute
}
