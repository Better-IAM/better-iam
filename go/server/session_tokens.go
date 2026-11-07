package server

// Skeleton of packages/server/src/session-tokens.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"regexp"

	"github.com/Better-IAM/better-iam/go/core"
)

// SessionTokenError is session-tokens.ts SessionTokenError (code INVALID_SESSION_TOKEN, status 401): Reason is
// malformed, signature, expired, ..., revoked; Message defaults to "The session token is invalid or expired".
type SessionTokenError struct {
	Reason  string
	Message string
}

func (e *SessionTokenError) Error() string {
	if e.Message == "" {
		return "The session token is invalid or expired"
	}
	return e.Message
}

// Code is the error code (INVALID_SESSION_TOKEN).
func (e *SessionTokenError) Code() string { return "INVALID_SESSION_TOKEN" }

// Status is the HTTP status (401).
func (e *SessionTokenError) Status() int { return 401 }

// Name is the JavaScript error name.
func (e *SessionTokenError) Name() string { return "SessionTokenError" }

// SessionTokenVerifier is session-tokens.ts SessionTokenVerifier.
type SessionTokenVerifier struct {
	server *ServerContext
}

// Verify (session-tokens.ts SessionTokenVerifier.verify): Verifies a compact session JWT and returns its claims, or
// throws `SessionTokenError`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SessionTokenVerifier) Verify(ctx context.Context, token string) (result *core.Object, err error) {
	err = notImplemented("session-tokens.ts SessionTokenVerifier.verify")
	return
}

// VerifyRequest (session-tokens.ts SessionTokenVerifier.verifyRequest): Verifies the `Authorization: Bearer <jwt>`
// header of a request (the scheme is case-insensitive).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SessionTokenVerifier) VerifyRequest(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	err = notImplemented("session-tokens.ts SessionTokenVerifier.verifyRequest")
	return
}

// CreateSessionTokenVerifier builds the SessionTokenVerifier (session-tokens.ts createSessionTokenVerifier). Its methods are stubs until the module is ported.
func CreateSessionTokenVerifier(options *core.Object) *SessionTokenVerifier {
	return &SessionTokenVerifier{}
}

// LooksLikeJwt (session-tokens.ts looksLikeJwt): true for a compact JWS shape (three base64url segments of at least
// two characters); says nothing about validity.
func LooksLikeJwt(value any) bool {
	text, ok := value.(string)
	return ok && jwtSegments.MatchString(text)
}

var jwtSegments = regexp.MustCompile(`^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$`)

// MaxSessionTokenLength is session-tokens.ts MAX_SESSION_TOKEN_LENGTH.
const MaxSessionTokenLength = 4096

// SessionTokenType is session-tokens.ts SESSION_TOKEN_TYPE.
const SessionTokenType = "biam-session+jwt"
