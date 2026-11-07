// Package auth is the Go port of @better-iam/auth (packages/auth): tenant-scoped authentication with passwords,
// passkeys, magic links, email and SMS codes, TOTP with recovery codes, remembered devices, and sessions, plus the
// sealed outbox, rate limiting, password screening, guarded outbound fetches and message templates the server
// builds on. Records, tokens, hashes and sealed values are byte-compatible with the TypeScript implementation, so a
// fleet of TypeScript and Go replicas can share one database.
//
// File names mirror the TypeScript modules: crypto.go, outbox.go, password_policy.go, rate_limit.go, safe_fetch.go,
// templates.go, types.go, validation.go, and the service modules base.go, sessions.go, account.go, passwordless.go,
// mfa.go and passkeys.go. argon2.go, totp.go, cbor.go and webauthn*.go port the behavior of the libraries the
// TypeScript service depends on (node-argon2, otplib, @simplewebauthn/server).
package auth

// AuthService is the authentication service assembled from the feature modules (sessions, account management,
// passwordless, MFA, passkeys) over a shared base. Low-level transaction helpers are for trusted server
// integrations only.
type AuthService = Service

// CreateAuth builds the authentication service.
func CreateAuth(options Options) (*AuthService, error) { return New(options) }
