package auth

// Port of packages/auth/src/types.ts. Records (identities, sessions, challenges, MFA records, passkeys, devices,
// rate counters, sign-in ledgers, network blocks, password history) are *core.Object values with exactly the
// TypeScript field names, so Go replicas read and write the same rows; the comments below list their fields.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// DeliveryMessage is one outbox message handed to a delivery callback.
type DeliveryMessage struct {
	ID       string            `json:"id"`
	TenantID string            `json:"tenantId"`
	To       string            `json:"to"`
	Template string            `json:"template"`
	Payload  map[string]string `json:"payload"`
	// SignInURL is the organization's sign-in URL (its own subdomain, custom hostname, or regional address), added by
	// the server when organization addresses or regions are configured, so the links in the message can point there.
	SignInURL string `json:"signInUrl,omitempty"`
}

// Deliverer delivers one outbox message (sendEmail, sendSms, deliverWebhook). Callbacks must deduplicate by ID.
type Deliverer func(ctx context.Context, message DeliveryMessage) error

// RateLimitInput is one attempt counted by a RateLimiter.
type RateLimitInput struct {
	Key      string
	TenantID string
	Limit    float64
	WindowMs int64
	Now      int64
}

// RateLimiter is a durable attempt counter. The default limiter stores counters in the IAM database; supply one
// backed by Redis or similar for multi-instance deployments.
type RateLimiter interface {
	// Consume returns true when the attempt is permitted. Implementations must count the attempt even when the
	// caller later fails.
	Consume(ctx context.Context, input RateLimitInput) (bool, error)
}

// RateLimitResetter is the optional RateLimiter.reset: clears one counter so an administrator can unlock an account.
type RateLimitResetter interface {
	Reset(ctx context.Context, key, tenantID string) error
}

// RateLimitOptions configures attempt limits; nil fields take the defaults.
type RateLimitOptions struct {
	// Attempts per window for ordinary flows such as password sign-in (default 10).
	Attempts *int64
	// SensitiveAttempts per window for sensitive flows such as MFA, recovery, and delivery requests (default 5).
	SensitiveAttempts *int64
	// WindowMs is the rolling window length (default 15 minutes).
	WindowMs *int64
	// IPAttempts per window from one client IP across every authentication flow of a tenant, on top of the
	// per-account limits (0, the default, disables it). Needs a recorded client IP (WithClient).
	IPAttempts *int64
	Limiter    RateLimiter
}

// PasskeyOptions enables WebAuthn passkeys for one relying party.
type PasskeyOptions struct {
	RPID string
	// RPName defaults to the application name.
	RPName string
}

// Options mirrors AuthOptions field for field; nil pointers take the TypeScript defaults.
type Options struct {
	Store  core.IamStore
	Secret string
	// PreviousSecrets are secrets being rotated out: values sealed with them (authenticator secrets, pending
	// deliveries) and challenge links issued under them keep working until re-sealed or expired. New values always
	// use Secret.
	PreviousSecrets []string
	BaseURL         string
	TrustedOrigins  []string
	// AppName defaults to "Better IAM" (an empty string means the default).
	AppName       string
	SignUpEnabled bool
	// RequireEmailVerification defaults to SignUpEnabled.
	RequireEmailVerification *bool
	// EmailPassword defaults to true.
	EmailPassword     *bool
	PasswordlessEmail bool
	PasswordlessSms   bool
	SendEmail         Deliverer
	SendSms           Deliverer
	// DeliverWebhook delivers webhook outbox messages; To is the webhook ID and the payload carries url and the
	// JSON body.
	DeliverWebhook Deliverer
	// MaxDeliveryAttempts abandons outbox messages after this many failed attempts (default 25).
	MaxDeliveryAttempts    *int64
	SessionLifetimeMs      *int64
	SessionIdleTimeoutMs   *int64
	RecentAuthenticationMs *int64
	// TrustedDeviceLifetimeMs: how long "remember this device" lets a browser skip MFA (default 30 days, at most
	// 365; 0 disables the feature).
	TrustedDeviceLifetimeMs *int64
	// SignInNotifications queues a new-sign-in email when a session starts from a client none of the person's live
	// sessions or remembered devices has used. Tenants override it with authPolicy.notifyNewSignIn.
	SignInNotifications bool
	// MfaEmailCodes lets people without an authenticator satisfy MFA with an emailed code. Tenants override it with
	// authPolicy.mfaEmailCodes.
	MfaEmailCodes bool
	// FailedSignInAlerts emails a sign-in-failures alert once this many attempts failed since the last sign-in
	// (0 disables it; at most 1000). Needs SendEmail.
	FailedSignInAlerts int64
	RateLimits         *RateLimitOptions
	// RequireMfa adds a tenant-level MFA requirement for an identity (tenant and identity records).
	RequireMfa func(ctx context.Context, tenant, identity *core.Object) (bool, error)
	Passkeys   *PasskeyOptions
	// OnAudit runs inside the transaction that records an authentication audit event, so hosts can fan events out
	// atomically.
	OnAudit func(ctx context.Context, tx core.IamStore, event *core.Object) error
	// Now injects time (epoch milliseconds) for deterministic integration tests.
	Now func() int64
	// PasswordPolicy is the deployment-wide password screening.
	PasswordPolicy *PasswordPolicyOptions
}

// SignInFailureReason is what a failed attempt presented wrongly: password, mfa or recovery-code.
type SignInFailureReason = string

// Principal is a verified identity and session (AuthenticatedPrincipal) as stored records.
type Principal struct {
	Identity *core.Object `json:"identity"`
	Session  *core.Object `json:"session"`
}

// Core returns the principal as typed core views (fields the structs do not model are dropped).
func (p *Principal) Core() (*core.AuthenticatedPrincipal, error) {
	var identity core.Identity
	var session core.Session
	if err := core.FromRecord(p.Identity, &identity); err != nil {
		return nil, err
	}
	if err := core.FromRecord(p.Session, &session); err != nil {
		return nil, err
	}
	return &core.AuthenticatedPrincipal{Identity: &identity, Session: &session}, nil
}

// MfaCredential is what MFA enrollment starts from: a session credential, or (when Credentials is nil) a login
// challenge of the tenant.
type MfaCredential struct {
	Credentials *core.CredentialInput
	TenantID    string
	Challenge   string
}

// Record field reference (collection: fields):
//
//	authChallenges  Challenge: id, tenantId, identityId, purpose, tokenHash, payload (string map), expiresAt, sessionId?
//	authMfa         MfaRecord: id (= identityId), tenantId, identityId, encryptedSecret, recoveryHashes, enabled,
//	                lastUsedStep, enrollmentExpiresAt?, enrollmentCredential?
//	authPasskeys    PasskeyRecord: id, tenantId, uniqueKey (= credentialId), identityId, credentialId, publicKey
//	                (base64url COSE key), counter, transports?, name?, createdAt?, lastUsedAt?, deviceType?
//	                ('singleDevice' | 'multiDevice'), backedUp?, aaguid?
//	authDevices     TrustedDevice: id, tenantId, identityId, tokenHash, uniqueKey, createdAt, expiresAt, lastUsedAt,
//	                client?
//	authRateLimits  RateRecord: id (= key), tenantId, count, resetAt
//	authSignIns     SignInLedger: id (= identityId), tenantId, identityId, lastAt?, lastClient?, failedAttempts,
//	                lastFailedAt?, lastFailedClient?
//	authBlocks      NetworkBlock: id, tenantId, network, reason, createdAt, createdBy, expiresAt?, platform?
//	passwordHistory PasswordHistoryRecord: id, tenantId, identityId, hash, createdAt
