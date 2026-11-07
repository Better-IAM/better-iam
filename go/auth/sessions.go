package auth

// Port of packages/auth/src/service/sessions.ts: password sign-up and sign-in, plus session listing and revocation.
// Inputs are request bodies (*core.Object), validated here exactly as the TypeScript service validates them.

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

func body(input *core.Object) *core.Object {
	if input == nil {
		return core.NewObject()
	}
	return input
}

func success() *core.Object { return core.NewObject("success", true) }

// optionalText is `value === undefined ? undefined : text(value, field, max)`.
func optionalText(input *core.Object, key, field string, max int) (string, error) {
	value := input.Get(key)
	if core.IsUndefined(value) {
		return "", nil
	}
	return Text(value, field, max)
}

// SignUp registers a person in a child tenant: { identity, verificationRequired }.
func (s *Service) SignUp(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	if !s.options.SignUpEnabled || !boolOr(s.options.EmailPassword, true) {
		return nil, core.NewIamError("FEATURE_DISABLED", "Self registration is disabled", 403)
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	normalized, err := Email(input.Get("email"))
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "signup:"+normalized, "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		tenant, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return nil, err
		}
		if !flag(tenant, "parentId") {
			return nil, core.NewIamError("FORBIDDEN", "Root identity provisioning requires an administrator", 403)
		}
		password, hasPassword := input.Lookup("password")
		created, err := s.CreateIdentity(ctx, tx, CreateIdentityInput{
			TenantID: tenantID, Email: normalized, Name: input.Get("name"),
			Password: password, HasPassword: hasPassword && !core.IsUndefined(password),
		})
		if err != nil {
			return nil, err
		}
		// Nobody has proven this address yet: see Identity.unprovenPassword (FinishPasswordless acts on it).
		identity, err := tx.Put(ctx, "identities", created.Spread(core.NewObject("unprovenPassword", true)))
		if err != nil {
			return nil, err
		}
		if s.requireEmailVerification {
			token, err := s.challenge(ctx, tx, identity, "verify-email", core.NewObject("email", normalized), 24*60*60_000, "", "")
			if err != nil {
				return nil, err
			}
			if err := s.enqueue(ctx, tx, identity, "email", normalized, "verify-email", core.NewObject("token", token)); err != nil {
				return nil, err
			}
		}
		return core.NewObject("identity", PublicIdentity(identity), "verificationRequired", s.requireEmailVerification), nil
	})
}

// SignIn is password sign-in: a session or an MFA challenge. deviceToken (from "remember this device") lets a
// browser that completed MFA before skip the second factor.
func (s *Service) SignIn(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	if !boolOr(s.options.EmailPassword, true) {
		return nil, core.NewIamError("FEATURE_DISABLED", "Password authentication is disabled", 403)
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	normalized, err := Email(input.Get("email"))
	if err != nil {
		return nil, err
	}
	password, err := Text(input.Get("password"), "password", 1024)
	if err != nil {
		return nil, err
	}
	deviceToken, err := optionalText(input, "deviceToken", "deviceToken", 512)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "signin:"+normalized, "default"); err != nil {
		return nil, err
	}
	// A wrong password for a real, active account is counted after the refused transaction rolled back, without
	// holding the refusal (an unknown address writes nothing, so waiting would reveal which accounts exist).
	var failed *core.Object
	result, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		if err := s.methodAllowed(ctx, tx, tenantID, "password"); err != nil {
			return nil, err
		}
		matches, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", normalized), nil)
		if err != nil {
			return nil, err
		}
		var identity *core.Object
		if len(matches) > 0 {
			identity = matches[0]
		}
		// Unknown and passwordless-only accounts perform the same password-hash operation.
		hash := ""
		if identity != nil && !nullish(identity, "passwordHash") {
			hash = jsString(identity.Get("passwordHash"))
		} else if hash, err = s.dummyHash(); err != nil {
			return nil, err
		}
		valid, err := VerifyPassword(hash, password)
		if err != nil {
			return nil, err
		}
		// An expired identity is refused like a disabled one (and, like it, leaves no failure record).
		usable := identity != nil && str(identity, "status") == "active" && !s.identityExpired(identity)
		if identity == nil || !valid || !usable {
			if identity != nil && !valid && str(identity, "kind") == "user" && usable {
				failed = identity
			}
			return nil, core.NewIamError("INVALID_CREDENTIALS", "Invalid email or password", 401)
		}
		if s.requireEmailVerification && !flag(identity, "emailVerified") {
			return nil, core.NewIamError("EMAIL_UNVERIFIED", "Verify your email before signing in", 403)
		}
		if err := s.assertPasswordCurrent(ctx, tx, identity); err != nil {
			return nil, err
		}
		return s.CompleteAuthentication(ctx, tx, identity, "password", deviceToken)
	})
	if err != nil {
		if failed != nil {
			s.deferSignInFailure(ctx, failed, "password")
		}
		return nil, err
	}
	return result, nil
}

func sortDescending(rows []*core.Object, key string, idDescending bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		if d := numOr(rows[j], key, math.NaN()) - numOr(rows[i], key, math.NaN()); d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		if idDescending {
			return str(rows[i], "id") > str(rows[j], "id")
		}
		return str(rows[i], "id") < str(rows[j], "id")
	})
}

// ListSecurityEvents is the caller's own authentication trail (the auth:* audit events recorded for their identity
// in this tenant), newest first: { id, action, timestamp, impersonatorId?, sequence?, metadata? }.
func (s *Service) ListSecurityEvents(ctx context.Context, credentials core.CredentialInput, input *core.Object) ([]*core.Object, error) {
	input = body(input)
	limit := 50.0
	if !nullish(input, "limit") {
		value, ok := input.Get("limit").(float64)
		if !ok || !core.IsSafeInteger(value) {
			return nil, core.NewIamError("INVALID_INPUT", "limit must be an integer between 1 and 200")
		}
		limit = value
	}
	if limit < 1 || limit > 200 {
		return nil, core.NewIamError("INVALID_INPUT", "limit must be an integer between 1 and 200")
	}
	principal, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	events, err := s.options.Store.Find(ctx, "audit", core.NewObject("tenantId", principal.Identity.Get("tenantId"), "actorId", principal.Identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	var trail []*core.Object
	for _, event := range events {
		if strings.HasPrefix(str(event, "action"), "auth:") {
			trail = append(trail, event)
		}
	}
	sortDescending(trail, "timestamp", true)
	if len(trail) > int(limit) {
		trail = trail[:int(limit)]
	}
	out := make([]*core.Object, 0, len(trail))
	for _, event := range trail {
		item := core.NewObject("id", event.Get("id"), "action", event.Get("action"), "timestamp", event.Get("timestamp"))
		if value := event.Get("impersonatorId"); truthy(value) {
			item.Set("impersonatorId", value)
		}
		if value, ok := event.Get("sequence").(float64); ok {
			item.Set("sequence", value)
		}
		if value := event.Get("metadata"); truthy(value) {
			item.Set("metadata", value)
		}
		out = append(out, item)
	}
	return out, nil
}

// ListTrustedDevices lists the caller's remembered devices in this tenant, most recently used first, without their
// tokens.
func (s *Service) ListTrustedDevices(ctx context.Context, credentials core.CredentialInput) ([]*core.Object, error) {
	principal, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	devices, err := s.options.Store.Find(ctx, "authDevices", core.NewObject("identityId", principal.Identity.Get("id"), "tenantId", principal.Identity.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	now := float64(s.now())
	var live []*core.Object
	for _, device := range devices {
		if numOr(device, "expiresAt", math.NaN()) > now {
			live = append(live, device)
		}
	}
	sortDescending(live, "lastUsedAt", false)
	out := make([]*core.Object, 0, len(live))
	for _, device := range live {
		safe := device.Spread()
		safe.Delete("tokenHash")
		safe.Delete("uniqueKey")
		out = append(out, safe)
	}
	return out, nil
}

// RevokeTrustedDevice forgets one remembered device; the next sign-in from it asks for MFA again. Requires recent
// authentication.
func (s *Service) RevokeTrustedDevice(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		deviceID, err := Text(input.Get("deviceId"), "deviceId")
		if err != nil {
			return nil, err
		}
		device, err := tx.Get(ctx, "authDevices", deviceID)
		if err != nil {
			return nil, err
		}
		if device == nil || !core.StrictEquals(device.Get("identityId"), principal.Identity.Get("id")) ||
			!core.StrictEquals(device.Get("tenantId"), principal.Identity.Get("tenantId")) {
			return nil, core.NewIamError("NOT_FOUND", "Device not found", 404)
		}
		if err := tx.Delete(ctx, "authDevices", str(device, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:device:revoke", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// RevokeTrustedDevices forgets every remembered device of the caller: { revoked }. Requires recent authentication.
func (s *Service) RevokeTrustedDevices(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		devices, err := tx.Find(ctx, "authDevices", core.NewObject("identityId", principal.Identity.Get("id"), "tenantId", principal.Identity.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		for _, device := range devices {
			if err := tx.Delete(ctx, "authDevices", str(device, "id")); err != nil {
				return nil, err
			}
		}
		if len(devices) > 0 {
			if err := s.audit(ctx, tx, principal.Identity, "auth:device:revoke", nil, nil); err != nil {
				return nil, err
			}
		}
		return core.NewObject("revoked", float64(len(devices))), nil
	})
}

// GetSession returns the caller's identity and session plus the limits in force for their tenant: { identity,
// session, limits: { lifetimeMs, idleTimeoutMs, idleExpiresAt, now } }.
func (s *Service) GetSession(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	principal, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	tenant, err := s.options.Store.Get(ctx, "tenants", str(principal.Identity, "tenantId"))
	if err != nil {
		return nil, err
	}
	lifetime, idle := s.SessionLimits(tenant)
	session := principal.Session
	return core.NewObject(
		"identity", PublicIdentity(principal.Identity),
		"session", PublicSession(session),
		"limits", core.NewObject(
			"lifetimeMs", lifetime,
			"idleTimeoutMs", idle,
			"idleExpiresAt", jsMin(numOr(session, "lastSeenAt", math.NaN())+idle, numOr(session, "expiresAt", math.NaN())),
			"now", float64(s.now()),
		),
	), nil
}

// ListSessions lists the caller's live sessions; current marks the one making this call.
func (s *Service) ListSessions(ctx context.Context, credentials core.CredentialInput) ([]*core.Object, error) {
	principal, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	sessions, err := s.options.Store.Find(ctx, "sessions", core.NewObject("identityId", principal.Identity.Get("id"), "tenantId", principal.Identity.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	now := float64(s.now())
	out := []*core.Object{}
	for _, session := range sessions {
		if numOr(session, "expiresAt", math.NaN()) > now {
			item := PublicSession(session)
			item.Set("current", str(session, "id") == str(principal.Session, "id"))
			out = append(out, item)
		}
	}
	return out, nil
}

// RevokeSession ends one of the caller's sessions. Requires recent authentication.
func (s *Service) RevokeSession(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		sessionID, err := Text(input.Get("sessionId"), "sessionId")
		if err != nil {
			return nil, err
		}
		session, err := tx.Get(ctx, "sessions", sessionID)
		if err != nil {
			return nil, err
		}
		if session == nil || !core.StrictEquals(session.Get("identityId"), principal.Identity.Get("id")) ||
			!core.StrictEquals(session.Get("tenantId"), principal.Identity.Get("tenantId")) {
			return nil, core.NewIamError("NOT_FOUND", "Session not found", 404)
		}
		if err := s.EndSession(ctx, tx, str(session, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:session:revoke", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// RevokeOtherSessions ends every other user session of the caller's identity in this tenant ("sign out everywhere
// else"): { revoked }.
func (s *Service) RevokeOtherSessions(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", principal.Identity.Get("id"), "tenantId", principal.Identity.Get("tenantId"), "kind", "user"), nil)
		if err != nil {
			return nil, err
		}
		revoked := 0
		for _, session := range sessions {
			if str(session, "id") != str(principal.Session, "id") {
				if err := s.EndSession(ctx, tx, str(session, "id")); err != nil {
					return nil, err
				}
				revoked++
			}
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:session:revoke-others", nil, nil); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", float64(revoked)), nil
	})
}

// SignOut ends the caller's session.
func (s *Service) SignOut(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.EndSession(ctx, tx, str(principal.Session, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:session:revoke", principal.Session, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}
