package auth

// Port of packages/auth/src/service/account.ts: email verification, password recovery and change,
// reauthentication, and email/phone changes.

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"strconv"

	"github.com/Better-IAM/better-iam/go/core"
)

// sixDigitCode is randomInt(0, 1_000_000) padded to six digits.
func sixDigitCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	code := strconv.FormatInt(n.Int64(), 10)
	for len(code) < 6 {
		code = "0" + code
	}
	return code
}

// RequestEmailVerification queues a verify-email link for an unverified, active person (and answers the same
// either way).
func (s *Service) RequestEmailVerification(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	normalized, err := Email(input.Get("email"))
	if err != nil {
		return nil, err
	}
	if s.options.SendEmail == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Email delivery is not configured")
	}
	if err := s.rate(ctx, tenantID, "verify-email:"+normalized, "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		matches, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", normalized, "status", "active", "kind", "user"), nil)
		if err != nil {
			return nil, err
		}
		if len(matches) > 0 && !flag(matches[0], "emailVerified") {
			identity := matches[0]
			token, err := s.challenge(ctx, tx, identity, "verify-email", core.NewObject("email", normalized), 24*60*60_000, "", "")
			if err != nil {
				return nil, err
			}
			if err := s.enqueue(ctx, tx, identity, "email", normalized, "verify-email", core.NewObject("token", token)); err != nil {
				return nil, err
			}
		}
		return success(), nil
	})
}

// VerifyEmail redeems a verify-email link.
func (s *Service) VerifyEmail(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("token"), "token")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "verify-token:"+HashToken(token), "default"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, input.Get("tenantId"), input.Get("token"), "verify-email", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		// The link proves control of the address it was mailed to, and only that one.
		if err := s.assertSameAddress(challenge, identity); err != nil {
			return nil, err
		}
		identity.Set("emailVerified", true)
		// The address owner completed the sign-up themselves, so the password they chose stands.
		identity.Delete("unprovenPassword")
		if _, err := tx.Put(ctx, "identities", identity); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, identity, "auth:email:verify", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// RequestPasswordReset queues a password-reset link for a verified, active person (and answers the same either way).
func (s *Service) RequestPasswordReset(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	normalized, err := Email(input.Get("email"))
	if err != nil {
		return nil, err
	}
	if s.options.SendEmail == nil || !boolOr(s.options.EmailPassword, true) {
		return nil, core.NewIamError("FEATURE_DISABLED", "Password recovery is unavailable")
	}
	if err := s.rate(ctx, tenantID, "password-reset:"+normalized, "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		matches, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", normalized, "status", "active", "kind", "user"), nil)
		if err != nil {
			return nil, err
		}
		if len(matches) > 0 && flag(matches[0], "emailVerified") {
			identity := matches[0]
			token, err := s.challenge(ctx, tx, identity, "password-reset", core.NewObject("email", normalized), 0, "", "")
			if err != nil {
				return nil, err
			}
			if err := s.enqueue(ctx, tx, identity, "email", normalized, "password-reset", core.NewObject("token", token)); err != nil {
				return nil, err
			}
		}
		return success(), nil
	})
}

// IssuePasswordReset queues a password-reset email for an identity on an administrator's behalf, verified or not.
func (s *Service) IssuePasswordReset(ctx context.Context, tx core.IamStore, identity *core.Object) error {
	if s.options.SendEmail == nil || !boolOr(s.options.EmailPassword, true) {
		return core.NewIamError("FEATURE_DISABLED", "Password recovery is unavailable")
	}
	if str(identity, "kind") != "user" || str(identity, "status") != "active" || !flag(identity, "email") {
		return core.NewIamError("INVALID_INPUT", "Only active people with an email can reset a password")
	}
	token, err := s.challenge(ctx, tx, identity, "password-reset", core.NewObject("email", identity.Get("email")), 0, "", "")
	if err != nil {
		return err
	}
	return s.enqueue(ctx, tx, identity, "email", jsString(identity.Get("email")), "password-reset", core.NewObject("token", token))
}

// assertSameAddress refuses a mailed link once the identity's address is no longer the one it was sent to.
func (s *Service) assertSameAddress(challenge, identity *core.Object) error {
	if !flag(identity, "email") || !core.StrictEquals(child(challenge, "payload").Get("email"), identity.Get("email")) {
		return core.NewIamError("INVALID_CHALLENGE", "Email has changed", 401)
	}
	return nil
}

// ResetPassword redeems a password-reset link with a new password; every session, challenge and remembered device
// of the person is revoked. Recovery never creates a session or removes MFA.
func (s *Service) ResetPassword(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	if !boolOr(s.options.EmailPassword, true) {
		return nil, core.NewIamError("FEATURE_DISABLED", "Password authentication is disabled", 403)
	}
	newPassword, err := Password(input.Get("password"))
	if err != nil {
		return nil, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("token"), "token")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "reset-token:"+HashToken(token), "default"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, input.Get("tenantId"), input.Get("token"), "password-reset", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		if err := s.assertSameAddress(challenge, identity); err != nil {
			return nil, err
		}
		// A password chosen through the mailed link is the address owner's.
		identity.Delete("unprovenPassword")
		tenant, err := tx.Get(ctx, "tenants", str(identity, "tenantId"))
		if err != nil {
			return nil, err
		}
		if err := s.SetPassword(ctx, tx, tenant, identity, newPassword); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "identities", identity); err != nil {
			return nil, err
		}
		if err := s.RevokeIdentity(ctx, tx, str(identity, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, identity, "auth:password:reset", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// ChangePassword replaces the caller's password after checking the current one; requires recent authentication and
// revokes every session.
func (s *Service) ChangePassword(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	newPassword, err := Password(input.Get("password"))
	if err != nil {
		return nil, err
	}
	current, err := Text(input.Get("currentPassword"), "currentPassword", 1024)
	if err != nil {
		return nil, err
	}
	initial, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, str(initial.Identity, "tenantId"), "password-change:"+str(initial.Identity, "id"), "default"); err != nil {
		return nil, err
	}
	// A wrong current password is a failed attempt on the account like one at sign-in; it is recorded once the
	// refusal rolled back.
	var failed *core.Object
	result, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		valid := false
		if hash := str(principal.Identity, "passwordHash"); hash != "" {
			if valid, err = VerifyPassword(hash, current); err != nil {
				return nil, err
			}
		}
		if !valid {
			failed = principal.Identity
			return nil, core.NewIamError("INVALID_CREDENTIALS", "Invalid current password", 401)
		}
		tenant, err := tx.Get(ctx, "tenants", str(principal.Identity, "tenantId"))
		if err != nil {
			return nil, err
		}
		if err := s.SetPassword(ctx, tx, tenant, principal.Identity, newPassword); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "identities", principal.Identity); err != nil {
			return nil, err
		}
		if err := s.RevokeIdentity(ctx, tx, str(principal.Identity, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:password:change", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
	if err != nil {
		if failed != nil {
			s.deferSignInFailure(ctx, failed, "password")
		}
		return nil, err
	}
	return result, nil
}

// Reauthenticate re-runs the password (and MFA) ceremony for an existing session so sensitive operations can
// require recent authentication: a new session or an MFA challenge.
func (s *Service) Reauthenticate(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	if !boolOr(s.options.EmailPassword, true) {
		return nil, core.NewIamError("FEATURE_DISABLED", "Password authentication is disabled", 403)
	}
	password, err := Text(input.Get("password"), "password", 1024)
	if err != nil {
		return nil, err
	}
	initial, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	if flag(initial.Session, "impersonatorId") {
		return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "An impersonated session cannot be re-authenticated", 403)
	}
	if err := s.rate(ctx, str(initial.Identity, "tenantId"), "reauth:"+str(initial.Identity, "id"), "default"); err != nil {
		return nil, err
	}
	var failed *core.Object
	result, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.methodAllowed(ctx, tx, str(principal.Identity, "tenantId"), "password"); err != nil {
			return nil, err
		}
		valid := false
		if hash := str(principal.Identity, "passwordHash"); hash != "" {
			if valid, err = VerifyPassword(hash, password); err != nil {
				return nil, err
			}
		}
		if !valid {
			failed = principal.Identity
			return nil, core.NewIamError("INVALID_CREDENTIALS", "Invalid password", 401)
		}
		// As at sign-in: an expired password is refused once verified, so each new session cannot dodge the expiry.
		if err := s.assertPasswordCurrent(ctx, tx, principal.Identity); err != nil {
			return nil, err
		}
		return s.CompleteAuthentication(ctx, tx, principal.Identity, "password", "")
	})
	if err != nil {
		if failed != nil {
			s.deferSignInFailure(ctx, failed, "password")
		}
		return nil, err
	}
	return result, nil
}

// RequestEmailChange mails a confirmation link to a new address. Requires recent authentication.
func (s *Service) RequestEmailChange(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	normalized, err := Email(input.Get("email"))
	if err != nil {
		return nil, err
	}
	initial, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, str(initial.Identity, "tenantId"), "email-change:"+str(initial.Identity, "id"), "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		// A guest's address is the one their invitation proved and the cross-tenant settings admitted.
		if flag(principal.Identity, "guest") {
			return nil, core.NewIamError("INVALID_INPUT", "A guest’s email address cannot change: ask the organization to invite the new address")
		}
		token, err := s.challenge(ctx, tx, principal.Identity, "email-change", core.NewObject("email", normalized), 10*60_000, "", str(principal.Session, "id"))
		if err != nil {
			return nil, err
		}
		if err := s.enqueue(ctx, tx, principal.Identity, "email", normalized, "email-change", core.NewObject("token", token)); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// ConfirmEmailChange redeems an email-change link while the session that asked for it is still valid; every session
// of the person is revoked.
func (s *Service) ConfirmEmailChange(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("token"), "token")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "email-change-token:"+HashToken(token), "default"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, input.Get("tenantId"), input.Get("token"), "email-change", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		var session *core.Object
		if sessionID := str(challenge, "sessionId"); sessionID != "" {
			if session, err = tx.Get(ctx, "sessions", sessionID); err != nil {
				return nil, err
			}
		}
		if session == nil || numOr(session, "expiresAt", math.NaN()) <= float64(s.now()) {
			return nil, core.NewIamError("UNAUTHENTICATED", "Original session is no longer valid", 401)
		}
		normalized, err := Email(child(challenge, "payload").Get("email"))
		if err != nil {
			return nil, err
		}
		others, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", normalized), nil)
		if err != nil {
			return nil, err
		}
		for _, item := range others {
			if str(item, "id") != str(identity, "id") {
				return nil, core.NewIamError("IDENTITY_EXISTS", "Email is already in use in this tenant", 409)
			}
		}
		identity.Set("email", normalized)
		identity.Set("emailVerified", true)
		identity.Set("uniqueKey", "email:"+normalized)
		if _, err := tx.Put(ctx, "identities", identity); err != nil {
			return nil, err
		}
		if err := s.RevokeIdentity(ctx, tx, str(identity, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, identity, "auth:email:change", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// StartPhoneVerification texts a six-digit code to a phone number. Requires recent authentication.
func (s *Service) StartPhoneVerification(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	normalized, err := Phone(input.Get("phone"))
	if err != nil {
		return nil, err
	}
	initial, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, str(initial.Identity, "tenantId"), "phone-verify:"+str(initial.Identity, "id"), "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		token := sixDigitCode()
		if _, err := s.challenge(ctx, tx, principal.Identity, "phone-verify", core.NewObject("phone", normalized), 5*60_000, token, str(principal.Session, "id")); err != nil {
			return nil, err
		}
		if err := s.enqueue(ctx, tx, principal.Identity, "sms", normalized, "phone-verify", core.NewObject("token", token)); err != nil {
			return nil, err
		}
		return success(), nil
	})
}

// ConfirmPhoneVerification redeems the texted code from the same session and marks the phone verified.
func (s *Service) ConfirmPhoneVerification(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	normalized, err := Phone(input.Get("phone"))
	if err != nil {
		return nil, err
	}
	if _, err := Text(input.Get("code"), "code", 6); err != nil {
		return nil, err
	}
	initial, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, str(initial.Identity, "tenantId"), "phone-code:"+str(initial.Identity, "id"), "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		identityID := str(principal.Identity, "id")
		challenge, err := s.readChallenge(ctx, tx, principal.Identity.Get("tenantId"), input.Get("code"), "phone-verify", challengeMatch{identityID: identityID})
		if err != nil {
			return nil, err
		}
		if str(challenge, "identityId") != identityID || !core.StrictEquals(challenge.Get("sessionId"), principal.Session.Get("id")) ||
			!core.StrictEquals(child(challenge, "payload").Get("phone"), normalized) {
			return nil, core.NewIamError("INVALID_CHALLENGE", "Invalid verification code", 401)
		}
		existing, err := tx.Find(ctx, "identities", core.NewObject("tenantId", principal.Identity.Get("tenantId"), "phone", normalized, "phoneVerified", true), nil)
		if err != nil {
			return nil, err
		}
		for _, identity := range existing {
			if str(identity, "id") != identityID {
				return nil, core.NewIamError("PHONE_EXISTS", "Phone is already verified by another identity", 409)
			}
		}
		principal.Identity.Set("phone", normalized)
		principal.Identity.Set("phoneVerified", true)
		if _, err := tx.Put(ctx, "identities", principal.Identity); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:phone:verify", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}
