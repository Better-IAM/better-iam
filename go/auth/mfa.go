package auth

// Port of packages/auth/src/service/mfa.ts: TOTP enrollment, verification, recovery codes, emailed MFA codes, and
// disabling where the tenant allows it.

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math"
	"regexp"

	"github.com/Better-IAM/better-iam/go/core"
)

// mfaCodeDigest is the stored form of an emailed MFA code: keyed with the deployment secret and bound to its login
// challenge, since a plain hash of six digits is reversed by trying all million values.
func (s *Service) mfaCodeDigest(challenge *core.Object, code string, secret string) string {
	return s.DigestChallenge(str(challenge, "tenantId"), "mfa-code:"+str(challenge, "id")+":"+code, secret)
}

type mfaActor struct {
	identity       *core.Object
	principal      *Principal
	loginChallenge *core.Object
}

// mfaActor resolves who is enrolling: a restricted login challenge (first factor passed) or a recently
// authenticated session.
func (s *Service) mfaActor(ctx context.Context, tx core.IamStore, credential MfaCredential) (*mfaActor, error) {
	if credential.Credentials == nil {
		loginChallenge, err := s.readChallenge(ctx, tx, credential.TenantID, credential.Challenge, "mfa-login", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(loginChallenge, "identityId"), credential.TenantID)
		if err != nil {
			return nil, err
		}
		// A password alone must not add a factor over an existing one: an enabled authenticator or a usable passkey
		// has to be presented first (then enroll from the recently authenticated session).
		record, err := tx.Get(ctx, "authMfa", str(identity, "id"))
		if err != nil {
			return nil, err
		}
		enrolled := flag(record, "enabled")
		if !enrolled {
			if enrolled, err = s.passkeyFactor(ctx, tx, identity); err != nil {
				return nil, err
			}
		}
		if enrolled {
			return nil, core.NewIamError("MFA_REQUIRED", "Use an existing MFA factor before changing enrollment", 403)
		}
		return &mfaActor{identity: identity, loginChallenge: loginChallenge}, nil
	}
	principal, err := s.Authenticate(ctx, *credential.Credentials)
	if err != nil {
		return nil, err
	}
	if err := s.RequireRecent(principal); err != nil {
		return nil, err
	}
	return &mfaActor{identity: principal.Identity, principal: principal}, nil
}

func (a *mfaActor) credentialID() any {
	if a.principal != nil {
		return a.principal.Session.Get("id")
	}
	if a.loginChallenge != nil {
		return a.loginChallenge.Get("id")
	}
	return core.Undefined
}

// BeginMfa starts authenticator enrollment: { secret, uri }.
func (s *Service) BeginMfa(ctx context.Context, credential MfaCredential) (*core.Object, error) {
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		actor, err := s.mfaActor(ctx, tx, credential)
		if err != nil {
			return nil, err
		}
		identityID := str(actor.identity, "id")
		existing, err := tx.Get(ctx, "authMfa", identityID)
		if err != nil {
			return nil, err
		}
		if flag(existing, "enabled") {
			return nil, core.NewIamError("MFA_ALREADY_ENABLED", "MFA is already enabled", 409)
		}
		// 160 bits, as RFC 4226 recommends.
		secret := GenerateTotpSecret(20)
		record := core.NewObject(
			"id", identityID,
			"tenantId", actor.identity.Get("tenantId"),
			"identityId", identityID,
			"encryptedSecret", EncryptSecret(secret, s.options.Secret, "mfa:"+identityID),
			"recoveryHashes", []any{},
			"enabled", false,
			"lastUsedStep", -1.0,
			"enrollmentExpiresAt", float64(s.now()+10*60_000),
			"enrollmentCredential", actor.credentialID(),
		)
		if existing != nil {
			_, err = tx.Put(ctx, "authMfa", record)
		} else {
			_, err = tx.Insert(ctx, "authMfa", record)
		}
		if err != nil {
			return nil, err
		}
		account := identityID
		if !nullish(actor.identity, "email") {
			account = jsString(actor.identity.Get("email"))
		}
		return core.NewObject("secret", secret, "uri", TotpKeyURI(account, s.appName, secret)), nil
	})
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

// checkTotp accepts a code once per time step; the step is recorded so a captured code cannot be replayed.
func (s *Service) checkTotp(record *core.Object, code string) (float64, error) {
	if !sixDigits.MatchString(code) {
		return 0, core.NewIamError("INVALID_MFA", "Invalid MFA code", 401)
	}
	secret, err := DecryptSecret(str(record, "encryptedSecret"), s.Secrets, "mfa:"+jsString(record.Get("identityId")))
	if err != nil {
		return 0, err
	}
	now := s.now()
	delta, ok, err := TotpCheckDelta(code, secret, now, 1)
	if err != nil {
		return 0, err
	}
	step := math.Floor(float64(now)/30_000) + float64(delta)
	if !ok || step <= numOr(record, "lastUsedStep", math.NaN()) {
		return 0, core.NewIamError("INVALID_MFA", "Invalid or previously used MFA code", 401)
	}
	return step, nil
}

// VerifyStepUpCode verifies a first-hand TOTP code for an MFA step-up on an existing credential, inside the
// caller's transaction: { verifiedAt }. Only an enrolled authenticator counts; the code's time step is recorded.
// The caller rate-limits the attempt (LimitAttempt, sensitive tier) outside the transaction.
func (s *Service) VerifyStepUpCode(ctx context.Context, tx core.IamStore, identity *core.Object, code any) (*core.Object, error) {
	var record *core.Object
	if str(identity, "kind") == "user" {
		var err error
		if record, err = tx.Get(ctx, "authMfa", str(identity, "id")); err != nil {
			return nil, err
		}
	}
	if !flag(record, "enabled") || !core.StrictEquals(record.Get("tenantId"), identity.Get("tenantId")) {
		return nil, core.NewIamError("MFA_NOT_ENROLLED", "MFA is not enrolled", 403)
	}
	text, _ := code.(string)
	step, err := s.checkTotp(record, text)
	if err != nil {
		return nil, err
	}
	record.Set("lastUsedStep", step)
	if _, err := tx.Put(ctx, "authMfa", record); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, tx, identity, "auth:mfa:step-up", nil, nil); err != nil {
		return nil, err
	}
	return core.NewObject("verifiedAt", float64(s.now())), nil
}

// ConfirmMfaInput is ConfirmMfa's input.
type ConfirmMfaInput struct {
	Credential     MfaCredential
	Code           string
	RememberDevice bool
}

func recoveryCodes() ([]any, []any) {
	codes := make([]any, 10)
	hashes := make([]any, 10)
	for index := range codes {
		code := hex.EncodeToString(randomBytes(12))
		codes[index] = code
		hashes[index] = HashToken(code)
	}
	return codes, hashes
}

// ConfirmMfa enables the authenticator with its first code: the new session ({ token, session }, plus deviceToken
// and deviceExpiresAt when RememberDevice is set and allowed) and recoveryCodes.
func (s *Service) ConfirmMfa(ctx context.Context, input ConfirmMfaInput) (*core.Object, error) {
	actor, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*mfaActor, error) {
		return s.mfaActor(ctx, tx, input.Credential)
	})
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, str(actor.identity, "tenantId"), "mfa-enroll:"+str(actor.identity, "id"), "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		verified, err := s.mfaActor(ctx, tx, input.Credential)
		if err != nil {
			return nil, err
		}
		record, err := tx.Get(ctx, "authMfa", str(verified.identity, "id"))
		if err != nil {
			return nil, err
		}
		enrollmentExpiresAt, isNumber := num(record, "enrollmentExpiresAt")
		valid := record != nil && !flag(record, "enabled") && isNumber && enrollmentExpiresAt > float64(s.now()) &&
			core.StrictEquals(record.Get("enrollmentCredential"), verified.credentialID())
		if !valid {
			return nil, core.NewIamError("INVALID_CHALLENGE", "MFA enrollment is invalid or expired", 401)
		}
		step, err := s.checkTotp(record, input.Code)
		if err != nil {
			return nil, err
		}
		record.Set("lastUsedStep", step)
		record.Set("enabled", true)
		codes, hashes := recoveryCodes()
		record.Set("recoveryHashes", hashes)
		if _, err := tx.Put(ctx, "authMfa", record); err != nil {
			return nil, err
		}
		if err := s.RevokeIdentity(ctx, tx, str(verified.identity, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, verified.identity, "auth:mfa:enable", nil, nil); err != nil {
			return nil, err
		}
		method := ""
		if verified.loginChallenge != nil {
			method = str(child(verified.loginChallenge, "payload"), "method")
		}
		if method == "" && verified.principal != nil {
			method = str(verified.principal.Session, "method")
		}
		session, err := s.IssueSession(ctx, tx, verified.identity, IssueSessionOptions{Mfa: true, Method: method})
		if err != nil {
			return nil, err
		}
		if input.RememberDevice {
			device, err := s.RememberDevice(ctx, tx, verified.identity)
			if err != nil {
				return nil, err
			}
			session.Assign(device)
		}
		session.Set("recoveryCodes", codes)
		return session, nil
	})
}

// VerifyMfa completes a login challenge with an authenticator code, or (with nothing enrolled) the code emailed for
// this very challenge: a session (plus the device token with rememberDevice). input: { tenantId, challenge, code,
// rememberDevice? }.
func (s *Service) VerifyMfa(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	code, err := Text(input.Get("code"), "code", 6)
	if err != nil {
		return nil, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("challenge"), "challenge")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "mfa:"+HashToken(token), "sensitive"); err != nil {
		return nil, err
	}
	// Also per person: each correct password mints a new challenge with a fresh per-challenge budget.
	if err := s.rateChallengeIdentity(ctx, tenantID, token, "mfa-login", "mfa-verify"); err != nil {
		return nil, err
	}
	// A wrong code for a real login challenge counts as a failed attempt once the refusal rolled back.
	var attempted *core.Object
	result, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, input.Get("tenantId"), input.Get("challenge"), "mfa-login", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		attempted = identity
		record, err := tx.Get(ctx, "authMfa", str(identity, "id"))
		if err != nil {
			return nil, err
		}
		payload := child(challenge, "payload")
		if flag(record, "enabled") {
			step, err := s.checkTotp(record, code)
			if err != nil {
				return nil, err
			}
			record.Set("lastUsedStep", step)
			if _, err := tx.Put(ctx, "authMfa", record); err != nil {
				return nil, err
			}
		} else {
			// No authenticator: only a code emailed for this very challenge (see RequestMfaCode) can satisfy it.
			expected := str(payload, "codeHash")
			validUntil := math.NaN()
			if !core.IsUndefined(payload.Get("codeExpiresAt")) {
				validUntil = toNumber(payload.Get("codeExpiresAt"))
			}
			matches := false
			for _, secret := range s.Secrets {
				provided := s.mfaCodeDigest(challenge, code, secret)
				if expected != "" && len(expected) == len(provided) && subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1 {
					matches = true
				}
			}
			if expected == "" || !(validUntil > float64(s.now())) || !matches {
				if expected != "" {
					return nil, core.NewIamError("INVALID_MFA", "Invalid or expired code", 401)
				}
				return nil, core.NewIamError("MFA_NOT_ENROLLED", "MFA is not enrolled", 403)
			}
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		session, err := s.IssueSession(ctx, tx, identity, IssueSessionOptions{Mfa: true, Method: str(payload, "method")})
		if err != nil {
			return nil, err
		}
		if isTrue(input, "rememberDevice") {
			device, err := s.RememberDevice(ctx, tx, identity)
			if err != nil {
				return nil, err
			}
			session.Assign(device)
		}
		return session, nil
	})
	if err != nil {
		var iam *core.IamError
		if attempted != nil && errors.As(err, &iam) && iam.Code == "INVALID_MFA" {
			s.deferSignInFailure(ctx, attempted, "mfa")
		}
		return nil, err
	}
	return result, nil
}

// RequestMfaCode emails a six-digit one-time code for a login challenge whose sign-in offered emailCodeAvailable:
// { success, expiresAt }. Requesting again replaces the code.
func (s *Service) RequestMfaCode(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("challenge"), "challenge", 512)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "mfa-code:"+HashToken(token), "sensitive"); err != nil {
		return nil, err
	}
	// Per person too, so repeated sign-ins cannot queue unbounded code emails to the account's inbox.
	if err := s.rateChallengeIdentity(ctx, tenantID, token, "mfa-login", "mfa-code-send"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, tenantID, token, "mfa-login", challengeMatch{})
		if err != nil {
			return nil, err
		}
		payload := child(challenge, "payload")
		if !core.StrictEquals(payload.Get("emailCodes"), "1") {
			return nil, core.NewIamError("FEATURE_DISABLED", "Emailed codes are not available for this sign-in", 403)
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		if !flag(identity, "email") || !flag(identity, "emailVerified") {
			return nil, core.NewIamError("FEATURE_DISABLED", "A verified email address is required", 403)
		}
		code := sixDigitCode()
		expiresAt := math.Min(numOr(challenge, "expiresAt", math.NaN()), float64(s.now()+10*60_000))
		updated := challenge.Spread(core.NewObject("payload", payload.Spread(core.NewObject(
			"codeHash", s.mfaCodeDigest(challenge, code, s.options.Secret),
			"codeExpiresAt", core.NumberString(expiresAt),
		))))
		if _, err := tx.Put(ctx, "authChallenges", updated); err != nil {
			return nil, err
		}
		if err := s.enqueue(ctx, tx, identity, "email", jsString(identity.Get("email")), "mfa-code", core.NewObject("code", code)); err != nil {
			return nil, err
		}
		return core.NewObject("success", true, "expiresAt", expiresAt), nil
	})
}

// RecoverMfa completes a login challenge with a recovery code (each code works once): a session. input: {
// tenantId, challenge, code }.
func (s *Service) RecoverMfa(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	code, err := Text(input.Get("code"), "code", 128)
	if err != nil {
		return nil, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("challenge"), "challenge")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "mfa-recover:"+HashToken(token), "sensitive"); err != nil {
		return nil, err
	}
	if err := s.rateChallengeIdentity(ctx, tenantID, token, "mfa-login", "mfa-recovery"); err != nil {
		return nil, err
	}
	var attempted *core.Object
	result, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, input.Get("tenantId"), input.Get("challenge"), "mfa-login", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		attempted = identity
		record, err := tx.Get(ctx, "authMfa", str(identity, "id"))
		if err != nil {
			return nil, err
		}
		codeHash := HashToken(code)
		index := -1
		hashes, _ := record.Get("recoveryHashes").([]any)
		for position, value := range hashes {
			stored := []byte(jsString(value))
			if len(stored) != len(codeHash) {
				return nil, errors.New("Input buffers must have the same byte length")
			}
			if subtle.ConstantTimeCompare(stored, []byte(codeHash)) == 1 {
				index = position
				break
			}
		}
		if !flag(record, "enabled") || index < 0 {
			return nil, core.NewIamError("INVALID_MFA", "Invalid recovery code", 401)
		}
		record.Set("recoveryHashes", append(append([]any{}, hashes[:index]...), hashes[index+1:]...))
		if _, err := tx.Put(ctx, "authMfa", record); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, identity, "auth:mfa:recover", nil, nil); err != nil {
			return nil, err
		}
		return s.IssueSession(ctx, tx, identity, IssueSessionOptions{Mfa: true, Method: str(child(challenge, "payload"), "method")})
	})
	if err != nil {
		var iam *core.IamError
		if attempted != nil && errors.As(err, &iam) && iam.Code == "INVALID_MFA" {
			s.deferSignInFailure(ctx, attempted, "recovery-code")
		}
		return nil, err
	}
	return result, nil
}

// MfaStatus is what the caller has set up: { enabled, recoveryCodesRemaining, passkeys, trustedDevices, sessionMfa }.
func (s *Service) MfaStatus(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	principal, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	scope := core.NewObject("tenantId", principal.Identity.Get("tenantId"), "identityId", principal.Identity.Get("id"))
	record, err := s.options.Store.Get(ctx, "authMfa", str(principal.Identity, "id"))
	if err != nil {
		return nil, err
	}
	enabled := flag(record, "enabled")
	passkeys, err := s.options.Store.Find(ctx, "authPasskeys", scope, nil)
	if err != nil {
		return nil, err
	}
	devices, err := s.options.Store.Find(ctx, "authDevices", scope, nil)
	if err != nil {
		return nil, err
	}
	now := float64(s.now())
	trusted := 0
	for _, device := range devices {
		if numOr(device, "expiresAt", math.NaN()) > now {
			trusted++
		}
	}
	remaining := 0.0
	if enabled {
		if hashes, ok := record.Get("recoveryHashes").([]any); ok {
			remaining = float64(len(hashes))
		}
	}
	return core.NewObject(
		"enabled", enabled,
		"recoveryCodesRemaining", remaining,
		"passkeys", float64(len(passkeys)),
		"trustedDevices", float64(trusted),
		"sessionMfa", principal.Session.Get("mfa"),
	), nil
}

// RegenerateRecoveryCodes replaces the caller's recovery codes: { recoveryCodes }. Requires recent, MFA-verified
// authentication.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		if !flag(principal.Session, "mfa") {
			return nil, core.NewIamError("MFA_REQUIRED", "Multi-factor authentication is required", 403)
		}
		record, err := tx.Get(ctx, "authMfa", str(principal.Identity, "id"))
		if err != nil {
			return nil, err
		}
		if !flag(record, "enabled") {
			return nil, core.NewIamError("MFA_NOT_ENROLLED", "MFA is not enrolled", 403)
		}
		codes, hashes := recoveryCodes()
		record.Set("recoveryHashes", hashes)
		if _, err := tx.Put(ctx, "authMfa", record); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:mfa:recovery-codes", nil, nil); err != nil {
			return nil, err
		}
		return core.NewObject("recoveryCodes", codes), nil
	})
}

// DisableMfa removes the caller's authenticator where neither the tenant nor root administration requires MFA.
func (s *Service) DisableMfa(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		if !flag(principal.Session, "mfa") {
			return nil, core.NewIamError("MFA_REQUIRED", "Multi-factor authentication is required", 403)
		}
		tenant, err := tx.Get(ctx, "tenants", str(principal.Identity, "tenantId"))
		if err != nil {
			return nil, err
		}
		required := flag(principal.Identity, "rootAdmin")
		if !required {
			if tenant == nil {
				return nil, &core.TypeError{Message: "Cannot read properties of undefined (reading 'authPolicy')"}
			}
			if required, err = s.TenantRequiresMfa(ctx, tenant, principal.Identity); err != nil {
				return nil, err
			}
		}
		if required {
			return nil, core.NewIamError("MFA_REQUIRED", "MFA is required by this tenant", 403)
		}
		if err := tx.Delete(ctx, "authMfa", str(principal.Identity, "id")); err != nil {
			return nil, err
		}
		if err := s.RevokeIdentity(ctx, tx, str(principal.Identity, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:mfa:disable", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}
