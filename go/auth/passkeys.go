package auth

// Port of packages/auth/src/service/passkeys.ts: WebAuthn passkeys, registered from a recently authenticated
// session, used for passwordless sign-in (which satisfies MFA) or as the second factor of another sign-in.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"math"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

const passkeyNameLimit = 64

// defaultPasskeyName is a readable default label from what the authenticator reported about itself.
func defaultPasskeyName(transports any) (string, error) {
	set := map[string]bool{}
	switch value := transports.(type) {
	case nil, core.UndefinedType:
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok {
				set[text] = true
			}
		}
	case string:
		for _, point := range core.CodePoints(value) {
			set[point] = true
		}
	default:
		return "", &core.TypeError{Message: "transports is not iterable"}
	}
	switch {
	case set["internal"]:
		return "This device", nil
	case set["hybrid"]:
		return "Phone", nil
	case set["usb"] || set["nfc"] || set["ble"]:
		return "Security key", nil
	}
	return "Passkey", nil
}

func passkeyName(value any, fallback string) (string, error) {
	if core.IsUndefined(value) {
		return fallback, nil
	}
	name, err := Text(value, "name", passkeyNameLimit)
	if err != nil {
		return "", err
	}
	name = core.JSTrim(name)
	if name == "" {
		return "", core.NewIamError("INVALID_INPUT", "name must not be empty")
	}
	return name, nil
}

// publicPasskey is everything but the key material.
func publicPasskey(record *core.Object) (*core.Object, error) {
	safe := record.Spread()
	safe.Delete("publicKey")
	safe.Delete("counter")
	safe.Delete("uniqueKey")
	name := record.Get("name")
	if name == nil || core.IsUndefined(name) {
		fallback, err := defaultPasskeyName(record.Get("transports"))
		if err != nil {
			return nil, err
		}
		name = fallback
	}
	safe.Set("name", name)
	return safe, nil
}

// passkeys is the passkey configuration for the current request.
func (s *Service) passkeys(ctx context.Context) (rpID, rpName string, err error) {
	if s.options.Passkeys == nil {
		return "", "", core.NewIamError("FEATURE_DISABLED", "Passkeys are not configured")
	}
	// A passkey belongs to one domain (the RP ID). On an organization's custom hostname outside it the browser would
	// refuse the ceremony, so say why up front.
	rpID = s.options.Passkeys.RPID
	if host := s.RequestHost(ctx); host != nil && host.Origin != "" {
		parsed, err := ParseFetchURL(host.Origin)
		if err != nil {
			return "", "", &core.TypeError{Message: "Invalid URL"}
		}
		if parsed.Hostname != rpID && !strings.HasSuffix(parsed.Hostname, "."+rpID) {
			return "", "", core.NewIamError("FEATURE_DISABLED", "Passkeys are not available at this address")
		}
	}
	rpName = s.options.Passkeys.RPName
	if rpName == "" {
		rpName = s.appName
	}
	return rpID, rpName, nil
}

func keyDescriptors(keys []*core.Object) []WebAuthnCredentialDescriptor {
	out := make([]WebAuthnCredentialDescriptor, 0, len(keys))
	for _, key := range keys {
		out = append(out, WebAuthnCredentialDescriptor{ID: str(key, "credentialId"), Transports: key.Get("transports")})
	}
	return out
}

// BeginPasskeyRegistration starts registering a passkey for the caller: { challengeId, options }. Requires recent
// authentication.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, credentials core.CredentialInput) (*core.Object, error) {
	rpID, rpName, err := s.passkeys(ctx)
	if err != nil {
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
		identity := principal.Identity
		existing, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		userName := str(identity, "id")
		if !nullish(identity, "email") {
			userName = jsString(identity.Get("email"))
		}
		options, err := GenerateRegistrationOptions(RegistrationOptionsInput{
			RPName:          rpName,
			RPID:            rpID,
			UserName:        userName,
			UserID:          utf8Bytes(str(identity, "id")),
			UserDisplayName: str(identity, "name"),
			Exclude:         keyDescriptors(existing),
		})
		if err != nil {
			return nil, err
		}
		challengeID, err := s.challenge(ctx, tx, identity, "passkey-register", core.NewObject("challenge", options.Get("challenge")), 5*60_000, "", str(principal.Session, "id"))
		if err != nil {
			return nil, err
		}
		return core.NewObject("challengeId", challengeID, "options", options), nil
	})
}

// FinishPasskeyRegistration verifies the registration response and stores the passkey: { id, name }. input: {
// challengeId, response, name? } (name labels the passkey, at most 64 characters).
func (s *Service) FinishPasskeyRegistration(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	rpID, _, err := s.passkeys(ctx)
	if err != nil {
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
		identity := principal.Identity
		challenge, err := s.readChallenge(ctx, tx, identity.Get("tenantId"), input.Get("challengeId"), "passkey-register", challengeMatch{})
		if err != nil {
			return nil, err
		}
		if !core.StrictEquals(challenge.Get("identityId"), identity.Get("id")) || !core.StrictEquals(challenge.Get("sessionId"), principal.Session.Get("id")) {
			return nil, core.NewIamError("INVALID_CHALLENGE", "Invalid passkey challenge", 401)
		}
		verified, info, err := VerifyRegistrationResponse(input.Get("response"), VerifyRegistrationOptions{
			ExpectedChallenge:       str(child(challenge, "payload"), "challenge"),
			ExpectedOrigins:         s.expectedOrigins(ctx),
			ExpectedRPID:            rpID,
			RequireUserVerification: true,
		})
		if err != nil {
			return nil, core.NewIamError("INVALID_PASSKEY", "Passkey registration verification failed", 401)
		}
		if !verified || info == nil {
			return nil, core.NewIamError("INVALID_PASSKEY", "Passkey verification failed", 401)
		}
		id := NewID("pk")
		// A credential is globally unique for this RP, including across tenant accounts.
		duplicates, err := tx.Find(ctx, "authPasskeys", core.NewObject("credentialId", info.CredentialID), nil)
		if err != nil {
			return nil, err
		}
		if len(duplicates) > 0 {
			return nil, core.NewIamError("PASSKEY_EXISTS", "Passkey is already registered", 409)
		}
		fallback, err := defaultPasskeyName(info.Transports)
		if err != nil {
			return nil, err
		}
		name, err := passkeyName(input.Get("name"), fallback)
		if err != nil {
			return nil, err
		}
		record := core.NewObject(
			"id", id,
			"tenantId", identity.Get("tenantId"),
			"uniqueKey", info.CredentialID,
			"identityId", identity.Get("id"),
			"credentialId", info.CredentialID,
			"publicKey", base64url(info.CredentialPublicKey),
			"counter", float64(info.Counter),
		)
		if info.Transports != nil && !core.IsUndefined(info.Transports) {
			record.Set("transports", core.CloneValue(info.Transports))
		}
		record.Set("name", name)
		record.Set("createdAt", float64(s.now()))
		record.Set("deviceType", info.CredentialDeviceType)
		record.Set("backedUp", info.CredentialBackedUp)
		if info.AAGUID != "" && info.AAGUID != "00000000-0000-0000-0000-000000000000" {
			record.Set("aaguid", info.AAGUID)
		}
		if _, err := tx.Insert(ctx, "authPasskeys", record); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, identity, "auth:passkey:create", nil, core.NewObject("name", name)); err != nil {
			return nil, err
		}
		return core.NewObject("id", id, "name", name), nil
	})
}

// BeginPasskeyAuthentication starts a passkey sign-in: { challengeId, options }. With email, the options name that
// person's credentials (answered like an account with a passkey even when there is none). Without it, the
// authenticator offers whatever discoverable credential it holds for this relying party.
func (s *Service) BeginPasskeyAuthentication(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	rpID, _, err := s.passkeys(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	if core.IsUndefined(input.Get("email")) {
		// Discovery names nobody, so the counter is per address (an IPv6 /64 as one).
		subject := "unknown"
		if ip := s.clientIP(ctx); ip != "" {
			subject = ip
			if key, ok := core.IPCounterKey(ip); ok {
				subject = key
			}
		}
		if err := s.rate(ctx, tenantID, "passkey-discover:"+subject, "generous"); err != nil {
			return nil, err
		}
		return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
				return nil, err
			}
			if err := s.methodAllowed(ctx, tx, tenantID, "passkey"); err != nil {
				return nil, err
			}
			options, err := GenerateAuthenticationOptions(rpID, nil)
			if err != nil {
				return nil, err
			}
			token := NewToken()
			if _, err := tx.Insert(ctx, "authChallenges", core.NewObject(
				"id", NewID("ch"),
				"tenantId", tenantID,
				"identityId", "",
				"purpose", "passkey-authenticate",
				"tokenHash", s.DigestChallenge(tenantID, token),
				"payload", core.NewObject("challenge", options.Get("challenge"), "discovery", "1"),
				"expiresAt", float64(s.now()+5*60_000),
			)); err != nil {
				return nil, err
			}
			return core.NewObject("challengeId", token, "options", options), nil
		})
	}
	normalized, err := Email(input.Get("email"))
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "passkey:"+normalized, "default"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		if err := s.methodAllowed(ctx, tx, tenantID, "passkey"); err != nil {
			return nil, err
		}
		matches, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", normalized, "status", "active", "kind", "user"), nil)
		if err != nil {
			return nil, err
		}
		var identity *core.Object
		var keys []*core.Object
		if len(matches) > 0 {
			identity = matches[0]
			if keys, err = tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id")), nil); err != nil {
				return nil, err
			}
		}
		if identity == nil || len(keys) == 0 {
			// Answered like an account with a passkey: a decoy credential id that is stable per address, and a challenge
			// id that finishes nowhere.
			mac := hmac.New(sha256.New, utf8Bytes(s.options.Secret))
			mac.Write(utf8Bytes("passkey-decoy:" + tenantID + ":" + normalized))
			options, err := GenerateAuthenticationOptions(rpID, []WebAuthnCredentialDescriptor{{ID: base64url(mac.Sum(nil))}})
			if err != nil {
				return nil, err
			}
			return core.NewObject("challengeId", NewToken(), "options", options), nil
		}
		options, err := GenerateAuthenticationOptions(rpID, keyDescriptors(keys))
		if err != nil {
			return nil, err
		}
		challengeID, err := s.challenge(ctx, tx, identity, "passkey-authenticate", core.NewObject("challenge", options.Get("challenge")), 5*60_000, "", "")
		if err != nil {
			return nil, err
		}
		return core.NewObject("challengeId", challengeID, "options", options), nil
	})
}

// validAssertionShape is the service's own check of a passkey response before anything else.
func validAssertionShape(response any) bool {
	object, ok := response.(*core.Object)
	if !ok || object == nil {
		return false
	}
	if _, ok := object.Get("id").(string); !ok {
		return false
	}
	return truthy(object.Get("response"))
}

func storedCredential(key *core.Object) WebAuthnCredential {
	return WebAuthnCredential{
		ID:        str(key, "credentialId"),
		PublicKey: nodeBase64Decode(str(key, "publicKey")),
		Counter:   numOr(key, "counter", math.NaN()),
	}
}

// verifyAssertion runs verifyAuthenticationResponse as the service does and records the new counter.
func (s *Service) verifyAssertion(ctx context.Context, tx core.IamStore, key, challenge *core.Object, response any, rpID string) error {
	verified, info, err := VerifyAuthenticationResponse(response, VerifyAuthenticationOptions{
		ExpectedChallenge:       str(child(challenge, "payload"), "challenge"),
		ExpectedOrigins:         s.expectedOrigins(ctx),
		ExpectedRPID:            rpID,
		Credential:              storedCredential(key),
		RequireUserVerification: true,
	})
	if err != nil {
		return core.NewIamError("INVALID_PASSKEY", "Passkey authentication verification failed", 401)
	}
	if !verified || !info.UserVerified {
		return core.NewIamError("INVALID_PASSKEY", "Passkey verification failed", 401)
	}
	key.Set("counter", float64(info.NewCounter))
	key.Set("lastUsedAt", float64(s.now()))
	_, err = tx.Put(ctx, "authPasskeys", key)
	return err
}

// FinishPasskeyAuthentication verifies a passkey assertion and signs in (the session satisfies MFA). input: {
// tenantId, challengeId, response }.
func (s *Service) FinishPasskeyAuthentication(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	rpID, _, err := s.passkeys(ctx)
	if err != nil {
		return nil, err
	}
	response := input.Get("response")
	if !validAssertionShape(response) {
		return nil, core.NewIamError("INVALID_INPUT", "A passkey authentication response is required")
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	challengeToken, err := Text(input.Get("challengeId"), "challengeId")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "passkey-finish:"+HashToken(challengeToken), "sensitive"); err != nil {
		return nil, err
	}
	responseObject := response.(*core.Object)
	credentialID := str(responseObject, "id")
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.methodAllowed(ctx, tx, tenantID, "passkey"); err != nil {
			return nil, err
		}
		challenge, err := s.readChallenge(ctx, tx, tenantID, challengeToken, "passkey-authenticate", challengeMatch{})
		if err != nil {
			return nil, err
		}
		// A discovery challenge names nobody: the presented credential identifies the account.
		discovery := core.StrictEquals(child(challenge, "payload").Get("discovery"), "1")
		var discovered *core.Object
		if discovery {
			found, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "credentialId", credentialID), nil)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				return nil, core.NewIamError("INVALID_PASSKEY", "Passkey is not registered for this organization", 401)
			}
			discovered = found[0]
		}
		identityID := str(challenge, "identityId")
		if discovered != nil {
			identityID = str(discovered, "identityId")
		}
		identity, err := s.user(ctx, tx, identityID, tenantID)
		if err != nil {
			return nil, err
		}
		assertion, _ := responseObject.Get("response").(*core.Object)
		if handle := assertion.Get("userHandle"); truthy(handle) && !core.StrictEquals(handle, base64url(utf8Bytes(str(identity, "id")))) {
			return nil, core.NewIamError("INVALID_PASSKEY", "Passkey user handle does not match this identity", 401)
		}
		key := discovered
		if key == nil {
			found, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id"), "credentialId", credentialID), nil)
			if err != nil {
				return nil, err
			}
			if len(found) > 0 {
				key = found[0]
			}
		}
		if key == nil {
			return nil, core.NewIamError("INVALID_PASSKEY", "Passkey does not belong to this tenant identity", 401)
		}
		if err := s.verifyAssertion(ctx, tx, key, challenge, response, rpID); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		return s.IssueSession(ctx, tx, identity, IssueSessionOptions{Mfa: true, Method: "passkey"})
	})
}

// BeginPasskeyMfa starts a passkey second factor after a sign-in returned mfaRequired with passkeyAvailable: {
// challengeId, options }. input: { tenantId, challenge }.
func (s *Service) BeginPasskeyMfa(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	rpID, _, err := s.passkeys(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("challenge"), "challenge", 512)
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "passkey-mfa:"+HashToken(token), "sensitive"); err != nil {
		return nil, err
	}
	if err := s.rateChallengeIdentity(ctx, tenantID, token, "mfa-login", "passkey-mfa-begin"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		login, err := s.readChallenge(ctx, tx, tenantID, token, "mfa-login", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(login, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		keys, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			return nil, core.NewIamError("FEATURE_DISABLED", "No passkey is registered for this account", 403)
		}
		options, err := GenerateAuthenticationOptions(rpID, keyDescriptors(keys))
		if err != nil {
			return nil, err
		}
		challengeID, err := s.challenge(ctx, tx, identity, "passkey-mfa", core.NewObject("challenge", options.Get("challenge"), "loginChallengeId", login.Get("id")), 5*60_000, "", "")
		if err != nil {
			return nil, err
		}
		return core.NewObject("challengeId", challengeID, "options", options), nil
	})
}

// FinishPasskeyMfa verifies the passkey assertion that completes a login challenge: a session (plus the device
// token with rememberDevice). input: { tenantId, challengeId, response, rememberDevice? }.
func (s *Service) FinishPasskeyMfa(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	rpID, _, err := s.passkeys(ctx)
	if err != nil {
		return nil, err
	}
	response := input.Get("response")
	if !validAssertionShape(response) {
		return nil, core.NewIamError("INVALID_INPUT", "A passkey authentication response is required")
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	token, err := Text(input.Get("challengeId"), "challengeId")
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "passkey-mfa-finish:"+HashToken(token), "sensitive"); err != nil {
		return nil, err
	}
	if err := s.rateChallengeIdentity(ctx, tenantID, token, "passkey-mfa", "passkey-mfa-verify"); err != nil {
		return nil, err
	}
	credentialID := str(response.(*core.Object), "id")
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		challenge, err := s.readChallenge(ctx, tx, tenantID, token, "passkey-mfa", challengeMatch{})
		if err != nil {
			return nil, err
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		// The login challenge this assertion completes must still be open and belong to the same person.
		loginID := str(child(challenge, "payload"), "loginChallengeId")
		login, err := tx.Get(ctx, "authChallenges", loginID)
		if err != nil {
			return nil, err
		}
		if login == nil || str(login, "purpose") != "mfa-login" || !core.StrictEquals(login.Get("identityId"), identity.Get("id")) ||
			numOr(login, "expiresAt", math.NaN()) <= float64(s.now()) {
			return nil, core.NewIamError("INVALID_CHALLENGE", "Sign-in challenge is invalid or expired", 401)
		}
		found, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id"), "credentialId", credentialID), nil)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			return nil, core.NewIamError("INVALID_PASSKEY", "Passkey does not belong to this account", 401)
		}
		key := found[0]
		if err := s.verifyAssertion(ctx, tx, key, challenge, response, rpID); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "authChallenges", str(login, "id")); err != nil {
			return nil, err
		}
		session, err := s.IssueSession(ctx, tx, identity, IssueSessionOptions{Mfa: true, Method: str(child(login, "payload"), "method")})
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
}

// ListPasskeys lists the caller's passkeys, newest first: name, when registered and last used, device kind, and
// transports.
func (s *Service) ListPasskeys(ctx context.Context, credentials core.CredentialInput) ([]*core.Object, error) {
	principal, err := s.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}
	keys, err := s.options.Store.Find(ctx, "authPasskeys", core.NewObject("tenantId", principal.Identity.Get("tenantId"), "identityId", principal.Identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if d := nullishOr(keys[j], "createdAt", 0) - nullishOr(keys[i], "createdAt", 0); d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		return str(keys[i], "id") < str(keys[j], "id")
	})
	out := make([]*core.Object, 0, len(keys))
	for _, key := range keys {
		safe, err := publicPasskey(key)
		if err != nil {
			return nil, err
		}
		out = append(out, safe)
	}
	return out, nil
}

// RenamePasskey relabels one of the caller's passkeys (at most 64 characters). input: { id, name }.
func (s *Service) RenamePasskey(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		id, err := Text(input.Get("id"), "id")
		if err != nil {
			return nil, err
		}
		passkey, err := tx.Get(ctx, "authPasskeys", id)
		if err != nil {
			return nil, err
		}
		if passkey == nil || !core.StrictEquals(passkey.Get("identityId"), principal.Identity.Get("id")) ||
			!core.StrictEquals(passkey.Get("tenantId"), principal.Identity.Get("tenantId")) {
			return nil, core.NewIamError("NOT_FOUND", "Passkey not found", 404)
		}
		fallback, err := defaultPasskeyName(passkey.Get("transports"))
		if err != nil {
			return nil, err
		}
		name, err := passkeyName(input.Get("name"), fallback)
		if err != nil {
			return nil, err
		}
		saved, err := tx.Put(ctx, "authPasskeys", passkey.Spread(core.NewObject("name", name)))
		if err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, principal.Identity, "auth:passkey:rename", principal.Session, core.NewObject("name", name)); err != nil {
			return nil, err
		}
		return publicPasskey(saved)
	})
}

// DeletePasskey removes one of the caller's passkeys (never the last one without another way to sign in) and
// revokes their sessions. Requires recent authentication. input: { id }.
func (s *Service) DeletePasskey(ctx context.Context, credentials core.CredentialInput, input *core.Object) (*core.Object, error) {
	input = body(input)
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := s.Authenticate(ctx, credentials)
		if err != nil {
			return nil, err
		}
		if err := s.RequireRecent(principal); err != nil {
			return nil, err
		}
		id, err := Text(input.Get("id"), "id")
		if err != nil {
			return nil, err
		}
		passkey, err := tx.Get(ctx, "authPasskeys", id)
		if err != nil {
			return nil, err
		}
		identity := principal.Identity
		if passkey == nil || !core.StrictEquals(passkey.Get("identityId"), identity.Get("id")) ||
			!core.StrictEquals(passkey.Get("tenantId"), identity.Get("tenantId")) {
			return nil, core.NewIamError("NOT_FOUND", "Passkey not found", 404)
		}
		// Require another login method before removing the last registered passkey.
		keys, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		alternative := flag(identity, "passwordHash") ||
			(s.options.PasswordlessEmail && flag(identity, "emailVerified")) ||
			(s.options.PasswordlessSms && flag(identity, "phoneVerified"))
		if len(keys) == 1 && !alternative {
			return nil, core.NewIamError("LAST_AUTHENTICATOR", "Configure another login method before removing the last passkey", 409)
		}
		if err := tx.Delete(ctx, "authPasskeys", str(passkey, "id")); err != nil {
			return nil, err
		}
		if err := s.RevokeIdentity(ctx, tx, str(identity, "id")); err != nil {
			return nil, err
		}
		if err := s.audit(ctx, tx, identity, "auth:passkey:delete", nil, nil); err != nil {
			return nil, err
		}
		return success(), nil
	})
}
