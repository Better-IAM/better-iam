package server

// Port of packages/server/src/api/sts.ts: the `sts` group, temporary credentials (GetSessionToken,
// GetCallerIdentity) plus the public web-identity exchange (web_identity_exchange.go). Every method takes the caller's
// credential first; tokens are returned once, in the response body, and never set a cookie.

import (
	"context"
	"math"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// StsAPI is the `sts` API group (packages/server/src/api/sts.ts createStsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/sts/{method} onto it.
type StsAPI struct {
	server *ServerContext
	web    *WebIdentityStsAPI
}

// CreateStsAPI builds the `sts` API group.
func CreateStsAPI(server *ServerContext) *StsAPI {
	return &StsAPI{server: server, web: CreateWebIdentityStsAPI(server)}
}

func stsChainingDisabled() error {
	return core.NewIamError("CREDENTIAL_CHAINING_DISABLED", "Temporary credentials cannot mint session tokens", 400)
}

// Token standings for the per-identity cap: `live` (usable, counts), `dead` (can never be used again, so it is
// deleted) or `suspended` (refused for now for a reason that can be lifted, such as a network block or a tenant's MFA
// requirement; neither counted nor deleted).
const (
	stsTokenLive      = "live"
	stsTokenDead      = "dead"
	stsTokenSuspended = "suspended"
)

// stsTokenStanding judges a session token of identity as principals would, without its per-use network checks: the
// token must be unexpired and consistent with a stored source (a user session or API key of the same identity and
// tenant, never an impersonation, which it does not outlive and whose authority it carries), and the source must
// still pass re-validation. A source refused as UNAUTHENTICATED (signed out, expired, idled out, key authority
// revoked) never comes back, so its tokens are dead. Source verdicts are cached per source in sources.
func stsTokenStanding(ctx context.Context, server *ServerContext, tx core.IamStore, identity, token *core.Object, now float64, sources map[string]string) (string, error) {
	sourceID, ok := token.Get("sourceSessionId").(string)
	if jsNumber(token.Get("expiresAt")) <= now || !ok {
		return stsTokenDead, nil
	}
	source, err := tx.Get(ctx, "sessions", sourceID)
	if err != nil {
		return "", err
	}
	if source == nil || (source.Get("kind") != "user" && source.Get("kind") != "api-key") || truthy(source.Get("impersonatorId")) ||
		!core.StrictEquals(source.Get("identityId"), identity.Get("id")) || !core.StrictEquals(source.Get("tenantId"), token.Get("tenantId")) ||
		!core.StrictEquals(token.Get("tenantId"), identity.Get("tenantId")) || jsNumber(source.Get("expiresAt")) <= now ||
		jsNumber(token.Get("expiresAt")) > jsNumber(source.Get("expiresAt")) ||
		!core.StrictEquals(token.Get("credentialAuthorityId"), source.Get("credentialAuthorityId")) {
		return stsTokenDead, nil
	}
	id := jsString(source.Get("id"))
	if cached, ok := sources[id]; ok {
		return cached, nil
	}
	standing := stsTokenLive
	if _, err := server.Principals.CurrentPrincipal(ctx, tx, &Principal{Identity: identity, Session: source}); err != nil {
		known, ok := asIamError(err)
		if !ok {
			return "", err
		}
		if known.Code == "UNAUTHENTICATED" {
			standing = stsTokenDead
		} else {
			standing = stsTokenSuspended
		}
	}
	sources[id] = standing
	return standing, nil
}

// AssumeRoleWithWebIdentity is POST {basePath}/sts/assumeRoleWithWebIdentity (public: no request credential). Exchanges a verified external OpenID Connect token, such as a GitHub Actions or Kubernetes token, for a role session under a web-identity trust.
func (api *StsAPI) AssumeRoleWithWebIdentity(ctx context.Context, input In[apitypes.StsAssumeRoleWithWebIdentityInput]) (Out[apitypes.StsAssumeRoleWithWebIdentityOutput], error) {
	result, err := api.web.AssumeRoleWithWebIdentity(ctx, input.Body)
	if err != nil {
		return Out[apitypes.StsAssumeRoleWithWebIdentityOutput]{}, err
	}
	return Out[apitypes.StsAssumeRoleWithWebIdentityOutput]{Value: result}, nil
}

// GetCallerIdentity is POST {basePath}/sts/getCallerIdentity. Returns who the presented credential acts as: identity, tenant, session kind and id, format, MFA, expiry, and any role, trust, session name, tags, or web identity behind it.
//
// Every session kind is described (user, impersonation, API key, role session, session token, session JWT). The
// credential is re-validated like any other use, so this doubles as the online revocation check for holders of a
// session JWT. Needs no permission and writes no audit event; the result is an allowlist projection that never carries
// hashes, policies or authority ids.
func (api *StsAPI) GetCallerIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.StsGetCallerIdentityInput]) (Out[apitypes.StsGetCallerIdentityOutput], error) {
	server := api.server
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.StsGetCallerIdentityOutput]{}, err
	}
	principal, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*Principal, error) {
		return server.Principals.CurrentPrincipal(ctx, tx, authenticated)
	})
	if err != nil {
		return Out[apitypes.StsGetCallerIdentityOutput]{}, err
	}
	result, err := CallerIdentity(principal)
	if err != nil {
		return Out[apitypes.StsGetCallerIdentityOutput]{}, err
	}
	return Out[apitypes.StsGetCallerIdentityOutput]{Value: result}, nil
}

// GetSessionToken is POST {basePath}/sts/getSessionToken. Mints a short-lived session token for your own identity from a signed-in session or an API key, optionally narrowed by a policy and attested with a fresh MFA code.
//
// The token is of kind 'session-token' (`biam_sts_…`, or a session JWT with `format: 'jwt'`) for the caller's own
// identity, minted from a user session (not impersonated) or an API key. Needs `iam:session-tokens:create` on
// `iam/{identityId}` in the identity's tenant. In-process integrations that pass the incoming request's headers as the
// credential (with no client scope set) get the client derived from those headers, exactly as behind the HTTP
// handler, so allowlists, network blocks and `bindSessionsToIp` judge the token.
func (api *StsAPI) GetSessionToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.StsGetSessionTokenInput]) (Out[apitypes.StsGetSessionTokenOutput], error) {
	server := api.server
	if server.Auth.CurrentClient(ctx) == nil && credential.Headers != nil {
		ctx = server.Auth.WithClient(ctx, ClientFromHeaders(server.Options, credential.Headers, server.Config.BaseURL.Href))
	}
	result, err := api.issueSessionToken(ctx, credential, input.Body)
	if err != nil {
		return Out[apitypes.StsGetSessionTokenOutput]{}, err
	}
	return Out[apitypes.StsGetSessionTokenOutput]{Value: result}, nil
}

// issueSessionToken is GetSessionToken inside the caller's client scope.
func (api *StsAPI) issueSessionToken(ctx context.Context, credential core.CredentialInput, request *core.Object) (*core.Object, error) {
	server := api.server
	authService := server.Auth
	source, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	if truthy(source.Session.Get("impersonatorId")) {
		return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Session tokens cannot be minted while impersonating a member", 403)
	}
	if !ActsInOwnRight(source.Session) {
		return nil, stsChainingDisabled()
	}
	if request == nil {
		request = core.NewObject()
	}
	mfaCode := request.Get("mfaCode")
	if !isUndefined(mfaCode) {
		if source.Session.Get("kind") != "user" {
			return nil, core.NewIamError("MFA_NOT_ENROLLED", "Only a signed-in person can verify MFA", 403)
		}
		// Counted before anything else is examined and outside any transaction, so a refusal cannot roll it back.
		if err := authService.LimitAttempt(ctx, jsString(source.Identity.Get("tenantId")), "step-up:"+jsString(source.Identity.Get("id")),
			auth.LimitAttemptOptions{Tier: "sensitive"}); err != nil {
			return nil, err
		}
		if _, ok := mfaCode.(string); !ok {
			return nil, core.NewIamError("INVALID_INPUT", "mfaCode must be a string")
		}
	}
	// Input shapes are refused before the operation; the policy is validated against the catalog inside it.
	sessionName, err := SessionNameValue(request.Get("sessionName"))
	if err != nil {
		return nil, err
	}
	format, err := CredentialFormat(request.Get("format"))
	if err != nil {
		return nil, err
	}
	audience, err := AudienceValue(request.Get("audience"), format)
	if err != nil {
		return nil, err
	}
	if format == "jwt" && server.SessionTokens == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Session JWTs are not enabled on this deployment (sts.jwt)", 403)
	}
	bounds, err := SessionTokenDurationBounds(server, format)
	if err != nil {
		return nil, err
	}
	durationSeconds, err := DurationWithin(request.Get("durationSeconds"), bounds)
	if err != nil {
		return nil, err
	}
	policy := request.Get("policy")
	if !isUndefined(policy) {
		if document, ok := policy.(*core.Object); !ok || document == nil {
			return nil, core.NewIamError("INVALID_INPUT", "policy must be a policy document")
		}
	}
	identityID := jsString(source.Identity.Get("id"))
	tenantID := jsString(source.Identity.Get("tenantId"))
	return Operate(ctx, server.Operations, credential, tenantID, "iam:session-tokens:create", identityID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		// The re-validated principal must still be the credential examined above, acting in its own right.
		if principal.Identity.Get("id") != identityID || !core.StrictEquals(principal.Session.Get("id"), source.Session.Get("id")) ||
			truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("UNAUTHENTICATED", "Credential revoked", 401)
		}
		if !ActsInOwnRight(principal.Session) {
			return nil, stsChainingDisabled()
		}
		if !isUndefined(policy) {
			if err := server.Catalog.Validate(ctx, tx, tenantID, policy); err != nil {
				return nil, err
			}
		}
		var stepUp *core.Object
		stepped := false
		if !isUndefined(mfaCode) {
			verified, err := authService.VerifyStepUpCode(ctx, tx, principal.Identity, mfaCode)
			if err != nil {
				return nil, err
			}
			stepUp, stepped = verified, true
		}
		// The injected clock, like user sessions, so validation and issuance agree under a test clock.
		now := server.Now()
		// Only tokens that can still be used hold a place under the cap, and dead ones are deleted here, so the cap
		// bounds the stored rows too: every issuance leaves at most `maxSessionTokensPerIdentity` rows behind, and no
		// row is added between issuances. (A refused issuance rolls its deletions back, but then nothing is added.)
		live := int64(0)
		sources := map[string]string{}
		tokens, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identityID, "kind", "session-token"), nil)
		if err != nil {
			return nil, err
		}
		for _, session := range tokens {
			if session.Get("kind") != "session-token" || session.Get("identityId") != identityID {
				continue
			}
			standing, err := stsTokenStanding(ctx, server, tx, principal.Identity, session, float64(now), sources)
			if err != nil {
				return nil, err
			}
			if standing == stsTokenDead {
				if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
					return nil, err
				}
			} else if standing == stsTokenLive {
				live++
			}
		}
		if live >= server.Config.Sts.MaxSessionTokensPerIdentity {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "This identity holds the maximum number of live session tokens", 409)
		}
		sourceSession := principal.Session
		// API keys never carry MFA; a person's session passes its own MFA state on unless a code was verified now.
		sourceMfa := sourceSession.Get("kind") == "user" && sourceSession.Get("mfa") == true
		mfa := sourceMfa
		if truthy(stepUp) {
			mfa = true
		}
		draft := core.NewObject(
			"id", ID(), "tenantId", tenantID, "identityId", identityID, "kind", "session-token",
			"sourceSessionId", sourceSession.Get("id"), "tokenHash", "", "createdAt", float64(now), "lastSeenAt", float64(now),
			"authenticatedAt", sourceSession.Get("authenticatedAt"),
			"expiresAt", math.Min(jsNumber(sourceSession.Get("expiresAt")), float64(now)+durationSeconds*1000),
			"mfa", mfa,
		)
		if truthy(stepUp) {
			draft.Set("mfaAuthenticatedAt", float64(now))
		} else if at, ok := sourceSession.Get("mfaAuthenticatedAt").(float64); sourceMfa && ok {
			draft.Set("mfaAuthenticatedAt", at)
		}
		if !isUndefined(policy) {
			draft.Set("policy", policy)
		}
		if truthy(sourceSession.Get("policy")) {
			draft.Set("sourcePolicy", sourceSession.Get("policy"))
		}
		if authority, ok := sourceSession.Get("credentialAuthorityId").(string); ok {
			draft.Set("credentialAuthorityId", authority)
		}
		if sessionName != "" {
			draft.Set("sessionName", sessionName)
		}
		// The issuing address: the tenant's allowlist judges it on every use, network blocks judge it and the
		// presenting address.
		if client := webIdentityClientRecord(authService.CurrentClient(ctx)); client != nil {
			draft.Set("client", client)
		}
		minted, err := MintCredential(ctx, server, tx, core.NewObject(
			"identity", principal.Identity, "draft", draft, "format", format, "audience", webIdentityAudienceValue(audience),
		))
		if err != nil {
			return nil, err
		}
		token, _ := minted.Get("token").(string)
		session, _ := minted.Get("session").(*core.Object)
		if err := server.Events.Audit(ctx, tx, principal, "session-token:issued", tenantID, identityID, "allow", false, core.NewObject(
			"sessionId", session.Get("id"), "sourceSessionKind", sourceSession.Get("kind"), "durationSeconds", durationSeconds,
			"format", format, "mfaStepUp", stepped,
		)); err != nil {
			return nil, err
		}
		return TemporaryCredential(token, session, now)
	}, false)
}
