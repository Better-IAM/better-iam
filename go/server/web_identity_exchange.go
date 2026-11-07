package server

// Port of packages/server/src/web-identity-exchange.ts: AssumeRoleWithWebIdentity, the public exchange of a verified
// external OIDC token (GitHub Actions, GitLab, Kubernetes, cloud workload identity) for a role session under a
// web-identity trust (`sts/assumeRoleWithWebIdentity`, a public API method), plus the administrators' dry run
// (`trust.evaluateWebIdentity`).
//
// The external token is the only credential, so the exchange is built against enumeration: the feature flag and the
// input shape are checked first, the per-trust rate limit is consumed before anything is looked up, and every failure
// that depends on stored state or on the token is the same WEB_IDENTITY_REJECTED (403). Only once a verified token has
// matched the trust do specific errors surface (rate and network refusals, the per-trust session cap, duration,
// policy, format and audience problems). Denials are audited best-effort, and only once the trust has resolved in its
// tenant; claims are recorded only when the signature verified, and the raw token is never stored or recorded.

import (
	"context"
	"errors"
	"sort"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	// webIdentityMaxClockTolerance is how long the replay record outlives the provider's acceptance window; an
	// unusable stored tolerance counts as the maximum.
	webIdentityMaxClockTolerance = 120
	webIdentityAuditAction       = "role:assumed-with-web-identity"
)

func webIdentityFeatureDisabled() error {
	return core.NewIamError("FEATURE_DISABLED", "Web identity federation is not enabled", 403)
}

func webIdentityRejected() error {
	return core.NewIamError("WEB_IDENTITY_REJECTED", "The web identity token was not accepted", 403)
}

// webIdentityRejection is a refusal that depends on stored state or on the token; it always surfaces as
// webIdentityRejected().
type webIdentityRejection struct {
	reason string
}

func (e *webIdentityRejection) Error() string {
	return "Web identity exchange rejected (" + e.reason + ")"
}

// Name is the JavaScript error name.
func (e *webIdentityRejection) Name() string { return "Rejection" }

// liveWebIdentityTrust is a live web-identity trust of the tenant (read fail-closed).
func liveWebIdentityTrust(trust *core.Object, tenantID any) bool {
	if trust == nil || !core.StrictEquals(trust.Get("tenantId"), tenantID) || trust.Get("kind") != "web-identity" || trust.Get("revoked") != false {
		return false
	}
	_, okProvider := trust.Get("providerId").(string)
	_, okRole := trust.Get("roleId").(string)
	_, okSource := trust.Get("sourceIdentityId").(string)
	return okProvider && okRole && okSource
}

// liveWebIdentityProvider is an enabled provider of the tenant (read fail-closed).
func liveWebIdentityProvider(provider *core.Object, tenantID any) bool {
	return provider != nil && core.StrictEquals(provider.Get("tenantId"), tenantID) && provider.Get("enabled") == true
}

// webIdentityInspection is what inspect concludes: the evaluation, and once the token verified, the verified
// identity and the mapped tags and source identity.
type webIdentityInspection struct {
	evaluation *core.Object
	// verified is nil until the token verified.
	verified       *core.Object
	sessionTags    *core.Object
	sourceIdentity string
	hasSource      bool
}

// inspectWebIdentity verifies a token against a provider and matches it against a trust: the signature and claims,
// the trust's claim conditions (re-validated, so a malformed or unpinned stored block matches nothing), then the
// claim mappings. Only string claims of at most 256 characters in the tag value charset become tags (others are left
// out, as is a tag that would overflow the packed size); a `sourceIdentityClaim` that is missing or not a valid
// source identity refuses the token.
func inspectWebIdentity(ctx context.Context, server *ServerContext, trust, provider *core.Object, token any) (*webIdentityInspection, error) {
	verifier := server.WebIdentity
	if verifier == nil {
		return nil, webIdentityFeatureDisabled()
	}
	// The deployment's issuer pin holds for providers registered before it was narrowed, too.
	if !webIdentityIssuerAllowed(server, provider) {
		return &webIdentityInspection{evaluation: core.NewObject("verified", false, "reason", "issuer")}, nil
	}
	text, _ := token.(string)
	verified, err := verifier.Verify(ctx, provider, text)
	if err != nil {
		// Anything but a typed refusal (a malformed stored provider, say) refuses the token all the same.
		reason := "malformed"
		var failure *WebIdentityFailure
		if errors.As(err, &failure) {
			reason = failure.Reason
		}
		return &webIdentityInspection{evaluation: core.NewObject("verified", false, "reason", reason)}, nil
	}
	return matchWebIdentityTrust(trust, verified)
}

// webIdentityIssuerAllowed is whether `sts.webIdentity.allowedIssuers` (when set) still admits the provider's issuer.
func webIdentityIssuerAllowed(server *ServerContext, provider *core.Object) bool {
	allowed := server.Config.Sts.WebIdentity.AllowedIssuers
	if allowed == nil {
		return true
	}
	issuer, ok := provider.Get("issuer").(string)
	return ok && containsString(allowed, issuer)
}

// webIdentityNullish is `value ?? null`.
func webIdentityNullish(value any) any {
	if nullish(value) {
		return nil
	}
	return value
}

// webIdentityVerificationSettings is the provider settings a verification depends on. Issuance compares them between
// the record the token was verified against and the one re-read in the transaction, so a key, audience or algorithm
// change in between refuses it.
func webIdentityVerificationSettings(provider *core.Object) string {
	text, _, err := core.Stringify([]any{
		provider.Get("issuer"), webIdentityNullish(provider.Get("audiences")),
		webIdentityNullish(provider.Get("algorithms")), webIdentityNullish(provider.Get("jwks")),
		webIdentityNullish(provider.Get("jwksUri")), webIdentityNullish(provider.Get("maxTokenLifetimeSeconds")),
		webIdentityNullish(provider.Get("clockToleranceSeconds")),
	})
	if err != nil {
		return ""
	}
	return text
}

// webIdentityNotImplemented is a NOT_IMPLEMENTED stub of another module, which must surface rather than be taken as
// an ordinary refusal.
func webIdentityNotImplemented(err error) bool {
	known, ok := asIamError(err)
	return ok && known.Code == "NOT_IMPLEMENTED"
}

// matchWebIdentityTrust matches a verified token against a trust: its claim conditions, then its claim mappings.
// Pure, so issuance can repeat it against the trust as re-read in the transaction.
func matchWebIdentityTrust(trust, verified *core.Object) (*webIdentityInspection, error) {
	claims := core.NewObject("iss", verified.Get("issuer"), "sub", verified.Get("subject"), "aud", verified.Get("audience"),
		"iat", verified.Get("issuedAt"), "exp", verified.Get("expiresAt"))
	if jti := verified.Get("jti"); !isUndefined(jti) {
		claims.Set("jti", jti)
	}
	evaluation := core.NewObject("verified", true, "claims", claims)
	context, _ := verified.Get("context").(*core.Object)
	if context == nil {
		context = core.NewObject()
	}
	conditions := core.NewObject("matched", false, "failed", []any{"conditions"})
	if validated, err := WebIdentityConditions(trust.Get("conditions")); err == nil {
		if matched, err := MatchWebIdentityConditions(validated, context, jsString(trust.Get("id"))); err == nil {
			conditions = matched
		}
	}
	evaluation.Set("conditions", conditions)
	claim := func(name any) any {
		text, ok := name.(string)
		if !ok || !context.Has(text) {
			return core.Undefined
		}
		return context.Get(text)
	}
	sessionTags := core.NewObject()
	if mapping, ok := trust.Get("tagClaims").(*core.Object); ok && mapping != nil {
		for _, key := range mapping.Keys() {
			value, ok := claim(mapping.Get(key)).(string)
			if !ok {
				continue
			}
			candidate := sessionTags.Clone()
			candidate.Set(key, value)
			if _, err := SessionTagsValue(candidate); err != nil {
				if webIdentityNotImplemented(err) {
					return nil, err
				}
				// Not a usable tag: left out.
				continue
			}
			sessionTags.Set(key, value)
		}
	}
	inspection := &webIdentityInspection{evaluation: evaluation, verified: verified}
	if sessionTags.Len() > 0 {
		inspection.sessionTags = sessionTags
		evaluation.Set("sessionTags", sessionTags.Clone())
	}
	sourceIdentityRefused := false
	if name := trust.Get("sourceIdentityClaim"); !isUndefined(name) {
		if value, ok := claim(name).(string); ok && SessionNamePattern.MatchString(value) {
			inspection.sourceIdentity, inspection.hasSource = value, true
		} else {
			sourceIdentityRefused = true
		}
	}
	if inspection.hasSource {
		evaluation.Set("sourceIdentity", inspection.sourceIdentity)
	}
	if conditions.Get("matched") != true {
		evaluation.Set("reason", "conditions")
	} else if sourceIdentityRefused {
		evaluation.Set("reason", "source-identity")
	}
	return inspection, nil
}

// webIdentitySessionBacking is what backs a live trust's sessions, read fail-closed: the role (present, unprotected,
// under a live authority), the service account (active, unexpired, in the tenant) and the authorities of the trust's
// and the provider's creators. Returns the role and the account, or the first refusal in the order issuance checks
// them ("role", "service-account" or "authority").
func webIdentitySessionBacking(ctx context.Context, server *ServerContext, tx core.IamStore, trust, provider *core.Object) (role, account *core.Object, reason string, err error) {
	tenantID := trust.Get("tenantId")
	live := func(authorityID any) (bool, error) {
		text, ok := authorityID.(string)
		if !ok {
			return false, nil
		}
		_, found, err := server.AuthorityChain(ctx, tx, text)
		return found, err
	}
	role, err = tx.Get(ctx, "roles", jsString(trust.Get("roleId")))
	if err != nil {
		return nil, nil, "", err
	}
	if role == nil || !core.StrictEquals(role.Get("tenantId"), tenantID) || truthy(role.Get("protected")) {
		return nil, nil, "role", nil
	}
	if ok, err := live(role.Get("authorityId")); err != nil || !ok {
		return nil, nil, "role", err
	}
	account, err = tx.Get(ctx, "identities", jsString(trust.Get("sourceIdentityId")))
	if err != nil {
		return nil, nil, "", err
	}
	if account == nil || account.Get("kind") != "service" || account.Get("status") != "active" ||
		!core.StrictEquals(account.Get("tenantId"), tenantID) || !core.StrictEquals(trust.Get("sourceTenantId"), tenantID) || server.IdentityExpired(account) {
		return nil, nil, "service-account", nil
	}
	// Sessions are bounded by the authorities of the trust's and the provider's creators.
	if ok, err := live(trust.Get("authorityId")); err != nil || !ok {
		return nil, nil, "authority", err
	}
	if ok, err := live(provider.Get("authorityId")); err != nil || !ok {
		return nil, nil, "authority", err
	}
	return role, account, "", nil
}

// EvaluateWebIdentity (web-identity-exchange.ts evaluateWebIdentity): The dry run behind
// `trust.evaluateWebIdentity`: verification, trust conditions and claim mappings for a token, with no replay record
// and no issuance. The caller has authorized the read and loaded the trust and its provider (input: trust, provider,
// token). Stored state that would refuse the exchange is reported too, in the exchange's order: a revoked trust or a
// disabled provider comes before the token's own problems, and the role, service account and authorities after them.
func EvaluateWebIdentity(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	trust, _ := input.Get("trust").(*core.Object)
	provider, _ := input.Get("provider").(*core.Object)
	inspection, err := inspectWebIdentity(ctx, server, trust, provider, input.Get("token"))
	if err != nil {
		return nil, err
	}
	evaluation := inspection.evaluation
	tenantID := trust.Get("tenantId")
	if !liveWebIdentityTrust(trust, tenantID) {
		evaluation.Set("reason", "trust")
	} else if !liveWebIdentityProvider(provider, tenantID) || !core.StrictEquals(trust.Get("providerId"), provider.Get("id")) {
		evaluation.Set("reason", "provider")
	} else if !evaluation.Has("reason") {
		var reason string
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			var err error
			_, _, reason, err = webIdentitySessionBacking(ctx, server, tx, trust, provider)
			return err
		})
		if err != nil {
			return nil, err
		}
		if reason != "" {
			evaluation.Set("reason", reason)
		}
	}
	return evaluation, nil
}

// WebIdentityStsAPI is web-identity-exchange.ts createWebIdentityStsApi(): the public side of the `sts` group.
type WebIdentityStsAPI struct {
	server *ServerContext
}

// CreateWebIdentityStsAPI builds the WebIdentityStsAPI (web-identity-exchange.ts createWebIdentityStsApi).
func CreateWebIdentityStsAPI(server *ServerContext) *WebIdentityStsAPI {
	return &WebIdentityStsAPI{server: server}
}

// recordDenial records a refusal in its own transaction; bookkeeping never masks the refusal itself.
func (s *WebIdentityStsAPI) recordDenial(ctx context.Context, trust *core.Object, reason string, verified *core.Object) {
	server := s.server
	providerID := trust.Get("providerId")
	if _, ok := providerID.(string); !ok {
		providerID = nil
	}
	metadata := core.NewObject("trustId", trust.Get("id"), "providerId", providerID, "reason", reason)
	// Claims are recorded only once the signature verified; unverified input never reaches the audit log.
	if verified != nil {
		issuer, _ := verified.Get("issuer").(string)
		subject, _ := verified.Get("subject").(string)
		metadata.Set("issuer", sliceUTF16(issuer, 0, 256))
		metadata.Set("subject", sliceUTF16(subject, 0, 256))
	}
	_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", trust.Get("tenantId"),
			// The trust's anchoring service account, the identity a session would have acted as.
			"actorId", trust.Get("sourceIdentityId"),
			"action", webIdentityAuditAction, "resourceId", trust.Get("roleId"), "outcome", "deny",
			"rootOverride", false, "timestamp", float64(server.Now()), "metadata", metadata,
		))
	})
}

// webIdentityIssueRequest is what the issuance transaction receives.
type webIdentityIssueRequest struct {
	tenantID        string
	trustID         string
	token           string
	sessionName     string
	durationSeconds any
	// policy is core.Undefined when absent.
	policy   any
	format   string
	audience []string
}

// webIdentityClientRecord is the recorded client ({ ip?, userAgent?, label? }); nil when there is none.
func webIdentityClientRecord(client *core.SessionClientInfo) *core.Object {
	if client == nil {
		return nil
	}
	record := core.NewObject()
	if client.IP != "" {
		record.Set("ip", client.IP)
	}
	if client.UserAgent != "" {
		record.Set("userAgent", client.UserAgent)
	}
	if client.Label != "" {
		record.Set("label", client.Label)
	}
	if record.Len() == 0 {
		return nil
	}
	return record
}

// webIdentityAudienceValue is a validated audience list as the mint input carries it (undefined when absent).
func webIdentityAudienceValue(audience []string) any {
	if audience == nil {
		return core.Undefined
	}
	return stringsOf(audience)
}

// issue is the issuance transaction: every stored-state check is repeated here, next to the replay record and the
// row.
func (s *WebIdentityStsAPI) issue(ctx context.Context, tx core.IamStore, request webIdentityIssueRequest, verifiedWith, verified *core.Object) (*core.Object, error) {
	server := s.server
	authService := server.Auth
	settings := server.Config.Sts.WebIdentity
	tenantID := request.tenantID
	trust, err := tx.Get(ctx, "trusts", request.trustID)
	if err != nil {
		return nil, err
	}
	if !liveWebIdentityTrust(trust, tenantID) || !core.StrictEquals(trust.Get("providerId"), verifiedWith.Get("id")) {
		return nil, &webIdentityRejection{reason: "trust"}
	}
	// The token was verified and matched outside this transaction: the provider settings it was verified against
	// must still be the live ones, and the live trust must still admit it (with its current mappings).
	provider, err := tx.Get(ctx, "oidcProviders", jsString(verifiedWith.Get("id")))
	if err != nil {
		return nil, err
	}
	if !liveWebIdentityProvider(provider, tenantID) || !core.StrictEquals(provider.Get("issuer"), verified.Get("issuer")) ||
		!webIdentityIssuerAllowed(server, provider) ||
		webIdentityVerificationSettings(provider) != webIdentityVerificationSettings(verifiedWith) {
		return nil, &webIdentityRejection{reason: "provider"}
	}
	inspection, err := matchWebIdentityTrust(trust, verified)
	if err != nil {
		return nil, err
	}
	if reason, ok := inspection.evaluation.Get("reason").(string); ok {
		return nil, &webIdentityRejection{reason: reason}
	}
	role, account, reason, err := webIdentitySessionBacking(ctx, server, tx, trust, provider)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return nil, &webIdentityRejection{reason: reason}
	}
	target, err := tx.Get(ctx, "tenants", tenantID)
	if err == nil && target != nil {
		ancestry, err := server.Ancestry(ctx, tx, target)
		if err != nil {
			target = nil
		}
		for _, item := range ancestry {
			if item.Get("status") != "active" {
				target = nil
				break
			}
		}
	} else {
		target = nil
	}
	if target == nil {
		return nil, &webIdentityRejection{reason: "tenant"}
	}

	// From here on the token matched a live trust, so specific refusals may surface.
	ip := ""
	if client := authService.CurrentClient(ctx); client != nil {
		ip = client.IP
	}
	if err := authService.AssertIPAllowed(target, ip); err != nil {
		return nil, err
	}
	if err := authService.AssertNetworkNotBlocked(ctx, tx, tenantID, ip); err != nil {
		return nil, err
	}
	// The injected clock, like user sessions, so validation and issuance agree under a test clock.
	now := server.Now()
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("roleId", trust.Get("roleId")), nil)
	if err != nil {
		return nil, err
	}
	live := 0
	for _, session := range sessions {
		if session.Get("kind") == "role" && core.StrictEquals(session.Get("trustId"), trust.Get("id")) && session.Get("tenantId") == tenantID &&
			jsNumber(session.Get("expiresAt")) > float64(now) {
			live++
		}
	}
	if int64(live) >= settings.MaxSessionsPerTrust {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "This trust holds the maximum number of live role sessions", 409)
	}
	if !isUndefined(request.policy) {
		if err := server.Catalog.Validate(ctx, tx, tenantID, request.policy); err != nil {
			return nil, err
		}
	}
	bounds, err := RoleDurationBounds(server, trust, request.format)
	if err != nil {
		return nil, err
	}
	durationSeconds, err := DurationWithin(request.durationSeconds, bounds)
	if err != nil {
		return nil, err
	}
	// Single use unless the provider opts out; recorded in this transaction, so a failed issuance does not burn it.
	if provider.Get("replayProtection") != "off" {
		jti, _ := verified.Get("jti").(string)
		replayID, err := WebIdentityReplayID(jsString(provider.Get("id")), jti, request.token)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Get(ctx, "webIdentityReplays", replayID)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, &webIdentityRejection{reason: "replay"}
		}
		// Kept for the largest tolerance any provider may be given, not this provider's current one: raising its
		// clockToleranceSeconds later must not reopen a window in which an already redeemed token is accepted again.
		if _, err := tx.Insert(ctx, "webIdentityReplays", core.NewObject(
			"id", replayID, "tenantId", provider.Get("tenantId"), "providerId", provider.Get("id"),
			"expiresAt", jsNumber(verified.Get("expiresAt"))*1000+webIdentityMaxClockTolerance*1000,
		)); err != nil {
			return nil, err
		}
	}
	webIdentity := core.NewObject("providerId", provider.Get("id"), "issuer", verified.Get("issuer"), "subject", verified.Get("subject"))
	draft := core.NewObject(
		"id", ID(), "tenantId", tenantID, "identityId", account.Get("id"), "originalIdentityId", account.Get("id"),
		"roleId", role.Get("id"), "trustId", trust.Get("id"), "kind", "role", "tokenHash", "",
		"createdAt", float64(now), "lastSeenAt", float64(now),
		// The exchange is the authentication; external tokens never attest MFA.
		"authenticatedAt", float64(now), "expiresAt", float64(now)+durationSeconds*1000, "mfa", false,
		"credentialAuthorityId", trust.Get("authorityId"), "webIdentity", webIdentity, "sessionName", request.sessionName,
	)
	if !isUndefined(request.policy) {
		draft.Set("policy", request.policy)
	}
	if inspection.sessionTags != nil {
		draft.Set("sessionTags", inspection.sessionTags.Clone())
	}
	if inspection.hasSource {
		draft.Set("sourceIdentity", inspection.sourceIdentity)
	}
	// The presenting address: the tenant's allowlist and network blocks judge it on every use.
	if client := webIdentityClientRecord(authService.CurrentClient(ctx)); client != nil {
		draft.Set("client", client)
	}
	minted, err := MintCredential(ctx, server, tx, core.NewObject(
		"identity", account, "draft", draft, "format", request.format, "audience", webIdentityAudienceValue(request.audience),
	))
	if err != nil {
		return nil, err
	}
	token, _ := minted.Get("token").(string)
	session, _ := minted.Get("session").(*core.Object)
	tagKeys := []string{}
	if inspection.sessionTags != nil {
		tagKeys = inspection.sessionTags.Keys()
	}
	sort.SliceStable(tagKeys, func(i, j int) bool { return compareUTF16(tagKeys[i], tagKeys[j]) < 0 })
	issuer, _ := verified.Get("issuer").(string)
	subject, _ := verified.Get("subject").(string)
	if err := server.Events.Audit(ctx, tx, &Principal{Identity: account, Session: session}, webIdentityAuditAction, tenantID,
		jsString(role.Get("id")), "allow", false, core.NewObject(
			"trustId", trust.Get("id"), "providerId", provider.Get("id"), "issuer", sliceUTF16(issuer, 0, 256),
			"subject", sliceUTF16(subject, 0, 256), "durationSeconds", durationSeconds, "format", request.format,
			"tagKeys", stringsOf(tagKeys),
		)); err != nil {
		return nil, err
	}
	credential, err := TemporaryCredential(token, session, now)
	if err != nil {
		return nil, err
	}
	result := credential.Clone()
	result.Set("webIdentity", webIdentity.Clone())
	return result, nil
}

// AssumeRoleWithWebIdentity (web-identity-exchange.ts createWebIdentityStsApi().assumeRoleWithWebIdentity):
// AssumeRoleWithWebIdentity (public; no IAM credential): exchanges a verified external OIDC token for a role session
// of kind 'role' under a web-identity trust, acting as the trust's service account and bounded by the role, the
// trust's ceiling, and the authorities of the trust's and the provider's creators. The token must be signed by the
// provider's keys with an allowed algorithm, name the provider's issuer and one of its audiences, be fresh, satisfy
// the trust's claim conditions and (by default) not have been redeemed before at this provider. Every refusal that
// depends on stored state or on the token is WEB_IDENTITY_REJECTED (403) with the same body. The attempt counts
// against `sts.webIdentity.maxExchangesPerWindow` for the trust before anything is looked up. The credential is
// returned once, in the body; this route never sets a cookie. Audited as `role:assumed-with-web-identity` (allow, or
// deny with a reason once the trust resolved).
func (s *WebIdentityStsAPI) AssumeRoleWithWebIdentity(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	authService := server.Auth
	settings := server.Config.Sts.WebIdentity
	if !settings.Enabled || server.WebIdentity == nil {
		return nil, webIdentityFeatureDisabled()
	}
	// (1) Shape only: nothing here depends on stored state.
	if input == nil {
		return nil, invalidInput("Expected an object")
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	trustID, err := Text(input.Get("trustId"), "trustId")
	if err != nil {
		return nil, err
	}
	token, ok := input.Get("webIdentityToken").(string)
	if !ok || utf16Len(token) > webIdentityMaxTokenLength || !webIdentityTokenShape.MatchString(token) {
		return nil, invalidInput("webIdentityToken must be a compact JWT of at most 8192 characters")
	}
	sessionName, ok := input.Get("sessionName").(string)
	if !ok || !SessionNamePattern.MatchString(sessionName) {
		return nil, invalidInput("sessionName must be 2-64 letters, digits or +=,.@_- characters")
	}
	if duration := input.Get("durationSeconds"); !isUndefined(duration) {
		if _, ok := duration.(float64); !ok {
			return nil, invalidInput("durationSeconds must be a number")
		}
	}
	policy := input.Get("policy")
	if !isUndefined(policy) {
		if document, ok := policy.(*core.Object); !ok || document == nil {
			return nil, invalidInput("policy must be a policy document")
		}
	}
	if format := input.Get("format"); !isUndefined(format) {
		if _, ok := format.(string); !ok {
			return nil, invalidInput("format must be 'opaque' or 'jwt'")
		}
	}
	if audience := input.Get("audience"); !isUndefined(audience) && !isArray(audience) {
		return nil, invalidInput("audience must be a list")
	}

	// (2) Counted before any lookup and outside any transaction, so a refusal cannot roll it back. Trust ids are
	// public (they sit in CI workflow files), so when the client's address is known the budget is per address, and
	// one source posting junk tokens cannot use up the trust's exchanges for everyone; the trust as a whole still has
	// a ceiling (ten budgets) that bounds the work any number of sources can cause.
	ip := ""
	if client := authService.CurrentClient(ctx); client != nil {
		ip = client.IP
	}
	limit := settings.MaxExchangesPerWindow
	if ip != "" {
		// An IPv6 /64 counts as one source, so rotating through it earns no fresh budget.
		source, ok := core.IPCounterKey(ip)
		if !ok {
			source = ip
		}
		if err := authService.LimitAttempt(ctx, tenantID, "web-identity:"+trustID+":"+source, auth.LimitAttemptOptions{Limit: &limit}); err != nil {
			return nil, err
		}
		ceiling := limit * 10
		if err := authService.LimitAttempt(ctx, tenantID, "web-identity:"+trustID, auth.LimitAttemptOptions{Limit: &ceiling, SkipClient: true}); err != nil {
			return nil, err
		}
	} else if err := authService.LimitAttempt(ctx, tenantID, "web-identity:"+trustID, auth.LimitAttemptOptions{Limit: &limit}); err != nil {
		return nil, err
	}

	// (3) The trust and its provider; an unknown trust is refused like every other failure, without an audit.
	trust, err := server.Store.Get(ctx, "trusts", trustID)
	if err != nil {
		return nil, err
	}
	if !liveWebIdentityTrust(trust, tenantID) {
		return nil, webIdentityRejected()
	}
	provider, err := server.Store.Get(ctx, "oidcProviders", jsString(trust.Get("providerId")))
	if err != nil {
		return nil, err
	}
	if !liveWebIdentityProvider(provider, tenantID) {
		return nil, webIdentityRejected()
	}

	// (4)-(6) Verification, claim conditions and mappings, outside any transaction (keys may be fetched).
	inspection, err := inspectWebIdentity(ctx, server, trust, provider, token)
	if err != nil {
		return nil, err
	}
	verified := inspection.verified
	if verified == nil || inspection.evaluation.Has("reason") {
		reason, ok := inspection.evaluation.Get("reason").(string)
		if !ok {
			reason = "malformed"
		}
		s.recordDenial(ctx, trust, reason, verified)
		return nil, webIdentityRejected()
	}

	// (7) Issuance. Stored-state failures and replays are rejections; the rest surface as themselves.
	result, err = func() (*core.Object, error) {
		format, err := CredentialFormat(input.Get("format"))
		if err != nil {
			return nil, err
		}
		audience, err := AudienceValue(input.Get("audience"), format)
		if err != nil {
			return nil, err
		}
		if format == "jwt" && server.SessionTokens == nil {
			return nil, core.NewIamError("FEATURE_DISABLED", "Session JWTs are not enabled on this deployment (sts.jwt)", 403)
		}
		return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			return s.issue(ctx, tx, webIdentityIssueRequest{
				tenantID: tenantID, trustID: trustID, token: token, sessionName: sessionName,
				durationSeconds: input.Get("durationSeconds"), policy: policy, format: format, audience: audience,
			}, provider, verified)
		})
	}()
	if err != nil {
		// A concurrent redemption of the same token loses the insert race: the same refusal as a replay.
		reason := ""
		var rejection *webIdentityRejection
		if errors.As(err, &rejection) {
			reason = rejection.reason
		} else if known, ok := asIamError(err); ok && known.Code == "CONFLICT" {
			reason = "replay"
		}
		if reason != "" {
			s.recordDenial(ctx, trust, reason, verified)
			return nil, webIdentityRejected()
		}
		if known, ok := asIamError(err); ok {
			s.recordDenial(ctx, trust, known.Code, verified)
		}
		return nil, err
	}
	return result, nil
}
