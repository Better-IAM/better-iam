package oauth

// The token endpoint and its grants, client authentication, DPoP proof validation, accounts and ID tokens,
// introspection, revocation and userinfo (oidc-provider actions/token.js, actions/grants, shared/client_auth.js,
// helpers/validate_dpop.js, actions/introspection.js, actions/revocation.js, actions/userinfo.js).

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var clientAuthParams = []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"}

var grantParams = map[string][]string{
	"authorization_code": {"grant_type", "code", "code_verifier", "redirect_uri", "resource"},
	"refresh_token":      {"grant_type", "refresh_token", "scope", "resource"},
	"client_credentials": {"grant_type", "scope", "resource"},
	deviceCodeGrant:      {"grant_type", "device_code", "resource"},
	tokenExchangeGrant:   {"grant_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "requested_token_type", "audience", "resource", "scope"},
}

var grantDupes = map[string][]string{
	"authorization_code": {"resource"}, "refresh_token": {"resource"}, "client_credentials": {"resource"},
	deviceCodeGrant: {"resource"}, tokenExchangeGrant: {"audience", "resource"},
}

func allGrantParams() []string {
	var out []string
	for _, grant := range []string{"authorization_code", "refresh_token", "client_credentials", deviceCodeGrant, tokenExchangeGrant} {
		out = append(out, grantParams[grant]...)
	}
	return unique(out)
}

// --- client authentication -------------------------------------------------------------------------------------------

var basic64 = regexp.MustCompile(`^([A-Za-z0-9+/]*)(={0,2})$`)

func isValidBase64(input string) bool {
	match := basic64.FindStringSubmatch(input)
	if match == nil || match[1] == "" {
		return false
	}
	remainder := len(match[1]) % 4
	if match[2] == "" {
		return remainder != 1
	}
	return (len(match[1])+len(match[2]))%4 == 0 && len(match[2]) == 4-remainder
}

func decodeAuthToken(token string) (string, error) {
	decoded, ok := decodeURIComponent(strings.ReplaceAll(token, "+", "%20"))
	if !ok {
		return "", errors.New("URI malformed")
	}
	if noVSChar.MatchString(decoded) {
		return "", errors.New("invalid character found")
	}
	return decoded, nil
}

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// authenticateClient is shared/client_auth.js (rejectClientAuthDupes, setWWWAuthenticateHeader, authenticateClient).
func (p *Provider) authenticateClient(oc *oidcCtx) error {
	if err := oc.rejectDupes(nil, clientAuthParams); err != nil {
		return err
	}
	err := p.authenticateClientInner(oc)
	if err != nil {
		if e, ok := asOIDC(err); ok && e.Status == 401 && len(oc.r.Header.Values("authorization")) > 0 {
			appendWWWAuthenticate(oc, "Basic", [][2]string{{"realm", p.issuer}, {"error", e.Code}, {"error_description", e.Description}})
		}
	}
	return err
}

func appendWWWAuthenticate(oc *oidcCtx, scheme string, fields [][2]string) {
	var parts []string
	for _, field := range fields {
		if field[1] == "" && (field[0] == "scope" || field[0] == "error_description" || field[0] == "algs") {
			continue
		}
		parts = append(parts, field[0]+`="`+strings.ReplaceAll(strings.ReplaceAll(field[1], `\`, `\\`), `"`, `\"`)+`"`)
	}
	oc.header.Add("WWW-Authenticate", scheme+" "+strings.Join(parts, ", "))
}

func (p *Provider) authenticateClientInner(oc *oidcCtx) error {
	var methods []string
	clientID, clientSecret := "", ""
	hasClientID := false
	setClientID := func(value string) error {
		if hasClientID && value != clientID {
			return errInvalidRequest("client_id mismatch")
		}
		clientID, hasClientID = value, true
		return nil
	}
	headerValues := oc.r.Header.Values("authorization")
	authorization := ""
	if len(headerValues) > 0 {
		authorization = headerValues[0]
	}
	hasAttestation := len(oc.r.Header.Values("oauth-client-attestation")) > 0
	hasAttestationPop := len(oc.r.Header.Values("oauth-client-attestation-pop")) > 0
	mechanisms := 0
	for _, value := range []any{authorization, oc.params.Get("client_assertion"), oc.params.Get("client_secret")} {
		if truthy(value) {
			mechanisms++
		}
	}
	if mechanisms > 1 || (mechanisms > 0 && (hasAttestation || hasAttestationPop)) {
		return errInvalidRequest("client authentication must only be provided using one mechanism")
	}
	if value := oc.params.Get("client_id"); !isUndefined(value) {
		if err := setClientID(jsString(value)); err != nil {
			return err
		}
	}
	switch {
	case truthy(oc.params.Get("client_secret")):
		clientSecret = jsString(oc.params.Get("client_secret"))
		methods = []string{"client_secret_basic", "client_secret_post"}
	case len(headerValues) > 0:
		parts := strings.Split(authorization, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "basic" || !isValidBase64(parts[1]) {
			return errInvalidRequest("invalid authorization header value format")
		}
		decoded, _ := base64.StdEncoding.DecodeString(parts[1])
		if decoded == nil {
			decoded = nodeBase64Decode(parts[1])
		}
		basic := decodeUTF8(decoded)
		index := strings.Index(basic, ":")
		if index == -1 {
			return errInvalidRequest("invalid authorization header value format")
		}
		basicClientID, err := decodeAuthToken(basic[:index])
		if err == nil {
			clientSecret, err = decodeAuthToken(basic[index+1:])
		}
		if err != nil {
			return errInvalidRequest("client_id and client_secret in the authorization header are not properly encoded")
		}
		if err := setClientID(basicClientID); err != nil {
			return err
		}
		if clientSecret == "" {
			return errInvalidRequest("client_secret must be provided in the Authorization header")
		}
		methods = []string{"client_secret_basic", "client_secret_post"}
	case hasAttestation:
		return errInvalidClientAuth("the provided authentication mechanism does not match the registered client authentication method")
	case !isUndefined(oc.params.Get("client_assertion")):
		payload, err := joseDecodePayload(jsString(oc.params.Get("client_assertion")))
		if err != nil {
			return errInvalidRequest("invalid client_assertion format")
		}
		if !truthy(payload.Get("sub")) {
			return errInvalidClientAuth("sub (JWT subject) must be provided in the client_assertion JWT")
		}
		if isUndefined(oc.params.Get("client_assertion_type")) {
			return errInvalidRequest("client_assertion_type must be provided")
		}
		if oc.params.Get("client_assertion_type") != assertionType {
			return errInvalidRequest("client_assertion_type must have value " + assertionType)
		}
		if err := setClientID(jsString(payload.Get("sub"))); err != nil {
			return err
		}
		methods = []string{"client_secret_jwt", "private_key_jwt"}
	default:
		methods = []string{"none", "tls_client_auth", "self_signed_tls_client_auth"}
	}
	if clientID == "" {
		return errInvalidRequest("no client authentication mechanism provided")
	}
	client, err := p.findClient(oc.ctx, clientID)
	if err != nil {
		return err
	}
	if client == nil {
		return errInvalidClientAuth("client not found")
	}
	if err := oc.assignClient(client); err != nil {
		return err
	}
	if !contains(methods, client.authMethod()) {
		return errInvalidClientAuth("the provided authentication mechanism does not match the registered client authentication method")
	}
	switch client.authMethod() {
	case "client_secret_basic", "client_secret_post":
		if err := p.checkClientSecretExpiration(client); err != nil {
			return err
		}
		if !client.compareSecret(clientSecret) {
			return errInvalidClientAuth("invalid secret provided")
		}
	case "client_secret_jwt":
		if err := p.checkClientSecretExpiration(client); err != nil {
			return err
		}
		return p.jwtClientAuth(oc, true)
	case "private_key_jwt":
		return p.jwtClientAuth(oc, false)
	case "tls_client_auth", "self_signed_tls_client_auth":
		return errInvalidClientAuth("client certificate was not provided")
	}
	return nil
}

func (p *Provider) checkClientSecretExpiration(client *oidcClient) error {
	expires, ok := client.metadata.Get("client_secret_expires_at").(float64)
	if !ok || expires == 0 {
		return nil
	}
	if float64(epoch(p.now()))-15 >= expires {
		return errInvalidClient("could not authenticate the client - its client secret is expired")
	}
	return nil
}

// clientJwtAuthExpectedAudience is { issuer, the token endpoint, the current endpoint }.
func (oc *oidcCtx) clientJwtAuthExpectedAudience() []string {
	return []string{oc.p.issuer, oc.urlFor("token", nil, nil), oc.urlFor(oc.route, nil, nil)}
}

// jwtClientAuth is shared/jwt_client_auth.js.
func (p *Provider) jwtClientAuth(oc *oidcCtx, symmetric bool) error {
	assertion := jsString(oc.params.Get("client_assertion"))
	header, payload, err := decodeUnsecured(assertion)
	if err != nil {
		return errInvalidClientAuth("")
	}
	alg := str(header, "alg")
	if configured := str(oc.client.metadata, "token_endpoint_auth_signing_alg"); configured != "" {
		if alg != configured {
			return errInvalidClientAuth("alg mismatch")
		}
	} else {
		allowed := false
		for _, candidate := range clientAuthAlgs {
			if strings.HasPrefix(candidate, "HS") == symmetric && candidate == alg {
				allowed = true
			}
		}
		if !allowed {
			return errInvalidClientAuth("alg mismatch")
		}
	}
	if !truthy(payload.Get("exp")) {
		return errInvalidClientAuth("expiration must be specified in the client_assertion JWT")
	}
	if !truthy(payload.Get("jti")) {
		return errInvalidClientAuth("unique jti (JWT ID) must be provided in the client_assertion JWT")
	}
	if !truthy(payload.Get("iss")) {
		return errInvalidClientAuth("iss (JWT issuer) must be provided in the client_assertion JWT")
	}
	if !jsEq(payload.Get("iss"), oc.client.clientID()) {
		return errInvalidClientAuth("iss (JWT issuer) must be the client_id")
	}
	if !truthy(payload.Get("aud")) {
		return errInvalidClientAuth("aud (JWT audience) must be provided in the client_assertion JWT")
	}
	accepted := oc.clientJwtAuthExpectedAudience()
	if list, ok := payload.Get("aud").([]any); ok {
		found := false
		for _, aud := range stringList(list) {
			if contains(accepted, aud) {
				found = true
			}
		}
		if !found {
			return errInvalidClientAuth("list of audience (aud) must include the endpoint url, issuer identifier or token endpoint url")
		}
	} else if !contains(accepted, jsString(payload.Get("aud"))) {
		return errInvalidClientAuth("audience (aud) must equal the endpoint url, issuer identifier or token endpoint url")
	}
	if symmetric {
		if !p.verifyHMAC(assertion, alg, str(oc.client.metadata, "client_secret")) {
			return errInvalidClientAuth("")
		}
	} else if err := p.verifyWithClientKeys(oc.ctx, oc.client, assertion, header); err != nil {
		return errInvalidClientAuth("")
	}
	if !p.assertPayload(payload, false) {
		return errInvalidClientAuth("")
	}
	exp, _ := payload.Get("exp").(float64)
	unique, err := p.replayUnique(oc.ctx, jsString(payload.Get("iss")), jsString(payload.Get("jti")), int64(exp)+15)
	if err != nil {
		return err
	}
	if !unique {
		return errInvalidClientAuth("client assertion tokens must only be used once")
	}
	return nil
}

func (p *Provider) verifyHMAC(token, alg, secret string) bool {
	entry, ok := joseAlgorithms[alg]
	if !ok || !entry.secret || secret == "" {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(entry.hash.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	signature, err := joseDecode(parts[2])
	return err == nil && hmac.Equal(mac.Sum(nil), signature)
}

// verifyWithClientKeys is JWT.verify against the client's asymmetric keystore, refreshing a stale jwks_uri once.
func (p *Provider) verifyWithClientKeys(ctx context.Context, client *oidcClient, token string, header *core.Object) error {
	for attempt := 0; attempt < 2; attempt++ {
		alg := str(header, "alg")
		entry, ok := joseAlgorithms[alg]
		verified := false
		if ok && !entry.secret {
			parts := strings.Split(token, ".")
			signature, err := joseDecode(parts[len(parts)-1])
			if len(parts) == 3 && err == nil {
				for _, jwk := range client.currentKeys() {
					if !clientKeyUsable(jwk, alg, header.Get("kid")) {
						continue
					}
					key, err := joseImportPublic(jwk, alg)
					if err != nil || (entry.minRsaBits > 0 && key.rsaBits < entry.minRsaBits) {
						continue
					}
					if joseVerifySignature(entry, key, signature, []byte(parts[0]+"."+parts[1])) {
						verified = true
						break
					}
				}
			}
		}
		if verified {
			return nil
		}
		if client.fresh() {
			return errors.New("signature verification failed")
		}
		if err := client.refresh(ctx); err != nil {
			return err
		}
	}
	return errors.New("signature verification failed")
}

func clientKeyUsable(jwk *core.Object, alg string, kid any) bool {
	if str(jwk, "kty") != ktyOfAlg(alg) {
		return false
	}
	if text, ok := kid.(string); ok && text != str(jwk, "kid") {
		return false
	}
	if value, ok := jwk.Get("alg").(string); ok && value != alg {
		return false
	}
	if value, ok := jwk.Get("use").(string); ok && value != "sig" {
		return false
	}
	if crv := crvOfAlg(alg); crv != "" && str(jwk, "crv") != crv {
		return false
	}
	if ops, ok := jwk.Get("key_ops").([]any); ok && !contains(stringList(ops), "verify") {
		return false
	}
	return true
}

// --- DPoP (helpers/validate_dpop.js) ---------------------------------------------------------------------------------

type dpopProof struct {
	thumbprint string
	jti        string
	iat        float64
}

func (p *Provider) validateDPoP(oc *oidcCtx, accessToken string) (*dpopProof, error) {
	if oc.dpopValidated {
		return oc.dpop, nil
	}
	proof := oc.r.Header.Get("dpop")
	if proof == "" {
		return nil, nil
	}
	nextNonce := ""
	if p.dpopNonces != nil {
		nextNonce = p.dpopNonces.nextChallenge()
	}
	payload, header, err := joseJwtVerify(oc.ctx, proof, joseEmbeddedJWK, joseVerifyOptions{algorithms: dpopSigningAlgs, typ: "dpop+jwt",
		clockTolerance: core.Undefined, maxTokenAge: core.Undefined, currentDate: float64(p.now())})
	fail := func(message string) error { return errInvalidDpopProof(message) }
	if err != nil {
		return nil, fail("invalid DPoP key binding")
	}
	iat, ok := payload.Get("iat").(float64)
	if !ok || iat == 0 {
		return nil, fail("DPoP proof must have a iat number property")
	}
	if jti, ok := payload.Get("jti").(string); !ok || jti == "" {
		return nil, fail("DPoP proof must have a jti string property")
	}
	nonce := payload.Get("nonce")
	if !isUndefined(nonce) {
		if _, ok := nonce.(string); !ok {
			return nil, fail("DPoP proof nonce must be a string")
		}
	}
	if !truthy(nonce) {
		if math.Abs(float64(epoch(p.now()))-iat) > challengeOKWindow {
			if nextNonce != "" {
				oc.header.Set("dpop-nonce", nextNonce)
				return nil, errUseDpopNonce("DPoP proof iat is not recent enough, use a DPoP nonce instead")
			}
			return nil, fail("DPoP proof iat is not recent enough")
		}
	} else if p.dpopNonces == nil {
		return nil, fail("DPoP nonces are not supported")
	}
	if !jsEq(payload.Get("htm"), oc.method) {
		return nil, fail("DPoP proof htm mismatch")
	}
	expected := oc.urlFor(oc.route, nil, nil)
	htu, ok := payload.Get("htu").(string)
	if !ok {
		return nil, fail("DPoP proof htu mismatch")
	}
	actual, err := parseURL(htu)
	if err != nil || withoutSearchAndHash(actual) != expected {
		return nil, fail("DPoP proof htu mismatch")
	}
	if accessToken != "" && !jsEq(payload.Get("ath"), sha256B64URL(accessToken)) {
		return nil, fail("DPoP proof ath mismatch")
	}
	if truthy(nonce) && !p.dpopNonces.checkChallenge(jsString(nonce)) {
		oc.header.Set("dpop-nonce", nextNonce)
		return nil, errUseDpopNonce("invalid nonce in DPoP proof")
	}
	if p.dpopNonces != nil && !jsEq(nonce, nextNonce) {
		oc.header.Set("dpop-nonce", nextNonce)
	}
	jwk, _ := header.Get("jwk").(*core.Object)
	thumbprint, err := joseThumbprint(jwk)
	if err != nil {
		return nil, fail("invalid DPoP key binding")
	}
	oc.dpop = &dpopProof{thumbprint: thumbprint, jti: jsString(payload.Get("jti")), iat: iat}
	oc.dpopValidated = true
	return oc.dpop, nil
}

// checkDPoPReplay is checkDpopReplay: a proof may be used once per client.
func (p *Provider) checkDPoPReplay(oc *oidcCtx, proof *dpopProof, clientID string, failure func(string) *OIDCError) error {
	if proof == nil {
		return nil
	}
	unique, err := p.replayUnique(oc.ctx, clientID, proof.jti, epoch(p.now())+challengeOKWindow)
	if err != nil {
		return err
	}
	if !unique {
		return failure("DPoP proof JWT Replay detected")
	}
	return nil
}

// --- accounts and claims ----------------------------------------------------------------------------------------------

type account struct {
	id       string
	identity *core.Object
}

// findAccount is the configured findAccount.
func (p *Provider) findAccount(oc *oidcCtx, accountID string) (*account, error) {
	if accountID == "" {
		return nil, nil
	}
	identity, err := p.config.Store.Get(oc.ctx, "identities", accountID)
	if err != nil {
		return nil, err
	}
	if identity == nil || str(identity, "status") != "active" {
		return nil, nil
	}
	active, err := core.TenantTreeActive(oc.ctx, p.config.Store, str(identity, "tenantId"))
	if err != nil || !active {
		return nil, err
	}
	if oc.client != nil {
		row, err := p.config.Store.Get(oc.ctx, "oauthClients", hash(oc.client.clientID()))
		if err != nil {
			return nil, err
		}
		if row == nil || truthy(row.Get("revoked")) || str(row, "tenantId") != str(identity, "tenantId") {
			return nil, nil
		}
		if p.config.ClientAllowed != nil {
			allowed, err := p.config.ClientAllowed(oc.ctx, str(identity, "id"), str(identity, "tenantId"), oc.client.clientID())
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, nil
			}
		}
	}
	return &account{id: accountID, identity: identity}, nil
}

// claims is the account's claims function.
func (p *Provider) accountClaims(ctx context.Context, a *account, scope string) (*core.Object, error) {
	base := core.NewObject("sub", a.id, "tenant_id", a.identity.Get("tenantId"), "email", a.identity.Get("email"),
		"email_verified", a.identity.Get("emailVerified"), "name", a.identity.Get("name"))
	if !contains(strings.Split(scope, " "), "iam") {
		return base, nil
	}
	var groups, roles []string
	tenantID := str(a.identity, "tenantId")
	if p.config.LiveGrants != nil {
		var err error
		groups, roles, err = p.config.LiveGrants(ctx, str(a.identity, "id"), tenantID)
		if err != nil {
			return nil, err
		}
	} else {
		now := float64(p.now())
		live := func(record *core.Object) bool {
			expiresAt, ok := record.Get("expiresAt").(float64)
			return !ok || expiresAt > now
		}
		memberships, err := p.config.Store.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", str(a.identity, "id")), nil)
		if err != nil {
			return nil, err
		}
		groups = []string{}
		for _, membership := range memberships {
			if live(membership) {
				groups = append(groups, jsString(membership.Get("groupId")))
			}
		}
		bindings, err := p.config.Store.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		roles = []string{}
		for _, binding := range bindings {
			startsAt, hasStart := binding.Get("startsAt").(float64)
			subject := (str(binding, "subjectType") == "identity" && jsEq(binding.Get("subjectId"), a.identity.Get("id"))) ||
				(str(binding, "subjectType") == "group" && contains(groups, jsString(binding.Get("subjectId"))))
			if live(binding) && (!hasStart || startsAt <= now) && binding.Get("eligible") != true && isUndefined(binding.Get("window")) && subject {
				roles = append(roles, jsString(binding.Get("roleId")))
			}
		}
	}
	sortedRoles := unique(roles)
	sort.Strings(sortedRoles)
	sortedGroups := append([]string{}, groups...)
	sort.Strings(sortedGroups)
	attributes := a.identity.Get("attributes")
	if attributes == nil || isUndefined(attributes) {
		attributes = core.NewObject()
	}
	return base.Spread(core.NewObject("roles", anyList(sortedRoles), "groups", anyList(sortedGroups), "attributes", attributes)), nil
}

// maskClaims is the Claims class: the available claims a scope and claims mask select.
func (p *Provider) maskClaims(available *core.Object, scope string, mask *core.Object, rejected []string) *core.Object {
	filter := core.NewObject()
	for _, item := range strings.Split(scope, " ") {
		for _, claim := range scopeClaims[item] {
			if !filter.Has(claim) {
				filter.Set(claim, nil)
			}
		}
	}
	mask.Entries(func(key string, value any) bool {
		if existing := obj(filter, key); existing != nil {
			if incoming, ok := value.(*core.Object); ok {
				existing.Assign(incoming)
				return true
			}
		}
		if !isUndefined(value) {
			filter.Set(key, value)
		}
		return true
	})
	for _, claim := range rejected {
		filter.Delete(claim)
	}
	out := core.NewObject()
	filter.Entries(func(key string, value any) bool {
		if _, isObject := value.(*core.Object); (value == nil || isObject) && contains(p.claimsSupported, key) && available.Has(key) {
			out.SetRaw(key, available.Get(key))
		}
		return true
	})
	return out
}

// filterClaims is helpers/filter_claims.js.
func filterClaims(source *core.Object, target string, grant *core.Object) *core.Object {
	claims := core.NewObject()
	if container := obj(source, target); container != nil {
		claims = container.Clone()
	}
	requested := claims.Keys()
	granted := grantOIDCClaims(grant)
	for _, claim := range requested {
		if contains(nonRejectableClaims, claim) {
			continue
		}
		if !contains(granted, claim) {
			claims.Delete(claim)
		}
	}
	return claims
}

// issueIDToken is helpers/grant_common.js issueIdToken.
func (p *Provider) issueIDToken(oc *oidcCtx, source, at *model, grant *model, scopeOverride []string) (any, error) {
	scopes := scopeOverride
	if scopes == nil {
		scopes = source.scopes()
	}
	if !contains(scopes, "openid") {
		return core.Undefined, nil
	}
	mask := filterClaims(obj(source.data, "claims"), "id_token", grant.data)
	rejected := rejectedOIDCClaims(grant.data)
	claimScope := strings.Join(scopes, " ")
	if scopeOverride == nil {
		if value, ok := source.get("scope").(string); ok {
			claimScope = value
		}
	}
	available, err := p.accountClaims(oc.ctx, oc.account, claimScope)
	if err != nil {
		return nil, err
	}
	available = available.Clone()
	available.Set("sub", oc.account.id)
	available.Set("acr", source.get("acr"))
	available.Set("amr", source.get("amr"))
	available.Set("auth_time", source.get("authTime"))
	tokenScope := "openid"
	if truthy(at.get("aud")) {
		tokenScope = grantOIDCScopeFiltered(grant.data, scopes)
	}
	payload := p.maskClaims(available, tokenScope, mask, rejected)
	if nonce := source.get("nonce"); !isUndefined(nonce) {
		payload.Set("nonce", nonce)
	}
	if sid := source.get("sid"); !isUndefined(sid) {
		payload.Set("sid", sid)
	}
	return p.signIDToken(oc.client, payload, 900)
}

// signIDToken signs an ID token (IdToken#issue with use 'idtoken').
func (p *Provider) signIDToken(client *oidcClient, payload *core.Object, expiresIn int64) (string, error) {
	now := epoch(p.now())
	payload.Set("aud", client.clientID())
	payload.Set("exp", now+expiresIn)
	if isUndefined(payload.Get("iat")) {
		payload.Set("iat", now)
	}
	payload.Set("iss", p.issuer)
	payload.Set("sub", payload.Get("sub"))
	alg := client.idTokenAlg()
	if alg == "" {
		alg = "RS256"
	}
	return p.keys.sign(payload, alg, "")
}

// validateIDToken is IdToken.validate (id_token_hint).
func (p *Provider) validateIDToken(oc *oidcCtx, token string, client *oidcClient) (*core.Object, error) {
	alg := client.idTokenAlg()
	header, err := joseDecodeProtectedHeader(token)
	if err != nil {
		return nil, err
	}
	keys := p.keys.selectForVerify(str(header, "alg"), header.Get("kid"))
	parts := strings.Split(token, ".")
	if len(parts) != 3 || str(header, "alg") != alg {
		return nil, errors.New("invalid id token")
	}
	entry, ok := joseAlgorithms[alg]
	signature, err := joseDecode(parts[2])
	if !ok || err != nil {
		return nil, errors.New("invalid id token")
	}
	verified := false
	for _, key := range keys {
		public, err := joseImportPublic(publicJWK(key.jwk), alg)
		if err == nil && joseVerifySignature(entry, public, signature, []byte(parts[0]+"."+parts[1])) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("signature verification failed")
	}
	payload, err := joseDecodePayload(token)
	if err != nil || !p.assertPayload(payload, true) {
		return nil, errors.New("invalid id token")
	}
	switch aud := payload.Get("aud").(type) {
	case string:
		if aud != client.clientID() {
			return nil, errors.New("jwt audience missing")
		}
	case []any:
		if !contains(stringList(aud), client.clientID()) {
			return nil, errors.New("jwt audience missing")
		}
	default:
		return nil, errors.New("jwt audience missing")
	}
	if !jsEq(payload.Get("iss"), p.issuer) {
		return nil, errors.New("jwt issuer invalid")
	}
	if _, ok := payload.Get("sub").(string); !ok {
		return nil, errors.New("invalid sub value")
	}
	return payload, nil
}

// extraTokenClaims is the configured extraTokenClaims.
func (p *Provider) extraTokenClaims(oc *oidcCtx, token *model) (*core.Object, error) {
	var exchange *exchangeState
	if oc != nil {
		exchange = oc.exchange
	}
	clientID := token.str("clientId")
	if clientID == "" {
		return core.NewObject(), nil
	}
	ctx := context.Background()
	if oc != nil {
		ctx = oc.ctx
	}
	row, err := p.config.Store.Get(ctx, "oauthClients", hash(clientID))
	if err != nil {
		return nil, err
	}
	if row == nil {
		return core.NewObject(), nil
	}
	out := core.NewObject("tenant_id", row.Get("tenantId"))
	forClient := !truthy(token.get("accountId"))
	if truthy(row.Get("serviceAccountId")) && exchange == nil && forClient {
		out.Set("identity_id", row.Get("serviceAccountId"))
	}
	if exchange != nil {
		out.Set("act", exchange.act)
	}
	return out, nil
}

// --- the token endpoint -----------------------------------------------------------------------------------------------

func (p *Provider) tokenEndpoint(oc *oidcCtx) error {
	oc.noCache()
	if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
		return err
	}
	oc.assembleParams(unique(append(allGrantParams(), clientAuthParams...)))
	if err := p.authenticateClient(oc); err != nil {
		return err
	}
	if err := oc.rejectDupes(nil, []string{"grant_type"}); err != nil {
		return err
	}
	grantType := oc.param("grant_type")
	if params, ok := grantParams[grantType]; ok {
		for _, key := range oc.params.Keys() {
			if !contains(clientAuthParams, key) && !contains(params, key) {
				oc.params.Delete(key)
			}
		}
	}
	if err := oc.presence("grant_type"); err != nil {
		return err
	}
	if !contains(p.grantTypes, grantType) {
		return errUnsupportedGrantType()
	}
	if !oc.client.grantTypeAllowed(grantType) {
		return errInvalidRequest("requested grant type is not allowed for this client")
	}
	if err := oc.rejectDupes(grantDupes[grantType], nil); err != nil {
		return err
	}
	if !validScope(oc.params.Get("scope")) {
		return errInvalidScope("scope contains invalid characters", "")
	}
	switch grantType {
	case "authorization_code":
		return p.authorizationCodeGrant(oc)
	case "refresh_token":
		return p.refreshTokenGrant(oc)
	case "client_credentials":
		return p.clientCredentialsGrant(oc)
	case deviceCodeGrant:
		return p.deviceCodeGrant(oc)
	case tokenExchangeGrant:
		return p.tokenExchangeGrant(oc)
	}
	return errUnsupportedGrantType()
}

// findGrantSource is helpers/grant_source.js findGrantSource.
func (p *Provider) findGrantSource(oc *oidcCtx, kind, value, label string) (*model, error) {
	source, err := p.findToken(oc.ctx, kind, value, true, false)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, errInvalidGrant(label + " not found")
	}
	if source.str("clientId") != oc.client.clientID() {
		return nil, errInvalidGrant("client mismatch")
	}
	return source, nil
}

// validateGrant is helpers/grant_source.js validateGrant.
func (p *Provider) validateGrant(oc *oidcCtx, grantID string) (*model, error) {
	grant, err := p.find(oc.ctx, "Grant", grantID, true)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, errInvalidGrant("grant not found")
	}
	if grant.isExpired(p.now()) {
		return nil, errInvalidGrant("grant is expired")
	}
	if grant.str("clientId") != oc.client.clientID() {
		return nil, errInvalidGrant("client mismatch")
	}
	return grant, nil
}

// revoke is helpers/revoke.js: every artifact of the grant (the adapter revokes the family).
func (p *Provider) revoke(oc *oidcCtx, grantID string) error {
	if grantID == "" {
		return nil
	}
	return p.adapter.Model("AccessToken").RevokeByGrantID(oc.ctx, grantID)
}

func pkceVerify(verifier, challenge, method string) error {
	if verifier != "" {
		if err := pkceFormat(verifier, "code_verifier"); err != nil {
			return err
		}
	}
	if verifier != "" || challenge != "" {
		if verifier == "" || method != "S256" || !constantEquals(challenge, sha256B64URL(verifier)) {
			return errInvalidGrant("")
		}
	}
	return nil
}

func (p *Provider) authorizationCodeGrant(oc *oidcCtx) error {
	if isUndefined(oc.params.Get("redirect_uri")) {
		if uris := oc.client.redirectURIs(); len(uris) == 1 {
			oc.params.Set("redirect_uri", uris[0])
		}
	}
	if err := oc.presence("code", "redirect_uri"); err != nil {
		return err
	}
	dpop, err := p.validateDPoP(oc, "")
	if err != nil {
		return err
	}
	code, err := p.findGrantSource(oc, "AuthorizationCode", oc.param("code"), "authorization code")
	if err != nil {
		return err
	}
	if code.isExpired(p.now()) {
		return errInvalidGrant("authorization code is expired")
	}
	grant, err := p.validateGrant(oc, code.str("grantId"))
	if err != nil {
		return err
	}
	if err := pkceVerify(oc.param("code_verifier"), code.str("codeChallenge"), code.str("codeChallengeMethod")); err != nil {
		return err
	}
	if dpop == nil && oc.client.dpopBound() {
		return errInvalidGrant("DPoP proof JWT not provided")
	}
	if !jsEq(code.get("redirectUri"), oc.params.Get("redirect_uri")) {
		return errInvalidGrant("authorization code redirect_uri mismatch")
	}
	if truthy(code.get("consumed")) {
		if err := p.revoke(oc, code.str("grantId")); err != nil {
			return err
		}
		return errInvalidGrant("authorization code already consumed")
	}
	if err := p.consume(oc.ctx, code); err != nil {
		return err
	}
	oc.authorizationCode = code
	oc.grant = grant
	return p.issueTokens(oc, code, grant, "authorization_code", "authorization code", dpop)
}

func (p *Provider) createAccessToken(oc *oidcCtx, source *model, accountID string, gty string) *model {
	at := newModel("AccessToken", "accountId", accountID, "expiresWithSession", source.get("expiresWithSession"),
		"grantId", source.get("grantId"), "gty", gty, "rar", source.get("rar"), "sessionUid", source.get("sessionUid"),
		"sid", source.get("sid"))
	at.setClient(oc.client)
	return at
}

// resolveResource is helpers/resolve_resource.js.
func (p *Provider) resolveResource(oc *oidcCtx, source *model, scopes []string) (string, error) {
	var resource any = core.Undefined
	requested := oc.params.Get("resource")
	sourceResource := source.get("resource")
	switch {
	case truthy(requested):
		resource = requested
	case !truthy(sourceResource):
	case func() bool { list, ok := sourceResource.([]any); return ok && len(list) == 0 }():
	case !truthy(requested) && !contains(scopes, "openid"):
		resource = sourceResource
	}
	if list, ok := resource.([]any); ok {
		if len(list) == 1 {
			resource = list[0]
		} else {
			return "", errInvalidTarget("only a single resource indicator value must be requested/resolved during Access Token Request")
		}
	}
	if isUndefined(resource) {
		return "", nil
	}
	value := jsString(resource)
	if value != "" && !contains(source.resourceIndicators(), value) {
		return "", errInvalidTarget()
	}
	return value, nil
}

// issueTokens is helpers/grant_common.js issueTokens.
func (p *Provider) issueTokens(oc *oidcCtx, source, grant *model, gty, label string, dpop *dpopProof) error {
	account, err := p.findAccount(oc, source.str("accountId"))
	if err != nil {
		return err
	}
	if account == nil {
		return errInvalidGrant(label + " invalid (referenced account not found)")
	}
	if source.str("accountId") != grant.str("accountId") {
		return errInvalidGrant("accountId mismatch")
	}
	oc.account = account
	at := p.createAccessToken(oc, source, account.id, gty)
	if gty == "authorization_code" && truthy(source.get("dpopJkt")) && dpop == nil {
		return errInvalidGrant("missing DPoP proof JWT")
	}
	if dpop != nil {
		if err := p.checkDPoPReplay(oc, dpop, oc.client.clientID(), errInvalidGrant); err != nil {
			return err
		}
		at.set("jkt", dpop.thumbprint)
	}
	if gty == "authorization_code" && dpop != nil && truthy(source.get("dpopJkt")) && !jsEq(source.get("dpopJkt"), dpop.thumbprint) {
		return errInvalidGrant("DPoP proof key thumbprint does not match dpop_jkt")
	}
	resource, err := p.resolveResource(oc, source, source.scopes())
	if err != nil {
		return err
	}
	if resource != "" {
		server, err := p.resourceServerInfo(oc, resource, oc.client)
		if err != nil {
			return err
		}
		at.setResourceServer(server)
		at.set("scope", grantResourceScopeFiltered(grant.data, resource, source.scopes()))
	} else {
		at.set("claims", source.get("claims"))
		at.set("scope", grantOIDCScopeFiltered(grant.data, source.scopes()))
	}
	oc.accessToken = at
	accessToken, err := p.save(oc.ctx, oc, at, 0)
	if err != nil {
		return err
	}
	var refreshToken any = core.Undefined
	issueRefresh := oc.client.grantTypeAllowed("refresh_token") &&
		(source.hasScope("offline_access") || (source.kind == "AuthorizationCode" && !source.hasScope("openid")))
	if issueRefresh {
		rt := newModel("RefreshToken", "accountId", source.get("accountId"), "acr", source.get("acr"), "amr", source.get("amr"),
			"authTime", source.get("authTime"), "claims", source.get("claims"), "expiresWithSession", source.get("expiresWithSession"),
			"grantId", source.get("grantId"), "gty", gty, "nonce", source.get("nonce"), "resource", source.get("resource"),
			"rotations", 0, "scope", source.get("scope"), "sessionUid", source.get("sessionUid"), "sid", source.get("sid"),
			"rar", source.get("rar"))
		rt.setClient(oc.client)
		rt.set("iiat", epoch(p.now()))
		if oc.client.authMethod() == "none" && truthy(at.get("jkt")) {
			rt.set("jkt", at.get("jkt"))
		}
		oc.refreshToken = rt
		value, err := p.save(oc.ctx, oc, rt, 0)
		if err != nil {
			return err
		}
		refreshToken = value
	}
	idToken, err := p.issueIDToken(oc, source, at, grant, nil)
	if err != nil {
		return err
	}
	var scope any = core.Undefined
	if truthy(source.get("scope")) {
		scope = at.get("scope")
	} else if truthy(at.get("scope")) {
		scope = at.get("scope")
	}
	oc.setJSON(tokenResponse(accessToken, p.expiration(oc, at), idToken, core.Undefined, refreshToken, scope, at.tokenType()))
	return nil
}

func tokenResponse(accessToken string, expiresIn int64, idToken, issuedTokenType, refreshToken, scope any, tokenType string) *core.Object {
	out := core.NewObject("access_token", accessToken, "expires_in", expiresIn)
	for _, pair := range []struct {
		key   string
		value any
	}{{"id_token", idToken}, {"issued_token_type", issuedTokenType}, {"refresh_token", refreshToken}, {"scope", scope}} {
		if !isUndefined(pair.value) {
			out.Set(pair.key, pair.value)
		}
	}
	out.Set("token_type", tokenType)
	return out
}

func (p *Provider) refreshTokenGrant(oc *oidcCtx) error {
	if err := oc.presence("refresh_token"); err != nil {
		return err
	}
	client := oc.client
	dpop, err := p.validateDPoP(oc, "")
	if err != nil {
		return err
	}
	value := oc.param("refresh_token")
	refreshToken, err := p.findToken(oc.ctx, "RefreshToken", value, true, false)
	if err != nil {
		return err
	}
	if refreshToken == nil {
		return errInvalidGrant("refresh token not found")
	}
	if refreshToken.str("clientId") != client.clientID() {
		return errInvalidGrant("client mismatch")
	}
	if refreshToken.isExpired(p.now()) {
		return errInvalidGrant("refresh token is expired")
	}
	if truthy(refreshToken.get("x5t#S256")) {
		return errInvalidGrant("mutual TLS client certificate not provided")
	}
	if dpop == nil && client.dpopBound() {
		return errInvalidGrant("DPoP proof JWT not provided")
	}
	grant, err := p.validateGrant(oc, refreshToken.str("grantId"))
	if err != nil {
		return err
	}
	if oc.param("scope") != "" {
		var missing []string
		for _, scope := range oc.requestParamScopes() {
			if !refreshToken.hasScope(scope) {
				missing = append(missing, scope)
			}
		}
		if len(missing) > 0 {
			return errInvalidScope("refresh token missing requested "+pluralize("scope", len(missing)), strings.Join(missing, " "))
		}
	}
	if err := p.checkDPoPReplay(oc, dpop, client.clientID(), errInvalidGrant); err != nil {
		return err
	}
	if jkt := refreshToken.str("jkt"); jkt != "" && (dpop == nil || jkt != dpop.thumbprint) {
		return errInvalidGrant("failed jkt verification")
	}
	oc.refreshToken = refreshToken
	oc.grant = grant
	account, err := p.findAccount(oc, refreshToken.str("accountId"))
	if err != nil {
		return err
	}
	if account == nil {
		return errInvalidGrant("refresh token invalid (referenced account not found)")
	}
	if refreshToken.str("accountId") != grant.str("accountId") {
		return errInvalidGrant("accountId mismatch")
	}
	oc.account = account
	if truthy(refreshToken.get("consumed")) {
		if err := p.destroy(oc.ctx, refreshToken); err != nil {
			return err
		}
		if err := p.revoke(oc, refreshToken.str("grantId")); err != nil {
			return err
		}
		return errInvalidGrant("refresh token already used")
	}
	// rotateRefreshToken: true.
	if err := p.consume(oc.ctx, refreshToken); err != nil {
		return err
	}
	oc.rotatedRefresh = refreshToken
	rotations := float64(1)
	if value, ok := refreshToken.get("rotations").(float64); ok {
		rotations = value + 1
	}
	next := newModel("RefreshToken", "accountId", refreshToken.get("accountId"), "acr", refreshToken.get("acr"),
		"amr", refreshToken.get("amr"), "authTime", refreshToken.get("authTime"), "claims", refreshToken.get("claims"),
		"expiresWithSession", refreshToken.get("expiresWithSession"), "iiat", refreshToken.get("iiat"),
		"grantId", refreshToken.get("grantId"), "gty", refreshToken.get("gty"), "nonce", refreshToken.get("nonce"),
		"resource", refreshToken.get("resource"), "rotations", rotations, "scope", refreshToken.get("scope"),
		"sessionUid", refreshToken.get("sessionUid"), "sid", refreshToken.get("sid"), "rar", refreshToken.get("rar"),
		"x5t#S256", refreshToken.get("x5t#S256"), "jkt", refreshToken.get("jkt"), "attestationJkt", refreshToken.get("attestationJkt"))
	next.setClient(client)
	if gty := next.str("gty"); gty != "" && !strings.HasSuffix(gty, "refresh_token") {
		next.set("gty", gty+" refresh_token")
	}
	oc.refreshToken = next
	refreshValue, err := p.save(oc.ctx, oc, next, 0)
	if err != nil {
		return err
	}
	at := newModel("AccessToken", "accountId", account.id, "expiresWithSession", next.get("expiresWithSession"),
		"grantId", next.get("grantId"), "gty", next.get("gty"), "rar", core.Undefined, "sessionUid", next.get("sessionUid"),
		"sid", next.get("sid"))
	at.setClient(client)
	if dpop != nil {
		at.set("jkt", dpop.thumbprint)
	}
	if gty := at.str("gty"); gty != "" && !strings.HasSuffix(gty, "refresh_token") {
		at.set("gty", gty+" refresh_token")
	}
	scopes := next.scopes()
	if oc.param("scope") != "" {
		scopes = oc.requestParamScopes()
	}
	resource, err := p.resolveResource(oc, next, scopes)
	if err != nil {
		return err
	}
	if resource != "" {
		server, err := p.resourceServerInfo(oc, resource, client)
		if err != nil {
			return err
		}
		at.setResourceServer(server)
		var filtered []string
		for _, scope := range scopes {
			if contains(server.scopes(), scope) {
				filtered = append(filtered, scope)
			}
		}
		at.set("scope", grantResourceScopeFiltered(grant.data, resource, filtered))
	} else {
		at.set("claims", next.get("claims"))
		at.set("scope", grantOIDCScopeFiltered(grant.data, scopes))
	}
	oc.accessToken = at
	accessToken, err := p.save(oc.ctx, oc, at, 0)
	if err != nil {
		return err
	}
	idToken, err := p.issueIDToken(oc, next, at, grant, scopes)
	if err != nil {
		return err
	}
	var scope any = core.Undefined
	if truthy(next.get("scope")) || truthy(at.get("scope")) {
		scope = at.get("scope")
	}
	oc.setJSON(tokenResponse(accessToken, p.expiration(oc, at), idToken, core.Undefined, refreshValue, scope, at.tokenType()))
	return nil
}

func (p *Provider) clientCredentialsGrant(oc *oidcCtx) error {
	client := oc.client
	dpop, err := p.validateDPoP(oc, "")
	if err != nil {
		return err
	}
	if err := p.checkResource(oc); err != nil {
		return err
	}
	scopes := oc.requestParamScopes()
	if clientScope := client.scope(); clientScope != "" {
		allow := strings.Split(clientScope, " ")
		for _, scope := range scopes {
			if contains(p.supportedScopes, scope) && !contains(allow, scope) {
				return errInvalidScope("requested scope is not allowed", scope)
			}
		}
	}
	token := newModel("ClientCredentials", "scope", nonEmpty(strings.Join(scopes, " ")))
	token.setClient(client)
	if len(oc.resourceServers) > 0 {
		if len(oc.resourceServers) != 1 {
			return errInvalidTarget("only a single resource indicator value is supported for this grant type")
		}
		server := oc.resourceServers[0]
		token.setResourceServer(server)
		var filtered []string
		for _, scope := range scopes {
			if contains(server.scopes(), scope) {
				filtered = append(filtered, scope)
			}
		}
		token.set("scope", nonEmpty(strings.Join(filtered, " ")))
	}
	if dpop != nil {
		if err := p.checkDPoPReplay(oc, dpop, client.clientID(), errInvalidGrant); err != nil {
			return err
		}
		token.set("jkt", dpop.thumbprint)
	}
	if dpop == nil && client.dpopBound() {
		return errInvalidGrant("DPoP proof JWT not provided")
	}
	value, err := p.save(oc.ctx, oc, token, 0)
	if err != nil {
		return err
	}
	var scope any = core.Undefined
	if truthy(token.get("scope")) {
		scope = token.get("scope")
	}
	oc.setJSON(tokenResponse(value, p.expiration(oc, token), core.Undefined, core.Undefined, core.Undefined, scope, token.tokenType()))
	return nil
}

func (p *Provider) deviceCodeGrant(oc *oidcCtx) error {
	if err := oc.presence("device_code"); err != nil {
		return err
	}
	dpop, err := p.validateDPoP(oc, "")
	if err != nil {
		return err
	}
	code, err := p.findGrantSource(oc, "DeviceCode", oc.param("device_code"), "device code")
	if err != nil {
		return err
	}
	if dpop == nil && oc.client.dpopBound() {
		return errInvalidGrant("DPoP proof JWT not provided")
	}
	if code.isExpired(p.now()) {
		return errExpiredToken("device code is expired")
	}
	if !truthy(code.get("accountId")) && !truthy(code.get("error")) {
		return errAuthorizationPending()
	}
	if truthy(code.get("consumed")) {
		if err := p.revoke(oc, code.str("grantId")); err != nil {
			return err
		}
		return errInvalidGrant("device code already consumed")
	}
	if err := p.consume(oc.ctx, code); err != nil {
		return err
	}
	if truthy(code.get("error")) {
		return errByCode(jsString(code.get("error")), nullishString(code.get("errorDescription")))
	}
	grant, err := p.validateGrant(oc, code.str("grantId"))
	if err != nil {
		return err
	}
	oc.deviceCode = code
	oc.grant = grant
	return p.issueTokens(oc, code, grant, "device_code", "device code", dpop)
}

// --- token exchange (RFC 8693) ----------------------------------------------------------------------------------------

type exchangedSubject struct {
	identityID string
	clientID   string
	scopes     []string
	expiresAt  float64
	grantID    string
	act        any
	format     string
	personal   bool
}

func (p *Provider) tokenExchangeGrant(oc *oidcCtx) error {
	client := oc.client
	value := func(name string) (string, error) {
		raw := oc.params.Get(name)
		if _, isArray := raw.([]any); isArray {
			return "", errInvalidRequest(name + " must be given at most once.")
		}
		text, _ := raw.(string)
		return text, nil
	}
	subjectToken, err := value("subject_token")
	if err != nil {
		return err
	}
	subjectType, err := value("subject_token_type")
	if err != nil {
		return err
	}
	if subjectToken == "" || subjectType != accessTokenType {
		return errInvalidRequest("subject_token must be an access token from this issuer.")
	}
	requested, err := value("requested_token_type")
	if err != nil {
		return err
	}
	if requested != "" && requested != accessTokenType {
		return errInvalidRequest("Only access tokens can be requested.")
	}
	actor, err := value("actor_token")
	if err != nil {
		return err
	}
	if actor != "" {
		return errInvalidRequest("actor_token is not supported; the client is the actor.")
	}
	row, err := p.config.Store.Get(oc.ctx, "oauthClients", hash(client.clientID()))
	if err != nil {
		return err
	}
	if row == nil || truthy(row.Get("revoked")) {
		return errInvalidClient("Client is unavailable.")
	}
	// The handler issues bearer tokens only: a client that must hold sender-constrained tokens gets none this way.
	if client.dpopBound() {
		return errInvalidRequest("This client requires DPoP-bound tokens, which token exchange does not issue.")
	}
	subject, err := p.exchangedSubject(oc, subjectToken)
	if err != nil {
		return err
	}
	tenantID := str(row, "tenantId")
	subjectRow, err := p.config.Store.Get(oc.ctx, "oauthClients", hash(subject.clientID))
	if err != nil {
		return err
	}
	if subjectRow == nil || truthy(subjectRow.Get("revoked")) || str(subjectRow, "tenantId") != tenantID {
		return errInvalidGrant("The subject token is not usable by this client.")
	}
	if subject.format == "jwt" && subject.personal {
		grants, err := p.accountGrants(oc.ctx, tenantID, subject.identityID)
		if err != nil {
			return err
		}
		connected := false
		for _, grant := range grants {
			if grant.summary.ClientID == subject.clientID {
				connected = true
			}
		}
		if !connected {
			return errInvalidGrant("The subject token was revoked.")
		}
	}
	identity, err := p.config.Store.Get(oc.ctx, "identities", subject.identityID)
	if err != nil {
		return err
	}
	usable := identity != nil && str(identity, "status") == "active" && str(identity, "tenantId") == tenantID
	if usable {
		if usable, err = core.TenantTreeActive(oc.ctx, p.config.Store, tenantID); err != nil {
			return err
		}
	}
	if !usable {
		return errInvalidGrant("The subject token is not usable by this client.")
	}
	indicator, err := value("resource")
	if err != nil {
		return err
	}
	if indicator == "" {
		if indicator, err = value("audience"); err != nil {
			return err
		}
	}
	server, known := p.resourceServers[indicator]
	if indicator == "" || !known || !contains(stringList(row.Get("resources")), indicator) {
		return errInvalidTarget("Name one resource this client may call.")
	}
	clientScopes := strings.Split(client.scope(), " ")
	var allowed []string
	for _, scope := range server.Scopes {
		if contains(clientScopes, scope) {
			allowed = append(allowed, scope)
		}
	}
	scopes := allowed
	if requestedScope, err := value("scope"); err != nil {
		return err
	} else if requestedScope != "" {
		scopes = splitFilter(requestedScope)
	}
	var refused []string
	for _, scope := range scopes {
		if !contains(allowed, scope) {
			refused = append(refused, scope)
		}
	}
	if len(refused) > 0 || len(scopes) == 0 {
		return errInvalidScope("The requested scope is not allowed.", strings.Join(refused, " "))
	}
	remaining := int64(subject.expiresAt) - epoch(p.now())
	if remaining <= 0 {
		return errInvalidGrant("The subject token has expired.")
	}
	request := TokenExchangeRequest{TenantID: tenantID, ClientID: client.clientID(), IdentityID: subject.identityID,
		SubjectClientID: subject.clientID, SubjectScopes: nonNil(subject.scopes), Resource: indicator, Scopes: scopes}
	if p.config.AuthorizeTokenExchange != nil {
		allowedExchange, err := p.config.AuthorizeTokenExchange(oc.ctx, request)
		if err != nil {
			return err
		}
		if !allowedExchange {
			return errAccessDenied("The token exchange is not permitted.")
		}
	}
	act := core.NewObject("sub", client.clientID())
	if subject.act != nil && !isUndefined(subject.act) {
		act.Set("act", subject.act)
	}
	oc.exchange = &exchangeState{act: act, remaining: remaining}
	info := &resourceServerInfo{identifier: indicator, scope: strings.Join(server.Scopes, " "), audience: server.Audience,
		accessTokenTTL: 900, format: server.AccessTokenFormat}
	if info.audience == "" {
		info.audience = indicator
	}
	if server.AccessTokenTTL != nil {
		info.accessTokenTTL = *server.AccessTokenTTL
	}
	if info.format == "" {
		info.format = "jwt"
	}
	token := newModel("AccessToken", "accountId", subject.identityID, "grantId", subject.grantID, "gty", "token_exchange",
		"scope", strings.Join(scopes, " "))
	token.setClient(client)
	token.setResourceServer(info)
	issued, err := p.save(oc.ctx, oc, token, 0)
	if err != nil {
		return err
	}
	if err := p.config.Store.Transaction(oc.ctx, func(ctx context.Context, tx core.IamStore) error {
		return p.audit(ctx, tx, tenantID, subject.identityID, "iam:oauth:TokenExchange", client.clientID())
	}); err != nil {
		return err
	}
	oc.setJSON(core.NewObject("access_token", issued, "issued_token_type", accessTokenType, "token_type", "Bearer",
		"expires_in", p.expiration(oc, token), "scope", strings.Join(scopes, " ")))
	return nil
}

// exchangedSubject is the account behind a subject token: a JWT access token of this issuer, or an opaque one.
func (p *Provider) exchangedSubject(oc *oidcCtx, value string) (*exchangedSubject, error) {
	if len(strings.Split(value, ".")) == 3 {
		set := p.keys.publicVerificationSet()
		claims, _, err := joseJwtVerify(oc.ctx, value, set.resolve, joseVerifyOptions{hasIssuer: true, issuer: p.issuer,
			typ: "at+jwt", requiredClaims: []string{"exp", "client_id", "sub"}, clockTolerance: core.Undefined,
			maxTokenAge: core.Undefined, currentDate: float64(p.now())})
		if err != nil {
			return nil, errInvalidGrant("The subject token is invalid.")
		}
		if cnf := obj(claims, "cnf"); cnf != nil && truthy(cnf.Get("jkt")) {
			return nil, errInvalidGrant("Sender-constrained tokens cannot be exchanged.")
		}
		identityID := jsString(claims.Get("sub"))
		if identity, ok := claims.Get("identity_id").(string); ok && jsEq(claims.Get("sub"), claims.Get("client_id")) {
			identityID = identity
		}
		subject := &exchangedSubject{identityID: identityID, clientID: jsString(claims.Get("client_id")), format: "jwt",
			personal: !jsEq(claims.Get("sub"), claims.Get("client_id")) && !truthy(claims.Get("act"))}
		if scope, ok := claims.Get("scope").(string); ok {
			subject.scopes = splitFilter(scope)
		}
		subject.expiresAt = jsNumberValue(claims.Get("exp"))
		if act := claims.Get("act"); truthy(act) {
			subject.act = act
		}
		return subject, nil
	}
	token, err := p.findToken(oc.ctx, "AccessToken", value, false, false)
	if err != nil {
		return nil, err
	}
	if token == nil || token.isExpired(p.now()) || !truthy(token.get("accountId")) {
		return nil, errInvalidGrant("The subject token is invalid.")
	}
	if token.senderConstrained() {
		return nil, errInvalidGrant("Sender-constrained tokens cannot be exchanged.")
	}
	subject := &exchangedSubject{identityID: token.str("accountId"), clientID: token.str("clientId"),
		scopes: splitFilter(nullishString(token.get("scope"))), expiresAt: float64(token.num("exp")), format: "opaque", personal: true}
	if grantID := token.str("grantId"); grantID != "" {
		subject.grantID = grantID
	}
	if act := get(obj(token.data, "extra"), "act"); truthy(act) {
		subject.act = act
	}
	return subject, nil
}

// --- introspection and revocation -------------------------------------------------------------------------------------

func (p *Provider) findAnyToken(oc *oidcCtx, value, hint string) (*model, error) {
	order := []string{"AccessToken", "ClientCredentials", "RefreshToken"}
	if hint == "refresh_token" || hint == "urn:ietf:params:oauth:token-type:refresh_token" {
		order = []string{"RefreshToken", "AccessToken", "ClientCredentials"}
	}
	for _, kind := range order {
		token, err := p.findToken(oc.ctx, kind, value, false, false)
		if err != nil {
			return nil, err
		}
		if token != nil {
			return token, nil
		}
	}
	return nil, nil
}

func (p *Provider) tokenRequestPrelude(oc *oidcCtx) error {
	if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
		return err
	}
	oc.assembleParams(append([]string{"token", "token_type_hint"}, clientAuthParams...))
	if err := p.authenticateClient(oc); err != nil {
		return err
	}
	if err := oc.rejectDupes(nil, nil); err != nil {
		return err
	}
	if err := oc.presence("token"); err != nil {
		return err
	}
	if _, err := joseDecodeProtectedHeader(oc.param("token")); err == nil {
		action := "introspected"
		if oc.route == "revocation" {
			action = "revoked"
		}
		return errUnsupportedTokenType("Structured JWT Tokens cannot be " + action + " via the " + oc.route + "_endpoint")
	}
	return nil
}

func (p *Provider) introspectionEndpoint(oc *oidcCtx) error {
	oc.noCache()
	if err := p.tokenRequestPrelude(oc); err != nil {
		return err
	}
	body := core.NewObject("active", false)
	oc.setJSON(body)
	token, err := p.findAnyToken(oc, oc.param("token"), oc.param("token_type_hint"))
	if err != nil || token == nil {
		return err
	}
	if token.isExpired(p.now()) || truthy(token.get("consumed")) {
		return nil
	}
	if grantID := token.str("grantId"); grantID != "" {
		grant, err := p.find(oc.ctx, "Grant", grantID, true)
		if err != nil {
			return err
		}
		if grant == nil || grant.isExpired(p.now()) || grant.str("clientId") != token.str("clientId") || !jsEq(grant.get("accountId"), token.get("accountId")) {
			return nil
		}
	}
	if oc.client.clientID() != token.str("clientId") {
		return nil
	}
	if accountID := token.get("accountId"); truthy(accountID) {
		body.Set("sub", accountID)
	}
	if extra := obj(token.data, "extra"); extra != nil {
		body.Assign(extra)
	}
	body.Set("active", true)
	body.Set("client_id", token.get("clientId"))
	body.Set("exp", token.get("exp"))
	body.Set("iat", token.get("iat"))
	body.Set("sid", token.get("sid"))
	body.Set("iss", p.issuer)
	if token.jti() != oc.param("token") {
		body.Set("jti", token.jti())
	}
	body.Set("aud", token.get("aud"))
	if scope := token.get("scope"); truthy(scope) {
		body.Set("scope", scope)
	}
	if token.senderConstrained() {
		cnf := core.NewObject()
		if value := token.get("x5t#S256"); truthy(value) {
			cnf.Set("x5t#S256", value)
		}
		if value := token.get("jkt"); truthy(value) {
			cnf.Set("jkt", value)
		}
		body.Set("cnf", cnf)
	}
	if token.kind != "RefreshToken" {
		body.Set("token_type", token.tokenType())
	}
	return nil
}

func (p *Provider) revocationEndpoint(oc *oidcCtx) error {
	if err := p.tokenRequestPrelude(oc); err != nil {
		return err
	}
	oc.setStatus(200)
	oc.respBody = ""
	oc.contentType = "text/plain; charset=utf-8"
	token, err := p.findAnyToken(oc, oc.param("token"), oc.param("token_type_hint"))
	if err != nil || token == nil {
		return err
	}
	// The configured allowedPolicy: a client revokes only its own tokens.
	if token.str("clientId") != oc.client.clientID() {
		return nil
	}
	if err := p.destroy(oc.ctx, token); err != nil {
		return err
	}
	if token.kind == "RefreshToken" || token.kind == "AccessToken" {
		return p.revoke(oc, token.str("grantId"))
	}
	return nil
}

// --- userinfo -------------------------------------------------------------------------------------------------------

// getAccessToken is OIDCContext#getAccessToken.
func (oc *oidcCtx) getAccessToken(acceptDPoP bool) (string, error) {
	if oc.accessTokenValue != "" {
		return oc.accessTokenValue, nil
	}
	type mechanism struct{ name, value string }
	var found []mechanism
	if strings.HasPrefix(strings.ToLower(oc.r.Header.Get("content-type")), "application/x-www-form-urlencoded") && oc.body != nil {
		if value, ok := oc.body.Get("access_token").(string); ok && value != "" {
			found = append(found, mechanism{"body", value})
		}
	}
	if value := oc.r.Header.Get("authorization"); value != "" {
		found = append(found, mechanism{"header", value})
	}
	if value, ok := oc.query.Get("access_token").(string); ok && value != "" {
		found = append(found, mechanism{"query", value})
	}
	if len(found) == 0 {
		return "", errNoAccessToken()
	}
	if len(found) > 1 {
		return "", errInvalidRequest("access token must only be provided using one mechanism")
	}
	if found[0].name == "query" {
		return "", errInvalidRequest("access tokens must not be provided via query parameter")
	}
	token := found[0].value
	dpop := acceptDPoP && oc.r.Header.Get("dpop") != ""
	if found[0].name == "header" {
		parts := strings.Split(token, " ")
		if len(parts) != 2 {
			return "", errInvalidRequest("invalid authorization header value format")
		}
		scheme := strings.ToLower(parts[0])
		switch {
		case dpop && scheme != "dpop":
			return "", errInvalidRequest("authorization header scheme must be `DPoP` when DPoP is used")
		case !dpop && scheme == "dpop":
			return "", errInvalidRequest("`DPoP` header not provided")
		case !dpop && scheme != "bearer":
			return "", errInvalidRequest("authorization header scheme must be `Bearer`")
		}
		token = parts[1]
	}
	if dpop && found[0].name != "header" {
		return "", errInvalidRequest("`DPoP` tokens must be provided via an authorization header")
	}
	oc.accessTokenValue = token
	return token, nil
}

// wwwAuthenticate is shared/set_www_authenticate_header.js.
func (p *Provider) wwwAuthenticate(oc *oidcCtx, err error, includeScope, dpopEnabled bool) error {
	e, ok := asOIDC(err)
	if !ok || !e.Expose || (!dpopEnabled && e.Status != 401) {
		return err
	}
	scope := ""
	if includeScope && e.HasScope {
		scope = e.Scope
	}
	algs := ""
	if dpopEnabled {
		algs = strings.Join(dpopSigningAlgs, " ")
	}
	if e.Class == "NoAccessTokenProvided" {
		appendWWWAuthenticate(oc, "Bearer", [][2]string{{"realm", p.issuer}, {"scope", scope}})
		if dpopEnabled {
			appendWWWAuthenticate(oc, "DPoP", [][2]string{{"realm", p.issuer}, {"scope", scope}, {"algs", algs}})
		}
		return err
	}
	scheme := "Bearer"
	if dpopEnabled {
		if regexp.MustCompile(`(?i)dpop`).MatchString(e.Description) || (oc.accessToken != nil && truthy(oc.accessToken.get("jkt"))) || oc.r.Header.Get("dpop") != "" {
			scheme = "DPoP"
		}
		if e.Class == "InvalidDpopProof" || e.Class == "UseDpopNonce" {
			e.Status = 401
		}
	}
	fields := [][2]string{{"realm", p.issuer}, {"error", e.Code}, {"error_description", e.Description}, {"scope", scope}}
	if scheme == "DPoP" {
		fields = append(fields, [2]string{"algs", algs})
	}
	appendWWWAuthenticate(oc, scheme, fields)
	return err
}

func (p *Provider) userinfoEndpoint(oc *oidcCtx) error {
	oc.noCache()
	err := p.userinfoSteps(oc)
	if err != nil {
		return p.wwwAuthenticate(oc, err, true, true)
	}
	return nil
}

func (p *Provider) userinfoSteps(oc *oidcCtx) error {
	if oc.method == http.MethodPost {
		if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
			return err
		}
	}
	oc.assembleParams([]string{"scope", "access_token"})
	if err := oc.rejectDupes(nil, nil); err != nil {
		return err
	}
	value, err := oc.getAccessToken(true)
	if err != nil {
		return err
	}
	dpop, err := p.validateDPoP(oc, value)
	if err != nil {
		return err
	}
	at, err := p.findToken(oc.ctx, "AccessToken", value, false, false)
	if err != nil {
		return err
	}
	if at == nil {
		return errInvalidToken("access token not found")
	}
	oc.accessToken = at
	if !at.hasScope("openid") || at.str("scope") == "" {
		return errInsufficientScope("access token missing openid scope", "openid")
	}
	if truthy(at.get("x5t#S256")) {
		return errInvalidToken("failed x5t#S256 verification")
	}
	if err := p.checkDPoPReplay(oc, dpop, at.str("clientId"), errInvalidToken); err != nil {
		return err
	}
	if dpop != nil && !truthy(at.get("jkt")) {
		return errInvalidToken("access token is not sender-constrained but proof of possession was provided")
	}
	if jkt := at.str("jkt"); jkt != "" && (dpop == nil || jkt != dpop.thumbprint) {
		return errInvalidToken("failed jkt verification")
	}
	if !isUndefined(at.get("aud")) {
		return errInvalidToken("token audience prevents accessing the userinfo endpoint")
	}
	if scope := oc.param("scope"); scope != "" {
		if !validScope(scope) {
			return errInvalidRequest("scope contains invalid characters")
		}
		var missing []string
		for _, item := range strings.Split(scope, " ") {
			if !at.hasScope(item) {
				missing = append(missing, item)
			}
		}
		if len(missing) > 0 {
			return errInsufficientScope("access token missing requested scope", strings.Join(missing, " "))
		}
	}
	client, err := p.findClient(oc.ctx, at.str("clientId"))
	if err != nil {
		return err
	}
	if client == nil {
		return errInvalidToken("associated client not found")
	}
	if err := oc.assignClient(client); err != nil {
		return err
	}
	account, err := p.findAccount(oc, at.str("accountId"))
	if err != nil {
		return err
	}
	if account == nil {
		return errInvalidToken("associated account not found")
	}
	oc.account = account
	grant, err := p.find(oc.ctx, "Grant", at.str("grantId"), true)
	if err != nil {
		return err
	}
	switch {
	case grant == nil:
		return errInvalidToken("grant not found")
	case grant.isExpired(p.now()):
		return errInvalidToken("grant is expired")
	case grant.str("clientId") != at.str("clientId"):
		return errInvalidToken("clientId mismatch")
	case !jsEq(grant.get("accountId"), at.get("accountId")):
		return errInvalidToken("accountId mismatch")
	}
	mask := filterClaims(obj(at.data, "claims"), "userinfo", grant.data)
	rejected := rejectedOIDCClaims(grant.data)
	requested := oc.param("scope")
	if requested == "" {
		requested = at.str("scope")
	}
	scope := grantOIDCScopeFiltered(grant.data, strings.Split(requested, " "))
	available, err := p.accountClaims(oc.ctx, account, scope)
	if err != nil {
		return err
	}
	available = available.Clone()
	available.Set("sub", account.id)
	oc.setJSON(p.maskClaims(available, scope, mask, rejected))
	return nil
}
