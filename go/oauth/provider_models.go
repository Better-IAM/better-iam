package oauth

// oidc-provider's models (lib/models): artifacts are *core.Object payloads in the oidc-provider format, persisted
// through the ProviderAdapter, so either implementation reads what the other wrote.

import (
	"context"
	"crypto/rand"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

const nanoidAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict"

// nanoid is helpers/nanoid.js (64-symbol URL alphabet).
func nanoid(size int) string {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer)
	out := make([]byte, size)
	for index, value := range buffer {
		out[index] = nanoidAlphabet[value&63]
	}
	return string(out)
}

var basePayload = []string{"iat", "exp", "jti", "kind"}

var modelPayload = map[string][]string{
	"AccessToken": {"clientId", "gty", "grantId", "x5t#S256", "jkt", "sessionUid", "expiresWithSession", "accountId", "aud", "rar", "claims", "extra", "scope", "sid"},
	"AuthorizationCode": {"clientId", "consumed", "sessionUid", "expiresWithSession", "grantId", "attestationJkt", "accountId", "acr", "amr", "authTime",
		"claims", "nonce", "resource", "scope", "sid", "codeChallenge", "codeChallengeMethod", "redirectUri", "dpopJkt", "rar"},
	"RefreshToken": {"clientId", "consumed", "gty", "grantId", "x5t#S256", "jkt", "attestationJkt", "sessionUid", "expiresWithSession", "accountId", "acr",
		"amr", "authTime", "claims", "nonce", "resource", "scope", "sid", "rar", "rotations", "iiat"},
	"ClientCredentials": {"clientId", "x5t#S256", "jkt", "aud", "extra", "rar", "scope"},
	"DeviceCode": {"clientId", "consumed", "grantId", "attestationJkt", "sessionUid", "expiresWithSession", "accountId", "acr", "amr", "authTime", "claims",
		"nonce", "resource", "scope", "sid", "error", "errorDescription", "params", "rar", "userCode", "inFlight", "deviceInfo"},
	"Grant":                      {"accountId", "clientId", "resources", "openid", "rejected", "rar"},
	"Session":                    {"uid", "acr", "amr", "accountId", "loginTs", "transient", "state", "authorizations"},
	"Interaction":                {"session", "params", "prompt", "result", "returnTo", "trusted", "grantId", "lastSubmission", "deviceCode", "cid", "parJti"},
	"PushedAuthorizationRequest": {"consumed", "attestationJkt", "request", "dpopJkt", "trusted"},
	"ReplayDetection":            {"iss"},
}

// baseTokens are the BaseToken models (their lifetime comes from the ttl configuration).
var baseTokens = map[string]bool{"AccessToken": true, "AuthorizationCode": true, "RefreshToken": true, "ClientCredentials": true, "DeviceCode": true, "Grant": true}

// model is one artifact: its kind and payload members, plus the BaseToken state that is never stored.
type model struct {
	kind           string
	data           *core.Object
	client         *oidcClient
	resourceServer *resourceServerInfo
	expiresIn      int64
	format         string
	// isNew marks a Session instantiated without a stored payload.
	isNew bool
	// touched, destroyed and oldID are Session state.
	touched   bool
	destroyed bool
	oldID     string
}

func newModel(kind string, members ...any) *model {
	data := core.NewObject(members...)
	if !data.Has("kind") {
		data.Set("kind", kind)
	}
	if !data.Has("jti") {
		data.Set("jti", core.Undefined)
	}
	return &model{kind: kind, data: data}
}

func (m *model) get(key string) any { return m.data.Get(key) }
func (m *model) str(key string) string {
	value, _ := m.data.Get(key).(string)
	return value
}
func (m *model) set(key string, value any) { m.data.Set(key, value) }
func (m *model) jti() string               { return m.str("jti") }
func (m *model) num(key string) int64 {
	value, _ := m.data.Get(key).(float64)
	return int64(value)
}

func (m *model) setClient(client *oidcClient) {
	m.client = client
	m.data.Set("clientId", client.clientID())
}

func (m *model) setResourceServer(server *resourceServerInfo) {
	m.resourceServer = server
	m.data.Set("aud", server.audience)
}

func (m *model) scopes() []string { return strings.Split(m.str("scope"), " ") }

func (m *model) hasScope(scope string) bool { return contains(m.scopes(), scope) }

func (m *model) isExpired(now int64) bool {
	exp, ok := m.data.Get("exp").(float64)
	return ok && int64(exp) <= epoch(now)
}

func (m *model) senderConstrained() bool { return truthy(m.get("jkt")) || truthy(m.get("x5t#S256")) }

func (m *model) tokenType() string {
	if truthy(m.get("jkt")) {
		return "DPoP"
	}
	return "Bearer"
}

func (m *model) resourceIndicators() []string {
	switch value := m.get("resource").(type) {
	case []any:
		return stringList(value)
	case string:
		return []string{value}
	}
	return nil
}

// expiration is BaseToken#expiration: expiresIn or the configured ttl.
func (p *Provider) expiration(oc *oidcCtx, m *model) int64 {
	if m.expiresIn > 0 {
		return m.expiresIn
	}
	var ttl int64
	switch m.kind {
	case "AccessToken", "ClientCredentials":
		ttl = 900
		if m.resourceServer != nil && m.resourceServer.accessTokenTTL > 0 {
			ttl = m.resourceServer.accessTokenTTL
		}
		if m.client != nil {
			if value, ok := m.client.lifetime("access_token_ttl"); ok && value < ttl {
				ttl = value
			}
		}
		if m.kind == "AccessToken" && oc != nil && oc.exchange != nil && oc.exchange.remaining > 0 && oc.exchange.remaining < ttl {
			ttl = oc.exchange.remaining
		}
	case "AuthorizationCode":
		ttl = 60
	case "DeviceCode":
		ttl = 600
	case "Grant":
		ttl = 30 * 86400
	case "RefreshToken":
		ttl = 30 * 86400
		if m.client != nil {
			if value, ok := m.client.lifetime("refresh_token_ttl"); ok {
				ttl = value
			}
		}
	}
	m.expiresIn = ttl
	return ttl
}

// remainingTTL is exp - now, or the expiration when exp is unset.
func (p *Provider) remainingTTL(oc *oidcCtx, m *model) int64 {
	if exp, ok := m.data.Get("exp").(float64); ok && exp != 0 {
		return int64(exp) - epoch(p.now())
	}
	return p.expiration(oc, m)
}

// payload is opaque getValueAndPayload: { iat, exp, ...the model's payload members }.
func (p *Provider) payload(oc *oidcCtx, m *model, exp int64) (*core.Object, error) {
	now := epoch(p.now())
	iat := any(now)
	if value, ok := m.data.Get("iat").(float64); ok && value != 0 {
		iat = value
	}
	out := core.NewObject("iat", iat)
	if exp != 0 {
		out.Set("exp", exp)
	}
	allowed := append(append([]string{}, basePayload...), modelPayload[m.kind]...)
	m.data.Entries(func(key string, value any) bool {
		if key == "iat" || key == "exp" || isUndefined(value) || !contains(allowed, key) {
			return true
		}
		out.SetRaw(key, value)
		return true
	})
	if m.kind == "AccessToken" || m.kind == "ClientCredentials" {
		extra, err := p.extraTokenClaims(oc, m)
		if err != nil {
			return nil, err
		}
		m.data.Set("extra", extra)
		out.Set("extra", extra)
	}
	return out, nil
}

// save persists a model and returns its value: the jti for opaque artifacts, a JWT for jwt access tokens.
func (p *Provider) save(ctx context.Context, oc *oidcCtx, m *model, ttl int64) (string, error) {
	if baseTokens[m.kind] {
		ttl = p.remainingTTL(oc, m)
	}
	if m.jti() == "" {
		switch {
		case (m.kind == "AccessToken" || m.kind == "ClientCredentials") && m.resourceServer != nil && m.resourceServer.format == "jwt":
			m.format = "jwt"
			m.data.Set("jti", nanoid(43))
		case m.kind == "Session" || m.kind == "PushedAuthorizationRequest" || m.kind == "ReplayDetection" || m.kind == "Interaction":
			m.data.Set("jti", nanoid(43))
		default:
			m.format = "opaque"
			m.data.Set("jti", nanoid(43))
		}
	}
	if !baseTokens[m.kind] {
		m.data.Set("exp", epoch(p.now())+ttl)
	}
	exp := int64(0)
	if value, ok := m.data.Get("exp").(float64); ok && value != 0 {
		exp = int64(value)
	} else {
		exp = epoch(p.now()) + p.expiration(oc, m)
	}
	if m.kind == "Grant" {
		cleanGrant(m.data)
		if rejected := obj(m.data, "rejected"); rejected != nil {
			cleanGrant(rejected)
		}
	}
	payload, err := p.payload(oc, m, exp)
	if err != nil {
		return "", err
	}
	if m.format == "jwt" {
		return p.jwtAccessToken(oc, m, payload)
	}
	if !m.data.Has("iat") || isUndefined(m.data.Get("iat")) {
		m.data.Set("iat", payload.Get("iat"))
	}
	m.data.Set("exp", exp)
	if err := p.adapter.Model(m.kind).Upsert(ctx, m.jti(), payload, ttl); err != nil {
		return "", err
	}
	return m.jti(), nil
}

// jwtAccessToken is formats/jwt.js getValueAndPayload: a signed `at+jwt`, never stored.
func (p *Provider) jwtAccessToken(oc *oidcCtx, m *model, payload *core.Object) (string, error) {
	claims := core.NewObject()
	if extra := obj(payload, "extra"); extra != nil {
		claims.Assign(extra)
	}
	sub := payload.Get("accountId")
	if !truthy(sub) {
		sub = payload.Get("clientId")
	}
	claims.Set("jti", payload.Get("jti"))
	claims.Set("sub", sub)
	claims.Set("iat", payload.Get("iat"))
	claims.Set("exp", payload.Get("exp"))
	if scope := payload.Get("scope"); truthy(scope) {
		claims.Set("scope", scope)
	}
	claims.Set("client_id", payload.Get("clientId"))
	claims.Set("iss", p.issuer)
	claims.Set("aud", payload.Get("aud"))
	if jkt := payload.Get("jkt"); truthy(jkt) {
		claims.Set("cnf", core.NewObject("jkt", jkt))
	}
	if !truthy(claims.Get("aud")) {
		return "", &core.TypeError{Message: "JWT Access Tokens must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format"}
	}
	// Resource servers sign with the provider-wide default algorithm (clientDefaults.id_token_signed_response_alg).
	return p.keys.sign(claims, "RS256", "at+jwt")
}

// cleanGrant is Grant#clean: drops empty openid and resources members.
func cleanGrant(grant *core.Object) {
	if openid := obj(grant, "openid"); openid != nil {
		claims, _ := openid.Get("claims").([]any)
		if !truthy(openid.Get("scope")) && len(claims) == 0 {
			grant.Delete("openid")
		}
	}
	if resources := obj(grant, "resources"); resources != nil {
		for _, key := range resources.Keys() {
			if !truthy(resources.Get(key)) {
				resources.Delete(key)
			}
		}
		if resources.Len() == 0 {
			grant.Delete("resources")
		}
	}
}

// assertPayload is helpers/jwt.js assertPayload for stored artifacts (clock tolerance 15 seconds).
func (p *Provider) assertPayload(payload *core.Object, ignoreExpiration bool) bool {
	now := float64(epoch(p.now()))
	if nbf := payload.Get("nbf"); !isUndefined(nbf) {
		value, ok := nbf.(float64)
		if !ok || value > now+15 {
			return false
		}
	}
	if iat := payload.Get("iat"); !isUndefined(iat) {
		value, ok := iat.(float64)
		if !ok || (isUndefined(payload.Get("exp")) && value > now+15) {
			return false
		}
	}
	if exp := payload.Get("exp"); !isUndefined(exp) && !ignoreExpiration {
		value, ok := exp.(float64)
		if !ok || now-15 >= value {
			return false
		}
	}
	if jti := payload.Get("jti"); !isUndefined(jti) {
		if _, ok := jti.(string); !ok {
			return false
		}
	}
	if iss := payload.Get("iss"); !isUndefined(iss) {
		if _, ok := iss.(string); !ok {
			return false
		}
	}
	return true
}

// find is Model.find: the stored artifact, verified (nil when missing or invalid).
func (p *Provider) find(ctx context.Context, kind, value string, ignoreExpiration bool) (*model, error) {
	if value == "" {
		return nil, nil
	}
	stored, err := p.adapter.Model(kind).Find(ctx, value)
	if err != nil || stored == nil {
		return nil, err
	}
	if kind != "Session" && kind != "Interaction" && kind != "ReplayDetection" && kind != "PushedAuthorizationRequest" && kind != "Grant" {
		if stored.Has("jwt") || stored.Has("jwt-ietf") || stored.Has("paseto") {
			return nil, nil
		}
		if format := stored.Get("format"); !isUndefined(format) && format != "opaque" {
			return nil, nil
		}
	}
	if !p.assertPayload(stored, ignoreExpiration) {
		return nil, nil
	}
	if k, ok := stored.Get("kind").(string); ok && k != kind {
		return nil, nil
	}
	return &model{kind: kind, data: stored}, nil
}

// findToken is find plus checkSessionBinding for the tokens that may expire with the session.
func (p *Provider) findToken(ctx context.Context, kind, value string, ignoreExpiration, ignoreSessionBinding bool) (*model, error) {
	token, err := p.find(ctx, kind, value, ignoreExpiration)
	if err != nil || token == nil {
		return token, err
	}
	if token.get("expiresWithSession") != true || ignoreSessionBinding {
		return token, nil
	}
	session, err := p.sessionByUID(ctx, token.str("sessionUid"))
	if err != nil {
		return nil, err
	}
	if session == nil || !jsEq(token.get("accountId"), session.get("accountId")) || !jsEq(token.get("grantId"), sessionGrantID(session, token.str("clientId"))) {
		return nil, nil
	}
	return token, nil
}

func (p *Provider) sessionByUID(ctx context.Context, uid string) (*model, error) {
	if uid == "" {
		return nil, nil
	}
	stored, err := p.adapter.Model("Session").FindByUID(ctx, uid)
	if err != nil || stored == nil {
		return nil, err
	}
	if !p.assertPayload(stored, false) {
		return nil, nil
	}
	return &model{kind: "Session", data: stored}, nil
}

func (p *Provider) destroy(ctx context.Context, m *model) error {
	return p.adapter.Model(m.kind).Destroy(ctx, m.jti())
}

func (p *Provider) consume(ctx context.Context, m *model) error {
	return p.adapter.Model(m.kind).Consume(ctx, m.jti())
}

// replayUnique is ReplayDetection.unique(iss, jti, exp).
func (p *Provider) replayUnique(ctx context.Context, iss, jti string, exp int64) (bool, error) {
	id := sha256B64URL(iss + jti)
	found, err := p.find(ctx, "ReplayDetection", id, false)
	if err != nil {
		return false, err
	}
	if found != nil {
		return false, nil
	}
	entry := newModel("ReplayDetection", "jti", id, "iss", iss)
	if _, err := p.save(ctx, nil, entry, exp-epoch(p.now())); err != nil {
		return false, err
	}
	return true, nil
}

// --- Grant ----------------------------------------------------------------------------------------------------------

func grantOIDCScope(grant *core.Object) string {
	openid := obj(grant, "openid")
	scope, _ := get(openid, "scope").(string)
	if scope == "" {
		return ""
	}
	if rejected := obj(grant, "rejected"); rejected != nil {
		removed := strings.Split(grantOIDCScope(rejected), " ")
		var kept []string
		for _, item := range unique(strings.Split(scope, " ")) {
			if contains(removed, item) && item != "openid" {
				continue
			}
			kept = append(kept, item)
		}
		return strings.Join(kept, " ")
	}
	return scope
}

func grantOIDCScopeFiltered(grant *core.Object, filter []string) string {
	var out []string
	for _, scope := range strings.Split(grantOIDCScope(grant), " ") {
		if contains(filter, scope) {
			out = append(out, scope)
		}
	}
	return strings.Join(out, " ")
}

func grantResourceScope(grant *core.Object, resource string) string {
	scope, _ := get(obj(grant, "resources"), resource).(string)
	if scope == "" {
		return ""
	}
	if rejected := obj(grant, "rejected"); rejected != nil {
		removed := strings.Split(grantResourceScope(rejected, resource), " ")
		var kept []string
		for _, item := range unique(strings.Split(scope, " ")) {
			if !contains(removed, item) {
				kept = append(kept, item)
			}
		}
		return strings.Join(kept, " ")
	}
	return scope
}

func grantResourceScopeFiltered(grant *core.Object, resource string, filter []string) string {
	var out []string
	for _, scope := range strings.Split(grantResourceScope(grant, resource), " ") {
		if contains(filter, scope) {
			out = append(out, scope)
		}
	}
	return strings.Join(out, " ")
}

func grantOIDCClaims(grant *core.Object) []string {
	claims := stringList(get(obj(grant, "openid"), "claims"))
	if claims == nil {
		return []string{}
	}
	if rejected := obj(grant, "rejected"); rejected != nil {
		removed := grantOIDCClaims(rejected)
		var kept []string
		for _, claim := range unique(claims) {
			if contains(removed, claim) && !contains(nonRejectableClaims, claim) {
				continue
			}
			kept = append(kept, claim)
		}
		return kept
	}
	return claims
}

func rejectedOIDCClaims(grant *core.Object) []string {
	rejected := obj(grant, "rejected")
	if rejected == nil {
		grant.Set("rejected", core.NewObject())
		return []string{}
	}
	return grantOIDCClaims(rejected)
}

var nonRejectableClaims = []string{"sub", "sid", "auth_time", "acr", "amr", "iss"}

func addOIDCScope(grant *core.Object, scope string) {
	openid := obj(grant, "openid")
	if openid == nil {
		openid = core.NewObject()
		grant.Set("openid", openid)
	}
	if existing, _ := openid.Get("scope").(string); existing != "" {
		openid.Set("scope", strings.Join(unique(append(strings.Split(existing, " "), strings.Split(scope, " ")...)), " "))
	} else {
		openid.Set("scope", scope)
	}
}

func addOIDCClaims(grant *core.Object, claims []string) {
	openid := obj(grant, "openid")
	if openid == nil {
		openid = core.NewObject()
		grant.Set("openid", openid)
	}
	if existing, ok := openid.Get("claims").([]any); ok {
		openid.Set("claims", anyList(unique(append(stringList(existing), claims...))))
	} else {
		openid.Set("claims", anyList(claims))
	}
}

func addResourceScope(grant *core.Object, resource string, scopes []string) {
	resources := obj(grant, "resources")
	if resources == nil {
		resources = core.NewObject()
		grant.Set("resources", resources)
	}
	scope := strings.Join(scopes, " ")
	if existing, _ := resources.Get(resource).(string); existing != "" {
		resources.Set(resource, strings.Join(unique(append(strings.Split(existing, " "), strings.Split(scope, " ")...)), " "))
	} else {
		resources.Set(resource, scope)
	}
}

func grantOIDCScopeEncountered(grant *core.Object) []string {
	rejected := obj(grant, "rejected")
	var rejectedScope string
	if rejected != nil {
		rejectedScope = grantOIDCScope(rejected)
	}
	return append(strings.Split(grantOIDCScope(grant), " "), strings.Split(rejectedScope, " ")...)
}

func grantResourceScopeEncountered(grant *core.Object, resource string) []string {
	rejected := obj(grant, "rejected")
	var rejectedScope string
	if rejected != nil {
		rejectedScope = grantResourceScope(rejected, resource)
	}
	return append(strings.Split(grantResourceScope(grant, resource), " "), strings.Split(rejectedScope, " ")...)
}

// --- Session --------------------------------------------------------------------------------------------------------

func newSession() *model {
	m := newModel("Session")
	m.data.Set("uid", nanoid(43))
	m.data.Set("jti", nanoid(43))
	m.isNew = true
	return m
}

func sessionAuthorization(session *model, clientID string, create bool) *core.Object {
	authorizations := obj(session.data, "authorizations")
	if authorizations == nil {
		if !create {
			return core.NewObject()
		}
		authorizations = core.NewObject()
		session.data.Set("authorizations", authorizations)
	}
	entry := obj(authorizations, clientID)
	if entry == nil {
		entry = core.NewObject()
		authorizations.Set(clientID, entry)
	}
	return entry
}

func sessionGrantID(session *model, clientID string) string {
	entry := obj(obj(session.data, "authorizations"), clientID)
	value, _ := get(entry, "grantId").(string)
	return value
}

func sessionSid(session *model, clientID string) string {
	entry := obj(obj(session.data, "authorizations"), clientID)
	value, _ := get(entry, "sid").(string)
	return value
}

// sessionSet sets a session member and marks it touched (the session Proxy).
func sessionSet(session *model, key string, value any) {
	session.data.Set(key, value)
	session.touched = true
}

func ensureClientContainer(session *model, clientID string) {
	if sessionSid(session, clientID) == "" {
		sessionAuthorization(session, clientID, true).Set("sid", nanoid(43))
		session.touched = true
	}
}

func setSessionGrantID(session *model, clientID, grantID string) {
	sessionAuthorization(session, clientID, true).Set("grantId", grantID)
	session.touched = true
}

func (p *Provider) sessionPast(session *model, maxAge float64) bool {
	loginTs, ok := session.data.Get("loginTs").(float64)
	if ok && loginTs != 0 {
		return float64(epoch(p.now()))-loginTs > maxAge
	}
	return true
}
