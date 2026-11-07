package server

// Port of packages/server/src/principals.ts: credential resolution (user sessions through the auth service; API
// keys, role sessions, session tokens and IAM-signed session JWTs here) and the re-validation of every revocation
// condition inside a transaction (currentPrincipal).

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// PrincipalService is principals.ts PrincipalService.
type PrincipalService interface {
	// Authenticate resolves a credential to its identity and session. Every credential is backed by a stored session
	// row.
	Authenticate(ctx context.Context, input core.CredentialInput) (*Principal, error)
	// CurrentPrincipal re-reads the principal inside a transaction and re-validates every revocation condition.
	CurrentPrincipal(ctx context.Context, tx core.IamStore, principal *Principal) (*Principal, error)
}

// sessionTokenSourceKinds are the kinds a session token may be minted from; temporary kinds never are.
var sessionTokenSourceKinds = newOrderedSet("user", "api-key")

// roleSourceKinds are the kinds a classic role session may be assumed from.
var roleSourceKinds = newOrderedSet("user", "api-key", "session-token")

// opaqueToken is the shape of every opaque token (legacy unprefixed ones included); anything else is never looked up.
var opaqueToken = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)

// jsSpace is JavaScript's \s (WhiteSpace and LineTerminator).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a || unicode.Is(unicode.Zs, r)
}

// bearerValue is /^Bearer (\S{1,4096})$/i: the token of an Authorization header ("" when it does not match).
func bearerValue(header string) string {
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return ""
	}
	value := header[7:]
	if value == "" || utf16Len(value) > 4096 {
		return ""
	}
	for _, r := range value {
		if jsSpace(r) {
			return ""
		}
	}
	return value
}

// credentialValue is the presented credential: input.token, else the bearer header, else "" (the auth service reads
// cookies).
func credentialValue(input core.CredentialInput) (string, error) {
	if input.Token != "" {
		return Text(input.Token, "token", 4096)
	}
	authorization, _ := headerValue(input.Headers, "authorization")
	return bearerValue(authorization), nil
}

func invalidCredentials() *core.IamError {
	return core.NewIamError("UNAUTHENTICATED", "Invalid credentials", 401)
}

func expiredOrRevoked() *core.IamError {
	return core.NewIamError("UNAUTHENTICATED", "Credential expired or revoked", 401)
}

func roleRevoked() *core.IamError {
	return core.NewIamError("UNAUTHENTICATED", "Role credential revoked", 401)
}

// sessionTokenNetworkMismatch is a session bound by bindSessionsToIp presented from another network. Authenticate
// records it as auth:session:mismatch after the refusal rolled back. It unwraps to the IamError.
type sessionTokenNetworkMismatch struct {
	*core.IamError
	sessionID  string
	identityID string
	sessionIP  string
}

func (e *sessionTokenNetworkMismatch) Unwrap() error { return e.IamError }

func newSessionTokenNetworkMismatch(session *core.Object) *sessionTokenNetworkMismatch {
	return &sessionTokenNetworkMismatch{
		IamError:   core.NewIamError("SESSION_NETWORK_MISMATCH", "This session can only be used from the network it was signed in from", 401),
		sessionID:  jsString(session.Get("id")),
		identityID: jsString(session.Get("identityId")),
		sessionIP:  clientIPOf(session),
	}
}

// clientIPOf is session.client?.ip ("" for none).
func clientIPOf(session *core.Object) string {
	ip, _ := member(session.Get("client"), "ip").(string)
	return ip
}

// boundToJwt is whether a stored row is the one a verified session JWT names.
func boundToJwt(session *core.Object, claims *core.Object) bool {
	return session.Get("format") == "jwt" && session.Get("kind") == claims.Get("kind") &&
		session.Get("identityId") == claims.Get("sub") && session.Get("tenantId") == claims.Get("tid")
}

type principals struct {
	server *ServerContext
}

// CreatePrincipals builds the principal service (createPrincipals).
func CreatePrincipals(server *ServerContext) PrincipalService {
	return &principals{server: server}
}

func (p *principals) currentClientIP(ctx context.Context) string {
	if client := p.server.Auth.CurrentClient(ctx); client != nil {
		return client.IP
	}
	return ""
}

// resolveStored is the path every non-user credential shares once its row is known.
func (p *principals) resolveStored(ctx context.Context, sessionID, tokenHash string, bound func(session *core.Object) bool, deviceProof string) (*Principal, error) {
	server := p.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*Principal, error) {
		session, err := tx.Get(ctx, "sessions", sessionID)
		if err != nil {
			return nil, err
		}
		if session == nil || jsNumber(session.Get("expiresAt")) <= float64(server.Now()) || !SameHash(session.Get("tokenHash"), tokenHash) ||
			(bound != nil && !bound(session)) {
			return nil, expiredOrRevoked()
		}
		identity, err := tx.Get(ctx, "identities", jsString(session.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if identity == nil || identity.Get("status") != "active" {
			return nil, core.NewIamError("UNAUTHENTICATED", "Identity disabled", 401)
		}
		if server.IdentityExpired(identity) {
			return nil, core.NewIamError("UNAUTHENTICATED", "Identity expired", 401)
		}
		// API keys record when they were last used (at most once a minute) so unused keys can be found and revoked.
		now := float64(server.Now())
		current := session
		if session.Get("kind") == "api-key" && now-jsNumber(session.Get("lastSeenAt")) >= 60_000 {
			if current, err = tx.Put(ctx, "sessions", session.Spread(core.NewObject("lastSeenAt", now))); err != nil {
				return nil, err
			}
		}
		// The request's device proof goes along: a role session's source decides its assumption again here.
		return p.CurrentPrincipal(ctx, tx, &Principal{Identity: identity, Session: current, DeviceProof: deviceProof})
	})
}

// resolveJwt verifies a hybrid session JWT, then requires the stored row its sid names, holding this token's hash.
func (p *principals) resolveJwt(ctx context.Context, value, deviceProof string) (*Principal, error) {
	signer := p.server.SessionTokens
	if signer == nil {
		return nil, invalidCredentials()
	}
	claims, err := signer.Verify(ctx, value, signer.Issuer)
	if err != nil {
		return nil, invalidCredentials()
	}
	tokenHash := Hash(value)
	candidate, err := p.server.Store.Get(ctx, "sessions", jsString(claims.Get("sid")))
	if err != nil {
		return nil, err
	}
	if candidate == nil || !boundToJwt(candidate, claims) || !SameHash(candidate.Get("tokenHash"), tokenHash) {
		return nil, expiredOrRevoked()
	}
	return p.resolveStored(ctx, jsString(candidate.Get("id")), tokenHash, func(session *core.Object) bool { return boundToJwt(session, claims) }, deviceProof)
}

func (p *principals) authenticateUser(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	principal, err := p.server.Auth.Authenticate(ctx, input)
	if err != nil {
		return nil, err
	}
	return PrincipalFromAuth(principal), nil
}

func (p *principals) resolveCredential(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	provided, err := credentialValue(input)
	if err != nil {
		return nil, err
	}
	if provided == "" {
		return p.authenticateUser(ctx, input)
	}
	deviceProof := DeviceProofOf(input.Headers)
	if LooksLikeJwt(provided) {
		return p.resolveJwt(ctx, provided, deviceProof)
	}
	// Prefixed tokens route by type; the stored kind stays authoritative and a mismatch never falls back to auth.
	expected := ""
	if strings.HasPrefix(provided, "biam_") {
		tokenType, ok := auth.ParseCredentialToken(provided)
		if !ok {
			return nil, invalidCredentials()
		}
		if tokenType == "ses" {
			return p.authenticateUser(ctx, input)
		}
		expected = auth.CredentialTokenKinds[tokenType]
	} else if !opaqueToken.MatchString(provided) {
		return p.authenticateUser(ctx, input) // refused there, unread
	}
	tokenHash := Hash(provided)
	found, err := p.server.Store.Find(ctx, "sessions", core.NewObject("tokenHash", tokenHash), nil)
	if err != nil {
		return nil, err
	}
	var candidate *core.Object
	if len(found) > 0 {
		candidate = found[0]
	}
	if expected != "" {
		if candidate == nil || candidate.Get("kind") != expected {
			return nil, invalidCredentials()
		}
	} else if candidate == nil || candidate.Get("kind") == "user" {
		return p.authenticateUser(ctx, input)
	}
	return p.resolveStored(ctx, jsString(candidate.Get("id")), tokenHash, nil, deviceProof)
}

// checkSessionToken: a session token lives only as long as its source, a user session or API key of the same
// identity and tenant (never an impersonation), re-validated under its own rules.
func (p *principals) checkSessionToken(ctx context.Context, tx core.IamStore, identity, session *core.Object) error {
	var source *core.Object
	if sourceID, ok := session.Get("sourceSessionId").(string); ok {
		found, err := tx.Get(ctx, "sessions", sourceID)
		if err != nil {
			return err
		}
		source = found
	}
	if source == nil || !sessionTokenSourceKinds.Has(jsString(source.Get("kind"))) || truthy(source.Get("impersonatorId")) ||
		source.Get("identityId") != identity.Get("id") || source.Get("tenantId") != session.Get("tenantId") ||
		session.Get("tenantId") != identity.Get("tenantId") || jsNumber(session.Get("expiresAt")) > jsNumber(source.Get("expiresAt")) ||
		session.Get("credentialAuthorityId") != source.Get("credentialAuthorityId") {
		return core.NewIamError("UNAUTHENTICATED", "Session token revoked", 401)
	}
	_, err := p.CurrentPrincipal(ctx, tx, &Principal{Identity: identity, Session: source})
	return err
}

// checkRoleSession: a live trust and role of the session's tenant that belong together, the anchoring identity, and
// the revocation watermarks; then the classic or the web-identity checks.
func (p *principals) checkRoleSession(ctx context.Context, tx core.IamStore, identity, session *core.Object, request *Principal) error {
	var trust, role *core.Object
	var err error
	if trustID, ok := session.Get("trustId").(string); ok {
		if trust, err = tx.Get(ctx, "trusts", trustID); err != nil {
			return err
		}
	}
	if roleID, ok := session.Get("roleId").(string); ok {
		if role, err = tx.Get(ctx, "roles", roleID); err != nil {
			return err
		}
	}
	if trust == nil || truthy(trust.Get("revoked")) || trust.Get("tenantId") != session.Get("tenantId") || role == nil ||
		role.Get("tenantId") != session.Get("tenantId") || trust.Get("roleId") != role.Get("id") ||
		session.Get("originalIdentityId") != identity.Get("id") ||
		RevokedByWatermark(jsNumber(session.Get("createdAt")), trust.Get("sessionsRevokedBefore"), role.Get("sessionsRevokedBefore")) {
		return roleRevoked()
	}
	if truthy(session.Get("webIdentity")) {
		return p.checkWebIdentitySession(ctx, tx, identity, session, trust, role)
	}
	return p.checkClassicRoleSession(ctx, tx, identity, session, trust, role, request)
}

func (p *principals) checkClassicRoleSession(ctx context.Context, tx core.IamStore, identity, session, trust, role *core.Object, request *Principal) error {
	server := p.server
	var source *core.Object
	if sourceID, ok := session.Get("sourceSessionId").(string); ok {
		found, err := tx.Get(ctx, "sessions", sourceID)
		if err != nil {
			return err
		}
		source = found
	}
	kind := trust.Get("kind")
	if isUndefined(kind) || kind == nil {
		kind = "identity"
	}
	consistent := kind == "identity" && trust.Get("sourceIdentityId") == identity.Get("id") &&
		trust.Get("sourceTenantId") == identity.Get("tenantId") && session.Get("sourceTenantId") == identity.Get("tenantId") &&
		source != nil && roleSourceKinds.Has(jsString(source.Get("kind"))) && source.Get("identityId") == identity.Get("id") &&
		source.Get("tenantId") == identity.Get("tenantId") &&
		// Read fail-closed: any stored value but false requires a source session that carries MFA.
		!(TrustRequiresMfa(trust) && source.Get("mfa") != true)
	if !consistent {
		return roleRevoked()
	}
	// The re-decision sees the device this request proves (bound to the role session).
	revalidated, err := p.CurrentPrincipal(ctx, tx, &Principal{Identity: identity, Session: source})
	if err != nil {
		return err
	}
	verifiedSource := WithRequestDevice(revalidated, request)
	authorities, _ := session.Get("sourceAuthorityIds").([]any)
	for _, authorityID := range authorities {
		_, ok, err := server.AuthorityChain(ctx, tx, jsString(authorityID))
		if err != nil {
			return err
		}
		if !ok {
			return core.NewIamError("UNAUTHENTICATED", "Source authority revoked", 401)
		}
	}
	if err := p.roleAuthorityLive(ctx, tx, role); err != nil {
		return err
	}
	decision, err := server.Decisions.Decide(ctx, tx, verifiedSource, AuthorizationRequest{
		TenantID: jsString(identity.Get("tenantId")), Action: "iam:roles:assume", Resource: ResourceTarget{Type: "iam", ID: jsString(role.Get("id"))},
	}, false)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return core.NewIamError("UNAUTHENTICATED", "Assumption permission revoked", 401)
	}
	return nil
}

func (p *principals) roleAuthorityLive(ctx context.Context, tx core.IamStore, role *core.Object) error {
	authorityID, ok := role.Get("authorityId").(string)
	if ok {
		_, ok, err := p.server.AuthorityChain(ctx, tx, authorityID)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return core.NewIamError("UNAUTHENTICATED", "Role authority revoked", 401)
}

// checkWebIdentitySession: web-identity role sessions have no source credential; they are anchored to the trust's
// service account and bounded by the authorities of the trust's and the provider's creators.
func (p *principals) checkWebIdentitySession(ctx context.Context, tx core.IamStore, identity, session, trust, role *core.Object) error {
	server := p.server
	web := session.Get("webIdentity")
	var provider *core.Object
	if providerID, ok := member(web, "providerId").(string); ok {
		found, err := tx.Get(ctx, "oidcProviders", providerID)
		if err != nil {
			return err
		}
		provider = found
	}
	trustAuthority, trustAuthorityOK := trust.Get("authorityId").(string)
	if !server.Config.Sts.WebIdentity.Enabled || trust.Get("kind") != "web-identity" || trust.Get("providerId") != member(web, "providerId") ||
		trust.Get("sourceIdentityId") != identity.Get("id") || trust.Get("sourceTenantId") != session.Get("tenantId") ||
		identity.Get("kind") != "service" || identity.Get("tenantId") != session.Get("tenantId") || !isUndefined(session.Get("sourceSessionId")) ||
		provider == nil || provider.Get("tenantId") != session.Get("tenantId") || provider.Get("enabled") != true ||
		provider.Get("issuer") != member(web, "issuer") ||
		RevokedByWatermark(jsNumber(session.Get("createdAt")), provider.Get("sessionsRevokedBefore")) ||
		!trustAuthorityOK || session.Get("credentialAuthorityId") != trustAuthority {
		return roleRevoked()
	}
	providerAuthority, ok := provider.Get("authorityId").(string)
	if !ok {
		return roleRevoked()
	}
	for _, authorityID := range []string{providerAuthority, trustAuthority} {
		_, live, err := server.AuthorityChain(ctx, tx, authorityID)
		if err != nil {
			return err
		}
		if !live {
			return roleRevoked()
		}
	}
	return p.roleAuthorityLive(ctx, tx, role)
}

// resolveRecorded is resolveCredential, noting in the identity's trail when a bound session token was presented
// from another network (auth:session:mismatch, in its own transaction once the refusal rolled back).
func (p *principals) resolveRecorded(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	principal, err := p.resolveCredential(ctx, input)
	if err == nil {
		return principal, nil
	}
	var mismatch *sessionTokenNetworkMismatch
	if errors.As(err, &mismatch) {
		server := p.server
		client := server.Auth.CurrentClient(ctx)
		_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			identity, err := tx.Get(ctx, "identities", mismatch.identityID)
			if err != nil {
				return err
			}
			session, err := tx.Get(ctx, "sessions", mismatch.sessionID)
			if err != nil || identity == nil || session == nil {
				return err
			}
			metadata := core.NewObject("sessionId", mismatch.sessionID, "sessionIp", mismatch.sessionIP)
			if client != nil && client.IP != "" {
				metadata.Set("ip", client.IP)
			}
			if client != nil && client.UserAgent != "" {
				metadata.Set("userAgent", client.UserAgent)
			}
			return server.Events.Audit(ctx, tx, &Principal{Identity: identity, Session: session}, "auth:session:mismatch",
				jsString(identity.Get("tenantId")), jsString(identity.Get("id")), "allow", false, metadata)
		})
	}
	return nil, err
}

func (p *principals) Authenticate(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	server := p.server
	// Framework integrations pass the incoming request's headers as the credential and set no client scope: the
	// client is derived from those headers so session binding and network checks judge the presenting address.
	if server.Auth.CurrentClient(ctx) == nil && input.Headers != nil {
		ctx = server.Auth.WithClient(ctx, ClientFromHeaders(server.Options, input.Headers, server.Config.BaseURL.Href))
	}
	principal, err := p.resolveRecorded(ctx, input)
	if err != nil {
		return nil, err
	}
	// On an organization's own address (`hosts`), only that organization's credentials are accepted.
	if err := server.Auth.AssertRequestHost(ctx, jsString(principal.Session.Get("tenantId"))); err != nil {
		return nil, err
	}
	// A device proof travels with the principal unverified; decisions verify it (devices.go).
	if proof := DeviceProofOf(input.Headers); proof != "" {
		return &Principal{Identity: principal.Identity, Session: principal.Session, DeviceProof: proof}, nil
	}
	return principal, nil
}

func (p *principals) CurrentPrincipal(ctx context.Context, tx core.IamStore, principal *Principal) (*Principal, error) {
	server := p.server
	authService := server.Auth
	identity, err := tx.Get(ctx, "identities", jsString(principal.Identity.Get("id")))
	if err != nil {
		return nil, err
	}
	session, err := tx.Get(ctx, "sessions", jsString(principal.Session.Get("id")))
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	if identity == nil || identity.Get("status") != "active" || session == nil || jsNumber(session.Get("expiresAt")) <= now ||
		session.Get("identityId") != identity.Get("id") || session.Get("tokenHash") != principal.Session.Get("tokenHash") {
		return nil, core.NewIamError("UNAUTHENTICATED", "Credential revoked", 401)
	}
	if server.IdentityExpired(identity) {
		return nil, core.NewIamError("UNAUTHENTICATED", "Identity expired", 401)
	}
	realm, err := server.Tenant(ctx, tx, identity.Get("tenantId"))
	if err != nil {
		return nil, err
	}
	inactive := func(tenant *core.Object) (bool, error) {
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return false, err
		}
		for _, item := range chain {
			if item.Get("status") != "active" {
				return true, nil
			}
		}
		return false, nil
	}
	homeInactive, err := inactive(realm)
	if err != nil {
		return nil, err
	}
	if !homeInactive {
		sessionTenant, err := server.Tenant(ctx, tx, session.Get("tenantId"))
		if err != nil {
			return nil, err
		}
		if homeInactive, err = inactive(sessionTenant); err != nil {
			return nil, err
		}
	}
	if homeInactive {
		return nil, core.NewIamError("TENANT_INACTIVE", "Tenant inactive", 403)
	}
	kind := session.Get("kind")
	sessionTenantID := jsString(session.Get("tenantId"))
	switch kind {
	case "user":
		lifetimeMs, idleTimeoutMs := authService.SessionLimits(realm)
		if identity.Get("kind") != "user" || identity.Get("tenantId") != session.Get("tenantId") ||
			now-jsNumber(session.Get("lastSeenAt")) >= idleTimeoutMs || now-jsNumber(session.Get("createdAt")) >= lifetimeMs {
			return nil, core.NewIamError("UNAUTHENTICATED", "User session expired", 401)
		}
		if !truthy(session.Get("mfa")) {
			required, err := authService.MfaRequired(ctx, tx, identity)
			if err != nil {
				return nil, err
			}
			if required {
				return nil, core.NewIamError("MFA_REQUIRED", "Multi-factor authentication is required", 403)
			}
		}
		if err := authService.AssertImpersonationSource(ctx, tx, session); err != nil {
			return nil, err
		}
		// The recorded address is judged as the auth service judges it.
		if err := authService.AssertIPAllowed(realm, clientIPOf(session)); err != nil {
			return nil, err
		}
		if err := authService.AssertNetworkNotBlocked(ctx, tx, sessionTenantID, clientIPOf(session)); err != nil {
			return nil, err
		}
		// The address presenting the credential now is judged too.
		presented := p.currentClientIP(ctx)
		if err := authService.AssertNetworkNotBlocked(ctx, tx, sessionTenantID, presented); err != nil {
			return nil, err
		}
		if truthy(member(realm.Get("authPolicy"), "bindSessionsToIp")) && clientIPOf(session) != "" && presented != "" && presented != clientIPOf(session) {
			return nil, newSessionTokenNetworkMismatch(session)
		}
	case "api-key":
		authorityID, ok := session.Get("credentialAuthorityId").(string)
		live := false
		if ok {
			if _, live, err = server.AuthorityChain(ctx, tx, authorityID); err != nil {
				return nil, err
			}
		}
		if !MachineIdentity(identity) || identity.Get("tenantId") != session.Get("tenantId") || !ok || !live {
			return nil, core.NewIamError("UNAUTHENTICATED", "Service credential revoked", 401)
		}
		// An agent's key works only while the agent and its sponsor are in good standing (agents.go).
		if identity.Get("kind") == "agent" {
			if err := AssertAgentUsable(ctx, server, tx, identity); err != nil {
				return nil, err
			}
		}
	case "session-token":
		if err := p.checkSessionToken(ctx, tx, identity, session); err != nil {
			return nil, err
		}
	case "role":
		if err := p.checkRoleSession(ctx, tx, identity, session, principal); err != nil {
			return nil, err
		}
	case "delegated":
		if err := CheckDelegatedSession(ctx, server, tx, identity, session, func(ctx context.Context, source *Principal) (*Principal, error) {
			return p.CurrentPrincipal(ctx, tx, source)
		}); err != nil {
			return nil, err
		}
	default:
		return nil, core.NewIamError("UNAUTHENTICATED", "Invalid credential kind", 401)
	}
	if kind != "user" {
		// API keys, assumed roles and session tokens are judged against the address presenting them now (and any
		// address recorded on them).
		var target *core.Object
		if kind == "role" {
			if target, err = server.Tenant(ctx, tx, session.Get("tenantId")); err != nil {
				return nil, err
			}
		}
		if kind == "session-token" {
			home, err := server.Tenant(ctx, tx, session.Get("tenantId"))
			if err != nil {
				return nil, err
			}
			if err := authService.AssertIPAllowed(home, clientIPOf(session)); err != nil {
				return nil, err
			}
			// With bindSessionsToIp, a session token works only from the network it was issued from.
			if truthy(member(home.Get("authPolicy"), "bindSessionsToIp")) {
				presented := p.currentClientIP(ctx)
				if clientIPOf(session) != "" && presented != "" && presented != clientIPOf(session) {
					return nil, newSessionTokenNetworkMismatch(session)
				}
			}
		}
		// new Set([presented, recorded]): undefined counts as one entry.
		addresses := []string{p.currentClientIP(ctx)}
		if recorded := clientIPOf(session); recorded != addresses[0] {
			addresses = append(addresses, recorded)
		}
		for _, ip := range addresses {
			if target != nil {
				if err := authService.AssertIPAllowed(target, ip); err != nil {
					return nil, err
				}
			}
			if err := authService.AssertNetworkNotBlocked(ctx, tx, sessionTenantID, ip); err != nil {
				return nil, err
			}
		}
	}
	// The request's device proof (still unverified) stays with the principal for decisions (devices.go). As in
	// TypeScript, the result is a new principal: a proof binding made by WithRequestDevice does not carry over.
	return &Principal{Identity: identity, Session: session, DeviceProof: principal.DeviceProof}, nil
}
