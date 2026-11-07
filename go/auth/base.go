package auth

// Port of packages/auth/src/service/base.ts: configuration, storage primitives, and the session core shared by every
// authentication feature. The TypeScript class chain (AuthBase -> SessionAuth -> AccountAuth -> PasswordlessAuth ->
// MfaAuth -> PasskeyAuth) is one Go type, Service, whose methods live in the files named after those modules
// (base.go, sessions.go, account.go, passwordless.go, mfa.go, passkeys.go).
//
// AsyncLocalStorage scopes (the request's client and address) are context values: WithClient and WithRequestHost
// derive a context, and every method reads them from its ctx. Calls made inside a transaction callback must pass the
// callback's ctx so nested store transactions join it, as the TypeScript adapters' AsyncLocalStorage routing does.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// passwordHistoryLimit is how many previous password hashes are kept per identity; passwordHistory policies may use
// up to this many.
const passwordHistoryLimit = 24

// blockCacheMs is how long a tenant's network block list is reused before storage is read again.
const blockCacheMs = 5_000

// SessionNetworkMismatch is the refusal of a bound session presented from another network; Authenticate records it
// after the refusal rolled back. It unwraps to the IamError (SESSION_NETWORK_MISMATCH, 401).
type SessionNetworkMismatch struct {
	*core.IamError
	Session     *core.Object
	PresentedIP string
}

func (e *SessionNetworkMismatch) Unwrap() error { return e.IamError }

// RateLimitedError is RATE_LIMITED (429); RetryAfterMs is the window length (the counter resets at most that far
// away). It unwraps to the IamError.
type RateLimitedError struct {
	*core.IamError
	RetryAfterMs int64
}

func (e *RateLimitedError) Unwrap() error { return e.IamError }

// RequestHost is the address a request arrived on, as the HTTP layer resolved it: Origin is the request's trusted
// Origin (an organization's own address counts), and TenantID the organization that address belongs to, if any.
type RequestHost struct {
	Origin   string
	TenantID string
}

type clientKey struct{}
type hostKey struct{}

type blockCacheEntry struct {
	at     int64
	blocks []*core.Object
}

// Service is the authentication service (AuthService).
type Service struct {
	options                  Options
	now                      func() int64
	origins                  []string
	sessionLifetime          int64
	idleLifetime             int64
	cookieName               string
	recentLifetime           int64
	deviceLifetime           int64
	failedAlertThreshold     int64
	appName                  string
	requireEmailVerification bool
	dummyHash                func() (string, error)
	limits                   ResolvedRateLimits
	outbox                   *OutboxContext

	blockMu    sync.Mutex
	blockCache map[string]blockCacheEntry

	bookkeeping sync.WaitGroup

	// Secrets is the current secret first, then the ones being rotated out (PreviousSecrets).
	Secrets []string
}

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func int64Or(value *int64, fallback int64) int64 {
	if value == nil {
		return fallback
	}
	return *value
}

// urlOrigin is URL#origin: scheme://host[:port] for the special schemes, "null" otherwise.
func urlOrigin(u *FetchURL) string {
	if _, special := specialPorts[strings.TrimSuffix(u.Protocol, ":")]; !special {
		return "null"
	}
	origin := u.Protocol + "//" + u.Hostname
	if u.Port != "" {
		origin += ":" + u.Port
	}
	return origin
}

// New builds the authentication service (createAuth), validating the options as the TypeScript constructor does.
func New(options Options) (*Service, error) {
	if core.UTF16Len(options.Secret) < 32 {
		return nil, core.NewIamError("INVALID_CONFIG", "secret must have at least 32 characters")
	}
	previous := options.PreviousSecrets
	seen := map[string]bool{}
	invalid := len(previous) > 5
	for _, value := range previous {
		if core.UTF16Len(value) < 32 || value == options.Secret || seen[value] {
			invalid = true
		}
		seen[value] = true
	}
	if invalid {
		return nil, core.NewIamError("INVALID_CONFIG", "previousSecrets must list at most 5 distinct secrets of at least 32 characters, other than secret")
	}
	s := &Service{options: options, blockCache: map[string]blockCacheEntry{}}
	s.Secrets = append([]string{options.Secret}, previous...)
	limits, err := ResolveRateLimits(options.RateLimits, options.Store)
	if err != nil {
		return nil, err
	}
	s.limits = limits
	maxAttempts := int64Or(options.MaxDeliveryAttempts, 25)
	if maxAttempts < 1 || maxAttempts > 1_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "maxDeliveryAttempts must be an integer between 1 and 1000")
	}
	base, err := ParseFetchURL(options.BaseURL)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	s.cookieName = "better-iam.session"
	if base.Protocol == "https:" {
		s.cookieName = "__Host-better-iam.session"
	}
	if (base.Protocol != "http:" && base.Protocol != "https:") ||
		(base.Protocol != "https:" && base.Hostname != "localhost" && base.Hostname != "127.0.0.1" && base.Hostname != "[::1]") {
		return nil, core.NewIamError("INVALID_CONFIG", "baseURL must use HTTPS, except loopback development")
	}
	s.requireEmailVerification = boolOr(options.RequireEmailVerification, options.SignUpEnabled)
	if (s.requireEmailVerification || options.PasswordlessEmail) && options.SendEmail == nil {
		return nil, core.NewIamError("INVALID_CONFIG", "Enabled email features require sendEmail")
	}
	if options.PasswordlessSms && options.SendSms == nil {
		return nil, core.NewIamError("INVALID_CONFIG", "Enabled SMS features require sendSms")
	}
	origins := []string{urlOrigin(base)}
	for _, origin := range options.TrustedOrigins {
		parsed, err := ParseFetchURL(origin)
		if err != nil {
			return nil, &core.TypeError{Message: "Invalid URL"}
		}
		if urlOrigin(parsed) != origin {
			return nil, core.NewIamError("INVALID_CONFIG", "Trusted origins must be exact origins")
		}
		duplicate := false
		for _, existing := range origins {
			if existing == origin {
				duplicate = true
			}
		}
		if !duplicate {
			origins = append(origins, origin)
		}
	}
	s.origins = origins
	s.now = options.Now
	if s.now == nil {
		s.now = core.NowMillis
	}
	s.sessionLifetime = int64Or(options.SessionLifetimeMs, 7*24*60*60_000)
	s.idleLifetime = int64Or(options.SessionIdleTimeoutMs, min(s.sessionLifetime, 24*60*60_000))
	s.recentLifetime = int64Or(options.RecentAuthenticationMs, 5*60_000)
	if s.sessionLifetime < 60_000 || s.sessionLifetime > 30*24*60*60_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "Session lifetime must be between one minute and thirty days")
	}
	if s.idleLifetime < 60_000 || s.idleLifetime > s.sessionLifetime {
		return nil, core.NewIamError("INVALID_CONFIG", "Session idle timeout must be between one minute and the absolute session lifetime")
	}
	if s.recentLifetime < 1_000 || s.recentLifetime > 15*60_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "Recent authentication lifetime must be between one second and fifteen minutes")
	}
	s.deviceLifetime = int64Or(options.TrustedDeviceLifetimeMs, 30*24*60*60_000)
	if s.deviceLifetime < 0 || (s.deviceLifetime > 0 && s.deviceLifetime < 60_000) || s.deviceLifetime > 365*24*60*60_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "Trusted device lifetime must be 0 (disabled) or between one minute and one year")
	}
	s.failedAlertThreshold = options.FailedSignInAlerts
	if s.failedAlertThreshold < 0 || s.failedAlertThreshold > 1_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "failedSignInAlerts must be 0 (disabled) or an integer between 1 and 1000")
	}
	if s.failedAlertThreshold > 0 && options.SendEmail == nil {
		return nil, core.NewIamError("INVALID_CONFIG", "failedSignInAlerts requires sendEmail")
	}
	s.appName = options.AppName
	if s.appName == "" {
		s.appName = "Better IAM"
	}
	if options.Passkeys != nil {
		valid := options.Passkeys.RPID != ""
		for _, origin := range s.origins {
			parsed, err := ParseFetchURL(origin)
			if err != nil {
				valid = false
				continue
			}
			if parsed.Hostname != options.Passkeys.RPID && !strings.HasSuffix(parsed.Hostname, "."+options.Passkeys.RPID) {
				valid = false
			}
		}
		if !valid {
			return nil, core.NewIamError("INVALID_CONFIG", "Passkey RP ID must match each trusted origin")
		}
	}
	// The dummy hash is computed in the background, as the TypeScript constructor starts argon2.hash.
	dummy := make(chan struct{})
	var dummyValue string
	var dummyErr error
	go func() {
		defer close(dummy)
		dummyValue, dummyErr = HashPassword(NewToken())
	}()
	s.dummyHash = func() (string, error) {
		<-dummy
		return dummyValue, dummyErr
	}
	s.outbox = &OutboxContext{
		Store:       options.Store,
		Secret:      options.Secret,
		Secrets:     s.Secrets,
		Now:         func() int64 { return s.now() },
		MaxAttempts: maxAttempts,
		Deliverer:   s.deliverer,
	}
	return s, nil
}

// Options returns the options the service was built with.
func (s *Service) Options() Options { return s.options }

// Store is the IAM store.
func (s *Service) Store() core.IamStore { return s.options.Store }

// Now is the service clock (epoch milliseconds).
func (s *Service) Now() int64 { return s.now() }

// CookieName is the session cookie name (__Host-better-iam.session on https deployments).
func (s *Service) CookieName() string { return s.cookieName }

// Origins are the deployment's trusted origins (the base URL's first).
func (s *Service) Origins() []string { return append([]string(nil), s.origins...) }

// AppName is the product name used in messages.
func (s *Service) AppName() string { return s.appName }

// RequireEmailVerification reports whether sign-in requires a verified email.
func (s *Service) RequireEmailVerification() bool { return s.requireEmailVerification }

// Limits are the rate limits in force.
func (s *Service) Limits() ResolvedRateLimits { return s.limits }

// --- request scopes ---------------------------------------------------------------------------------------------------

// cleanClientValue trims, strips C0 controls and DEL, and bounds a client detail; "" when it is blank.
func cleanClientValue(value string, max int) string {
	if core.JSTrim(value) == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range runes(value) {
		if r <= 0x1f || r == 0x7f {
			continue
		}
		b.WriteString(core.FromUTF16(utf16Units(r)))
	}
	return sliceUTF16(core.JSTrim(b.String()), 0, max)
}

func utf16Units(r rune) []uint16 {
	if r >= 0x10000 {
		r -= 0x10000
		return []uint16{uint16(0xD800 + (r >> 10)), uint16(0xDC00 + (r & 0x3FF))}
	}
	return []uint16{uint16(r)}
}

// clientObject is the recorded client as a record value ({ ip?, userAgent?, label? }).
func clientObject(client *core.SessionClientInfo) *core.Object {
	if client == nil {
		return nil
	}
	info := core.NewObject()
	if client.IP != "" {
		info.Set("ip", client.IP)
	}
	if client.UserAgent != "" {
		info.Set("userAgent", client.UserAgent)
	}
	if client.Label != "" {
		info.Set("label", client.Label)
	}
	return info
}

// WithClient returns a context whose sessions record client (IP, user agent, label); values are trimmed and
// bounded. A client with nothing left after cleaning leaves ctx as it is.
func (s *Service) WithClient(ctx context.Context, client *core.SessionClientInfo) context.Context {
	if client == nil {
		return ctx
	}
	info := &core.SessionClientInfo{
		IP:        cleanClientValue(client.IP, 64),
		UserAgent: cleanClientValue(client.UserAgent, 512),
		Label:     cleanClientValue(client.Label, 128),
	}
	if info.IP == "" && info.UserAgent == "" && info.Label == "" {
		return ctx
	}
	return context.WithValue(ctx, clientKey{}, info)
}

// CurrentClient is the client of the current request (set by WithClient), if any.
func (s *Service) CurrentClient(ctx context.Context) *core.SessionClientInfo {
	client, _ := ctx.Value(clientKey{}).(*core.SessionClientInfo)
	return client
}

func (s *Service) clientIP(ctx context.Context) string {
	if client := s.CurrentClient(ctx); client != nil {
		return client.IP
	}
	return ""
}

// WithRequestHost returns a context for a request that arrived on host: credentials of another organization are
// refused on an organization's own address (HOST_MISMATCH), and passkey ceremonies accept that address's origin.
func (s *Service) WithRequestHost(ctx context.Context, host *RequestHost) context.Context {
	if host == nil || (host.Origin == "" && host.TenantID == "") {
		return ctx
	}
	copy := *host
	return context.WithValue(ctx, hostKey{}, &copy)
}

// RequestHost is the address of the current request (set by WithRequestHost), if any.
func (s *Service) RequestHost(ctx context.Context) *RequestHost {
	host, _ := ctx.Value(hostKey{}).(*RequestHost)
	return host
}

// detached is a context with the request scopes of ctx but no transaction or deadline (for work that outlives the
// request, such as deferred sign-in bookkeeping).
func (s *Service) detached(ctx context.Context) context.Context {
	out := context.Background()
	if client := s.CurrentClient(ctx); client != nil {
		out = context.WithValue(out, clientKey{}, client)
	}
	if host := s.RequestHost(ctx); host != nil {
		out = context.WithValue(out, hostKey{}, host)
	}
	return out
}

// AssertRequestHost refuses a credential of another organization on an organization's own address.
func (s *Service) AssertRequestHost(ctx context.Context, tenantID string) error {
	if host := s.RequestHost(ctx); host != nil && host.TenantID != "" && host.TenantID != tenantID {
		return core.NewIamError("HOST_MISMATCH", "This address belongs to another organization", 403)
	}
	return nil
}

// expectedOrigins are the origins a WebAuthn response may come from: the deployment's, plus the current request's
// organization address.
func (s *Service) expectedOrigins(ctx context.Context) []string {
	host := s.RequestHost(ctx)
	if host == nil || host.Origin == "" {
		return s.origins
	}
	for _, origin := range s.origins {
		if origin == host.Origin {
			return s.origins
		}
	}
	return append(append([]string(nil), s.origins...), host.Origin)
}

// --- tenants and rate limits -------------------------------------------------------------------------------------------

// AssertTenantActive validates every ancestor; tenant identifiers are never inferred from email.
func (s *Service) AssertTenantActive(ctx context.Context, tx core.IamStore, tenantID any) error {
	current, err := Text(tenantID, "tenantId")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for current != "" {
		if seen[current] {
			return core.NewIamError("INVALID_TENANT_TREE", "Invalid tenant hierarchy", 403)
		}
		seen[current] = true
		tenant, err := tx.Get(ctx, "tenants", current)
		if err != nil {
			return err
		}
		if tenant == nil || str(tenant, "status") != "active" {
			return core.NewIamError("TENANT_UNAVAILABLE", "Tenant is not active", 403)
		}
		current = str(tenant, "parentId")
	}
	return nil
}

// rate counts an attempt before any credential is examined: first against the client IP when one is recorded and
// rateLimits.ipAttempts is set, then against the subject. tier is default, sensitive or generous.
func (s *Service) rate(ctx context.Context, tenantID, subject, tier string) error {
	if err := s.rateClient(ctx, tenantID); err != nil {
		return err
	}
	return s.rateSubject(ctx, tenantID, subject, tier)
}

// LimitAttemptOptions configures LimitAttempt.
type LimitAttemptOptions struct {
	// Tier is default (when empty), sensitive or generous.
	Tier string
	// Limit, when set, is a dedicated per-subject budget per window that ignores the tenant's maxAttempts.
	Limit *int64
	// SkipClient (with Limit) skips the network steps (blocks, per-IP counter) when the same attempt already ran
	// them (countClient: false).
	SkipClient bool
}

// LimitAttempt counts an attempt for a server flow outside the sign-in paths (MFA step-ups, web-identity
// exchanges). Without Limit it is exactly the sign-in rate limit for the tier. Call it outside any transaction.
// Fails with RATE_LIMITED (429, *RateLimitedError) or the network refusals.
func (s *Service) LimitAttempt(ctx context.Context, tenantID, subject string, options LimitAttemptOptions) error {
	if options.Limit == nil {
		tier := options.Tier
		if tier == "" {
			tier = "default"
		}
		return s.rate(ctx, tenantID, subject, tier)
	}
	if *options.Limit < 1 || *options.Limit > 9007199254740991 {
		return core.NewIamError("INVALID_INPUT", "limit must be a positive integer")
	}
	if !options.SkipClient {
		if err := s.rateClient(ctx, tenantID); err != nil {
			return err
		}
	}
	return s.consume(ctx, HashToken(tenantID+":"+subject), tenantID, float64(*options.Limit))
}

// rateClient performs the network steps of rate: network blocks, then the per-IP counter.
func (s *Service) rateClient(ctx context.Context, tenantID string) error {
	ip := s.clientIP(ctx)
	// A blocked network is refused before any credential is examined or any counter moves.
	if err := s.AssertNetworkNotBlocked(ctx, s.options.Store, tenantID, ip); err != nil {
		return err
	}
	if s.limits.IPAttempts > 0 && ip != "" {
		// IPv6 clients are counted per /64 and an IPv4-mapped address as its IPv4 form; a value that is not an IP
		// counts as is.
		network, ok := core.IPCounterKey(ip)
		if !ok {
			network = ip
		}
		return s.consume(ctx, HashToken(tenantID+":ip:"+network), tenantID, float64(s.limits.IPAttempts))
	}
	return nil
}

// rateChallengeIdentity counts a second-factor attempt against the person a challenge names (subject
// `${subject}:${identityId}`), on top of the flow's per-challenge counter. The challenge is read outside any
// transaction; an unknown or expired challenge counts nothing more here (the flow refuses it).
func (s *Service) rateChallengeIdentity(ctx context.Context, tenantID, token, purpose, subject string) error {
	challenge, err := s.readChallenge(ctx, s.options.Store, tenantID, token, purpose, challengeMatch{})
	if err != nil || challenge == nil {
		return nil
	}
	if identityID := str(challenge, "identityId"); identityID != "" {
		return s.rateSubject(ctx, tenantID, subject+":"+identityID, "sensitive")
	}
	return nil
}

// toNumber is JavaScript ToNumber for values of the core model.
func toNumber(value any) float64 {
	switch v := value.(type) {
	case nil:
		return 0
	case core.UndefinedType:
		return math.NaN()
	case bool:
		if v {
			return 1
		}
		return 0
	case float64:
		return v
	case string:
		return jsNumber(v)
	case []any:
		if len(v) == 0 {
			return 0
		}
		if len(v) == 1 {
			return toNumber(jsString(v[0]))
		}
	}
	return math.NaN()
}

// jsMin is Math.min (NaN propagates).
func jsMin(values ...float64) float64 {
	out := math.Inf(1)
	for _, value := range values {
		if math.IsNaN(value) {
			return math.NaN()
		}
		out = math.Min(out, value)
	}
	return out
}

// rateSubject is one subject's counter, without the network checks rate performs first.
func (s *Service) rateSubject(ctx context.Context, tenantID, subject, tier string) error {
	key := HashToken(tenantID + ":" + subject)
	// generous covers anonymous, credential-free starts (passkey discovery): ten times the ordinary allowance.
	limit := float64(s.limits.Attempts)
	switch tier {
	case "sensitive":
		limit = float64(s.limits.SensitiveAttempts)
	case "generous":
		limit = float64(s.limits.Attempts * 10)
	}
	// A tenant policy can only tighten the deployment's limit; an unknown tenant keeps the default.
	if tenant, err := s.options.Store.Get(ctx, "tenants", tenantID); err == nil && tenant != nil {
		if policy := child(tenant, "authPolicy"); policy != nil {
			if cap, ok := policy.Lookup("maxAttempts"); ok && !core.IsUndefined(cap) {
				limit = jsMin(limit, toNumber(cap))
			}
		}
	}
	return s.consume(ctx, key, tenantID, limit)
}

func (s *Service) consume(ctx context.Context, key, tenantID string, limit float64) error {
	permitted, err := s.limits.Limiter.Consume(ctx, RateLimitInput{
		Key: key, TenantID: tenantID, Limit: limit, WindowMs: s.limits.WindowMs, Now: s.now(),
	})
	if err != nil {
		return err
	}
	if !permitted {
		return &RateLimitedError{
			IamError:     core.NewIamError("RATE_LIMITED", "Too many attempts; try again later", 429),
			RetryAfterMs: s.limits.WindowMs,
		}
	}
	return nil
}

// --- passwords ------------------------------------------------------------------------------------------------------

// SetPassword validates and sets identity.passwordHash (the caller persists the identity): the deployment minimum
// (12), the tenant's password rules, the deployment screen (common, breached, custom), and, for an existing
// password, the tenant's passwordHistory. The replaced hash joins the identity's history.
func (s *Service) SetPassword(ctx context.Context, tx core.IamStore, tenant, identity *core.Object, value any) error {
	plain, err := Password(value)
	if err != nil {
		return err
	}
	policy := child(tenant, "authPolicy")
	screening := s.options.PasswordPolicy
	if err := AssertPasswordRules(plain, policy, screening, identity); err != nil {
		return err
	}
	if screening != nil && screening.Check != nil {
		checkIdentity := core.NewObject("id", identity.Get("id"), "email", identity.Get("email"), "name", identity.Get("name"))
		custom, err := screening.Check(ctx, plain, PasswordCheckContext{TenantID: str(identity, "tenantId"), Identity: checkIdentity})
		if err != nil {
			return err
		}
		if custom != "" {
			return core.NewIamError("WEAK_PASSWORD", custom)
		}
	}
	if screening != nil && screening.IsBreached != nil {
		breached, err := screening.IsBreached(ctx, plain)
		if err != nil {
			return err
		}
		if breached {
			return core.NewIamError("BREACHED_PASSWORD", "This password appears in a known data breach; choose a different one")
		}
	}
	currentHash := str(identity, "passwordHash")
	var history []*core.Object
	if currentHash != "" {
		history, err = tx.Find(ctx, "passwordHistory", core.NewObject("identityId", identity.Get("id")), nil)
		if err != nil {
			return err
		}
		sort.SliceStable(history, func(i, j int) bool {
			return numOr(history[j], "createdAt", math.NaN())-numOr(history[i], "createdAt", math.NaN()) < 0
		})
	}
	depth := 0.0
	if value, ok := num(policy, "passwordHistory"); ok {
		depth = value
	}
	if currentHash != "" && depth > 0 {
		recent := []string{currentHash}
		for index, row := range history {
			if float64(index) >= math.Trunc(depth-1) {
				break
			}
			recent = append(recent, str(row, "hash"))
		}
		for _, hash := range recent {
			reused, err := VerifyPassword(hash, plain)
			if err != nil {
				return err
			}
			if reused {
				suffix := "s"
				if depth == 1 {
					suffix = ""
				}
				return core.NewIamError("PASSWORD_REUSED", "Password must differ from your last "+core.NumberString(depth)+" password"+suffix)
			}
		}
	}
	now := s.now()
	if currentHash != "" {
		latest := 0.0
		if len(history) > 0 {
			latest = numOr(history[0], "createdAt", 0)
		}
		if _, err := tx.Insert(ctx, "passwordHistory", core.NewObject(
			"id", NewID("pwh"),
			"tenantId", identity.Get("tenantId"),
			"identityId", identity.Get("id"),
			"hash", currentHash,
			// Strictly increasing per identity, so history order survives changes within one clock tick.
			"createdAt", math.Max(float64(now), latest+1),
		)); err != nil {
			return err
		}
		if len(history) > passwordHistoryLimit-1 {
			for _, stale := range history[passwordHistoryLimit-1:] {
				if err := tx.Delete(ctx, "passwordHistory", str(stale, "id")); err != nil {
					return err
				}
			}
		}
	}
	hash, err := HashPassword(plain)
	if err != nil {
		return err
	}
	identity.Set("passwordHash", hash)
	identity.Set("passwordChangedAt", float64(now))
	return nil
}

// PasswordExpiresAt is when the identity's password expires under its tenant's passwordMaxAgeDays, if it does.
func (s *Service) PasswordExpiresAt(tenant, identity *core.Object) (float64, bool) {
	days, ok := num(child(tenant, "authPolicy"), "passwordMaxAgeDays")
	if !ok || days == 0 || math.IsNaN(days) || !flag(identity, "passwordHash") {
		return 0, false
	}
	changed, ok := num(identity, "passwordChangedAt")
	if nullish(identity, "passwordChangedAt") {
		changed, ok = num(identity, "createdAt")
	}
	if !ok {
		changed = math.NaN()
	}
	return changed + days*24*60*60_000, true
}

// assertPasswordCurrent refuses a correct but expired password; the person recovers through password reset.
func (s *Service) assertPasswordCurrent(ctx context.Context, tx core.IamStore, identity *core.Object) error {
	tenant, err := tx.Get(ctx, "tenants", str(identity, "tenantId"))
	if err != nil {
		return err
	}
	if expiresAt, ok := s.PasswordExpiresAt(tenant, identity); ok && expiresAt <= float64(s.now()) {
		return core.NewIamError("PASSWORD_EXPIRED", "Your password has expired; reset it to continue", 403)
	}
	return nil
}

// ResetRateLimits clears the rate-limit counters an identity's sign-in and recovery flows use, so an administrator
// can unlock an account after a burst of failures: { supported, cleared }. supported is false when the configured
// limiter cannot reset counters.
func (s *Service) ResetRateLimits(ctx context.Context, identity *core.Object) (*core.Object, error) {
	resetter, ok := s.limits.Limiter.(RateLimitResetter)
	if !ok {
		return core.NewObject("supported", false, "cleared", 0.0), nil
	}
	id := str(identity, "id")
	subjects := []string{
		"mfa-enroll:" + id, "password-change:" + id, "reauth:" + id, "email-change:" + id, "phone-verify:" + id,
		"phone-code:" + id,
		// Per-person second-factor counters (see rateChallengeIdentity).
		"mfa-verify:" + id, "mfa-recovery:" + id, "mfa-code-send:" + id, "passkey-mfa-begin:" + id,
		"passkey-mfa-verify:" + id,
	}
	for _, key := range []string{"email", "phone"} {
		if destination := identity.Get(key); truthy(destination) {
			d := jsString(destination)
			subjects = append(subjects, "signup:"+d, "signin:"+d, "verify-email:"+d, "password-reset:"+d,
				"passwordless-start:"+d, "passwordless-finish:"+d, "passkey:"+d)
		}
	}
	tenantID := str(identity, "tenantId")
	for _, subject := range subjects {
		if err := resetter.Reset(ctx, HashToken(tenantID+":"+subject), tenantID); err != nil {
			return nil, err
		}
	}
	return core.NewObject("supported", true, "cleared", float64(len(subjects))), nil
}

// --- identities -------------------------------------------------------------------------------------------------------

// identityExpired is true once an identity's expiresAt has passed: it is refused everywhere, before the purge worker
// disables it.
func (s *Service) identityExpired(identity *core.Object) bool {
	expiresAt, ok := num(identity, "expiresAt")
	return ok && expiresAt <= float64(s.now())
}

// user is an active, unexpired human identity in an active tenant tree (tenantID "" skips the tenant match).
func (s *Service) user(ctx context.Context, tx core.IamStore, identityID, tenantID string) (*core.Object, error) {
	identity, err := tx.Get(ctx, "identities", identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil || str(identity, "kind") != "user" || str(identity, "status") != "active" || s.identityExpired(identity) ||
		(tenantID != "" && str(identity, "tenantId") != tenantID) {
		return nil, core.NewIamError("UNAUTHENTICATED", "Invalid authentication", 401)
	}
	if err := s.AssertTenantActive(ctx, tx, identity.Get("tenantId")); err != nil {
		return nil, err
	}
	return identity, nil
}

// MfaRequired covers root administrators, enrolled people, and members of tenants that require MFA (by callback or
// tenant policy).
func (s *Service) MfaRequired(ctx context.Context, tx core.IamStore, identity *core.Object) (bool, error) {
	mfa, err := tx.Get(ctx, "authMfa", str(identity, "id"))
	if err != nil {
		return false, err
	}
	tenant, err := tx.Get(ctx, "tenants", str(identity, "tenantId"))
	if err != nil {
		return false, err
	}
	if flag(identity, "rootAdmin") || flag(mfa, "enabled") {
		return true, nil
	}
	if tenant == nil {
		return false, nil
	}
	return s.TenantRequiresMfa(ctx, tenant, identity)
}

// TenantRequiresMfa is the tenant-level MFA requirement alone: the configured callback or the tenant's own policy.
func (s *Service) TenantRequiresMfa(ctx context.Context, tenant, identity *core.Object) (bool, error) {
	policy := child(tenant, "authPolicy")
	if isTrue(policy, "requireMfa") || (isTrue(policy, "requireMfaForOwners") && flag(identity, "owner")) {
		return true, nil
	}
	if s.options.RequireMfa != nil {
		return s.options.RequireMfa(ctx, tenant, identity)
	}
	return false, nil
}

// nullishOr is `value ?? fallback` as a number.
func nullishOr(o *core.Object, key string, fallback float64) float64 {
	if nullish(o, key) {
		return fallback
	}
	return toNumber(o.Get(key))
}

// SessionLimits are a tenant's session limits: its policy can shorten, never extend, the deployment's lifetimes.
func (s *Service) SessionLimits(tenant *core.Object) (lifetimeMs, idleTimeoutMs float64) {
	policy := child(tenant, "authPolicy")
	lifetimeMs = jsMin(float64(s.sessionLifetime), nullishOr(policy, "sessionLifetimeMs", math.Inf(1)))
	idleTimeoutMs = jsMin(lifetimeMs, float64(s.idleLifetime), nullishOr(policy, "sessionIdleTimeoutMs", math.Inf(1)))
	return lifetimeMs, idleTimeoutMs
}

// methodAllowed rejects a sign-in method the tenant's policy excludes; called before any credential is examined so
// failures never reveal validity.
func (s *Service) methodAllowed(ctx context.Context, tx core.IamStore, tenantID, method string) error {
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return err
	}
	allowed := child(tenant, "authPolicy").Get("allowedMethods")
	if !truthy(allowed) {
		return nil
	}
	included := false
	switch list := allowed.(type) {
	case []any:
		for _, item := range list {
			if item == method {
				included = true
			}
		}
	case string:
		included = strings.Contains(list, method)
	}
	if !included {
		return core.NewIamError("METHOD_NOT_ALLOWED", "This sign-in method is not permitted for this organization", 403)
	}
	return nil
}

// audit records an authentication event; when session is an impersonation session the administrator is
// attributed. metadata carries small facts about the event (never secrets).
func (s *Service) audit(ctx context.Context, tx core.IamStore, identity *core.Object, action string, session, metadata *core.Object) error {
	event := core.NewObject(
		"id", NewID("audit"),
		"tenantId", identity.Get("tenantId"),
		"actorId", identity.Get("id"),
		"action", action,
		"resourceId", identity.Get("id"),
		"timestamp", float64(s.now()),
		"outcome", "allow",
	)
	if impersonator := session.Get("impersonatorId"); truthy(impersonator) {
		event.Set("impersonatorId", impersonator)
	}
	if metadata != nil && metadata.Len() > 0 {
		event.Set("metadata", metadata)
	}
	chained, err := core.AppendAuditEvent(ctx, tx, event)
	if err != nil {
		return err
	}
	if s.options.OnAudit != nil {
		return s.options.OnAudit(ctx, tx, chained)
	}
	return nil
}

// clientMetadata is the recorded client of the current request as audit metadata (IP and user agent only).
func (s *Service) clientMetadata(ctx context.Context) *core.Object {
	out := core.NewObject()
	if client := s.CurrentClient(ctx); client != nil {
		if client.IP != "" {
			out.Set("ip", client.IP)
		}
		if client.UserAgent != "" {
			out.Set("userAgent", client.UserAgent)
		}
	}
	return out
}

// DigestChallenge is HMAC-SHA256(secret, `${tenantId}:${token}`) in hex; the secret defaults to the current one.
func (s *Service) DigestChallenge(tenantID, token string, secret ...string) string {
	key := s.options.Secret
	if len(secret) > 0 {
		key = secret[0]
	}
	mac := hmac.New(sha256.New, utf8Bytes(key))
	mac.Write(utf8Bytes(tenantID + ":" + token))
	return hex.EncodeToString(mac.Sum(nil))
}

// challenge stores a single-use, purpose-bound challenge and returns the plaintext token to deliver (token ""
// generates one; lifetimeMs 0 is ten minutes).
func (s *Service) challenge(ctx context.Context, tx core.IamStore, identity *core.Object, purpose string, payload *core.Object,
	lifetimeMs int64, token string, sessionID string) (string, error) {
	if lifetimeMs == 0 {
		lifetimeMs = 10 * 60_000
	}
	if token == "" {
		token = NewToken()
	}
	tenantID := str(identity, "tenantId")
	record := core.NewObject(
		"id", NewID("ch"),
		"tenantId", tenantID,
		"identityId", identity.Get("id"),
		"purpose", purpose,
		"tokenHash", s.DigestChallenge(tenantID, token),
		"payload", payload,
		"expiresAt", float64(s.now()+lifetimeMs),
	)
	if sessionID != "" {
		record.Set("sessionId", sessionID)
	}
	if _, err := tx.Insert(ctx, "authChallenges", record); err != nil {
		return "", err
	}
	return token, nil
}

type challengeMatch struct {
	identityID  string
	destination string
}

// readChallenge finds a live challenge by token and purpose, under the current secret or a previous one.
func (s *Service) readChallenge(ctx context.Context, tx core.IamStore, tenantID, token any, purpose string, match challengeMatch) (*core.Object, error) {
	tenant, err := Text(tenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	plain, err := Text(token, "token", 512)
	if err != nil {
		return nil, err
	}
	var item *core.Object
	// Links issued before a secret rotation carry digests under a previous secret.
	for _, secret := range s.Secrets {
		rows, err := tx.Find(ctx, "authChallenges", core.NewObject("tenantId", tenant, "tokenHash", s.DigestChallenge(tenant, plain, secret), "purpose", purpose), nil)
		if err != nil {
			return nil, err
		}
		for _, entry := range rows {
			if (match.identityID == "" || str(entry, "identityId") == match.identityID) &&
				(match.destination == "" || core.StrictEquals(child(entry, "payload").Get("destination"), match.destination)) {
				item = entry
				break
			}
		}
		if item != nil {
			break
		}
	}
	if item == nil || numOr(item, "expiresAt", math.NaN()) <= float64(s.now()) {
		return nil, core.NewIamError("INVALID_CHALLENGE", "Challenge is invalid or expired", 401)
	}
	return item, nil
}

func (s *Service) enqueue(ctx context.Context, tx core.IamStore, identity *core.Object, kind, to, template string, payload *core.Object) error {
	_, err := s.EnqueueDelivery(ctx, tx, EnqueueInput{TenantID: str(identity, "tenantId"), Kind: kind, To: to, Template: template, Payload: payload})
	return err
}

func (s *Service) deliverer(kind string) Deliverer {
	switch kind {
	case "email":
		return s.options.SendEmail
	case "sms":
		return s.options.SendSms
	}
	return s.options.DeliverWebhook
}

// EnqueueDelivery queues a sealed delivery in the caller's transaction (internal server integrations enqueue
// callbacks in the same transaction as provisioning) and returns the message ID.
func (s *Service) EnqueueDelivery(ctx context.Context, tx core.IamStore, input EnqueueInput) (string, error) {
	return EnqueueDelivery(ctx, s.outbox, tx, input)
}

// DispatchOutbox delivers at least once with backoff (limit 0 means 100); see outbox.go.
func (s *Service) DispatchOutbox(ctx context.Context, limit int) (DispatchResult, error) {
	if limit == 0 {
		limit = 100
	}
	return DispatchOutbox(ctx, s.outbox, limit)
}

// CreateIdentityInput is the internal provisioning input. Name and Password are request values (validated here);
// Password is set only when HasPassword is true.
type CreateIdentityInput struct {
	TenantID      any
	Email         any
	Name          any
	Password      any
	HasPassword   bool
	Owner         bool
	RootAdmin     bool
	EmailVerified bool
}

// CreateIdentity is the internal provisioning primitive. It does not grant application permissions.
func (s *Service) CreateIdentity(ctx context.Context, tx core.IamStore, input CreateIdentityInput) (*core.Object, error) {
	tenantID, err := Text(input.TenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	normalized, err := Email(input.Email)
	if err != nil {
		return nil, err
	}
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, core.NewIamError("TENANT_NOT_FOUND", "Tenant does not exist", 404)
	}
	existing, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", normalized), nil)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return nil, core.NewIamError("IDENTITY_EXISTS", "An identity with this email already exists in this tenant", 409)
	}
	// Every path that creates a person (administration, invitations, self-registration, federation, SCIM) ends here.
	if limits := child(tenant, "limits"); limits != nil {
		if limit, ok := limits.Lookup("identities"); ok && !core.IsUndefined(limit) {
			people, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "user"), nil)
			if err != nil {
				return nil, err
			}
			count := 0
			for _, item := range people {
				if str(item, "status") != "deleted" {
					count++
				}
			}
			if float64(count) >= toNumber(limit) {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "This tenant has reached its member limit ("+jsString(limit)+")", 409)
			}
		}
	}
	name, err := DisplayName(input.Name, 256)
	if err != nil {
		return nil, err
	}
	identity := core.NewObject(
		"id", NewID("usr"),
		"tenantId", tenantID,
		"uniqueKey", "email:"+normalized,
		"kind", "user",
		"email", normalized,
		"name", name,
		"status", "active",
		"emailVerified", input.EmailVerified,
		"rootAdmin", input.RootAdmin,
		"owner", input.Owner,
		"createdAt", float64(s.now()),
	)
	if input.HasPassword {
		if err := s.SetPassword(ctx, tx, tenant, identity, input.Password); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Insert(ctx, "identities", identity); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, tx, identity, "auth:identity:create", nil, nil); err != nil {
		return nil, err
	}
	return identity, nil
}

// DeviceLifetimeFor is how long this tenant remembers a device: the deployment ceiling, shortened by policy; 0 when
// either disables it.
func (s *Service) DeviceLifetimeFor(tenant *core.Object) float64 {
	policy := child(tenant, "authPolicy")
	days, present := policy.Lookup("trustedDeviceDays")
	present = present && !core.IsUndefined(days)
	if s.deviceLifetime == 0 || (present && toNumber(days) == 0 && isNumber(days)) {
		return 0
	}
	if !present {
		return float64(s.deviceLifetime)
	}
	return jsMin(float64(s.deviceLifetime), toNumber(days)*24*60*60_000)
}

// RememberDevice remembers the current client for an identity that just completed MFA: { deviceToken,
// deviceExpiresAt }, or nil when the deployment, the tenant, or the identity (root administrators) rules it out.
func (s *Service) RememberDevice(ctx context.Context, tx core.IamStore, identity *core.Object) (*core.Object, error) {
	if flag(identity, "rootAdmin") {
		return nil, nil
	}
	tenant, err := tx.Get(ctx, "tenants", str(identity, "tenantId"))
	if err != nil {
		return nil, err
	}
	lifetime := s.DeviceLifetimeFor(tenant)
	if lifetime == 0 {
		return nil, nil
	}
	now := float64(s.now())
	token := NewToken()
	device := core.NewObject(
		"id", NewID("dev"),
		"tenantId", identity.Get("tenantId"),
		"identityId", identity.Get("id"),
		"tokenHash", HashToken(token),
		"uniqueKey", HashToken(token),
		"createdAt", now,
		"expiresAt", now+lifetime,
		"lastUsedAt", now,
	)
	if client := s.CurrentClient(ctx); client != nil {
		device.Set("client", clientObject(client))
	}
	if _, err := tx.Insert(ctx, "authDevices", device); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, tx, identity, "auth:device:trust", nil, nil); err != nil {
		return nil, err
	}
	return core.NewObject("deviceToken", token, "deviceExpiresAt", device.Get("expiresAt")), nil
}

var deviceTokenShape = func(token string) bool {
	if len(token) < 32 || len(token) > 512 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// trustedDevice is the live trusted device behind a token for this identity, touched on use; nil when it cannot
// vouch.
func (s *Service) trustedDevice(ctx context.Context, tx core.IamStore, identity *core.Object, deviceToken string) (*core.Object, error) {
	if flag(identity, "rootAdmin") || !deviceTokenShape(deviceToken) {
		return nil, nil
	}
	tenant, err := tx.Get(ctx, "tenants", str(identity, "tenantId"))
	if err != nil {
		return nil, err
	}
	lifetime := s.DeviceLifetimeFor(tenant)
	if lifetime == 0 {
		return nil, nil
	}
	devices, err := tx.Find(ctx, "authDevices", core.NewObject("tokenHash", HashToken(deviceToken)), nil)
	if err != nil || len(devices) == 0 {
		return nil, err
	}
	device := devices[0]
	now := float64(s.now())
	// The current policy also bounds devices remembered under a longer one (trustedDeviceDays lowered later).
	if str(device, "identityId") != str(identity, "id") || str(device, "tenantId") != str(identity, "tenantId") ||
		numOr(device, "expiresAt", math.NaN()) <= now || now-numOr(device, "createdAt", math.NaN()) >= lifetime {
		return nil, nil
	}
	device.Set("lastUsedAt", now)
	if _, err := tx.Put(ctx, "authDevices", device); err != nil {
		return nil, err
	}
	return device, nil
}

// signInSummary is the public part of a sign-in ledger, as stamped on a new session.
func signInSummary(ledger *core.Object) *core.Object {
	summary := core.NewObject("failedAttempts", ledger.Get("failedAttempts"))
	if value := ledger.Get("lastAt"); !core.IsUndefined(value) {
		summary.Set("lastAt", value)
	}
	if value := ledger.Get("lastClient"); truthy(value) {
		summary.Set("lastClient", value)
	}
	if value := ledger.Get("lastFailedAt"); !core.IsUndefined(value) {
		summary.Set("lastFailedAt", value)
	}
	if value := ledger.Get("lastFailedClient"); truthy(value) {
		summary.Set("lastFailedClient", value)
	}
	return summary
}

// IssueSessionOptions configures IssueSession.
type IssueSessionOptions struct {
	Mfa             bool
	AuthenticatedAt *float64
	Method          string
	TrustedDeviceID string
	// MfaAuthenticatedAt is when the second factor behind Mfa was verified, for sessions that carry an earlier
	// ceremony forward (such as a linked-identity switch). Without it, a first-hand MFA session (Mfa, no remembered
	// device, no carried AuthenticatedAt) records the issue time.
	MfaAuthenticatedAt *float64
}

// IssueSession issues a user session: { token, session }. The caller must already have verified the
// authentication ceremony.
func (s *Service) IssueSession(ctx context.Context, tx core.IamStore, identity *core.Object, options IssueSessionOptions) (*core.Object, error) {
	active, err := s.user(ctx, tx, str(identity, "id"), str(identity, "tenantId"))
	if err != nil {
		return nil, err
	}
	if s.requireEmailVerification && !flag(active, "emailVerified") {
		return nil, core.NewIamError("EMAIL_UNVERIFIED", "Verify your email before signing in", 403)
	}
	required, err := s.MfaRequired(ctx, tx, active)
	if err != nil {
		return nil, err
	}
	if required && !options.Mfa {
		return nil, core.NewIamError("MFA_REQUIRED", "Multi-factor authentication is required", 403)
	}
	tenantID := str(active, "tenantId")
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.AssertIPAllowed(tenant, s.clientIP(ctx)); err != nil {
		return nil, err
	}
	if err := s.AssertNetworkNotBlocked(ctx, tx, tenantID, s.clientIP(ctx)); err != nil {
		return nil, err
	}
	now := float64(s.now())
	token := mustCredentialToken("ses")
	lifetime, _ := s.SessionLimits(tenant)
	authenticatedAt := now
	if options.AuthenticatedAt != nil {
		authenticatedAt = *options.AuthenticatedAt
	}
	session := core.NewObject(
		"id", NewID("ses"),
		"tenantId", tenantID,
		"identityId", active.Get("id"),
		"kind", "user",
		"tokenHash", HashToken(token),
		"uniqueKey", HashToken(token),
		"createdAt", now,
		"lastSeenAt", now,
		"expiresAt", now+lifetime,
		"authenticatedAt", authenticatedAt,
		"mfa", options.Mfa,
	)
	if options.Method != "" {
		session.Set("method", options.Method)
	}
	if options.TrustedDeviceID != "" {
		session.Set("trustedDeviceId", options.TrustedDeviceID)
	}
	// principal.mfaTime: only a first-hand factor counts, never a remembered device.
	if options.Mfa && options.TrustedDeviceID == "" {
		if options.MfaAuthenticatedAt != nil {
			session.Set("mfaAuthenticatedAt", *options.MfaAuthenticatedAt)
		} else if options.AuthenticatedAt == nil {
			session.Set("mfaAuthenticatedAt", now)
		}
	}
	client := s.CurrentClient(ctx)
	if client != nil {
		session.Set("client", clientObject(client))
	}
	// The previous sign-in, and the attempts that failed since, travel on the session for a "last sign-in" notice;
	// the ledger then restarts from this session.
	ledger, err := tx.Get(ctx, "authSignIns", str(active, "id"))
	if err != nil {
		return nil, err
	}
	if ledger != nil {
		session.Set("previousSignIn", signInSummary(ledger))
	}
	if _, err := tx.Insert(ctx, "sessions", session); err != nil {
		return nil, err
	}
	next := core.NewObject("id", active.Get("id"), "tenantId", tenantID, "identityId", active.Get("id"), "lastAt", now, "failedAttempts", 0.0)
	if client != nil && (client.IP != "" || client.UserAgent != "" || client.Label != "") {
		next.Set("lastClient", clientObject(client))
	}
	if ledger != nil {
		_, err = tx.Put(ctx, "authSignIns", next)
	} else {
		_, err = tx.Insert(ctx, "authSignIns", next)
	}
	if err != nil {
		return nil, err
	}
	// A tenant may cap concurrent sessions per person; the oldest live sessions make room for the new one.
	if policy := child(tenant, "authPolicy"); policy != nil {
		if maxSessions, ok := policy.Lookup("maxSessions"); ok && !core.IsUndefined(maxSessions) {
			rows, err := tx.Find(ctx, "sessions", core.NewObject("tenantId", tenantID, "identityId", active.Get("id"), "kind", "user"), nil)
			if err != nil {
				return nil, err
			}
			var live []*core.Object
			for _, item := range rows {
				if numOr(item, "expiresAt", math.NaN()) > now && !flag(item, "impersonatorId") {
					live = append(live, item)
				}
			}
			sortByCreatedThenID(live)
			excess := math.Max(0, float64(len(live))-toNumber(maxSessions))
			if math.IsNaN(excess) {
				excess = 0
			}
			for _, stale := range live[:int(math.Min(excess, float64(len(live))))] {
				if err := s.EndSession(ctx, tx, str(stale, "id")); err != nil {
					return nil, err
				}
			}
		}
	}
	metadata := core.NewObject()
	if options.Method != "" {
		metadata.Set("method", options.Method)
	}
	metadata.Assign(s.clientMetadata(ctx))
	if err := s.audit(ctx, tx, active, "auth:session:create", nil, metadata); err != nil {
		return nil, err
	}
	if options.TrustedDeviceID == "" {
		if err := s.notifyNewSignIn(ctx, tx, active, tenant, session); err != nil {
			return nil, err
		}
	}
	return core.NewObject("token", token, "session", PublicSession(session)), nil
}

// sortByCreatedThenID orders records by createdAt, then id.
func sortByCreatedThenID(rows []*core.Object) {
	sort.SliceStable(rows, func(i, j int) bool {
		if d := numOr(rows[i], "createdAt", math.NaN()) - numOr(rows[j], "createdAt", math.NaN()); d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		return str(rows[i], "id") < str(rows[j], "id")
	})
}

// RecordSignInFailure counts an attempt that named a known, active person with a wrong password, factor, or
// recovery code, in its own transaction; it never fails (the credential error is what the caller reports). at is
// when the attempt was refused (0: now).
func (s *Service) RecordSignInFailure(ctx context.Context, identity *core.Object, reason SignInFailureReason, at int64) {
	if str(identity, "kind") != "user" || str(identity, "status") != "active" {
		return
	}
	if at == 0 {
		at = s.now()
	}
	_ = s.options.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		now := float64(at)
		client := s.CurrentClient(ctx)
		existing, err := tx.Get(ctx, "authSignIns", str(identity, "id"))
		if err != nil {
			return err
		}
		failed := 1.0
		if existing != nil && !nullish(existing, "failedAttempts") {
			failed = toNumber(existing.Get("failedAttempts")) + 1
		}
		ledger := core.NewObject("id", identity.Get("id"), "tenantId", identity.Get("tenantId"), "identityId", identity.Get("id"),
			"failedAttempts", failed, "lastFailedAt", now)
		if value := existing.Get("lastAt"); !core.IsUndefined(value) {
			ledger.Set("lastAt", value)
		}
		if value := existing.Get("lastClient"); truthy(value) {
			ledger.Set("lastClient", value)
		}
		if client != nil && (client.IP != "" || client.UserAgent != "" || client.Label != "") {
			ledger.Set("lastFailedClient", clientObject(client))
		}
		if existing != nil {
			_, err = tx.Put(ctx, "authSignIns", ledger)
		} else {
			_, err = tx.Insert(ctx, "authSignIns", ledger)
		}
		if err != nil {
			return err
		}
		if err := s.audit(ctx, tx, identity, "auth:signin:fail", nil, core.NewObject("reason", reason).Assign(s.clientMetadata(ctx))); err != nil {
			return err
		}
		// One alert per streak: exactly when the threshold is reached, and the streak ends with a sign-in.
		if s.failedAlertThreshold > 0 && failed == float64(s.failedAlertThreshold) && flag(identity, "email") &&
			flag(identity, "emailVerified") && s.options.SendEmail != nil {
			payload := core.NewObject("attempts", core.NumberString(failed), "time", isoString(now)).Assign(s.clientMetadata(ctx))
			return s.enqueue(ctx, tx, identity, "email", str(identity, "email"), "sign-in-failures", payload)
		}
		return nil
	})
}

// deferSignInFailure records a refused attempt (RecordSignInFailure) without delaying the refusal: awaiting the
// ledger and audit transaction would make a wrong password for a real account measurably slower than one for an
// unknown address. SettleBookkeeping waits for it.
func (s *Service) deferSignInFailure(ctx context.Context, identity *core.Object, reason SignInFailureReason) {
	at := s.now()
	detached := s.detached(ctx)
	s.bookkeeping.Add(1)
	go func() {
		defer s.bookkeeping.Done()
		defer func() { _ = recover() }()
		s.RecordSignInFailure(detached, identity, reason, at)
	}()
}

// SettleBookkeeping returns once the failed-attempt bookkeeping of refusals already answered has been written (and
// the store limiter's background sweep has finished). Tests that read the sign-in ledger right after a refusal call
// it first; a graceful shutdown can call it so those records are not lost.
func (s *Service) SettleBookkeeping() {
	s.bookkeeping.Wait()
	if limiter, ok := s.limits.Limiter.(*storeRateLimiter); ok {
		limiter.settle()
	}
}

// notifyNewSignIn emails the person about a session from a client that no live session or remembered device of
// theirs has used.
func (s *Service) notifyNewSignIn(ctx context.Context, tx core.IamStore, identity, tenant, session *core.Object) error {
	enabled := s.options.SignInNotifications
	if policy := child(tenant, "authPolicy"); !nullish(policy, "notifyNewSignIn") {
		enabled = truthy(policy.Get("notifyNewSignIn"))
	}
	if !enabled || !flag(identity, "email") || s.options.SendEmail == nil {
		return nil
	}
	fingerprint := func(client *core.Object) string {
		if client == nil || !(flag(client, "userAgent") || flag(client, "ip")) {
			return ""
		}
		part := func(key string) string {
			if nullish(client, key) {
				return ""
			}
			return jsString(client.Get(key))
		}
		return part("userAgent") + "|" + part("ip")
	}
	current := fingerprint(child(session, "client"))
	if current == "" {
		return nil
	}
	now := float64(s.now())
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identity.Get("id"), "tenantId", identity.Get("tenantId"), "kind", "user"), nil)
	if err != nil {
		return err
	}
	for _, other := range sessions {
		if str(other, "id") != str(session, "id") && numOr(other, "expiresAt", math.NaN()) > now && fingerprint(child(other, "client")) == current {
			return nil
		}
	}
	devices, err := tx.Find(ctx, "authDevices", core.NewObject("identityId", identity.Get("id"), "tenantId", identity.Get("tenantId")), nil)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if numOr(device, "expiresAt", math.NaN()) > now && fingerprint(child(device, "client")) == current {
			return nil
		}
	}
	method := str(session, "method")
	if method == "" {
		method = "unknown"
	}
	payload := core.NewObject("sessionId", session.Get("id"), "time", isoString(now), "method", method)
	client := child(session, "client")
	for _, key := range []string{"userAgent", "ip", "label"} {
		if value := client.Get(key); truthy(value) {
			payload.Set(key, value)
		}
	}
	return s.enqueue(ctx, tx, identity, "email", str(identity, "email"), "new-sign-in", payload)
}

// IssueImpersonationSession opens a session as target on behalf of actor ("view as"). The server authorizes and
// audits the request; here the tenant must allow impersonation, the actor must hold an ordinary session of their
// own, and the new session inherits the actor's MFA state, expires with the actor's session, and is marked.
func (s *Service) IssueImpersonationSession(ctx context.Context, tx core.IamStore, actor *Principal, target *core.Object, durationMs float64) (*core.Object, error) {
	if str(actor.Session, "kind") != "user" || flag(actor.Session, "impersonatorId") {
		return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Only a person acting through their own session can impersonate", 403)
	}
	active, err := s.user(ctx, tx, str(target, "id"), str(target, "tenantId"))
	if err != nil {
		return nil, err
	}
	tenantID := str(active, "tenantId")
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.AssertIPAllowed(tenant, s.clientIP(ctx)); err != nil {
		return nil, err
	}
	if err := s.AssertNetworkNotBlocked(ctx, tx, tenantID, s.clientIP(ctx)); err != nil {
		return nil, err
	}
	if !flag(child(tenant, "authPolicy"), "allowImpersonation") {
		return nil, core.NewIamError("FEATURE_DISABLED", "Impersonation is not enabled for this organization", 403)
	}
	required, err := s.MfaRequired(ctx, tx, active)
	if err != nil {
		return nil, err
	}
	if required && !flag(actor.Session, "mfa") {
		return nil, core.NewIamError("MFA_REQUIRED", "Complete multi-factor authentication before impersonating a member who requires it", 403)
	}
	now := float64(s.now())
	// Impersonation inherits the actor's MFA flag but never a first-hand factor time (no principal.mfaTime).
	token := mustCredentialToken("ses")
	session := core.NewObject(
		"id", NewID("ses"),
		"tenantId", tenantID,
		"identityId", active.Get("id"),
		"kind", "user",
		"tokenHash", HashToken(token),
		"uniqueKey", HashToken(token),
		"createdAt", now,
		"lastSeenAt", now,
		"expiresAt", jsMin(numOr(actor.Session, "expiresAt", math.NaN()), now+durationMs),
		"authenticatedAt", now,
		"mfa", actor.Session.Get("mfa"),
		"method", "impersonation",
		"impersonatorId", actor.Identity.Get("id"),
		"impersonatorSessionId", actor.Session.Get("id"),
	)
	if client := s.CurrentClient(ctx); client != nil {
		session.Set("client", clientObject(client))
	}
	if _, err := tx.Insert(ctx, "sessions", session); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, tx, active, "auth:session:create", session, nil); err != nil {
		return nil, err
	}
	return core.NewObject("token", token, "session", PublicSession(session)), nil
}

// EndSession removes a session together with any impersonation sessions an administrator opened through it.
func (s *Service) EndSession(ctx context.Context, tx core.IamStore, sessionID string) error {
	if err := tx.Delete(ctx, "sessions", sessionID); err != nil {
		return err
	}
	dependents, err := tx.Find(ctx, "sessions", core.NewObject("impersonatorSessionId", sessionID), nil)
	if err != nil {
		return err
	}
	for _, dependent := range dependents {
		if err := tx.Delete(ctx, "sessions", str(dependent, "id")); err != nil {
			return err
		}
	}
	return nil
}

// AssertImpersonationSource keeps an impersonation session alive only while the administrator's own session and
// identity do, while the member's tenant still allows impersonation, and while the member may still be
// impersonated; otherwise it is refused (and removed on sight). The administrator's tenant idle timeout applies too.
func (s *Service) AssertImpersonationSource(ctx context.Context, tx core.IamStore, session *core.Object) error {
	if !flag(session, "impersonatorId") {
		return nil
	}
	var source *core.Object
	var err error
	if sourceID := str(session, "impersonatorSessionId"); sourceID != "" {
		if source, err = tx.Get(ctx, "sessions", sourceID); err != nil {
			return err
		}
	}
	actor, err := tx.Get(ctx, "identities", str(session, "impersonatorId"))
	if err != nil {
		return err
	}
	member, err := tx.Get(ctx, "identities", str(session, "identityId"))
	if err != nil {
		return err
	}
	memberTenant, err := tx.Get(ctx, "tenants", str(session, "tenantId"))
	if err != nil {
		return err
	}
	var sourceTenant *core.Object
	if source != nil {
		if sourceTenant, err = tx.Get(ctx, "tenants", str(source, "tenantId")); err != nil {
			return err
		}
	}
	lastActive := math.Max(nullishOr(source, "lastSeenAt", 0), numOr(session, "lastSeenAt", math.NaN()))
	_, idle := s.SessionLimits(sourceTenant)
	now := float64(s.now())
	if source == nil || str(source, "kind") != "user" || !core.StrictEquals(source.Get("identityId"), session.Get("impersonatorId")) ||
		numOr(source, "expiresAt", math.NaN()) <= now || now-lastActive >= idle ||
		actor == nil || str(actor, "status") != "active" || s.identityExpired(actor) ||
		!flag(child(memberTenant, "authPolicy"), "allowImpersonation") ||
		member == nil || flag(member, "owner") || flag(member, "rootAdmin") {
		if err := tx.Delete(ctx, "sessions", str(session, "id")); err != nil {
			return err
		}
		return core.NewIamError("UNAUTHENTICATED", "Impersonation has ended", 401)
	}
	return nil
}

// passkeyFactor reports whether the person has a registered passkey that can serve as their second factor on this
// deployment.
func (s *Service) passkeyFactor(ctx context.Context, tx core.IamStore, identity *core.Object) (bool, error) {
	if s.options.Passkeys == nil {
		return false, nil
	}
	keys, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
	return len(keys) > 0, err
}

// CompleteAuthentication finishes a sign-in whose first factor (or federated assertion) the caller verified: a
// session ({ token, session }) or an MFA challenge ({ mfaRequired, challenge, enrollmentRequired, ... }). method is
// recorded on the session, carried through the MFA challenge, and checked against the tenant's allowed methods. A
// valid deviceToken from "remember this device" satisfies the MFA requirement.
func (s *Service) CompleteAuthentication(ctx context.Context, tx core.IamStore, identity *core.Object, method, deviceToken string) (*core.Object, error) {
	active, err := s.user(ctx, tx, str(identity, "id"), str(identity, "tenantId"))
	if err != nil {
		return nil, err
	}
	if method != "" {
		if err := s.methodAllowed(ctx, tx, str(active, "tenantId"), method); err != nil {
			return nil, err
		}
	}
	required, err := s.MfaRequired(ctx, tx, active)
	if err != nil {
		return nil, err
	}
	if !required {
		return s.IssueSession(ctx, tx, active, IssueSessionOptions{Method: method})
	}
	if deviceToken != "" {
		device, err := s.trustedDevice(ctx, tx, active, deviceToken)
		if err != nil {
			return nil, err
		}
		if device != nil {
			return s.IssueSession(ctx, tx, active, IssueSessionOptions{Mfa: true, Method: method, TrustedDeviceID: str(device, "id")})
		}
	}
	mfa, err := tx.Get(ctx, "authMfa", str(active, "id"))
	if err != nil {
		return nil, err
	}
	// Emailed one-time codes stand in for an authenticator only when nothing is enrolled and policy allows it.
	tenant, err := tx.Get(ctx, "tenants", str(active, "tenantId"))
	if err != nil {
		return nil, err
	}
	allowCodes := s.options.MfaEmailCodes
	if policy := child(tenant, "authPolicy"); !nullish(policy, "mfaEmailCodes") {
		allowCodes = truthy(policy.Get("mfaEmailCodes"))
	}
	enrolled := flag(mfa, "enabled")
	emailCodes := !enrolled && !flag(active, "rootAdmin") && flag(active, "email") && flag(active, "emailVerified") &&
		s.options.SendEmail != nil && allowCodes
	passkeys, err := s.passkeyFactor(ctx, tx, active)
	if err != nil {
		return nil, err
	}
	payload := core.NewObject()
	if method != "" {
		payload.Set("method", method)
	}
	if emailCodes {
		payload.Set("emailCodes", "1")
	}
	challenge, err := s.challenge(ctx, tx, active, "mfa-login", payload, 5*60_000, "", "")
	if err != nil {
		return nil, err
	}
	result := core.NewObject(
		"mfaRequired", true,
		"challenge", challenge,
		// A registered passkey is a second factor: the login challenge cannot enroll an authenticator over it.
		"enrollmentRequired", !enrolled && !passkeys,
		"authenticatorEnrolled", enrolled,
	)
	if emailCodes {
		result.Set("emailCodeAvailable", true)
	}
	if passkeys {
		result.Set("passkeyAvailable", true)
	}
	return result, nil
}

var bearerPattern = func(header string) bool {
	if len(header) < 8 || !strings.EqualFold(header[:7], "bearer ") {
		return false
	}
	for i := 7; i < len(header); i++ {
		c := header[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

const httpWhitespace = " \t\r\n"

// headerValue is Headers#get: repeated values joined with ", ", surrounding HTTP whitespace removed.
func headerValue(headers map[string][]string, name string) (string, bool) {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.Trim(strings.Join(values, ", "), httpWhitespace), true
		}
	}
	return "", false
}

// Authenticate resolves a bearer token or session cookie to its verified identity and session.
func (s *Service) Authenticate(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	token := input.Token
	hasToken := token != ""
	if !hasToken {
		if authorization, ok := headerValue(input.Headers, "authorization"); ok && authorization != "" {
			if !bearerPattern(authorization) {
				return nil, core.NewIamError("UNAUTHENTICATED", "Invalid credentials", 401)
			}
			token, hasToken = authorization[7:], true
		} else if cookie, ok := headerValue(input.Headers, "cookie"); ok {
			for _, part := range strings.Split(cookie, ";") {
				part = core.JSTrim(part)
				if strings.HasPrefix(part, s.cookieName+"=") {
					token, hasToken = part[len(s.cookieName)+1:], true
					break
				}
			}
		}
	}
	if !hasToken || !deviceTokenShape(token) {
		return nil, core.NewIamError("UNAUTHENTICATED", "Invalid or missing credentials", 401)
	}
	// A prefixed token with a bad shape or checksum is refused before any storage read (bearer and cookie alike).
	if strings.HasPrefix(token, "biam_") {
		if _, ok := ParseCredentialToken(token); !ok {
			return nil, core.NewIamError("UNAUTHENTICATED", "Invalid or missing credentials", 401)
		}
	}
	principal, err := core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*Principal, error) {
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("tokenHash", HashToken(token)), nil)
		if err != nil {
			return nil, err
		}
		var session *core.Object
		if len(sessions) > 0 {
			session = sessions[0]
		}
		return s.validateStoredSession(ctx, tx, session)
	})
	if err != nil {
		var mismatch *SessionNetworkMismatch
		if errors.As(err, &mismatch) {
			s.recordSessionMismatch(ctx, mismatch)
		}
		return nil, err
	}
	if err := s.AssertRequestHost(ctx, str(principal.Session, "tenantId")); err != nil {
		return nil, err
	}
	return principal, nil
}

// recordSessionMismatch notes in the person's trail that their bound session was presented from another network
// (auth:session:mismatch, with both addresses), in its own transaction; it never fails.
func (s *Service) recordSessionMismatch(ctx context.Context, mismatch *SessionNetworkMismatch) {
	_ = s.options.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		identity, err := tx.Get(ctx, "identities", str(mismatch.Session, "identityId"))
		if err != nil || identity == nil {
			return err
		}
		sessionIP := ""
		if client := child(mismatch.Session, "client"); !nullish(client, "ip") {
			sessionIP = jsString(client.Get("ip"))
		}
		metadata := core.NewObject("sessionId", mismatch.Session.Get("id"), "sessionIp", sessionIP).Assign(s.clientMetadata(ctx))
		return s.audit(ctx, tx, identity, "auth:session:mismatch", nil, metadata)
	})
}

func (s *Service) validateStoredSession(ctx context.Context, tx core.IamStore, session *core.Object) (*Principal, error) {
	now := float64(s.now())
	if session == nil || str(session, "kind") != "user" || numOr(session, "expiresAt", math.NaN()) <= now {
		return nil, core.NewIamError("UNAUTHENTICATED", "Invalid or expired credentials", 401)
	}
	tenantID := str(session, "tenantId")
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return nil, err
	}
	lifetime, idle := s.SessionLimits(tenant)
	// Both limits are judged against the tenant's current policy, so shortening the lifetime also ends sessions
	// issued under the longer one.
	if now-numOr(session, "lastSeenAt", math.NaN()) >= idle || now-numOr(session, "createdAt", math.NaN()) >= lifetime {
		return nil, core.NewIamError("UNAUTHENTICATED", "Invalid or expired credentials", 401)
	}
	identity, err := s.user(ctx, tx, str(session, "identityId"), tenantID)
	if err != nil {
		return nil, err
	}
	if s.requireEmailVerification && !flag(identity, "emailVerified") {
		return nil, core.NewIamError("EMAIL_UNVERIFIED", "Verify your email before signing in", 403)
	}
	required, err := s.MfaRequired(ctx, tx, identity)
	if err != nil {
		return nil, err
	}
	if required && !flag(session, "mfa") {
		return nil, core.NewIamError("MFA_REQUIRED", "Multi-factor authentication is required", 403)
	}
	if err := s.AssertImpersonationSource(ctx, tx, session); err != nil {
		return nil, err
	}
	// A session issued from a network the tenant no longer allows, or has since blocked, stops working at its next use.
	sessionIP := str(child(session, "client"), "ip")
	if err := s.AssertIPAllowed(tenant, sessionIP); err != nil {
		return nil, err
	}
	if err := s.AssertNetworkNotBlocked(ctx, tx, tenantID, sessionIP); err != nil {
		return nil, err
	}
	// The address presenting the cookie now is judged against network blocks too.
	presented := s.clientIP(ctx)
	if presented != "" && presented != sessionIP {
		if err := s.AssertNetworkNotBlocked(ctx, tx, tenantID, presented); err != nil {
			return nil, err
		}
	}
	// Opt-in per tenant: the session works only from the network it was issued from.
	if flag(child(tenant, "authPolicy"), "bindSessionsToIp") && sessionIP != "" && presented != "" && presented != sessionIP {
		return nil, &SessionNetworkMismatch{
			IamError:    core.NewIamError("SESSION_NETWORK_MISMATCH", "This session can only be used from the network it was signed in from", 401),
			Session:     session,
			PresentedIP: presented,
		}
	}
	// A touch at most every tenth of the idle window (at most once a minute) keeps idle expiry within that margin.
	if now-numOr(session, "lastSeenAt", math.NaN()) >= math.Min(60_000, math.Floor(idle/10)) {
		session.Set("lastSeenAt", now)
		if _, err := tx.Put(ctx, "sessions", session); err != nil {
			return nil, err
		}
	}
	return &Principal{Identity: identity, Session: session}, nil
}

// networkBlocks are the blocks that apply to a tenant, its own and the platform-wide ones, read through reader and
// cached briefly.
func (s *Service) networkBlocks(ctx context.Context, reader core.IamStore, tenantID string) ([]*core.Object, error) {
	now := s.now()
	s.blockMu.Lock()
	cached, ok := s.blockCache[tenantID]
	s.blockMu.Unlock()
	if ok && now >= cached.at && now-cached.at < blockCacheMs {
		return cached.blocks, nil
	}
	own, err := reader.Find(ctx, "authBlocks", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	platform, err := reader.Find(ctx, "authBlocks", core.NewObject("platform", true), nil)
	if err != nil {
		return nil, err
	}
	blocks := append([]*core.Object(nil), own...)
	for _, block := range platform {
		if str(block, "tenantId") != tenantID {
			blocks = append(blocks, block)
		}
	}
	s.blockMu.Lock()
	if len(s.blockCache) >= 10_000 {
		s.blockCache = map[string]blockCacheEntry{}
	}
	s.blockCache[tenantID] = blockCacheEntry{at: now, blocks: blocks}
	s.blockMu.Unlock()
	return blocks, nil
}

// InvalidateNetworkBlocks forgets the cached block lists so a change applies at once in this process (other
// processes follow within seconds).
func (s *Service) InvalidateNetworkBlocks() {
	s.blockMu.Lock()
	s.blockCache = map[string]blockCacheEntry{}
	s.blockMu.Unlock()
}

// BlockedNetwork is the live block covering an IP for a tenant, if any; unknown IPs are never blocked.
func (s *Service) BlockedNetwork(ctx context.Context, reader core.IamStore, tenantID, ip string) (*core.Object, error) {
	if ip == "" {
		return nil, nil
	}
	now := float64(s.now())
	blocks, err := s.networkBlocks(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	for _, block := range blocks {
		expiresAt, present := block.Lookup("expiresAt")
		live := !present || core.IsUndefined(expiresAt) || toNumber(expiresAt) > now
		network := str(block, "network")
		if live && core.IsIPRange(network) && core.IPMatches(ip, network) {
			return block, nil
		}
	}
	return nil, nil
}

// AssertNetworkNotBlocked refuses a recorded client IP that a live block of the tenant or the platform covers
// (IP_BLOCKED, 403).
func (s *Service) AssertNetworkNotBlocked(ctx context.Context, reader core.IamStore, tenantID, ip string) error {
	block, err := s.BlockedNetwork(ctx, reader, tenantID, ip)
	if err != nil {
		return err
	}
	if block != nil {
		return core.NewIamError("IP_BLOCKED", "Sign-in from this network is blocked", 403)
	}
	return nil
}

// AssertIPAllowed refuses a recorded client IP outside the tenant's allowedIpRanges; unknown IPs are not judged.
func (s *Service) AssertIPAllowed(tenant *core.Object, ip string) error {
	ranges, _ := child(tenant, "authPolicy").Get("allowedIpRanges").([]any)
	if len(ranges) == 0 || ip == "" {
		return nil
	}
	for _, network := range ranges {
		if text, ok := network.(string); ok && core.IPMatches(ip, text) {
			return nil
		}
	}
	return core.NewIamError("IP_NOT_ALLOWED", "Sign-in from this network is not permitted for this organization", 403)
}

// ValidateSessionID revalidates the IAM session attached to a stored OAuth grant (internal protocol integrations).
func (s *Service) ValidateSessionID(ctx context.Context, sessionID any) (*Principal, error) {
	id, err := Text(sessionID, "sessionId")
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*Principal, error) {
		session, err := tx.Get(ctx, "sessions", id)
		if err != nil {
			return nil, err
		}
		return s.validateStoredSession(ctx, tx, session)
	})
}

// RequireRecent requires a fresh authentication for sensitive operations; an impersonated session never qualifies,
// and neither does a temporary credential (a role session, a session token, any derived session, or an unknown kind).
func (s *Service) RequireRecent(principal *Principal) error {
	session := principal.Session
	if flag(session, "impersonatorId") {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "This operation is unavailable while impersonating a member", 403)
	}
	kind := str(session, "kind")
	if (kind != "user" && kind != "api-key") || !core.IsUndefined(session.Get("sourceSessionId")) {
		return core.NewIamError("RECENT_AUTH_REQUIRED", "Temporary credentials cannot perform this operation; use a signed-in session", 403)
	}
	now := float64(s.now())
	authenticatedAt := numOr(session, "authenticatedAt", math.NaN())
	if now-authenticatedAt > float64(s.recentLifetime) || authenticatedAt > now {
		return core.NewIamError("RECENT_AUTH_REQUIRED", "Reauthenticate to perform this operation", 403)
	}
	return nil
}

// RevokeIdentity revokes every session, pending challenge, and remembered device of an identity.
func (s *Service) RevokeIdentity(ctx context.Context, tx core.IamStore, identityID string) error {
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if err := s.EndSession(ctx, tx, str(session, "id")); err != nil {
			return err
		}
	}
	for _, collection := range []string{"authDevices", "authChallenges"} {
		rows, err := tx.Find(ctx, collection, core.NewObject("identityId", identityID), nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := tx.Delete(ctx, collection, str(row, "id")); err != nil {
				return err
			}
		}
	}
	return nil
}

// itoa formats an int.
func itoa(n int) string { return strconv.Itoa(n) }
