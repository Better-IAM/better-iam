package server

// Port of packages/server/src/index.ts betterIam(): the composition root. Configuration and catalog validation, the
// authentication service, the shared context, the service modules, the provisioning API, deployment helpers,
// federation callbacks, and the HTTP transports.

import (
	"context"
	"net/http"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// IamSessionTokens are IAM-signed session JWTs (sts.jwt): the issuer, the public keys downstream services verify with,
// and an online, revocation-aware check. Present only when sts.jwt is configured.
type IamSessionTokens struct {
	server *ServerContext
	signer *SessionTokenSigner
	// Issuer is the `iss` of every session JWT, also the audience IAM itself requires.
	Issuer string
}

// Jwks is the public signing and verification keys, as served at {basePath}/.well-known/jwks.json.
func (t *IamSessionTokens) Jwks() (*core.Object, error) { return t.signer.PublicJwks() }

// Verify verifies a session JWT for options.Audience ("": the issuer) and then requires its stored session to be
// live: the row, its identity and every revocation condition are re-validated. A revoked token fails with
// SessionTokenError reason `revoked`.
func (t *IamSessionTokens) Verify(ctx context.Context, token string, options SessionTokenVerifyOptions) (*core.Object, error) {
	server := t.server
	claims, err := t.signer.Verify(ctx, token, options.Audience)
	if err != nil {
		return nil, err
	}
	err = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		session, err := tx.Get(ctx, "sessions", jsString(claims.Get("sid")))
		if err != nil {
			return err
		}
		if session == nil || session.Get("format") != "jwt" || session.Get("kind") != claims.Get("kind") ||
			session.Get("identityId") != claims.Get("sub") || session.Get("tenantId") != claims.Get("tid") ||
			!SameHash(session.Get("tokenHash"), Hash(token)) || jsNumber(session.Get("expiresAt")) <= float64(server.Now()) {
			return revokedSessionToken()
		}
		identity, err := tx.Get(ctx, "identities", jsString(session.Get("identityId")))
		if err != nil {
			return err
		}
		if identity == nil || identity.Get("status") != "active" || server.IdentityExpired(identity) {
			return revokedSessionToken()
		}
		_, err = server.Principals.CurrentPrincipal(ctx, tx, &Principal{Identity: identity, Session: session})
		return err
	})
	if err != nil {
		return nil, revokedSessionToken()
	}
	return claims, nil
}

// revokedSessionToken is `new SessionTokenError('revoked')`.
func revokedSessionToken() error { return &SessionTokenError{Reason: "revoked"} }

// EventsRuntime is the in-process event surface (iam.events): subscribe to audit events and dispatch them.
type EventsRuntime struct {
	server *ServerContext
}

// Subscribe registers an in-process subscriber for audit events matching pattern (a string or a list); the returned
// function removes it.
func (e *EventsRuntime) Subscribe(pattern any, handler func(ctx context.Context, event *core.Object) error) (func(), error) {
	return e.server.Events.Subscribe(pattern, handler)
}

// Dispatch delivers pending audit events to subscribers and plugin hooks (a scheduler job).
func (e *EventsRuntime) Dispatch(ctx context.Context) (int, error) {
	return e.server.Events.Dispatch(ctx)
}

// HostsRuntime is organization sign-in addresses and regions, for framework integrations and edge routing.
type HostsRuntime struct {
	server *ServerContext
	// Region is this deployment's region, when `regions` is configured ("" otherwise).
	Region string
	// CustomHostnames is whether organizations may verify custom hostnames.
	CustomHostnames bool
}

// Resolve is the organization an address (host with optional port) belongs to; nil for the deployment's own and
// unknown hosts. NOT_FOUND for the address of an unknown or inactive organization, WRONG_REGION when another region
// serves it.
func (h *HostsRuntime) Resolve(ctx context.Context, host string) (*HostMatch, error) {
	return h.server.Hosts.Resolve(ctx, host, nil)
}

// SignInURL is an organization's canonical sign-in URL ("" when none).
func (h *HostsRuntime) SignInURL(ctx context.Context, tenantID string) (string, error) {
	return h.server.Hosts.SignInURL(ctx, tenantID, nil)
}

// Allowed is whether a TLS certificate may be issued for hostname (an on-demand TLS "ask" check).
func (h *HostsRuntime) Allowed(ctx context.Context, hostname string) (bool, error) {
	return h.server.Hosts.Allowed(ctx, hostname)
}

// Endpoint is where the HTTP handler is mounted, for framework integrations that call it server-side.
type Endpoint struct {
	Origin   string `json:"origin"`
	BasePath string `json:"basePath"`
	Secure   bool   `json:"secure"`
	// CookieSameSite and PersistentCookies are the handler's cookie settings.
	CookieSameSite    string `json:"cookieSameSite"`
	PersistentCookies bool   `json:"persistentCookies"`
}

// BetterIam is the composed server (the object betterIam returns).
type BetterIam struct {
	// API is the provisioning API, one field per group.
	API *API
	// Auth is the authentication service.
	Auth *auth.Service
	// HTTP serves the HTTP surface (Handle: fetch style; ServeHTTP: an http.Handler).
	HTTP *HTTPTransport
	// Context is the shared server context the modules use.
	Context *ServerContext
	Store   core.IamStore

	// The runtimes: server-side surfaces of the modules (see the TypeScript documentation of each).
	Features              *IamFeatures
	Inference             *InferenceRuntime
	A2a                   *A2aRuntime
	Billing               *IamBilling
	Kms                   *KmsRuntime
	Pki                   *PkiRuntime
	Protection            *ProtectionRuntime
	Vault                 *IamVault
	Quotas                *IamQuotas
	Privacy               *PrivacyRuntime
	Workflows             *WorkflowsRuntime
	Compliance            *ComplianceRuntime
	Applications          *ApplicationsRuntime
	Ssh                   *SshRuntime
	VerifiableCredentials *VcRuntime
	Ldap                  *LdapRuntime
	Signals               *IamSignals
	Licenses              *IamLicenses
	Guests                *IamGuests
	Clearances            *IamClearances
	Events                *EventsRuntime
	Hosts                 *HostsRuntime
	// Metrics is the Prometheus-style collector when observability.metrics is enabled (nil otherwise).
	Metrics *MetricsCollector
	// SessionTokens is session JWT keys and online verification; nil unless sts.jwt is configured.
	SessionTokens *IamSessionTokens
	// ProtocolHost is the federation callbacks' host (federation.ts protocolHost).
	ProtocolHost any
	Endpoint     Endpoint

	lifecycle           *Lifecycle
	retention           *Retention
	auditArchive        *AuditArchive
	certificationWorker *CertificationWorker
	selfCheck           func(ctx context.Context, options *core.Object) (*core.Object, error)
	planResources       func(ctx context.Context, request PlanResourcesRequest) (*core.Object, error)
}

// New composes the IAM server (betterIam): it validates the configuration and the catalog (INVALID_CONFIG and
// friends) and wires every module.
func New(options *BetterIamOptions) (*BetterIam, error) {
	if options == nil {
		return nil, invalidConfig("Options are required")
	}
	config, err := ResolveConfig(options)
	if err != nil {
		return nil, err
	}
	// Built-in modules that extend the catalog (inference: the `model` type and `inference:invoke`) come last.
	plugins := append([]*core.IamPlugin(nil), options.Plugins...)
	for _, extra := range []func(*BetterIamOptions) ([]*core.IamPlugin, error){InferencePlugins, SshPlugins, VcPlugins} {
		more, err := extra(options)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, more...)
	}
	catalog, err := NewCatalog(OptionsValue(options), plugins, config)
	if err != nil {
		return nil, err
	}
	if err := ValidatePlugins(plugins, catalog); err != nil {
		return nil, err
	}
	wall := options.WallClock
	if wall == nil {
		wall = func() int64 { return time.Now().UnixMilli() }
	}
	now := wall
	if options.Authentication != nil && options.Authentication.Now != nil {
		now = options.Authentication.Now
	}
	selfIssuer := urlOrigin(config.BaseURL) + config.BasePath
	// Session JWT keys are validated here, so a bad sts.jwt fails construction with INVALID_CONFIG.
	var jwtOptions *SessionTokenSigningOptions
	if options.Sts != nil {
		jwtOptions = options.Sts.JWT
	}
	sessionTokens, err := CreateSessionTokenSigner(jwtOptions, selfIssuer, now)
	if err != nil {
		return nil, err
	}
	var server *ServerContext
	// With organization addresses or regions, every email and SMS names its organization's sign-in URL.
	withSignInURL := func(send auth.Deliverer) auth.Deliverer {
		return func(ctx context.Context, message auth.DeliveryMessage) error {
			if !config.Hosts.Enabled && config.Regions == nil {
				return send(ctx, message)
			}
			if url, err := server.Hosts.SignInURL(ctx, message.TenantID, nil); err == nil && url != "" {
				message.SignInURL = url
			}
			return send(ctx, message)
		}
	}
	authOptions := auth.Options{}
	if options.Authentication != nil {
		authOptions = *options.Authentication
	}
	if authOptions.SendEmail != nil {
		authOptions.SendEmail = withSignInURL(authOptions.SendEmail)
	}
	if authOptions.SendSms != nil {
		authOptions.SendSms = withSignInURL(authOptions.SendSms)
	}
	authOptions.Store = options.Database
	authOptions.Secret = options.Secret
	authOptions.PreviousSecrets = options.PreviousSecrets
	authOptions.BaseURL = options.BaseURL
	authOptions.TrustedOrigins = options.TrustedOrigins
	authOptions.OnAudit = func(ctx context.Context, tx core.IamStore, event *core.Object) error {
		return server.Events.FanOut(ctx, tx, event)
	}
	authOptions.DeliverWebhook = func(ctx context.Context, message auth.DeliveryMessage) error {
		return server.Events.DeliverWebhookMessage(ctx, message)
	}
	authService, err := auth.New(authOptions)
	if err != nil {
		return nil, err
	}
	var metrics *MetricsCollector
	var metricsOptions *MetricsOptions
	if options.Observability != nil && options.Observability.Metrics.IsOn() {
		metricsOptions = &MetricsOptions{}
		if options.Observability.Metrics.Options != nil {
			metricsOptions = options.Observability.Metrics.Options
		}
		if metrics, err = CreateMetrics(metricsOptions); err != nil {
			return nil, err
		}
	}
	var onSpan func(IamSpan)
	if options.Observability != nil {
		onSpan = options.Observability.OnSpan
	}
	observerOptions := &ObservabilityOptions{OnSpan: onSpan}
	if metrics != nil {
		observerOptions.OnSpan = func(span IamSpan) {
			metrics.OnSpan(span)
			if onSpan != nil {
				onSpan(span)
			}
		}
	}
	observe := CreateObserver(observerOptions)
	server = CreateContext(ContextBase{
		Options: options, Config: config, Store: options.Database, Auth: authService, Plugins: plugins,
		Catalog: catalog, Now: now, Observe: observe,
	})
	server.SessionTokens = sessionTokens
	server.Hosts = CreateHosts(server)
	// The external-token verifier exists only while web-identity federation is enabled.
	if config.Sts.WebIdentity.Enabled {
		web := config.Sts.WebIdentity
		verifierOptions := &WebIdentityVerifierOptions{
			JwksCacheSeconds: float64(web.JwksCacheSeconds), FetchTimeoutMs: float64(web.FetchTimeoutMs),
			MaxJwksBytes: float64(web.MaxJwksBytes), AllowPrivateNetworks: web.AllowPrivateNetworks,
			AllowInsecureLocalhost: web.AllowInsecureLocalhost, Now: func() float64 { return float64(now()) },
			SelfIssuer: selfIssuer,
		}
		if sessionTokens != nil {
			verifierOptions.SelfIssuer = sessionTokens.Issuer
		}
		if options.Sts != nil && options.Sts.WebIdentity != nil && options.Sts.WebIdentity.FetchJSON != nil {
			fetch := options.Sts.WebIdentity.FetchJSON
			verifierOptions.FetchJSON = func(ctx context.Context, url *auth.FetchURL) (any, error) { return fetch(ctx, url.Href) }
		}
		server.WebIdentity = CreateWebIdentityVerifier(verifierOptions)
	}
	server.Events = CreateEvents(server)
	server.Decisions = CreateDecisions(server)
	server.Principals = CreatePrincipals(server)
	server.Operations = CreateOperations(server)
	server.Flows = CreateFlows(server)
	server.Usage = CreateUsageRecorder(server)
	// The billing ledger; validates the billing option, so a bad value fails construction with INVALID_CONFIG.
	billing := BillingServiceOf(server)
	if known, ok := asIamError(billing.BillingSettingsError()); ok && known.Code == "INVALID_CONFIG" {
		return nil, known
	}
	server.Billing = billing.Hooks
	// Wallet-facing issuer endpoints ({basePath}/vc/{tenantId}/... and their /.well-known metadata).
	if options.VerifiableCredentials.IsOn() {
		protocol, err := CreateVcProtocol(server)
		if err != nil {
			return nil, err
		}
		server.MountedProtocols = append(server.MountedProtocols, protocol)
	}
	// The Shared Signals push endpoint ({signals.pushPath}/{sourceId}, RFC 8935).
	server.MountedProtocols = append(server.MountedProtocols, CreateSignalsProtocol(server))

	// In-process calls that carry request headers record and judge the same client the HTTP handler would.
	authAPI := CreateAuthAPI(authService, observe, func(headers http.Header) *core.SessionClientInfo {
		return ClientFromHeaders(options, headers, config.BaseURL.Href)
	})
	// createDomainsApi refuses a domains.recordName that is not a single DNS label (INVALID_CONFIG).
	if err := CheckDomainOptions(options); err != nil {
		return nil, err
	}
	api := CreateAPI(server, authAPI)
	retention := CreateRetention(server)
	// Validates the auditArchive option, so a bad batchSize or leaseMs fails construction with INVALID_CONFIG.
	auditArchive := CreateAuditArchive(server)
	if err := auditArchive.ConfigError(); err != nil {
		return nil, err
	}
	federation := CreateFederation(server, api.Bindings)
	extras := HTTPExtras{Metrics: metrics}
	if metricsOptions != nil {
		if metricsOptions.BearerToken != nil {
			extras.MetricsToken = *metricsOptions.BearerToken
		}
		extras.MetricsGauges = metricsOptions.Gauges != nil && *metricsOptions.Gauges
	}
	transport, err := CreateHTTP(server, api, authAPI, extras)
	if err != nil {
		return nil, err
	}
	// Validates the a2a option, so invalid card keys fail construction with INVALID_CONFIG.
	a2a := CreateA2aRuntime(server)
	if err := a2a.ConfigError(); err != nil {
		return nil, err
	}
	iam := &BetterIam{
		API: api, Auth: authService, HTTP: transport, Context: server, Store: options.Database,
		Features: CreateFeatureEvaluator(server), Inference: CreateInferenceRuntime(server), A2a: a2a,
		Billing: CreateBillingRuntime(server), Kms: CreateKmsRuntime(server), Pki: CreatePkiRuntime(server),
		Protection: CreateProtectionRuntime(server), Vault: CreateVaultRuntime(server), Quotas: CreateQuotasRuntime(server),
		Privacy: CreatePrivacyRuntime(server), Workflows: CreateWorkflowsRuntime(server),
		Compliance: CreateComplianceRuntime(server), Applications: CreateApplicationsRuntime(server),
		Ssh: CreateSshRuntime(server), VerifiableCredentials: CreateVcRuntime(server), Ldap: CreateLdapRuntime(server),
		Signals: CreateSignalsRuntime(server), Licenses: CreateLicensesRuntime(server), Guests: CreateGuestsRuntime(server),
		Clearances: CreateClearancesRuntime(server), Events: &EventsRuntime{server: server},
		Hosts:   &HostsRuntime{server: server, CustomHostnames: config.Hosts.CustomHostnames},
		Metrics: metrics, ProtocolHost: federation.ProtocolHost,
		Endpoint: Endpoint{
			Origin: urlOrigin(config.BaseURL), BasePath: config.BasePath, Secure: config.BaseURL.Protocol == "https:",
			CookieSameSite: transport.sameSite, PersistentCookies: transport.persistent == nil || *transport.persistent,
		},
		lifecycle: CreateLifecycle(server), retention: retention, auditArchive: auditArchive,
		certificationWorker: CreateCertificationWorker(server), planResources: CreatePlanRuntime(server),
	}
	if config.Regions != nil {
		iam.Hosts.Region = config.Regions.Current
	}
	if sessionTokens != nil {
		iam.SessionTokens = &IamSessionTokens{server: server, signer: sessionTokens, Issuer: sessionTokens.Issuer}
	}
	iam.selfCheck = CreateSelfCheck(server, retention.CountDue, func(ctx context.Context, limit float64) (*SecretRotationResult, error) {
		return RotateSecrets(ctx, server, SecretRotationOptions{DryRun: true, Limit: &limit})
	})
	return iam, nil
}

// ServeHTTP serves the HTTP surface (the Node transport: nodeHandler).
func (iam *BetterIam) ServeHTTP(w http.ResponseWriter, r *http.Request) { iam.HTTP.ServeHTTP(w, r) }

// Handle is the fetch-style handler (handler): it answers a request with a Response.
func (iam *BetterIam) Handle(r *http.Request) *Response { return iam.HTTP.Handle(r) }

// UseProtocol mounts a protocol service under its base path for both transports.
func (iam *BetterIam) UseProtocol(protocol ProtocolService) { iam.HTTP.UseProtocol(protocol) }

// Authorize is one authorization decision for the request's credential (operations.authorize).
func (iam *BetterIam) Authorize(ctx context.Context, request AuthorizationRequest) (core.Decision, error) {
	return iam.Context.Operations.Authorize(ctx, request)
}

// AuthorizeMany evaluates up to 50 checks for one tenant (advisory UI state).
func (iam *BetterIam) AuthorizeMany(ctx context.Context, request BatchAuthorizationRequest) (*core.Object, error) {
	results, err := iam.Context.Operations.AuthorizeMany(ctx, request)
	if err != nil {
		return nil, err
	}
	return batchResults(results), nil
}

// ListAccessible is the registered resources of one managed type the caller may perform an action on.
func (iam *BetterIam) ListAccessible(ctx context.Context, request AccessibleResourcesRequest) (*core.Object, error) {
	result, err := iam.Context.Operations.ListAccessible(ctx, request)
	if err != nil {
		return nil, err
	}
	return result.Model(), nil
}

// Require refuses with ACCESS_DENIED unless the request is allowed (operations.requireAccess).
func (iam *BetterIam) Require(ctx context.Context, request AuthorizationRequest) error {
	return iam.Context.Operations.RequireAccess(ctx, request)
}

// Authenticate resolves a credential to its identity and session.
func (iam *BetterIam) Authenticate(ctx context.Context, credential core.CredentialInput) (*Principal, error) {
	return iam.Context.Principals.Authenticate(ctx, credential)
}

// Initialize runs the migrations (and the plugins'), and the one-time backfills.
func (iam *BetterIam) Initialize(ctx context.Context) error { return iam.lifecycle.Initialize(ctx) }

// Bootstrap creates the installation root and its first root administrator.
func (iam *BetterIam) Bootstrap(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.Bootstrap(ctx, input)
}

// RecoverRoot adds a root administrator to the installation root.
func (iam *BetterIam) RecoverRoot(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.RecoverRoot(ctx, input)
}

// PurgeDeleted is the retention worker (a scheduler job).
func (iam *BetterIam) PurgeDeleted(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.PurgeDeleted(ctx, input)
}

// PruneAudit deletes a tenant's oldest chained audit events past the retention window.
func (iam *BetterIam) PruneAudit(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.PruneAudit(ctx, input)
}

// ArchiveAudit copies new audit events, verified and in chain order, to auditArchive (a scheduler job).
func (iam *BetterIam) ArchiveAudit(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.auditArchive.ArchiveAudit(ctx, input)
}

// SweepExpired deletes expired sessions, protocol artifacts, and old delivery records in short batches.
func (iam *BetterIam) SweepExpired(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.retention.SweepExpired(ctx, input)
}

// SelfCheck reports configuration and storage problems: schema, durability, secrets, transports, and jobs.
func (iam *BetterIam) SelfCheck(ctx context.Context, options *core.Object) (*core.Object, error) {
	return iam.selfCheck(ctx, options)
}

// SendAccessDigest emails each organization's owners its access report (a scheduler job).
func (iam *BetterIam) SendAccessDigest(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.SendAccessDigest(ctx, input)
}

// SendExpiryReminders emails each person whose access ends soon a reminder (a scheduler job).
func (iam *BetterIam) SendExpiryReminders(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.SendExpiryReminders(ctx, input)
}

// ReconcilePackages assigns and removes rule-based access packages (a scheduler job).
func (iam *BetterIam) ReconcilePackages(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.lifecycle.ReconcilePackages(ctx, input)
}

// CloseOverdueCertifications closes and applies auto-closing certification campaigns past their due date.
func (iam *BetterIam) CloseOverdueCertifications(ctx context.Context, input *core.Object) (*core.Object, error) {
	return iam.certificationWorker.CloseOverdueCertifications(ctx, input)
}

// CloseOverdueTeamReviews completes open team membership reviews past their due date (a scheduler job).
func (iam *BetterIam) CloseOverdueTeamReviews(ctx context.Context, input *core.Object) (*core.Object, error) {
	return CloseOverdueTeamReviews(ctx, iam.Context, input)
}

// CheckInvariants evaluates every tenant's access invariants and audits breaks and restorations (a scheduler job).
func (iam *BetterIam) CheckInvariants(ctx context.Context, input *core.Object) (*core.Object, error) {
	return CheckInvariants(ctx, iam.Context, input)
}

// DetectThreats is identity threat detection (a scheduler job).
func (iam *BetterIam) DetectThreats(ctx context.Context, input *core.Object) (*core.Object, error) {
	return DetectThreats(ctx, iam.Context, input)
}

// FlushAccessUsage writes buffered access usage now (accessUsage option); call it before shutting down.
func (iam *BetterIam) FlushAccessUsage(ctx context.Context) (*core.Object, error) {
	written, err := iam.Context.Usage.Flush(ctx)
	if err != nil {
		return nil, err
	}
	return core.NewObject("written", float64(written)), nil
}

// PlanResources is data filtering: which resources of a type the caller may perform an action on, as a filter.
func (iam *BetterIam) PlanResources(ctx context.Context, request PlanResourcesRequest) (*core.Object, error) {
	return iam.planResources(ctx, request)
}

// DispatchAuditHooks delivers pending audit events to subscribers and plugin hooks (a scheduler job).
func (iam *BetterIam) DispatchAuditHooks(ctx context.Context) (int, error) {
	return iam.Context.Events.Dispatch(ctx)
}

// CallPlugin dispatches a plugin endpoint through the operation envelope.
func (iam *BetterIam) CallPlugin(ctx context.Context, credential core.CredentialInput, call PluginCall) (any, error) {
	return iam.Context.Operations.CallPlugin(ctx, credential, call)
}

// AssertionKey is the derived key downstream services use with VerifyAssertion; a deployment secret, never exposed
// over HTTP.
func (iam *BetterIam) AssertionKey() string { return AssertionKey(iam.Context.Options.Secret) }

// AssertionKeys is the current assertion key first, then those of previousSecrets.
func (iam *BetterIam) AssertionKeys() []string {
	keys := []string{AssertionKey(iam.Context.Options.Secret)}
	for _, secret := range iam.Context.Options.PreviousSecrets {
		keys = append(keys, AssertionKey(secret))
	}
	return keys
}

// RotateSecrets re-seals values encrypted with previousSecrets using secret (a deployment operation).
func (iam *BetterIam) RotateSecrets(ctx context.Context, options SecretRotationOptions) (*SecretRotationResult, error) {
	return RotateSecrets(ctx, iam.Context, options)
}

// Close stops the background work of the instance: the access usage writer's timer (the recorder's stop() in
// packages/server/src/usage.ts). It neither flushes buffered access usage (call FlushAccessUsage first to keep it)
// nor closes the store. That matches TypeScript, where the instance has no close at all and the database stays with
// whoever opened it (the CLI calls iam.store.close() itself): close the store with iam.Store.Close(ctx) after Close.
func (iam *BetterIam) Close() { iam.Context.Usage.Stop() }
