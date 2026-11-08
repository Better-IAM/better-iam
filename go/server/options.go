package server

// Port of packages/server/src/options.ts: every option type of BetterIamOptions (field for field; JavaScript callbacks
// are func fields with the same names) and resolveConfig, the validation that turns options into ServerConfig with
// the same INVALID_CONFIG (and, where TypeScript throws them, INVALID_INPUT) codes and messages, in the same order.
//
// Validation reads options as a model value (OptionsValue): the JSON-representable members spelled as in TypeScript,
// callbacks as Function markers. That is what lets the standalone JSON configuration (standalone_config.go) and
// in-process Go options be refused with identical errors, including for values a Go type could not hold (a string
// where a number belongs): the configuration reader keeps the JSON it read as the options' value.
//
// Option types of modules that are not ported yet (audit archiving, access usage, inference, A2A, billing, SSH,
// verifiable credentials, vault, domains) are declared here too, with the TypeScript module named; those modules
// validate them when they are ported.

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// WebhookEvent is the JSON body delivered to a webhook endpoint (webhookBody builds it as a *core.Object in this
// member order).
type WebhookEvent struct {
	ID              string                    `json:"id"`
	Type            string                    `json:"type"`
	TenantID        string                    `json:"tenantId"`
	ActorID         string                    `json:"actorId"`
	ResourceID      string                    `json:"resourceId"`
	Outcome         string                    `json:"outcome"`
	Timestamp       float64                   `json:"timestamp"`
	OriginalActorID string                    `json:"originalActorId,omitempty"`
	ImpersonatorID  string                    `json:"impersonatorId,omitempty"`
	RootOverride    bool                      `json:"rootOverride,omitempty"`
	Metadata        *core.Object              `json:"metadata,omitempty"`
	SessionContext  *core.AuditSessionContext `json:"sessionContext,omitempty"`
	Sequence        *float64                  `json:"sequence,omitempty"`
	Hash            string                    `json:"hash,omitempty"`
}

// WebhookDelivery is a signed delivery handed to EventOptions.DeliverWebhook when the default HTTP transport is
// replaced. Headers is an object of strings in the TypeScript order (content-type, user-agent, x-better-iam-event,
// -delivery, -webhook, -timestamp, -signature).
type WebhookDelivery struct {
	ID        string       `json:"id"`
	TenantID  string       `json:"tenantId"`
	WebhookID string       `json:"webhookId"`
	URL       string       `json:"url"`
	Event     string       `json:"event"`
	Body      string       `json:"body"`
	Headers   *core.Object `json:"headers"`
}

// HTTPHeader returns the delivery's headers as an http.Header.
func (d WebhookDelivery) HTTPHeader() http.Header {
	header := http.Header{}
	d.Headers.Entries(func(key string, value any) bool {
		header.Set(key, jsString(value))
		return true
	})
	return header
}

// EventOptions configure audit fan-out and webhooks.
type EventOptions struct {
	// OnEvent is called after commit for every audit event, from the dispatcher; at-least-once.
	OnEvent func(ctx context.Context, event *core.Object) error `json:"-"`
	// DeliverWebhook replaces the built-in HTTPS POST transport; signature headers are already computed.
	DeliverWebhook func(ctx context.Context, delivery WebhookDelivery) error `json:"-"`
	// WebhookTimeoutMs is the timeout of the built-in transport (default 10 seconds).
	WebhookTimeoutMs *float64 `json:"webhookTimeoutMs,omitempty"`
	// AllowPrivateNetworks lets webhook endpoints reach private and reserved addresses. Off by default.
	AllowPrivateNetworks *bool `json:"allowPrivateNetworks,omitempty"`
}

// AccessRequestOptions bound access requests.
type AccessRequestOptions struct {
	// LifetimeMs is how long a pending request stays open (default 7 days).
	LifetimeMs *float64 `json:"lifetimeMs,omitempty"`
	// MaxDurationSeconds is the longest temporary grant a request may ask for (default 90 days).
	MaxDurationSeconds *float64 `json:"maxDurationSeconds,omitempty"`
}

// HttpOptions configure the HTTP handler.
type HttpOptions struct {
	// ClientInfo derives the client details recorded on sessions issued by a request (default: User-Agent only).
	ClientInfo func(request *http.Request) *core.SessionClientInfo `json:"-"`
	// CookieSameSite is "lax" (default) or "strict".
	CookieSameSite *string `json:"cookieSameSite,omitempty"`
	// PersistentCookies: whether session cookies outlive the browser by default (default true).
	PersistentCookies *bool `json:"persistentCookies,omitempty"`
}

// ProtocolMount is a protocol handler (OAuth/OIDC, SAML, SCIM, ...) mounted in front of the IAM routes. Handle
// answers the request and returns true, or returns false to pass it on.
type ProtocolMount struct {
	Handle func(w http.ResponseWriter, r *http.Request) bool
	// Node marks a Node-style mount (ProtocolService.NodeHandler): it runs before the body is read, and its answers
	// never set the session cookie.
	Node bool
}

// ResourceTarget is the resource of an authorization request.
type ResourceTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AuthorizationRequest is one authorization question.
type AuthorizationRequest struct {
	Credential core.CredentialInput `json:"-"`
	TenantID   string               `json:"tenantId"`
	Action     string               `json:"action"`
	Resource   ResourceTarget       `json:"resource"`
}

// AuthorizationCheck is one check of a batch.
type AuthorizationCheck struct {
	Action   string         `json:"action"`
	Resource ResourceTarget `json:"resource"`
}

// BatchAuthorizationRequest is up to 50 checks for one tenant.
type BatchAuthorizationRequest struct {
	Credential core.CredentialInput `json:"-"`
	TenantID   string               `json:"tenantId"`
	Checks     []AuthorizationCheck `json:"checks"`
	// ChecksValue is the checks as the request gave them (a model value), validated by EvaluateMany as TypeScript
	// validates `request.checks`; when it is nil, Checks is used.
	ChecksValue any `json:"-"`
}

// AccessibleResourcesRequest is the reverse query: which registered resources of a managed type may the caller act on.
type AccessibleResourcesRequest struct {
	Credential core.CredentialInput `json:"-"`
	TenantID   string               `json:"tenantId"`
	Action     string               `json:"action"`
	Type       string               `json:"type"`
	Limit      *float64             `json:"limit,omitempty"`
	Offset     *float64             `json:"offset,omitempty"`
	// LimitValue and OffsetValue are limit and offset as the request gave them (model values, validated by
	// QueryAccessible); when nil, Limit and Offset are used.
	LimitValue  any `json:"-"`
	OffsetValue any `json:"-"`
}

// ResolvedResource is a resource reference with its trusted attributes.
type ResolvedResource struct {
	TenantID   string       `json:"tenantId"`
	Type       string       `json:"type"`
	ID         string       `json:"id"`
	Attributes *core.Object `json:"attributes,omitempty"`
	// HasClassification says Classification is set: a label (*core.Object), or nil for "looked up and unlabeled"
	// (TypeScript null). Without it the resource carries no classification member (undefined).
	HasClassification bool `json:"-"`
	Classification    any  `json:"-"`
}

// SessionTokenSigningOptions are the signing keys of session JWTs (JWKs as JSON objects, RFC 7517).
type SessionTokenSigningOptions struct {
	SigningKeys        []*core.Object `json:"signingKeys"`
	ActiveKeyID        *string        `json:"activeKeyId,omitempty"`
	VerificationKeys   []*core.Object `json:"verificationKeys,omitzero"`
	Issuer             *string        `json:"issuer,omitempty"`
	Audiences          []string       `json:"audiences,omitzero"`
	MaxLifetimeSeconds *float64       `json:"maxLifetimeSeconds,omitempty"`
}

// StsWebIdentityOptions configure AssumeRoleWithWebIdentity.
type StsWebIdentityOptions struct {
	Enabled                *bool    `json:"enabled,omitempty"`
	AllowedIssuers         []string `json:"allowedIssuers,omitzero"`
	JwksCacheSeconds       *float64 `json:"jwksCacheSeconds,omitempty"`
	FetchTimeoutMs         *float64 `json:"fetchTimeoutMs,omitempty"`
	MaxJwksBytes           *float64 `json:"maxJwksBytes,omitempty"`
	MaxExchangesPerWindow  *float64 `json:"maxExchangesPerWindow,omitempty"`
	MaxSessionsPerTrust    *float64 `json:"maxSessionsPerTrust,omitempty"`
	AllowPrivateNetworks   *bool    `json:"allowPrivateNetworks,omitempty"`
	AllowInsecureLocalhost *bool    `json:"allowInsecureLocalhost,omitempty"`
	// FetchJSON replaces the built-in guarded fetch of discovery documents and JWKS.
	FetchJSON func(ctx context.Context, url string) (any, error) `json:"-"`
}

// StsOptions configure temporary credentials.
type StsOptions struct {
	MaxRoleSessionSeconds       *float64                    `json:"maxRoleSessionSeconds,omitempty"`
	MaxSessionTokenSeconds      *float64                    `json:"maxSessionTokenSeconds,omitempty"`
	MaxSessionTokensPerIdentity *float64                    `json:"maxSessionTokensPerIdentity,omitempty"`
	JWT                         *SessionTokenSigningOptions `json:"jwt,omitempty"`
	WebIdentity                 *StsWebIdentityOptions      `json:"webIdentity,omitempty"`
}

// ResolvedWebIdentityConfig is the validated sts.webIdentity.
type ResolvedWebIdentityConfig struct {
	Enabled bool `json:"enabled"`
	// AllowedIssuers is nil when unset.
	AllowedIssuers         []string `json:"allowedIssuers,omitempty"`
	JwksCacheSeconds       int64    `json:"jwksCacheSeconds"`
	FetchTimeoutMs         int64    `json:"fetchTimeoutMs"`
	MaxJwksBytes           int64    `json:"maxJwksBytes"`
	MaxExchangesPerWindow  int64    `json:"maxExchangesPerWindow"`
	MaxSessionsPerTrust    int64    `json:"maxSessionsPerTrust"`
	AllowPrivateNetworks   bool     `json:"allowPrivateNetworks"`
	AllowInsecureLocalhost bool     `json:"allowInsecureLocalhost"`
}

// ResolvedStsConfig is the validated sts option (jwt is validated by the session token signer).
type ResolvedStsConfig struct {
	MaxRoleSessionSeconds       int64                     `json:"maxRoleSessionSeconds"`
	MaxSessionTokenSeconds      int64                     `json:"maxSessionTokenSeconds"`
	MaxSessionTokensPerIdentity int64                     `json:"maxSessionTokensPerIdentity"`
	WebIdentity                 ResolvedWebIdentityConfig `json:"webIdentity"`
}

// ClearanceOptions enable security clearances; their presence enables the module.
type ClearanceOptions struct {
	// AppliesToRoot: whether root administrators are bound by classification labels too (default true).
	AppliesToRoot *bool `json:"appliesToRoot,omitempty"`
}

// ResolvedClearanceConfig is the validated clearances option.
type ResolvedClearanceConfig struct {
	AppliesToRoot bool `json:"appliesToRoot"`
}

// SignalsOptions configure the Shared Signals receiver.
type SignalsOptions struct {
	AllowPrivateNetworks   *bool   `json:"allowPrivateNetworks,omitempty"`
	AllowInsecureLocalhost *bool   `json:"allowInsecureLocalhost,omitempty"`
	PushPath               *string `json:"pushPath,omitempty"`
}

// ResolvedSignalsConfig is the validated signals option.
type ResolvedSignalsConfig struct {
	AllowPrivateNetworks   bool   `json:"allowPrivateNetworks"`
	AllowInsecureLocalhost bool   `json:"allowInsecureLocalhost"`
	PushPath               string `json:"pushPath"`
}

// OnboardingOptions choose how tenant owners are onboarded.
type OnboardingOptions struct {
	// Mode is "invitation" (default) or "linked".
	Mode                 *string  `json:"mode,omitempty"`
	InvitationLifetimeMs *float64 `json:"invitationLifetimeMs,omitempty"`
}

// TenantDefaults are plan limits and an authentication policy applied to every tenant created through
// tenants.create. Each is validated as tenantLimits / tenantAuthPolicy validate their input: a *core.Object, a
// *core.TenantLimits / *core.TenantAuthPolicy, or any value encoding/json turns into an object.
type TenantDefaults struct {
	Limits     any `json:"limits,omitempty"`
	AuthPolicy any `json:"authPolicy,omitempty"`
}

// Toggle is a `boolean | Options` option: Enabled with default settings, or Options.
type Toggle[T any] struct {
	Enabled bool
	Options *T
}

// On enables a module with its defaults.
func On[T any]() *Toggle[T] { return &Toggle[T]{Enabled: true} }

// With enables a module with options.
func With[T any](options T) *Toggle[T] { return &Toggle[T]{Enabled: true, Options: &options} }

// IsOn reports whether the toggle enables the module (true, or an options object).
func (t *Toggle[T]) IsOn() bool { return t != nil && (t.Enabled || t.Options != nil) }

// MarshalJSON writes the options object, or the boolean.
func (t Toggle[T]) MarshalJSON() ([]byte, error) {
	if t.Options != nil {
		return json.Marshal(t.Options)
	}
	return json.Marshal(t.Enabled)
}

// AuditArchiveBatch is one verified batch of a tenant's audit chain (audit-archive.ts).
type AuditArchiveBatch struct {
	TenantID     string         `json:"tenantId"`
	FromSequence float64        `json:"fromSequence"`
	ToSequence   float64        `json:"toSequence"`
	PreviousHash string         `json:"previousHash"`
	LastHash     string         `json:"lastHash"`
	Events       []*core.Object `json:"events"`
}

// AuditArchiveOptions configure continuous audit archiving (audit-archive.ts).
type AuditArchiveOptions struct {
	Write     func(ctx context.Context, batch AuditArchiveBatch) error `json:"-"`
	BatchSize *float64                                                 `json:"batchSize,omitempty"`
	LeaseMs   *float64                                                 `json:"leaseMs,omitempty"`
}

// AccessUsageOptions configure access usage tracking (usage.ts).
type AccessUsageOptions struct {
	FlushIntervalMs *float64 `json:"flushIntervalMs,omitempty"`
	MaxBuffered     *float64 `json:"maxBuffered,omitempty"`
}

// InferenceOptions configure inference access control (inference.ts).
type InferenceOptions struct {
	AllowCustomBaseUrls    *bool    `json:"allowCustomBaseUrls,omitempty"`
	UsageRetentionDays     *float64 `json:"usageRetentionDays,omitempty"`
	AllowInsecureLocalhost *bool    `json:"allowInsecureLocalhost,omitempty"`
	AllowPrivateNetworks   *bool    `json:"allowPrivateNetworks,omitempty"`
}

// A2aOptions configure IAM-attested A2A agent cards (a2a.ts). JWKs are JSON objects.
type A2aOptions struct {
	SigningKeys         []*core.Object `json:"signingKeys"`
	ActiveKeyID         *string        `json:"activeKeyId,omitempty"`
	VerificationKeys    []*core.Object `json:"verificationKeys,omitzero"`
	JwksURL             *string        `json:"jwksUrl,omitempty"`
	CardLifetimeSeconds *float64       `json:"cardLifetimeSeconds,omitempty"`
	Issuer              *string        `json:"issuer,omitempty"`
}

// InvoiceIssuer is who issues invoices (billing.ts).
type InvoiceIssuer struct {
	Name                string  `json:"name"`
	Address             *string `json:"address,omitempty"`
	TaxID               *string `json:"taxId,omitempty"`
	Email               *string `json:"email,omitempty"`
	URL                 *string `json:"url,omitempty"`
	PaymentInstructions *string `json:"paymentInstructions,omitempty"`
}

// BillingOptions tune billing and spend tracking (billing.ts).
type BillingOptions struct {
	Currency            *string        `json:"currency,omitempty"`
	TimeZone            *string        `json:"timeZone,omitempty"`
	UsageRetentionDays  *float64       `json:"usageRetentionDays,omitempty"`
	TeamAttribution     *string        `json:"teamAttribution,omitempty"`
	PaymentTermsDays    *float64       `json:"paymentTermsDays,omitempty"`
	StatementPrefix     *string        `json:"statementPrefix,omitempty"`
	Issuer              *InvoiceIssuer `json:"issuer,omitempty"`
	PaymentReminderDays []float64      `json:"paymentReminderDays,omitzero"`
	AutoFinalize        *bool          `json:"autoFinalize,omitempty"`
}

// SshOptions configure the SSH certificate authority (ssh.ts).
type SshOptions struct {
	MaxUserCertificateMs   *float64 `json:"maxUserCertificateMs,omitempty"`
	HostCertificateMs      *float64 `json:"hostCertificateMs,omitempty"`
	ClockSkewMs            *float64 `json:"clockSkewMs,omitempty"`
	MaxHostsPerCertificate *float64 `json:"maxHostsPerCertificate,omitempty"`
	RecordRetentionDays    *float64 `json:"recordRetentionDays,omitempty"`
	JoinTokenMs            *float64 `json:"joinTokenMs,omitempty"`
	IssuanceLimit          *float64 `json:"issuanceLimit,omitempty"`
}

// VerifiableCredentialOptions configure SD-JWT VC issuance (vc.ts).
type VerifiableCredentialOptions struct {
	MaxLifetimeMs        *float64 `json:"maxLifetimeMs,omitempty"`
	StatusListSize       *float64 `json:"statusListSize,omitempty"`
	OfferLifetimeMs      *float64 `json:"offerLifetimeMs,omitempty"`
	StatusListLifetimeMs *float64 `json:"statusListLifetimeMs,omitempty"`
	StatusListTtlSeconds *float64 `json:"statusListTtlSeconds,omitempty"`
	RecordRetentionDays  *float64 `json:"recordRetentionDays,omitempty"`
}

// RotatorInput is what a vault rotator receives (vault.ts).
type RotatorInput struct {
	TenantID       string            `json:"tenantId"`
	Name           string            `json:"name"`
	Version        float64           `json:"version"`
	Value          string            `json:"value"`
	Fields         *core.Object      `json:"fields,omitempty"`
	Previous       *string           `json:"previous,omitempty"`
	PreviousFields *core.Object      `json:"previousFields,omitempty"`
	Tags           map[string]string `json:"tags"`
}

// VaultRotator applies a new value to the system a secret unlocks (vault.ts).
type VaultRotator struct {
	Rotate func(ctx context.Context, input RotatorInput) error
}

// EngineHolder is who a dynamic secret lease is issued to (vault.ts).
type EngineHolder struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// EngineIssueInput is what a dynamic secret engine's Issue receives (vault.ts).
type EngineIssueInput struct {
	TenantID string       `json:"tenantId"`
	Name     string       `json:"name"`
	LeaseID  string       `json:"leaseId"`
	Config   any          `json:"config"`
	TtlMs    float64      `json:"ttlMs"`
	Holder   EngineHolder `json:"holder"`
}

// EngineIssued is a minted credential (vault.ts).
type EngineIssued struct {
	Value  *string      `json:"value,omitempty"`
	Fields *core.Object `json:"fields,omitempty"`
	Handle *string      `json:"handle,omitempty"`
}

// EngineLeaseInput is what Revoke and Renew receive (vault.ts); Renew also gets TtlMs.
type EngineLeaseInput struct {
	TenantID string   `json:"tenantId"`
	Name     string   `json:"name"`
	LeaseID  string   `json:"leaseId"`
	Config   any      `json:"config"`
	Handle   *string  `json:"handle,omitempty"`
	TtlMs    *float64 `json:"ttlMs,omitempty"`
}

// VaultEngine mints short-lived credentials per lease and takes them back (vault.ts). Revoke and Renew are optional.
type VaultEngine struct {
	Issue  func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error)
	Revoke func(ctx context.Context, input EngineLeaseInput) error
	Renew  func(ctx context.Context, input EngineLeaseInput) error
}

// VaultOptions configure the secrets vault (vault.ts).
type VaultOptions struct {
	Rotators            map[string]VaultRotator `json:"-"`
	Engines             map[string]VaultEngine  `json:"-"`
	MaxValueBytes       *float64                `json:"maxValueBytes,omitempty"`
	MaxSecretsPerTenant *float64                `json:"maxSecretsPerTenant,omitempty"`
	AccessRetentionDays *float64                `json:"accessRetentionDays,omitempty"`
	CallTimeoutMs       *float64                `json:"callTimeoutMs,omitempty"`
}

// DomainOptions configure verified email domains (api/domains.ts).
type DomainOptions struct {
	// ResolveTxt looks up TXT records (default: the system resolver).
	ResolveTxt func(ctx context.Context, hostname string) ([][]string, error) `json:"-"`
	// RecordName is the label under the domain that holds the TXT record (default `_better-iam-challenge`).
	RecordName *string `json:"recordName,omitempty"`
	// BlockedDomains no tenant may claim (default: widely used consumer mailbox providers).
	BlockedDomains []string `json:"blockedDomains,omitzero"`
}

// BetterIamOptions are the deployment options, field for field as in TypeScript.
type BetterIamOptions struct {
	Database core.IamStore `json:"-"`
	Secret   string        `json:"secret"`
	// PreviousSecrets are deployment secrets being rotated out (at most five).
	PreviousSecrets []string `json:"previousSecrets,omitzero"`
	BaseURL         string   `json:"baseURL"`
	BasePath        *string  `json:"basePath,omitempty"`
	TrustedOrigins  []string `json:"trustedOrigins,omitzero"`
	// Authentication are the auth service options; Store, Secret, PreviousSecrets, BaseURL and TrustedOrigins are
	// supplied by the server and ignored here.
	Authentication *auth.Options           `json:"-"`
	Hierarchy      *core.HierarchyConfig   `json:"-"`
	Permissions    *core.PermissionsConfig `json:"-"`
	Onboarding     *OnboardingOptions      `json:"onboarding,omitempty"`
	Plugins        []*core.IamPlugin       `json:"-"`
	Events         *EventOptions           `json:"events,omitempty"`
	// AuditArchive enables continuous audit archiving (iam.archiveAudit()).
	AuditArchive   *AuditArchiveOptions  `json:"auditArchive,omitempty"`
	AccessRequests *AccessRequestOptions `json:"accessRequests,omitempty"`
	// Observability reports the timing and outcome of every operation, authorization query, authentication call and
	// HTTP request.
	Observability         *ObservabilityOptions                `json:"observability,omitempty"`
	AccessUsage           *Toggle[AccessUsageOptions]          `json:"accessUsage,omitempty"`
	Inference             *Toggle[InferenceOptions]            `json:"inference,omitempty"`
	A2a                   *A2aOptions                          `json:"a2a,omitempty"`
	Billing               *BillingOptions                      `json:"billing,omitempty"`
	Ssh                   *Toggle[SshOptions]                  `json:"ssh,omitempty"`
	VerifiableCredentials *Toggle[VerifiableCredentialOptions] `json:"verifiableCredentials,omitempty"`
	Clearances            *ClearanceOptions                    `json:"clearances,omitempty"`
	Vault                 *VaultOptions                        `json:"vault,omitempty"`
	HTTP                  *HttpOptions                         `json:"http,omitempty"`
	TenantDefaults        *TenantDefaults                      `json:"tenantDefaults,omitempty"`
	Domains               *DomainOptions                       `json:"domains,omitempty"`
	Hosts                 *HostOptions                         `json:"hosts,omitempty"`
	Regions               *RegionOptions                       `json:"regions,omitempty"`
	// ResolveResource is required for product resource types; it resolves ownership and attributes from trusted
	// storage (and, with clearances, may return a classification label that can only raise the IAM-held one).
	ResolveResource func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) `json:"-"`
	ResolveContext  func(ctx context.Context, principal *Principal) (*core.Object, error)            `json:"-"`
	Protocols       []ProtocolMount                                                                  `json:"-"`
	Sts             *StsOptions                                                                      `json:"sts,omitempty"`
	Signals         *SignalsOptions                                                                  `json:"signals,omitempty"`
	// WallClock is Go-only: it stands for Date.now(), the wall clock the TypeScript server reads directly (tenant
	// createdAt, audit timestamps, ...); the conformance server controls it. Default time.Now.
	WallClock func() int64 `json:"-"`

	// value is the configuration a standalone JSON file described (standalone_config.go): validation reads it
	// instead of the typed fields, so a JSON value no Go type can hold is refused with the TypeScript error.
	value *core.Object
	// mismatches are JSON members the reader could not hold in the typed fields; refused after validation.
	mismatches []string
}

// ServerConfig is the validated, defaulted configuration derived once from the options.
type ServerConfig struct {
	BaseURL  *auth.FetchURL
	BasePath string
	// TrustedOrigins holds the base URL's origin, then the configured origins, without duplicates.
	TrustedOrigins []string
	trustedOrigins map[string]bool
	// Hierarchy is the tenant hierarchy (types in declaration order).
	Hierarchy                       core.HierarchyConfig
	MaxDepth                        int
	TenantDefined                   bool
	StrictResourceTypes             bool
	LinkedOnboarding                bool
	InvitationLifetimeMs            float64
	AccessRequestLifetimeMs         int64
	AccessRequestMaxDurationSeconds int64
	WebhookTimeoutMs                int64
	// TenantDefaults holds the validated limits and authPolicy (nil when unset).
	TenantDefaults ResolvedTenantDefaults
	Sts            ResolvedStsConfig
	Hosts          *ResolvedHostConfig
	// Regions is nil for single-region deployments.
	Regions *ResolvedRegionConfig
	Signals ResolvedSignalsConfig
	// Clearances is nil when the module is off.
	Clearances *ResolvedClearanceConfig
}

// TrustedOrigin reports whether an origin is trusted.
func (c *ServerConfig) TrustedOrigin(origin string) bool { return c.trustedOrigins[origin] }

// BaseOrigin is baseURL.origin.
func (c *ServerConfig) BaseOrigin() string { return urlOrigin(c.BaseURL) }

// ResolvedTenantDefaults are the validated tenantDefaults.
type ResolvedTenantDefaults struct {
	Limits     *core.Object
	AuthPolicy *core.Object
}

// defaultHierarchy is root > organization > project, at most eight levels deep.
func defaultHierarchy() *core.Object {
	return core.NewObject(
		"types", core.NewObject(
			"root", core.NewObject("allowedChildren", []any{"organization"}),
			"organization", core.NewObject("allowedChildren", []any{"project"}),
			"project", core.NewObject("allowedChildren", []any{}),
		),
		"maxDepth", 8.0,
	)
}

var basePathPattern = regexp.MustCompile(`^/[\w/-]+$`)

// ResolveConfig validates the options and derives the server configuration (resolveConfig).
func ResolveConfig(options *BetterIamOptions) (*ServerConfig, error) {
	if options == nil || options.Database == nil {
		return nil, invalidConfig("database is required")
	}
	value := OptionsValue(options)
	var locate func(ctx context.Context, alias string) (*string, error)
	if options.Regions != nil {
		locate = options.Regions.Locate
	}
	config, err := resolveConfigValue(value, locate)
	if err != nil {
		return nil, err
	}
	if len(options.mismatches) > 0 {
		return nil, invalidConfig("Invalid better-iam.json: " + options.mismatches[0])
	}
	return config, nil
}

// resolveConfigValue is resolveConfig over the options' model value.
func resolveConfigValue(options *core.Object, locate func(ctx context.Context, alias string) (*string, error)) (*ServerConfig, error) {
	baseURL, err := auth.ParseFetchURL(jsString(options.Get("baseURL")))
	if err != nil {
		return nil, invalidConfig("baseURL must be an absolute URL")
	}
	if baseURL.Protocol != "https:" && !containsString([]string{"localhost", "127.0.0.1", "[::1]"}, baseURL.Hostname) {
		return nil, invalidConfig("HTTPS is required outside localhost")
	}
	rawBasePath := coalesce(options.Get("basePath"), "/api/iam")
	if !basePathPattern.MatchString(jsString(rawBasePath)) {
		return nil, invalidConfig("Invalid basePath")
	}
	basePath, isString := rawBasePath.(string)
	if !isString {
		return nil, &core.TypeError{Message: "basePath.endsWith is not a function"}
	}
	if strings.HasSuffix(basePath, "/") {
		return nil, invalidConfig("Invalid basePath")
	}
	hierarchy := coalesce(options.Get("hierarchy"), defaultHierarchy())
	rawMaxDepth := coalesce(member(hierarchy, "maxDepth"), 8.0)
	maxDepth, err := Integer(rawMaxDepth, "maxDepth", 1, 100)
	if err != nil {
		return nil, err
	}
	types := member(hierarchy, "types")
	if nullish(types) {
		return nil, &core.TypeError{Message: "Cannot read properties of " + jsString(types) + " (reading 'root')"}
	}
	if !truthy(member(types, "root")) {
		return nil, invalidConfig("Hierarchy must define root")
	}
	resolvedHierarchy := core.HierarchyConfig{}
	for _, entry := range objectEntries(types) {
		if _, err := Text(entry.key, "tenant type"); err != nil {
			return nil, err
		}
		children, ok := member(entry.value, "allowedChildren").([]any)
		if !ok {
			return nil, &core.TypeError{Message: "type.allowedChildren is not iterable"}
		}
		named := core.NamedTenantType{Name: entry.key, Type: core.TenantType{AllowedChildren: []string{}}}
		for _, child := range children {
			name := jsString(child)
			if !truthy(member(types, name)) || name == "root" {
				return nil, invalidConfig("Invalid allowed child type")
			}
			named.Type.AllowedChildren = append(named.Type.AllowedChildren, name)
		}
		resolvedHierarchy.Types = append(resolvedHierarchy.Types, named)
	}
	depth := int(maxDepth)
	resolvedHierarchy.MaxDepth = &depth

	config := &ServerConfig{BaseURL: baseURL, BasePath: basePath, Hierarchy: resolvedHierarchy, MaxDepth: depth}
	defaults := options.Get("tenantDefaults")
	if limits := member(defaults, "limits"); !isUndefined(limits) {
		validated, err := TenantLimits(limits)
		if err != nil {
			return nil, invalidConfig("tenantDefaults: " + errorMessage(err))
		}
		config.TenantDefaults.Limits = validated
	}
	if policy := member(defaults, "authPolicy"); !isUndefined(policy) {
		validated, err := TenantAuthPolicy(policy)
		if err != nil {
			return nil, invalidConfig("tenantDefaults: " + errorMessage(err))
		}
		config.TenantDefaults.AuthPolicy = validated
	}
	if config.Clearances, err = ResolveClearanceConfig(options.Get("clearances")); err != nil {
		return nil, err
	}
	if config.Regions, err = ResolveRegionConfig(options.Get("regions"), locate); err != nil {
		return nil, err
	}
	rpID, _ := member(member(options.Get("authentication"), "passkeys"), "rpID").(string)
	if !truthy(member(member(options.Get("authentication"), "passkeys"), "rpID")) {
		rpID = ""
	}
	if config.Hosts, err = ResolveHostConfig(options.Get("hosts"), HostConfigContext{BaseURL: baseURL, Regions: config.Regions, PasskeyRpID: rpID}); err != nil {
		return nil, err
	}
	config.trustedOrigins = map[string]bool{}
	addOrigin := func(origin string) {
		if !config.trustedOrigins[origin] {
			config.trustedOrigins[origin] = true
			config.TrustedOrigins = append(config.TrustedOrigins, origin)
		}
	}
	addOrigin(urlOrigin(baseURL))
	if origins := options.Get("trustedOrigins"); !nullish(origins) {
		list, ok := origins.([]any)
		if !ok {
			return nil, &core.TypeError{Message: "options.trustedOrigins is not iterable"}
		}
		for _, origin := range list {
			addOrigin(jsString(origin))
		}
	}
	permissions := options.Get("permissions")
	config.TenantDefined = member(permissions, "mode") == "tenant-defined"
	config.StrictResourceTypes = !isUndefined(member(permissions, "resourceTypes"))
	onboarding := options.Get("onboarding")
	config.LinkedOnboarding = member(onboarding, "mode") == "linked"
	config.InvitationLifetimeMs = numberOr(member(onboarding, "invitationLifetimeMs"), 86400000)
	accessRequests := options.Get("accessRequests")
	lifetime, err := Integer(coalesce(member(accessRequests, "lifetimeMs"), 7*86400000.0), "accessRequests.lifetimeMs", 60_000, 365*86400000)
	if err != nil {
		return nil, err
	}
	config.AccessRequestLifetimeMs = int64(lifetime)
	duration, err := Integer(coalesce(member(accessRequests, "maxDurationSeconds"), 90*86400.0), "accessRequests.maxDurationSeconds", 60, 10*365*86400)
	if err != nil {
		return nil, err
	}
	config.AccessRequestMaxDurationSeconds = int64(duration)
	timeout, err := Integer(coalesce(member(options.Get("events"), "webhookTimeoutMs"), 10_000.0), "events.webhookTimeoutMs", 1_000, 120_000)
	if err != nil {
		return nil, err
	}
	config.WebhookTimeoutMs = int64(timeout)
	sts := options.Get("sts")
	selfIssuer := coalesce(member(member(sts, "jwt"), "issuer"), urlOrigin(baseURL)+basePath)
	if config.Sts, err = ResolveStsConfig(sts, jsString(selfIssuer)); err != nil {
		return nil, err
	}
	if config.Signals, err = ResolveSignalsConfig(options.Get("signals"), basePath); err != nil {
		return nil, err
	}
	return config, nil
}

// ResolveClearanceConfig validates `options.clearances` (an object, or absent to leave the module off) and applies
// the defaults. Anything but an object fails construction, so `clearances: true` cannot be mistaken for a setting.
func ResolveClearanceConfig(options any) (*ResolvedClearanceConfig, error) {
	if isUndefined(options) {
		return nil, nil
	}
	if !isPlainObject(options) {
		return nil, invalidConfig("clearances must be an object")
	}
	object := options.(*core.Object)
	for _, key := range object.Keys() {
		if key != "appliesToRoot" {
			return nil, invalidConfig("clearances." + key + " is not a known setting")
		}
	}
	applies := object.Get("appliesToRoot")
	if !isUndefined(applies) && typeOf(applies) != "boolean" {
		return nil, invalidConfig("clearances.appliesToRoot must be a boolean")
	}
	return &ResolvedClearanceConfig{AppliesToRoot: applies != false}, nil
}

var pushPathPattern = regexp.MustCompile(`^/[\w/-]+$`)

// ResolveSignalsConfig validates `options.signals` and applies the defaults.
func ResolveSignalsConfig(options any, basePath string) (ResolvedSignalsConfig, error) {
	invalid := func(field, detail string) error { return invalidConfig("signals." + field + " " + detail) }
	if !isUndefined(options) && (options == nil || typeOf(options) != "object") {
		return ResolvedSignalsConfig{}, invalidConfig("signals must be an object")
	}
	flag := func(value any, field string) (bool, error) {
		if !isUndefined(value) && typeOf(value) != "boolean" {
			return false, invalid(field, "must be a boolean")
		}
		return value == true, nil
	}
	pushPath := coalesce(member(options, "pushPath"), basePath+"/signals/push")
	path, ok := pushPath.(string)
	if !ok || utf16Len(path) > 256 || !pushPathPattern.MatchString(path) || strings.HasSuffix(path, "/") ||
		strings.Contains(path, "//") {
		return ResolvedSignalsConfig{}, invalid("pushPath", "must be an absolute path such as /api/iam/signals/push")
	}
	allowPrivate, err := flag(member(options, "allowPrivateNetworks"), "allowPrivateNetworks")
	if err != nil {
		return ResolvedSignalsConfig{}, err
	}
	allowInsecure, err := flag(member(options, "allowInsecureLocalhost"), "allowInsecureLocalhost")
	if err != nil {
		return ResolvedSignalsConfig{}, err
	}
	return ResolvedSignalsConfig{AllowPrivateNetworks: allowPrivate, AllowInsecureLocalhost: allowInsecure, PushPath: path}, nil
}

// ResolveStsConfig validates `options.sts` (except `jwt`, which the session token signer checks) and applies the
// defaults. selfIssuer is IAM's own issuer, which web-identity trusts may never name.
func ResolveStsConfig(options any, selfIssuer string) (ResolvedStsConfig, error) {
	var resolved ResolvedStsConfig
	invalid := func(field, detail string) error { return invalidConfig("sts." + field + " " + detail) }
	if !isUndefined(options) && (options == nil || typeOf(options) != "object") {
		return resolved, invalid("options", "must be an object")
	}
	number := func(value any, fallback float64, field string, min, max float64) (int64, error) {
		valid, err := Integer(coalesce(value, fallback), field, min, max)
		if err != nil {
			return 0, invalid(field, "must be an integer from "+core.NumberString(min)+" to "+core.NumberString(max))
		}
		return int64(valid), nil
	}
	flag := func(value any, field string) (bool, error) {
		if !isUndefined(value) && typeOf(value) != "boolean" {
			return false, invalid(field, "must be a boolean")
		}
		return value == true, nil
	}
	web := member(options, "webIdentity")
	if !isUndefined(web) && (web == nil || typeOf(web) != "object") {
		return resolved, invalid("webIdentity", "must be an object")
	}
	if fetch := member(web, "fetchJson"); !isUndefined(fetch) && typeOf(fetch) != "function" {
		return resolved, invalid("webIdentity.fetchJson", "must be a function")
	}
	allowInsecureLocalhost, err := flag(member(web, "allowInsecureLocalhost"), "webIdentity.allowInsecureLocalhost")
	if err != nil {
		return resolved, err
	}
	if issuers := member(web, "allowedIssuers"); !isUndefined(issuers) {
		list, ok := issuers.([]any)
		if !ok || len(list) > 100 {
			return resolved, invalid("webIdentity.allowedIssuers", "must be an array of at most 100 issuers")
		}
		self := selfIssuer
		accepted := newOrderedSet()
		for _, issuer := range list {
			valid, err := WebIdentityIssuer(issuer, WebIdentityIssuerOptions{AllowInsecureLocalhost: allowInsecureLocalhost, SelfIssuer: &self})
			if err != nil {
				return resolved, invalid("webIdentity.allowedIssuers", "contains an invalid issuer: "+errorMessage(err))
			}
			accepted.Add(valid)
		}
		resolved.WebIdentity.AllowedIssuers = accepted.Values()
		if resolved.WebIdentity.AllowedIssuers == nil {
			resolved.WebIdentity.AllowedIssuers = []string{}
		}
	}
	steps := []struct {
		target   *int64
		value    any
		fallback float64
		field    string
		min, max float64
	}{
		{&resolved.MaxRoleSessionSeconds, member(options, "maxRoleSessionSeconds"), 3600, "maxRoleSessionSeconds", 900, 43200},
		{&resolved.MaxSessionTokenSeconds, member(options, "maxSessionTokenSeconds"), 43200, "maxSessionTokenSeconds", 900, 129600},
		{&resolved.MaxSessionTokensPerIdentity, member(options, "maxSessionTokensPerIdentity"), 50, "maxSessionTokensPerIdentity", 1, 1000},
	}
	for _, step := range steps {
		if *step.target, err = number(step.value, step.fallback, step.field, step.min, step.max); err != nil {
			return resolved, err
		}
	}
	if resolved.WebIdentity.Enabled, err = flag(member(web, "enabled"), "webIdentity.enabled"); err != nil {
		return resolved, err
	}
	webSteps := []struct {
		target   *int64
		key      string
		fallback float64
		min, max float64
	}{
		{&resolved.WebIdentity.JwksCacheSeconds, "jwksCacheSeconds", 600, 60, 3600},
		{&resolved.WebIdentity.FetchTimeoutMs, "fetchTimeoutMs", 5000, 500, 10_000},
		{&resolved.WebIdentity.MaxJwksBytes, "maxJwksBytes", 65536, 1024, 1_048_576},
		{&resolved.WebIdentity.MaxExchangesPerWindow, "maxExchangesPerWindow", 600, 1, 100_000},
		{&resolved.WebIdentity.MaxSessionsPerTrust, "maxSessionsPerTrust", 1000, 1, 100_000},
	}
	for _, step := range webSteps {
		if *step.target, err = number(member(web, step.key), step.fallback, "webIdentity."+step.key, step.min, step.max); err != nil {
			return resolved, err
		}
	}
	if resolved.WebIdentity.AllowPrivateNetworks, err = flag(member(web, "allowPrivateNetworks"), "webIdentity.allowPrivateNetworks"); err != nil {
		return resolved, err
	}
	resolved.WebIdentity.AllowInsecureLocalhost = allowInsecureLocalhost
	return resolved, nil
}
