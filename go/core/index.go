// Package core holds the shared, dependency-free contracts of better-iam: the store contract and its reference
// semantics (storage.go, sql.go), the policy engine (policy.go), query planning (plan.go, filter_compilers.go), the
// audit hash chain (audit.go), canonical JSON (jcs.go), snapshots, store instrumentation, classification, shared
// signals and delegation token claims. It is the Go port of @better-iam/core; file names mirror the TypeScript
// modules (packages/core/src/*.ts).
//
// Records are JavaScript-compatible JSON values (see json.go): *Object for objects, float64 for numbers, WTF-8
// strings, and Undefined for JavaScript's undefined, so Go replicas read and write exactly the records the
// TypeScript implementation does.
package core

import (
	"context"
	"net/http"
)

// IamError is the error every better-iam operation fails with: a stable code, a message, and an HTTP status.
type IamError struct {
	Code    string
	Message string
	Status  int
}

// NewIamError builds an IamError; the status defaults to 400 like the TypeScript constructor.
func NewIamError(code, message string, status ...int) *IamError {
	s := 400
	if len(status) > 0 {
		s = status[0]
	}
	return &IamError{Code: code, Message: message, Status: s}
}

func (e *IamError) Error() string { return e.Message }

// Name is the JavaScript error name ("IamError").
func (e *IamError) Name() string { return "IamError" }

// Json is any value of the core value model (see json.go).
type Json = any

// FindOptions pages a find. Nil fields are unset.
type FindOptions struct {
	Limit  *int
	Offset *int
	// After is keyset pagination: only records whose id sorts after this id (code-point order). Unlike a growing
	// offset, each page costs the same however deep it is. Offset applies after it.
	After *string
}

// OrderOptions orders FindOrdered results by a numeric top-level field (ties by id, ascending), keeping only records
// whose field is a number within [From, To].
type OrderOptions struct {
	Field string
	// Direction is "asc" (the default when empty) or "desc".
	Direction string
	From      *float64
	To        *float64
	Offset    *int
	Limit     *int
}

// MigrationInfo is one applied migration in a StoreDescription.
type MigrationInfo struct {
	Name      string `json:"name"`
	AppliedAt int64  `json:"appliedAt"`
}

// CollectionInfo is one collection's record count in a StoreDescription.
type CollectionInfo struct {
	Name    string `json:"name"`
	Records int64  `json:"records"`
}

// StoreDescription is what IamStore.Describe reports about a database.
type StoreDescription struct {
	Adapter       string           `json:"adapter"`
	SchemaVersion *int64           `json:"schemaVersion"`
	Migrations    []MigrationInfo  `json:"migrations"`
	Collections   []CollectionInfo `json:"collections"`
	// Settings are adapter settings worth checking in production (journal mode, durability, size, server version);
	// values are strings, float64, bools or nil, in the adapter's order.
	Settings *Object `json:"settings"`
}

// TxFunc is a transaction callback. It must use the ctx and tx it receives: calls on the outer store with this ctx
// join the transaction (the Go counterpart of the TypeScript adapters' AsyncLocalStorage routing).
type TxFunc func(ctx context.Context, tx IamStore) error

// IamStore is the storage contract. Filters are strict equality against JSON fields (a nil filter is {}); all writes
// require Transaction. Get returns nil when the record does not exist.
type IamStore interface {
	Get(ctx context.Context, collection, id string) (*Object, error)
	Find(ctx context.Context, collection string, filter *Object, options *FindOptions) ([]*Object, error)
	Insert(ctx context.Context, collection string, record *Object) (*Object, error)
	Put(ctx context.Context, collection string, record *Object) (*Object, error)
	Delete(ctx context.Context, collection, id string) error
	// Transaction runs fn in a serializable read/modify/write transaction; nested transactions join the outer one.
	// The callback's error is returned unchanged.
	Transaction(ctx context.Context, fn TxFunc) error
	Migrate(ctx context.Context) error
	Close(ctx context.Context) error
}

// OrderedFinder is the optional IamStore.findOrdered: Find ordered and bounded by a numeric field, paged by the
// database. Call it through FindOrdered, which falls back to Find for stores without it.
type OrderedFinder interface {
	FindOrdered(ctx context.Context, collection string, filter *Object, order OrderOptions) ([]*Object, error)
}

// CollectionLister is the optional IamStore.collections: every collection holding at least one record, sorted.
type CollectionLister interface {
	Collections(ctx context.Context) ([]string, error)
}

// Describer is the optional IamStore.describe: adapter, applied migrations, record counts and settings.
type Describer interface {
	Describe(ctx context.Context) (*StoreDescription, error)
}

// Transact runs fn in a transaction and returns its result (the typed form of IamStore.Transaction).
func Transact[T any](ctx context.Context, store IamStore, fn func(ctx context.Context, tx IamStore) (T, error)) (T, error) {
	var result T
	err := store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
		value, err := fn(ctx, tx)
		if err != nil {
			return err
		}
		result = value
		return nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}

// TenantTreeActive walks a tenant and its ancestors: true only when every one exists and is active. Cycles read as
// inactive.
func TenantTreeActive(ctx context.Context, store interface {
	Get(ctx context.Context, collection, id string) (*Object, error)
}, tenantID string) (bool, error) {
	visited := map[string]bool{}
	current := tenantID
	for current != "" {
		if visited[current] {
			return false, nil
		}
		visited[current] = true
		tenant, err := store.Get(ctx, "tenants", current)
		if err != nil {
			return false, err
		}
		if tenant == nil {
			return false, nil
		}
		if status, _ := tenant.String("status"); status != "active" {
			return false, nil
		}
		parent, ok := tenant.String("parentId")
		if !ok {
			return true, nil
		}
		current = parent
		if current == "" {
			// An empty parentId is falsy in JavaScript and ends the walk.
			return true, nil
		}
	}
	return true, nil
}

// TenantStatus is pending, active, suspended or deleted.
type TenantStatus = string

// AuthMethod is how a user session was established.
type AuthMethod = string

// AuthMethods are the sign-in methods a tenant policy can allow or restrict; impersonation is an administrative
// action, not a sign-in.
var AuthMethods = []AuthMethod{"password", "passwordless-email", "passwordless-sms", "passkey", "federated"}

// StoredRecord holds the fields every record has.
type StoredRecord struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	// UniqueKey is an optional database-enforced natural key, unique within collection and tenant.
	UniqueKey string `json:"uniqueKey,omitempty"`
}

// TenantAuthPolicy holds per-tenant authentication rules layered under the deployment's configuration.
type TenantAuthPolicy struct {
	RequireMfa                 *bool        `json:"requireMfa,omitempty"`
	AllowedMethods             []AuthMethod `json:"allowedMethods,omitempty"`
	SessionLifetimeMs          *int64       `json:"sessionLifetimeMs,omitempty"`
	SessionIdleTimeoutMs       *int64       `json:"sessionIdleTimeoutMs,omitempty"`
	MaxAttempts                *int64       `json:"maxAttempts,omitempty"`
	MinPasswordLength          *int64       `json:"minPasswordLength,omitempty"`
	MaxSessions                *int64       `json:"maxSessions,omitempty"`
	AllowImpersonation         *bool        `json:"allowImpersonation,omitempty"`
	TrustedDeviceDays          *int64       `json:"trustedDeviceDays,omitempty"`
	PasswordHistory            *int64       `json:"passwordHistory,omitempty"`
	PasswordMaxAgeDays         *int64       `json:"passwordMaxAgeDays,omitempty"`
	PasswordMinClasses         *int64       `json:"passwordMinClasses,omitempty"`
	PasswordRejectPersonalInfo *bool        `json:"passwordRejectPersonalInfo,omitempty"`
	NotifyNewSignIn            *bool        `json:"notifyNewSignIn,omitempty"`
	AllowedIPRanges            []string     `json:"allowedIpRanges,omitempty"`
	MfaEmailCodes              *bool        `json:"mfaEmailCodes,omitempty"`
	RequireMfaForOwners        *bool        `json:"requireMfaForOwners,omitempty"`
	BindSessionsToIP           *bool        `json:"bindSessionsToIp,omitempty"`
}

// TenantAccessPolicy holds floors for just-in-time activation across a tenant.
type TenantAccessPolicy struct {
	MaxActivationMs      *int64 `json:"maxActivationMs,omitempty"`
	RequireJustification *bool  `json:"requireJustification,omitempty"`
	RequireMfa           *bool  `json:"requireMfa,omitempty"`
	RequireApproval      *bool  `json:"requireApproval,omitempty"`
	ApprovalLifetimeMs   *int64 `json:"approvalLifetimeMs,omitempty"`
}

// TenantLimits are plan limits a platform administrator sets on a tenant.
type TenantLimits struct {
	Identities      *int64 `json:"identities,omitempty"`
	ServiceAccounts *int64 `json:"serviceAccounts,omitempty"`
	Agents          *int64 `json:"agents,omitempty"`
	Groups          *int64 `json:"groups,omitempty"`
	Roles           *int64 `json:"roles,omitempty"`
	Policies        *int64 `json:"policies,omitempty"`
	Resources       *int64 `json:"resources,omitempty"`
	Webhooks        *int64 `json:"webhooks,omitempty"`
}

// Tenant is a record of the `tenants` collection.
type Tenant struct {
	StoredRecord
	Name         string              `json:"name"`
	Type         string              `json:"type"`
	ParentID     *string             `json:"parentId"`
	Status       TenantStatus        `json:"status"`
	Slug         string              `json:"slug,omitempty"`
	Region       string              `json:"region,omitempty"`
	Boundary     *PolicyDocument     `json:"boundary,omitempty"`
	AuthPolicy   *TenantAuthPolicy   `json:"authPolicy,omitempty"`
	AccessPolicy *TenantAccessPolicy `json:"accessPolicy,omitempty"`
	Limits       *TenantLimits       `json:"limits,omitempty"`
	CreatedAt    int64               `json:"createdAt"`
	DeletedAt    *int64              `json:"deletedAt,omitempty"`
}

// AgentSuspension records who suspended an agent, when, and why.
type AgentSuspension struct {
	By     string `json:"by"`
	At     int64  `json:"at"`
	Reason string `json:"reason,omitempty"`
}

// AgentProfile is the account profile of an AI agent (Identity.Kind == "agent").
type AgentProfile struct {
	SponsorID                  string           `json:"sponsorId"`
	Model                      string           `json:"model,omitempty"`
	Provider                   string           `json:"provider,omitempty"`
	Purpose                    string           `json:"purpose,omitempty"`
	URL                        string           `json:"url,omitempty"`
	Protocols                  []string         `json:"protocols,omitempty"`
	Delegable                  *bool            `json:"delegable,omitempty"`
	MaxDelegatedSessionSeconds *int64           `json:"maxDelegatedSessionSeconds,omitempty"`
	Boundary                   *PolicyDocument  `json:"boundary,omitempty"`
	TokenAudiences             []string         `json:"tokenAudiences,omitempty"`
	Suspended                  *AgentSuspension `json:"suspended,omitempty"`
}

// GuestProfile marks a guest of the host tenant.
type GuestProfile struct {
	SponsorID    string `json:"sponsorId"`
	Since        int64  `json:"since"`
	HomeTenantID string `json:"homeTenantId,omitempty"`
	HomeDomain   string `json:"homeDomain,omitempty"`
}

// Identity is a record of the `identities` collection.
type Identity struct {
	StoredRecord
	// Kind is user, service or agent.
	Kind              string        `json:"kind"`
	Agent             *AgentProfile `json:"agent,omitempty"`
	Guest             *GuestProfile `json:"guest,omitempty"`
	Email             string        `json:"email,omitempty"`
	Name              string        `json:"name"`
	Description       string        `json:"description,omitempty"`
	Attributes        *Object       `json:"attributes,omitempty"`
	Status            string        `json:"status"`
	EmailVerified     bool          `json:"emailVerified"`
	RootAdmin         bool          `json:"rootAdmin"`
	Owner             bool          `json:"owner"`
	CreatedAt         int64         `json:"createdAt"`
	PasswordHash      string        `json:"passwordHash,omitempty"`
	PasswordChangedAt *int64        `json:"passwordChangedAt,omitempty"`
	UnprovenPassword  *bool         `json:"unprovenPassword,omitempty"`
	Phone             string        `json:"phone,omitempty"`
	PhoneVerified     *bool         `json:"phoneVerified,omitempty"`
	ExpiresAt         *int64        `json:"expiresAt,omitempty"`
	ManagerID         string        `json:"managerId,omitempty"`
	DeletedAt         *int64        `json:"deletedAt,omitempty"`
	DeletedEmail      string        `json:"deletedEmail,omitempty"`
}

// SessionClientInfo holds client details recorded on a session for device lists; never used for authorization.
type SessionClientInfo struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	Label     string `json:"label,omitempty"`
}

// SignInRecord is the sign-in bookkeeping kept per person (`authSignIns`).
type SignInRecord struct {
	LastAt           *int64             `json:"lastAt,omitempty"`
	LastClient       *SessionClientInfo `json:"lastClient,omitempty"`
	FailedAttempts   int64              `json:"failedAttempts"`
	LastFailedAt     *int64             `json:"lastFailedAt,omitempty"`
	LastFailedClient *SessionClientInfo `json:"lastFailedClient,omitempty"`
}

// WebIdentity is the OIDC provider and verified external subject behind a web-identity session.
type WebIdentity struct {
	ProviderID string `json:"providerId"`
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
}

// Session is a record of the `sessions` collection.
type Session struct {
	StoredRecord
	IdentityID            string             `json:"identityId"`
	TokenHash             string             `json:"tokenHash"`
	CreatedAt             int64              `json:"createdAt"`
	ExpiresAt             int64              `json:"expiresAt"`
	LastSeenAt            int64              `json:"lastSeenAt"`
	AuthenticatedAt       int64              `json:"authenticatedAt"`
	Mfa                   bool               `json:"mfa"`
	Kind                  string             `json:"kind"`
	AgentID               string             `json:"agentId,omitempty"`
	DelegationID          string             `json:"delegationId,omitempty"`
	MfaAuthenticatedAt    *int64             `json:"mfaAuthenticatedAt,omitempty"`
	CredentialAuthorityID string             `json:"credentialAuthorityId,omitempty"`
	SessionName           string             `json:"sessionName,omitempty"`
	SourceIdentity        string             `json:"sourceIdentity,omitempty"`
	SessionTags           map[string]string  `json:"sessionTags,omitempty"`
	SourcePolicy          *PolicyDocument    `json:"sourcePolicy,omitempty"`
	Format                string             `json:"format,omitempty"`
	Audience              []string           `json:"audience,omitempty"`
	WebIdentity           *WebIdentity       `json:"webIdentity,omitempty"`
	Method                AuthMethod         `json:"method,omitempty"`
	Client                *SessionClientInfo `json:"client,omitempty"`
	Name                  string             `json:"name,omitempty"`
	Description           string             `json:"description,omitempty"`
	ImpersonatorID        string             `json:"impersonatorId,omitempty"`
	ImpersonatorSessionID string             `json:"impersonatorSessionId,omitempty"`
	TrustedDeviceID       string             `json:"trustedDeviceId,omitempty"`
	OriginalIdentityID    string             `json:"originalIdentityId,omitempty"`
	SourceTenantID        string             `json:"sourceTenantId,omitempty"`
	RoleID                string             `json:"roleId,omitempty"`
	TrustID               string             `json:"trustId,omitempty"`
	SourceSessionID       string             `json:"sourceSessionId,omitempty"`
	SourceAuthorityIDs    []string           `json:"sourceAuthorityIds,omitempty"`
	Policy                *PolicyDocument    `json:"policy,omitempty"`
	PreviousSignIn        *SignInRecord      `json:"previousSignIn,omitempty"`
}

// SessionKind is user, role, api-key, session-token or delegated.
type SessionKind = string

// AuditSessionContext is the session an audited action ran under: an allowlist projection of the session.
type AuditSessionContext struct {
	SessionID             string `json:"sessionId"`
	Kind                  string `json:"kind"`
	RoleID                string `json:"roleId,omitempty"`
	TrustID               string `json:"trustId,omitempty"`
	SourceTenantID        string `json:"sourceTenantId,omitempty"`
	SessionName           string `json:"sessionName,omitempty"`
	SourceIdentity        string `json:"sourceIdentity,omitempty"`
	WebIdentityProviderID string `json:"webIdentityProviderId,omitempty"`
	WebIdentitySubject    string `json:"webIdentitySubject,omitempty"`
	Format                string `json:"format,omitempty"`
	AgentID               string `json:"agentId,omitempty"`
	DelegationID          string `json:"delegationId,omitempty"`
}

// AuthenticatedPrincipal is produced by verified credential resolution. Server services never accept it from JSON.
type AuthenticatedPrincipal struct {
	Identity *Identity
	Session  *Session
	// DeviceProof is the unverified device proof the request carried (x-better-iam-device).
	DeviceProof string
}

// AuditEvent is a record of the `audit` collection. Events are hashed as *Object (see audit.go); this struct is a
// typed view.
type AuditEvent struct {
	StoredRecord
	ActorID         string               `json:"actorId"`
	Action          string               `json:"action"`
	ResourceID      string               `json:"resourceId"`
	Timestamp       int64                `json:"timestamp"`
	Outcome         string               `json:"outcome"`
	RootOverride    *bool                `json:"rootOverride,omitempty"`
	OriginalActorID string               `json:"originalActorId,omitempty"`
	ImpersonatorID  string               `json:"impersonatorId,omitempty"`
	Metadata        *Object              `json:"metadata,omitempty"`
	SessionContext  *AuditSessionContext `json:"sessionContext,omitempty"`
	Sequence        *int64               `json:"sequence,omitempty"`
	PreviousHash    string               `json:"previousHash,omitempty"`
	Hash            string               `json:"hash,omitempty"`
}

// OutboxMessage is a record of the `outbox` collection.
type OutboxMessage struct {
	StoredRecord
	// Kind is email, sms or webhook.
	Kind        string            `json:"kind"`
	To          string            `json:"to"`
	Template    string            `json:"template"`
	Payload     map[string]string `json:"payload"`
	CreatedAt   int64             `json:"createdAt"`
	DeliveredAt *int64            `json:"deliveredAt,omitempty"`
	Attempts    int64             `json:"attempts"`
	FailedAt    *int64            `json:"failedAt,omitempty"`
	LastError   string            `json:"lastError,omitempty"`
	Reference   string            `json:"reference,omitempty"`
}

// CredentialInput carries request headers or a bare token.
type CredentialInput struct {
	Headers http.Header
	Token   string
}

// ResourceRef names a resource within a tenant.
type ResourceRef struct {
	TenantID string `json:"tenantId"`
	Type     string `json:"type"`
	ID       string `json:"id"`
}

// TenantType lists the tenant types allowed below a type.
type TenantType struct {
	AllowedChildren []string `json:"allowedChildren"`
}

// NamedTenantType is one entry of HierarchyConfig.Types, in declaration order.
type NamedTenantType struct {
	Name string
	Type TenantType
}

// HierarchyConfig declares the tenant hierarchy.
type HierarchyConfig struct {
	Types    []NamedTenantType
	MaxDepth *int
}

// AttributeType is string, number or boolean.
type AttributeType = string

// NamedAttribute is one typed attribute, in declaration order.
type NamedAttribute struct {
	Name string
	Type AttributeType
}

// ResourceTypeDefinition declares a resource type.
type ResourceTypeDefinition struct {
	Description string
	Actions     []string
	Attributes  []NamedAttribute
	Parent      string
	Managed     bool
	Relations   []string
}

// NamedResourceType is one entry of a resource type map, in declaration order (TypeScript object order).
type NamedResourceType struct {
	Name       string
	Definition ResourceTypeDefinition
}

// PermissionsConfig is the permission catalog configuration.
type PermissionsConfig struct {
	// Mode is "catalog" (default) or "tenant-defined".
	Mode               string
	Actions            []string
	ResourceTypes      []NamedResourceType
	IdentityAttributes []NamedAttribute
}

// PluginDelivery is a delivery a plugin handler may queue in its transaction.
type PluginDelivery struct {
	Kind     string            `json:"kind"`
	To       string            `json:"to"`
	Template string            `json:"template"`
	Payload  map[string]string `json:"payload"`
}

// PluginEndpointContext is what a plugin endpoint handler receives.
type PluginEndpointContext struct {
	Store     IamStore
	Principal *AuthenticatedPrincipal
	TenantID  string
	// Deliver queues an outbox delivery in the endpoint's transaction and returns the message ID.
	Deliver func(ctx context.Context, delivery PluginDelivery) (string, error)
}

// PluginEndpoint is a POST endpoint a plugin contributes under plugins/{pluginId}/{path}.
type PluginEndpoint struct {
	Method string
	Path   string
	Action string
	// Validate must reject unknown or invalid fields before the handler runs.
	Validate func(input any) (*Object, error)
	// Resource names the record the endpoint acts on (`project/{id}`); nil authorizes on the tenant itself.
	Resource func(input *Object) string
	Handler  func(ctx context.Context, endpoint PluginEndpointContext, input *Object) (any, error)
}

// OperationHookInput is passed to plugin operation hooks.
type OperationHookInput struct {
	Store      IamStore
	Principal  *AuthenticatedPrincipal
	TenantID   string
	Action     string
	ResourceID string
	// Result is set for AfterOperation.
	Result any
}

// PluginHooks run inside an operation's transaction; an error aborts the operation.
type PluginHooks struct {
	BeforeOperation func(ctx context.Context, input OperationHookInput) error
	AfterOperation  func(ctx context.Context, input OperationHookInput) error
}

// IamPlugin extends a deployment with actions, resource types, endpoints and hooks.
type IamPlugin struct {
	ID             string
	Actions        []string
	ResourceTypes  []NamedResourceType
	Endpoints      []PluginEndpoint
	Hooks          *PluginHooks
	ValidateConfig func() error
	Migrate        func(ctx context.Context, store IamStore) error
	// ResolveContext adds trusted, server-derived keys to the policy evaluation context.
	ResolveContext func(ctx context.Context, principal *AuthenticatedPrincipal) (*Object, error)
	AfterAudit     func(ctx context.Context, event *Object) error
	// Purge removes plugin-owned records before the server deletes purged tenants in the same transaction.
	Purge func(ctx context.Context, store IamStore, tenantIDs []string) error
}
