package server

// Port of packages/server/src/models.ts: the server's record types. Records are stored and passed around as
// *core.Object (so a Go replica keeps every member a TypeScript replica wrote); these types are typed views for
// decoding with core.FromRecord and for building records with core.ToRecord. Where go/apitypes generates the same
// schema from spec/api/openapi.json, the model is an alias of the generated type (which keeps unknown members in
// Extra); the others are declared here with the TypeScript member names, numbers as float64 and optional members as
// pointers or omitempty.

import (
	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// Generated record types (go/apitypes) that match models.ts.
type (
	Role                 = apitypes.Role
	AccessWindow         = apitypes.AccessWindow
	Policy               = apitypes.Policy
	GrantAuthority       = apitypes.GrantAuthority
	Binding              = apitypes.Binding
	AccessRequest        = apitypes.AccessRequest
	AccessRequestStatus  = apitypes.AccessRequestStatus
	Group                = apitypes.Group
	GroupMember          = apitypes.GroupMember
	PackageRequestStatus = apitypes.PackageRequestStatus
	PublicTrust          = apitypes.PublicTrust
	WebIdentityAlgorithm = apitypes.WebIdentityAlgorithm
	PublicJwk            = apitypes.PublicJwk
	PublicOidcProvider   = apitypes.PublicOidcProvider
	IdentityLink         = apitypes.IdentityLink
	ActionDefinition     = apitypes.ActionDefinition
	Relationship         = apitypes.Relationship
	ResourceRecord       = apitypes.ResourceRecord
)

// PackageRuleConditions is one clause of an access-package rule: exactly a policy statement's `conditions` block.
type PackageRuleConditions = *core.Object

// TrustConditions are the claim conditions of a web-identity trust: a policy statement's `conditions` block over
// `token.<claim>` keys.
type TrustConditions = *core.Object

// SourceIdentityMode is forbidden, optional or required.
type SourceIdentityMode = string

// BindingActivation is an activation of an eligible binding by one identity (collection bindingActivations;
// uniqueKey `{bindingId}:{identityId}`).
type BindingActivation struct {
	core.StoredRecord
	BindingID     string  `json:"bindingId"`
	IdentityID    string  `json:"identityId"`
	RoleID        string  `json:"roleId"`
	ActivatedAt   float64 `json:"activatedAt"`
	ExpiresAt     float64 `json:"expiresAt"`
	Justification string  `json:"justification,omitempty"`
	SessionID     string  `json:"sessionId"`
	// Status is absent (live until expiresAt), pending, active or denied.
	Status              string   `json:"status,omitempty"`
	RequestedDurationMs *float64 `json:"requestedDurationMs,omitempty"`
	DecidedBy           string   `json:"decidedBy,omitempty"`
	DecidedAt           *float64 `json:"decidedAt,omitempty"`
	Note                string   `json:"note,omitempty"`
}

// Webhook is a webhook subscription. The signing secret is sealed at rest.
type Webhook struct {
	core.StoredRecord
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description,omitempty"`
	Active      bool     `json:"active"`
	// Scope is tenant or subtree (also events of descendant tenants).
	Scope        string   `json:"scope"`
	Outcomes     []string `json:"outcomes,omitzero"`
	Resources    []string `json:"resources,omitzero"`
	SecretSealed string   `json:"secretSealed"`
	CreatedAt    float64  `json:"createdAt"`
	UpdatedAt    float64  `json:"updatedAt"`
	CreatedBy    string   `json:"createdBy"`
}

// AutoAssignApproval is a planned change count a person approved for unattended package-rule runs.
type AutoAssignApproval struct {
	Grants   float64 `json:"grants"`
	Removals float64 `json:"removals"`
	Until    float64 `json:"until"`
}

// AutoAssignRule is the birthright rule of an access package.
type AutoAssignRule struct {
	Include     []*core.Object      `json:"include"`
	Exclude     []*core.Object      `json:"exclude,omitzero"`
	GraceMs     *float64            `json:"graceMs,omitempty"`
	MaxGrants   *float64            `json:"maxGrants,omitempty"`
	MaxRemovals *float64            `json:"maxRemovals,omitempty"`
	OwnerID     string              `json:"ownerId"`
	AuthorityID string              `json:"authorityId"`
	Revision    float64             `json:"revision"`
	UpdatedAt   float64             `json:"updatedAt"`
	Approved    *AutoAssignApproval `json:"approved,omitempty"`
}

// AccessPackage bundles roles and groups granted together (uniqueKey `name:{lowercase}`).
type AccessPackage struct {
	core.StoredRecord
	Name                 string          `json:"name"`
	Description          string          `json:"description,omitempty"`
	RoleIDs              []string        `json:"roleIds"`
	GroupIDs             []string        `json:"groupIds"`
	MaxDurationMs        *float64        `json:"maxDurationMs,omitempty"`
	RequireJustification *bool           `json:"requireJustification,omitempty"`
	Requestable          *bool           `json:"requestable,omitempty"`
	ApproverGroupID      string          `json:"approverGroupId,omitempty"`
	ManagerApproval      *bool           `json:"managerApproval,omitempty"`
	AutoAssign           *AutoAssignRule `json:"autoAssign,omitempty"`
	CreatedAt            float64         `json:"createdAt"`
	UpdatedAt            float64         `json:"updatedAt"`
}

// PackageRuleIssue is a problem the package-rule reconciler met.
type PackageRuleIssue struct {
	core.StoredRecord
	PackageID  string  `json:"packageId"`
	Kind       string  `json:"kind"`
	IdentityID string  `json:"identityId,omitempty"`
	Code       string  `json:"code"`
	Message    string  `json:"message"`
	Revision   float64 `json:"revision"`
	Since      float64 `json:"since"`
}

// ExpiryReminderMark remembers that the expiry reminder for one item was sent (uniqueKey `{kind}:{id}:{expiresAt}`).
type ExpiryReminderMark struct {
	core.StoredRecord
	IdentityID string  `json:"identityId"`
	ExpiresAt  float64 `json:"expiresAt"`
}

// PackageRequest is a member's request for a requestable package.
type PackageRequest struct {
	core.StoredRecord
	PackageID        string   `json:"packageId"`
	IdentityID       string   `json:"identityId"`
	Status           string   `json:"status"`
	RequestedAt      float64  `json:"requestedAt"`
	ExpiresAt        float64  `json:"expiresAt"`
	DesiredExpiresAt *float64 `json:"desiredExpiresAt,omitempty"`
	Justification    string   `json:"justification,omitempty"`
	DecidedBy        string   `json:"decidedBy,omitempty"`
	DecidedAt        *float64 `json:"decidedAt,omitempty"`
	Note             string   `json:"note,omitempty"`
	AssignmentID     string   `json:"assignmentId,omitempty"`
}

// PackageAssignment is one person's assignment of a package (uniqueKey `{packageId}:{identityId}`).
type PackageAssignment struct {
	core.StoredRecord
	PackageID     string   `json:"packageId"`
	IdentityID    string   `json:"identityId"`
	AssignedBy    string   `json:"assignedBy"`
	AssignedAt    float64  `json:"assignedAt"`
	ExpiresAt     *float64 `json:"expiresAt,omitempty"`
	Justification string   `json:"justification,omitempty"`
	RuleRevision  *float64 `json:"ruleRevision,omitempty"`
	BindingIDs    []string `json:"bindingIds"`
	MembershipIDs []string `json:"membershipIds"`
}

// Trust is permission to assume a role of this tenant (identity or web-identity trust).
type Trust struct {
	core.StoredRecord
	// Kind is absent on legacy records, which are identity trusts.
	Kind                  string               `json:"kind,omitempty"`
	SourceTenantID        string               `json:"sourceTenantId"`
	SourceIdentityID      string               `json:"sourceIdentityId"`
	RoleID                string               `json:"roleId"`
	RequireMfa            bool                 `json:"requireMfa"`
	ExternalIDHash        string               `json:"externalIdHash,omitempty"`
	Revoked               bool                 `json:"revoked"`
	Ceiling               *core.PolicyDocument `json:"ceiling,omitempty"`
	MaxSessionSeconds     *float64             `json:"maxSessionSeconds,omitempty"`
	PassSourceAttributes  *bool                `json:"passSourceAttributes,omitempty"`
	AllowedTagKeys        []string             `json:"allowedTagKeys,omitzero"`
	SourceIdentityMode    string               `json:"sourceIdentityMode,omitempty"`
	SessionsRevokedBefore *float64             `json:"sessionsRevokedBefore,omitempty"`
	ProviderID            string               `json:"providerId,omitempty"`
	Conditions            *core.Object         `json:"conditions,omitempty"`
	TagClaims             map[string]string    `json:"tagClaims,omitempty"`
	SourceIdentityClaim   string               `json:"sourceIdentityClaim,omitempty"`
	AuthorityID           string               `json:"authorityId,omitempty"`
	Description           string               `json:"description,omitempty"`
	CreatedAt             *float64             `json:"createdAt,omitempty"`
	CreatedBy             string               `json:"createdBy,omitempty"`
	UpdatedAt             *float64             `json:"updatedAt,omitempty"`
}

// OidcProviderJwks are static public keys of an OIDC provider.
type OidcProviderJwks struct {
	Keys []*core.Object `json:"keys"`
}

// OidcProvider is an external OpenID Connect issuer whose ID tokens web-identity trusts admit (collection
// oidcProviders, uniqueKey `issuer:{issuer}`).
type OidcProvider struct {
	core.StoredRecord
	Name                    string            `json:"name"`
	Issuer                  string            `json:"issuer"`
	Audiences               []string          `json:"audiences"`
	JwksURI                 string            `json:"jwksUri,omitempty"`
	Jwks                    *OidcProviderJwks `json:"jwks,omitempty"`
	Algorithms              []string          `json:"algorithms"`
	MaxTokenLifetimeSeconds float64           `json:"maxTokenLifetimeSeconds"`
	ClockToleranceSeconds   float64           `json:"clockToleranceSeconds"`
	ReplayProtection        string            `json:"replayProtection"`
	Enabled                 bool              `json:"enabled"`
	AuthorityID             string            `json:"authorityId"`
	SessionsRevokedBefore   *float64          `json:"sessionsRevokedBefore,omitempty"`
	CreatedAt               float64           `json:"createdAt"`
	CreatedBy               string            `json:"createdBy"`
	UpdatedAt               float64           `json:"updatedAt"`
}

// WebIdentityReplay is a redeemed web-identity token (collection webIdentityReplays; the id is the replay key).
type WebIdentityReplay struct {
	core.StoredRecord
	ProviderID string  `json:"providerId"`
	ExpiresAt  float64 `json:"expiresAt"`
}

// OwnerInvitation invites a tenant's first owner.
type OwnerInvitation struct {
	core.StoredRecord
	TokenHash   string  `json:"tokenHash"`
	Email       string  `json:"email"`
	CreatedAt   float64 `json:"createdAt"`
	ExpiresAt   float64 `json:"expiresAt"`
	AuthorityID string  `json:"authorityId"`
	Consumed    bool    `json:"consumed"`
	Revoked     *bool   `json:"revoked,omitempty"`
}

// MemberInvitation invites a member; AuthorityID is present only when the invitation carries roles or groups.
type MemberInvitation struct {
	core.StoredRecord
	TokenHash   string   `json:"tokenHash"`
	Email       string   `json:"email"`
	Name        string   `json:"name,omitempty"`
	RoleIDs     []string `json:"roleIds"`
	GroupIDs    []string `json:"groupIds"`
	AuthorityID string   `json:"authorityId,omitempty"`
	InviterID   string   `json:"inviterId"`
	CreatedAt   float64  `json:"createdAt"`
	ExpiresAt   float64  `json:"expiresAt"`
	Consumed    bool     `json:"consumed"`
	Revoked     *bool    `json:"revoked,omitempty"`
}

// PrincipalBoundary is an identity's permission boundary.
type PrincipalBoundary struct {
	core.StoredRecord
	IdentityID string              `json:"identityId"`
	Document   core.PolicyDocument `json:"document"`
}

// ResourceTypeRecord is a tenant-defined resource type; its actions are namespaced under the type name.
type ResourceTypeRecord struct {
	core.StoredRecord
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Attributes  map[string]string `json:"attributes"`
	Parent      string            `json:"parent,omitempty"`
	Relations   []string          `json:"relations,omitzero"`
	CreatedAt   float64           `json:"createdAt"`
}

// TenantAlias is a global sign-in alias; the record id is the alias itself.
type TenantAlias struct {
	core.StoredRecord
	CreatedAt float64 `json:"createdAt"`
}
