// Package scim is the Go port of @better-iam/scim (packages/scim): a SCIM 2.0 (RFC 7643/7644) provisioning server
// with connection-scoped bearer tokens, Users and Groups with filtering, sorting, projection, `/.search`, PATCH,
// `/Bulk`, ETags and pagination, the JSON administration API for connections, and the outbound provisioner that keeps
// downstream SCIM services in step with a tenant's members.
//
// Records are *core.Object values shared with the TypeScript and Rust implementations (collections scimConnections,
// scimUsers, scimGroups, provisioningTargets, provisioningLinks, provisioningGroupLinks), with the same member names
// and order, so replicas of all three can serve one database.
package scim

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	UserSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	EnterpriseSchema   = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	GroupSchema        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
	PatchSchema        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ListSchema         = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SearchSchema       = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	BulkRequestSchema  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	BulkResponseSchema = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	// BulkMaxOperations is the bulk limit advertised in ServiceProviderConfig and enforced by the /Bulk endpoint.
	BulkMaxOperations = 100
	// MaxPayloadSize is the largest SCIM request body.
	MaxPayloadSize = 1024 * 1024
)

// ResourceType is "Users" or "Groups".
type ResourceType = string

// ProvisionedUser is the provisioned attributes handed to MapAttributes. Optional members are nil when absent.
type ProvisionedUser struct {
	UserName    string
	DisplayName string
	ExternalID  *string
	Active      bool
	Title       *string
	// Enterprise is the enterprise User extension as provisioned.
	Enterprise *core.Object
	// Emails is the emails attribute as provisioned (nil when absent).
	Emails []any
	// Name is the name attribute as provisioned.
	Name *core.Object
}

// RoleMappingInput is what SyncRoleMappings receives.
type RoleMappingInput struct {
	TenantID     string
	ConnectionID string
	GroupID      string
	IdentityIDs  []string
	RoleIDs      []string
	// Credential is the administrator's credential when an administrator changed the mapping, nil otherwise.
	Credential *core.CredentialInput
}

// IdentityStatusChange is what IdentityStatusChanged receives.
type IdentityStatusChange struct {
	TenantID     string
	ConnectionID string
	IdentityID   string
}

// GroupDeletion is what GroupDeleted receives.
type GroupDeletion struct {
	TenantID     string
	ConnectionID string
	GroupID      string
}

// Config configures the SCIM service (ScimConfig).
type Config struct {
	Store core.IamStore
	// Authorize must authenticate the credential and fail on a denied IAM permission.
	Authorize func(ctx context.Context, credential core.CredentialInput, action string, resource core.ResourceRef) error
	// Authenticate resolves a credential to the ID of its identity.
	Authenticate func(ctx context.Context, credential core.CredentialInput) (identityID string, err error)
	// BasePath is where the SCIM protocol is served (default "/scim/v2"); "" means the default.
	BasePath string
	// AdminBasePath is where the JSON administration API for connections is served (`{adminBasePath}/connections/{list,
	// create,rotate,revoke,groups,mappings}`), default "/scim/admin"; "" means the default. Must be absolute and must
	// not overlap BasePath.
	AdminBasePath string
	// MapManager maps the enterprise extension's `manager.value` (a SCIM user ID, `externalId`, or `userName` of the
	// same connection) to `Identity.managerId`, back-filling reports provisioned before their manager. Managers an
	// administrator set are never cleared by SCIM. Default true (nil).
	MapManager *bool
	// UnsupportedAttributes is what happens to attributes this service provider does not store: "ignore" (default,
	// also "") accepts and drops them; "reject" answers 400 `mutability` for them.
	UnsupportedAttributes string
	// MapAttributes maps a provisioned user's SCIM attributes to the identity attributes the product declares; nil
	// leaves attributes untouched.
	MapAttributes func(user ProvisionedUser) *core.Object
	// ValidateIdentityAttributes validates mapped attributes against the declared identity attributes.
	ValidateIdentityAttributes func(attributes *core.Object) (*core.Object, error)
	// RecordAudit records an audit event and fans it out; without it events are only appended to the audit chain.
	RecordAudit func(ctx context.Context, tx core.IamStore, event *core.Object) error
	// SyncRoleMappings is the trusted server callback applying administrator-configured role mappings (in the
	// transaction).
	SyncRoleMappings func(ctx context.Context, tx core.IamStore, input RoleMappingInput) error
	// IdentityStatusChanged runs in the transaction after SCIM changed whether a user's identity is active.
	IdentityStatusChanged func(ctx context.Context, tx core.IamStore, input IdentityStatusChange) error
	// GroupDeleted runs in the transaction before SCIM deletes a group's record.
	GroupDeleted func(ctx context.Context, tx core.IamStore, input GroupDeletion) error
	// Now is Go-only: the wall clock the TypeScript package reads with Date.now(), in milliseconds (default: the
	// system clock).
	Now func() float64
}

func (c *Config) now() float64 {
	if c.Now != nil {
		return c.Now()
	}
	return wallClock()
}
