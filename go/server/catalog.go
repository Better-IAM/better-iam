package server

// Port of packages/server/src/catalog.ts: the permission catalog.

import (
	"context"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// builtInActionNames are every operation the platform itself authorizes, without the `iam:` prefix.
var builtInActionNames = []string{
	"tenants:create",
	"tenants:read",
	"tenants:update",
	"tenants:delete",
	"identities:create",
	"identities:read",
	"identities:update",
	"identities:delete",
	"identities:impersonate",
	"groups:create",
	"groups:read",
	"groups:update",
	"groups:delete",
	"roles:create",
	"roles:read",
	"roles:update",
	"roles:delete",
	"policies:create",
	"policies:read",
	"policies:update",
	"policies:delete",
	"bindings:create",
	"bindings:read",
	"bindings:delete",
	"bindings:activate",
	"bindings:approve",
	"packages:create",
	"packages:read",
	"packages:update",
	"packages:delete",
	"packages:assign",
	"packages:request",
	"packages:approve",
	"authorities:create",
	"authorities:revoke",
	"boundaries:update",
	"actions:create",
	"actions:read",
	"actions:delete",
	"resource-types:create",
	"resource-types:read",
	"resource-types:update",
	"resource-types:delete",
	"resources:create",
	"resources:read",
	"resources:update",
	"resources:delete",
	"relationships:create",
	"relationships:read",
	"relationships:delete",
	"credentials:create",
	"credentials:read",
	"credentials:revoke",
	"trust:create",
	"trust:read",
	"trust:update",
	"trust:revoke",
	"roles:assume",
	"roles:revoke-sessions",
	"session-tokens:create",
	"oidc-providers:create",
	"oidc-providers:read",
	"oidc-providers:update",
	"oidc-providers:delete",
	"audit:read",
	"assertions:create",
	"policies:simulate",
	"config:read",
	"config:apply",
	"root:grant",
	"access-requests:create",
	"access-requests:read",
	"access-requests:review",
	"webhooks:create",
	"webhooks:read",
	"webhooks:update",
	"webhooks:delete",
	"oauth:clients:create",
	"oauth:clients:read",
	"oauth:clients:delete",
	"oauth:clients:update",
	"oauth:grants:read",
	"oauth:grants:revoke",
	"scim:connections:create",
	"scim:connections:read",
	"scim:connections:delete",
	"scim:credentials:create",
	"scim:credentials:revoke",
	"scim:mappings:update",
	"scim:targets:create",
	"scim:targets:read",
	"scim:targets:update",
	"scim:targets:delete",
	"scim:targets:sync",
	"saml:connections:create",
	"saml:connections:read",
	"saml:connections:update",
	"saml:connections:delete",
	"ssf:streams:create",
	"ssf:streams:read",
	"ssf:streams:update",
	"ssf:streams:delete",
	"domains:create",
	"domains:read",
	"domains:update",
	"domains:delete",
	"hostnames:create",
	"hostnames:read",
	"hostnames:update",
	"hostnames:delete",
	"analysis:read",
	"analysis:update",
	"certifications:read",
	"certifications:review",
	"certifications:manage",
	"sod:read",
	"sod:manage",
	"security:read",
	"security:manage",
	"invariants:read",
	"invariants:manage",
	"agreements:read",
	"agreements:manage",
	"features:read",
	"features:manage",
	"features:override",
	"onboarding:read",
	"onboarding:manage",
	// AI agents as accounts and the delegations people give them (agents.ts, delegations.ts).
	"agents:create",
	"agents:read",
	"agents:update",
	"agents:delete",
	"delegations:read",
	"delegations:revoke",
	// Inference access control (inference.ts): providers, models and budgets; usage reports; gateway metering.
	"inference:manage",
	"inference:read",
	"inference:record",
	// Teams inside the organization (teams.ts) and its department structure (departments.ts).
	"teams:create",
	"teams:read",
	"teams:update",
	"teams:delete",
	"departments:read",
	"departments:manage",
	// Billing and spend tracking (billing.ts): meters, prices, budgets, profiles; spend reports; usage metering.
	"billing:read",
	"billing:manage",
	"billing:record",
	// Key management (kms.ts): key administration and grants; encryption, signatures and MACs with a key.
	"kms:create",
	"kms:read",
	"kms:update",
	"kms:delete",
	"kms:grant",
	"kms:encrypt",
	"kms:decrypt",
	"kms:generate-data-key",
	"kms:sign",
	"kms:verify",
	"kms:generate-mac",
	"kms:verify-mac",
	// Private certificate authority (pki.ts): authorities, issuing, workload certificates, revocation.
	"pki:create",
	"pki:read",
	"pki:update",
	"pki:issue",
	"pki:request",
	"pki:revoke",
	// Data protection (tokenization.ts): profiles; tokenizing, detokenizing for a purpose, masking, erasure.
	"protection:read",
	"protection:manage",
	"protection:tokenize",
	"protection:detokenize",
	"protection:mask",
	"protection:delete",
	// Secrets vault (vault.ts): metadata, values, new versions, rotation, check-outs and leases, administration.
	"vault:read",
	"vault:reveal",
	"vault:write",
	"vault:rotate",
	"vault:lease",
	"vault:manage",
	// API usage plans and quotas (quotas.ts): reading plans, assignments and usage; defining and assigning plans.
	"quotas:read",
	"quotas:manage",
	// Privacy and consent (privacy.ts): purposes and settings, consent records and reports, application-recorded
	// decisions, consent checks, and handling data-subject requests.
	"privacy:read",
	"privacy:manage",
	"privacy:record",
	"privacy:check",
	"privacy:handle",
	// SSH certificate authority (ssh.ts, api/ssh.ts): authorities, hosts, settings and revocation; reviews and listings.
	// Getting a certificate is `ssh:login` on `ssh-login/{host}/{login}`, decided like any application action.
	"ssh:read",
	"ssh:manage",
	// Identity threat detection and response (threats.ts, api/threats.ts): reading detections, incidents and risk;
	// tuning rules, triage and playbooks; responding to identities and networks (contain, release, block, set risk).
	"threats:read",
	"threats:manage",
	"threats:respond",
	// Lifecycle workflows (workflows.ts, api/workflows.ts): reading workflows and runs; saving them; running them.
	"workflows:read",
	"workflows:manage",
	"workflows:run",
	// Compliance center (compliance.ts, api/compliance.ts): reading controls, results and evidence; running
	// evaluations; managing controls and exceptions.
	"compliance:read",
	"compliance:evaluate",
	"compliance:manage",
	// Application catalog (applications.ts, api/applications.ts): reading apps and usage; registering apps; assigning
	// them to people and groups. Launching one's own apps needs no permission.
	"applications:read",
	"applications:manage",
	"applications:assign",
	// Verifiable credentials (vc.ts, api/verifiable-credentials.ts): types and keys; issued credentials; wallet offers
	// for others; revocation and suspension. People get their own with `vc:request` on `credential-type/{name}`.
	"vc:read",
	"vc:manage",
	"vc:issue",
	"vc:revoke",
	// The LDAP directory gateway (ldap.ts, api/ldap.ts, @better-iam/ldap): reading the published directory; settings.
	"ldap:read",
	"ldap:manage",
	// Device posture (devices.ts, api/devices.ts): devices, keys, integrations and settings; managing them; integrations
	// reporting devices and posture on `iam/devices/integrations/{id}`.
	"devices:read",
	"devices:manage",
	"devices:report",
	// Shared Signals receiver (signal-receiver.ts, api/signals.ts): reading sources and received events; registering
	// and changing sources, reprocessing events and polling on demand.
	"signals:read",
	"signals:manage",
	// License management (licenses.ts, api/licenses.ts): reading products, pools, assignments, seats and usage; defining
	// products, adding capacity and settings; assigning products to people and groups.
	"licenses:read",
	"licenses:manage",
	"licenses:assign",
	// B2B guest collaboration (guests.ts, api/guests.ts): reading guests, invitations and settings; inviting guests;
	// managing guests (revoking invitations, renewing, sponsors, removal, conversion); cross-tenant access settings.
	"guests:read",
	"guests:invite",
	"guests:manage",
	"guests:settings",
	// Security clearances (clearances.ts, api/clearances.ts): reading clearances, schemes and labels; adjudicating
	// (grant, update, read-in, debrief, reinstate, revoke, explain); suspending in an incident; defining the scheme;
	// labeling resources (raise only); declassifying (lowering or removing a label).
	"clearances:read",
	"clearances:adjudicate",
	"clearances:suspend",
	"classifications:manage",
	"classifications:label",
	"classifications:declassify",
}

// BuiltInActions are the platform's own actions (`iam:{name}`), in catalog order. Products, plugins, and tenants
// add their own names.
var BuiltInActions = func() []string {
	actions := make([]string, len(builtInActionNames))
	for index, name := range builtInActionNames {
		actions[index] = "iam:" + name
	}
	return actions
}()

// InternalResourceTypes are resource types the platform resolves itself; products and tenants cannot redefine them.
var InternalResourceTypes = newOrderedSet("iam", "oauth-client", "scim", "saml", "ssf", "role")

// ReservedResourceTypes are the internal types plus tenant, identity and session.
var ReservedResourceTypes = newOrderedSet(append(InternalResourceTypes.Values(), "tenant", "identity", "session")...)

// ResourceTypeName is the shape of a resource type name.
var ResourceTypeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

var attributeTypes = map[string]bool{"string": true, "number": true, "boolean": true}

// CatalogResourceType is a platform or tenant-defined resource type.
type CatalogResourceType struct {
	Name string `json:"name"`
	// Source is platform or tenant.
	Source      string   `json:"source"`
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions"`
	// Attributes maps attribute names to string, number or boolean, in declaration order.
	Attributes *core.Object `json:"attributes"`
	Parent     string       `json:"parent,omitempty"`
	Managed    bool         `json:"managed"`
	// Relations are the relation names identities and groups may hold on resources of this type.
	Relations []string `json:"relations"`
}

var relationNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// RelationNames validates relation names: short identifiers, at most 32 distinct per type.
func RelationNames(value any) ([]string, error) {
	if isUndefined(value) {
		return []string{}, nil
	}
	names, err := Strings(value, "relations")
	if err != nil {
		return nil, err
	}
	names = unique(names)
	invalid := len(names) > 32
	for _, name := range names {
		if !relationNamePattern.MatchString(name) {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput("relations must contain at most 32 lowercase identifiers")
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

var attributeNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

// AttributeSchema validates declared attributes; reserved holds names the deployment reserves besides tenantId
// (Catalog.ReservedAttributes; nil for none).
func AttributeSchema(value any, reserved *orderedSet) (*core.Object, error) {
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	schema, err := Object(value)
	if err != nil {
		return nil, err
	}
	result := core.NewObject()
	if schema.Len() > 64 {
		return nil, invalidInput("At most 64 attributes may be declared")
	}
	for _, entry := range objectEntries(schema) {
		key := entry.key
		if !attributeNamePattern.MatchString(key) || key == "tenantId" {
			return nil, invalidInput("Invalid attribute name " + key)
		}
		if reserved.Has(key) {
			return nil, invalidInput("Attribute name " + key + " is reserved")
		}
		kind, ok := entry.value.(string)
		if !ok || !attributeTypes[kind] {
			return nil, invalidInput("Attribute " + key + " must be string, number, or boolean")
		}
		result.Set(key, kind)
	}
	return result, nil
}

const maxFloat = 1.7976931348623157e308

// AttributeValues validates attribute values against a schema.
func AttributeValues(schema *core.Object, value any) (*core.Object, error) {
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	result := core.NewObject()
	for _, entry := range objectEntries(input) {
		key, item := entry.key, entry.value
		kind, _ := schema.Get(key).(string)
		if kind == "" {
			return nil, invalidInput("Attribute " + key + " is not declared for this resource type")
		}
		invalid := typeOf(item) != kind
		if !invalid && kind == "number" {
			number := item.(float64)
			invalid = number != number || number > maxFloat || number < -maxFloat
		}
		if !invalid && kind == "string" {
			text := item.(string)
			invalid = utf16Len(text) > 2048 || hasControl(text)
		}
		if invalid {
			return nil, invalidInput("Attribute " + key + " must be a " + kind)
		}
		result.Set(key, item)
	}
	return result, nil
}

// ManagedResource is a registered managed resource, keyed by `{type}/{resourceId}` within its tenant (nil when none).
func ManagedResource(ctx context.Context, tx core.IamStore, tenantID, kind, resourceID string) (*core.Object, error) {
	found, err := tx.Find(ctx, "resources", core.NewObject("tenantId", tenantID, "uniqueKey", kind+"/"+resourceID), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// ResolvedManaged presents a managed registration to the policy engine: attributes plus owner and parent links.
func ResolvedManaged(record *core.Object) ResolvedResource {
	attributes := core.NewObject()
	if stored, ok := record.Object("attributes"); ok {
		attributes = stored.Spread()
	}
	if owner := record.Get("ownerId"); !isUndefined(owner) {
		attributes.Set("ownerId", owner)
	}
	if parent := record.Get("parentId"); !isUndefined(parent) {
		attributes.Set("parentId", parent)
		attributes.Set("parentType", record.Get("parentType"))
	}
	tenantID, _ := record.String("tenantId")
	kind, _ := record.String("type")
	id, _ := record.String("resourceId")
	return ResolvedResource{TenantID: tenantID, Type: kind, ID: id, Attributes: attributes}
}

// ReservedPrincipalKeys are principal context keys the server derives itself; identity attributes cannot shadow
// them. The session-derived names (ReservedSessionPrincipalNames) are reserved as well.
var ReservedPrincipalKeys = newOrderedSet(append([]string{
	"id", "tenantId", "mfa", "kind", "owner", "rootAdmin", "groups", "roles", "sessionKind", "authMethod",
	"impersonated", "impersonatorId", "agreements", "pendingAgreements", "onboarding", "pendingOnboarding", "teams",
	"departments", "departmentId", "spendExceeded", "budgetsExceeded", "consents", "riskLevel", "riskScore",
	"licenses", "guest", "guestSponsorId", "homeTenantId",
}, ReservedSessionPrincipalNames...)...)

func clearanceNames(prefix string) *orderedSet {
	set := newOrderedSet()
	for _, key := range ClearanceServerKeys.Values() {
		if strings.HasPrefix(key, prefix) {
			set.Add(key[len(prefix):])
		}
	}
	return set
}

// ClearancePrincipalNames are the clearance keys as identity attribute names (reserved only with clearances).
var ClearancePrincipalNames = clearanceNames("principal.")

// ClassificationAttributeNames are a classification label's keys as resource attribute names (reserved only with
// clearances).
var ClassificationAttributeNames = clearanceNames("resource.")

var reservedActionPattern = regexp.MustCompile(`[*?` + jsWhitespace + `]`)

// Catalog is the permission catalog: platform actions and resource types declared in configuration plus, per tenant,
// the types and `{type}:{verb}` actions a tenant registered itself when permissions.mode is tenant-defined.
type Catalog struct {
	// Actions are the platform's actions in catalog order: built-ins, configured actions, plugin actions.
	Actions *orderedSet
	// ActionTypes maps an action to the resource type that declared it.
	ActionTypes map[string]string
	// ResourceTypes are the platform resource types; ResourceTypeNames lists them in declaration order.
	ResourceTypes     map[string]*CatalogResourceType
	ResourceTypeNames []string
	Namespaces        *orderedSet
	// IdentityAttributes are the typed attributes administrators may set on identities (principal.{name}).
	IdentityAttributes *core.Object
	// ReservedAttributes are the resource attribute names this deployment reserves besides tenantId: a
	// classification label's keys with options.clearances, nil otherwise.
	ReservedAttributes *orderedSet
	config             *ServerConfig
}

// NewCatalog builds the catalog from the options (OptionsValue) and plugins.
func NewCatalog(options *core.Object, plugins []*core.IamPlugin, config *ServerConfig) (*Catalog, error) {
	catalog := &Catalog{
		Actions:       newOrderedSet(BuiltInActions...),
		ActionTypes:   map[string]string{},
		ResourceTypes: map[string]*CatalogResourceType{},
		config:        config,
	}
	permissions := member(options, "permissions")
	var actions []any
	if configured := member(permissions, "actions"); !nullish(configured) {
		list, ok := configured.([]any)
		if !ok {
			return nil, &core.TypeError{Message: "options.permissions.actions is not iterable"}
		}
		actions = append(actions, list...)
	}
	for _, plugin := range plugins {
		actions = append(actions, stringsOf(plugin.Actions)...)
	}
	for _, action := range actions {
		if err := catalog.registerAction(action, ""); err != nil {
			return nil, err
		}
	}
	attributes, err := AttributeSchema(member(permissions, "identityAttributes"), nil)
	if err != nil {
		return nil, invalidConfig("identityAttributes: " + errorMessage(err))
	}
	catalog.IdentityAttributes = attributes
	for _, key := range attributes.Keys() {
		if ReservedPrincipalKeys.Has(key) || (config.Clearances != nil && ClearancePrincipalNames.Has(key)) {
			return nil, invalidConfig("identityAttributes cannot redefine principal." + key)
		}
	}
	if config.Clearances != nil {
		catalog.ReservedAttributes = ClassificationAttributeNames
	}
	declared := objectEntries(coalesce(member(permissions, "resourceTypes"), core.NewObject()))
	for _, plugin := range plugins {
		if plugin.ResourceTypes != nil {
			declared = append(declared, objectEntries(ResourceTypesValue(plugin.ResourceTypes))...)
		}
	}
	for _, entry := range declared {
		name := entry.key
		if !ResourceTypeName.MatchString(name) || ReservedResourceTypes.Has(name) {
			return nil, invalidConfig("Invalid or reserved resource type name " + name)
		}
		if _, exists := catalog.ResourceTypes[name]; exists {
			return nil, invalidConfig("Resource type " + name + " is declared more than once")
		}
		definition, err := Object(entry.value)
		if err != nil {
			return nil, err
		}
		attributes, err := AttributeSchema(definition.Get("attributes"), catalog.ReservedAttributes)
		if err != nil {
			return nil, invalidConfig("Resource type " + name + ": " + errorMessage(err))
		}
		relations, err := RelationNames(definition.Get("relations"))
		if err != nil {
			return nil, invalidConfig("Resource type " + name + ": " + errorMessage(err))
		}
		typeActions, err := Strings(coalesce(definition.Get("actions"), []any{}), "actions")
		if err != nil {
			return nil, err
		}
		for _, action := range typeActions {
			if err := catalog.registerAction(action, name); err != nil {
				return nil, err
			}
		}
		description := definition.Get("description")
		if !isUndefined(description) {
			if _, err := Text(description, "description", 512); err != nil {
				return nil, err
			}
		}
		resourceType := &CatalogResourceType{
			Name: name, Source: "platform", Actions: typeActions, Attributes: attributes,
			Managed: truthy(coalesce(definition.Get("managed"), false)), Relations: relations,
		}
		resourceType.Description, _ = description.(string)
		if parent := definition.Get("parent"); !isUndefined(parent) {
			resourceType.Parent = jsString(parent)
		}
		catalog.ResourceTypes[name] = resourceType
		catalog.ResourceTypeNames = append(catalog.ResourceTypeNames, name)
	}
	for _, name := range catalog.ResourceTypeNames {
		definition := catalog.ResourceTypes[name]
		seen := map[string]bool{}
		current := definition.Parent
		for current != "" {
			parent, known := catalog.ResourceTypes[current]
			if current == definition.Name || seen[current] || !known {
				return nil, invalidConfig("Resource type " + definition.Name + " has an invalid parent chain")
			}
			if definition.Managed && !parent.Managed {
				return nil, invalidConfig("Managed resource type " + definition.Name + " requires a managed parent")
			}
			seen[current] = true
			current = parent.Parent
		}
	}
	catalog.Namespaces = newOrderedSet()
	for _, action := range catalog.Actions.Values() {
		namespace, _, _ := strings.Cut(action, ":")
		catalog.Namespaces.Add(namespace)
	}
	return catalog, nil
}

func (c *Catalog) registerAction(value any, resourceType string) error {
	action, err := Text(value, "action")
	if err != nil {
		return err
	}
	if strings.HasPrefix(action, "iam:") || strings.HasPrefix(action, "tenant/") || reservedActionPattern.MatchString(action) {
		return invalidConfig("Reserved or invalid action")
	}
	c.Actions.Add(action)
	if resourceType != "" {
		if _, exists := c.ActionTypes[action]; !exists {
			c.ActionTypes[action] = resourceType
		}
	}
	return nil
}

// TenantResourceType is a tenant-defined resource type record (nil when none).
func (c *Catalog) TenantResourceType(ctx context.Context, tx core.IamStore, tenantID, name string) (*core.Object, error) {
	found, err := tx.Find(ctx, "resourceTypes", core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// ResourceTypeDefinition is a platform or tenant-defined resource type, or nil when the name is unknown.
func (c *Catalog) ResourceTypeDefinition(ctx context.Context, tx core.IamStore, tenantID, name string) (*CatalogResourceType, error) {
	if platform, ok := c.ResourceTypes[name]; ok {
		return platform, nil
	}
	record, err := c.TenantResourceType(ctx, tx, tenantID, name)
	if err != nil || record == nil {
		return nil, err
	}
	actions, err := tx.Find(ctx, "actions", core.NewObject("tenantId", tenantID, "resourceType", name), nil)
	if err != nil {
		return nil, err
	}
	typeActions := make([]string, len(actions))
	for index, action := range actions {
		typeActions[index] = jsString(action.Get("name"))
	}
	definition := &CatalogResourceType{Name: name, Source: "tenant", Actions: typeActions, Managed: true, Relations: []string{}}
	definition.Description, _ = record.String("description")
	definition.Attributes, _ = record.Object("attributes")
	definition.Parent, _ = record.String("parent")
	if relations, ok := record.Array("relations"); ok {
		for _, relation := range relations {
			definition.Relations = append(definition.Relations, jsString(relation))
		}
	}
	return definition, nil
}

// ManagedDefinition is a managed type (platform-declared with managed: true, or any tenant-defined type).
func (c *Catalog) ManagedDefinition(ctx context.Context, tx core.IamStore, tenantID string, kind any) (*CatalogResourceType, error) {
	name, err := Text(kind, "resource type", 64)
	if err != nil {
		return nil, err
	}
	definition, err := c.ResourceTypeDefinition(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if definition == nil {
		return nil, core.NewIamError("INVALID_RESOURCE_TYPE", "Unknown resource type")
	}
	if !definition.Managed {
		return nil, core.NewIamError("INVALID_RESOURCE_TYPE", "This resource type is resolved by the application, not registered with IAM")
	}
	return definition, nil
}

// KnownAction reports whether an action is a platform action or one the tenant registered.
func (c *Catalog) KnownAction(ctx context.Context, tx core.IamStore, tenantID, action string) (bool, error) {
	if c.Actions.Has(action) {
		return true, nil
	}
	found, err := tx.Find(ctx, "actions", core.NewObject("tenantId", tenantID, "uniqueKey", action), nil)
	if err != nil {
		return false, err
	}
	return len(found) > 0, nil
}

var tenantActionPattern = regexp.MustCompile(`^([a-z][a-z0-9-]{0,63}):([a-zA-Z][a-zA-Z0-9_-]{0,63})$`)

// RegisterTenantAction registers a tenant-defined action, namespaced under a tenant-defined resource type:
// `{type}:{verb}`. description is core.Undefined when absent.
func (c *Catalog) RegisterTenantAction(ctx context.Context, tx core.IamStore, tenantID string, rawName any, description any) (*core.Object, error) {
	if !c.config.TenantDefined {
		return nil, core.NewIamError("CATALOG_LOCKED", "Tenant-defined actions are disabled", 403)
	}
	name, err := Text(rawName, "action", 128)
	if err != nil {
		return nil, err
	}
	match := tenantActionPattern.FindStringSubmatch(name)
	if match == nil || c.Actions.Has(name) || c.Namespaces.Has(match[1]) {
		return nil, core.NewIamError("INVALID_ACTION", "Tenant actions must be {resourceType}:{verb} under a tenant-defined resource type")
	}
	resourceType, err := c.TenantResourceType(ctx, tx, tenantID, match[1])
	if err != nil {
		return nil, err
	}
	if resourceType == nil {
		return nil, core.NewIamError("INVALID_ACTION", "Register resource type "+match[1]+" before its actions")
	}
	known, err := c.KnownAction(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if known {
		return nil, core.NewIamError("CONFLICT", "Action already exists", 409)
	}
	definition := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", name, "name", name, "resourceType", match[1])
	if !isUndefined(description) {
		text, err := Text(description, "description", 512)
		if err != nil {
			return nil, err
		}
		definition.Set("description", text)
	}
	return tx.Insert(ctx, "actions", definition)
}

// documentsReference reports whether any statement of the documents lists the action.
func documentsReference(documents []any, name string) bool {
	for _, document := range documents {
		statements, _ := member(document, "statements").([]any)
		for _, statement := range statements {
			actions, _ := member(statement, "actions").([]any)
			for _, action := range actions {
				if action == name {
					return true
				}
			}
		}
	}
	return false
}

// AssertActionUnused refuses deleting an action while any policy or inline role document still names it.
func (c *Catalog) AssertActionUnused(ctx context.Context, tx core.IamStore, tenantID, name string) error {
	policies, err := tx.Find(ctx, "policies", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	documents := make([]any, len(policies))
	for index, policy := range policies {
		documents[index] = policy.Get("document")
	}
	roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	var inline []any
	for _, role := range roles {
		if document := role.Get("document"); truthy(document) {
			inline = append(inline, document)
		}
	}
	if documentsReference(documents, name) || documentsReference(inline, name) {
		return core.NewIamError("RESOURCE_IN_USE", "Remove the action from policies and roles first", 409)
	}
	return nil
}

// Validate requires policies to name only actions and resource types that exist for the tenant; wildcard patterns
// are not resolved. The document is a model value (or a core.PolicyDocument).
func (c *Catalog) Validate(ctx context.Context, tx core.IamStore, tenantID string, document any) error {
	if err := core.ValidatePolicy(document); err != nil {
		return err
	}
	value := core.PolicyValue(document)
	statements, _ := member(value, "statements").([]any)
	for _, statement := range statements {
		actions, _ := member(statement, "actions").([]any)
		for _, item := range actions {
			action, _ := item.(string)
			if !strings.ContainsAny(action, "*?") {
				known, err := c.KnownAction(ctx, tx, tenantID, action)
				if err != nil {
					return err
				}
				if !known {
					return core.NewIamError("INVALID_ACTION", "Unknown action "+action)
				}
			}
		}
		if !c.config.StrictResourceTypes {
			continue
		}
		resources, _ := member(statement, "resources").([]any)
		for _, item := range resources {
			pattern, _ := item.(string)
			kind, _, _ := strings.Cut(pattern, "/")
			if !strings.ContainsAny(kind, "*?") && !InternalResourceTypes.Has(kind) {
				definition, err := c.ResourceTypeDefinition(ctx, tx, tenantID, kind)
				if err != nil {
					return err
				}
				if definition == nil {
					return core.NewIamError("INVALID_RESOURCE_TYPE", "Unknown resource type "+kind)
				}
			}
		}
	}
	return nil
}
