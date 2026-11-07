package server

// Port of packages/server/src/decisions.ts: the decision engine. Grant paths (bindings -> roles -> policies, each
// bounded by every authority ceiling on the way down), the principal and request context, resource resolution, and
// the prepared evaluator that decides one tenant and action against many resources.

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// GrantPath is one way a principal receives a policy: the grant plus every ceiling that bounds it. Documents are
// model values (policy documents as *core.Object).
type GrantPath struct {
	Grants      []any
	Boundaries  []any
	AuthorityID string
}

// DecisionInputs is what a prepared decision evaluates from (everything but the resource). Read-only.
type DecisionInputs struct {
	// Context holds the principal, request and tenant context keys.
	Context *core.Object
	// Boundaries are the ceilings over every grant path.
	Boundaries []any
	// Paths are the grant paths (deny-only paths included).
	Paths []GrantPath
	// Denies are the deny statements across every path.
	Denies []any
	// Held are the relations the principal holds, keyed by `{type}/{id}` (relation sets in insertion order).
	Held map[string][]string
	// HeldOrder lists the keys of Held in the order they were first held (a Map's order).
	HeldOrder []string
	// Confirm is a delegation's per-action confirmation gate, when the session has one (nil decision: no gate).
	Confirm func(action, resourceType, resourceID string) *core.Decision
	// Mandatory is the mandatory access check (security clearances); nil when off or the tenant has no scheme.
	Mandatory *MandatoryAccess
}

// PreparedDecision is a decision prepared for one tenant and action: Fixed, or an evaluator applied per resource.
type PreparedDecision struct {
	// Fixed is the decision for every resource (root override, refusals before any grant).
	Fixed *core.Decision
	// Evaluate evaluates the prepared grants against one resource, for the prepared action or an override ("").
	Evaluate func(resource ResolvedResource, action string) (core.Decision, error)
	// Inputs is what Evaluate decides from, for query planning.
	Inputs *DecisionInputs
	// RootOverride marks the platform's root override under mandatory access control.
	RootOverride bool
}

// IsRootOverride reports whether a prepared decision is the platform's root override: the fixed form, or the
// evaluator it becomes under security clearances.
func IsRootOverride(prepared *PreparedDecision) bool {
	if prepared.Fixed != nil {
		return prepared.Fixed.Reason == "ROOT_OVERRIDE"
	}
	return prepared.RootOverride
}

// DecideOn is the decision a prepared decision makes on one resource, for the prepared action or action ("").
func DecideOn(prepared *PreparedDecision, resource ResolvedResource, action string) (core.Decision, error) {
	if prepared.Fixed != nil {
		return *prepared.Fixed, nil
	}
	return prepared.Evaluate(resource, action)
}

// SchemeKnown is what Resolve may take as known from a decision prepared in the same tenant: the scheme its
// mandatory check enforces (Scheme nil: none).
type SchemeKnown struct {
	Scheme *core.Object
}

// PreparedLabeling is the SchemeKnown of a prepared decision; nil for a fixed decision, which says nothing about it.
func PreparedLabeling(prepared *PreparedDecision) *SchemeKnown {
	if prepared.Fixed != nil || prepared.Inputs == nil {
		return nil
	}
	known := &SchemeKnown{}
	if prepared.Inputs.Mandatory != nil {
		known.Scheme = prepared.Inputs.Mandatory.Scheme
	}
	return known
}

// GrantSources are an identity's group memberships and every live binding that applies to it.
type GrantSources struct {
	// GroupIDs in insertion order (a TypeScript Set).
	GroupIDs []string
	Bindings []*core.Object
}

func (s *GrantSources) hasGroup(id string) bool { return containsString(s.GroupIDs, id) }

// EffectiveBinding is a binding that applies to an identity directly or through a group.
type EffectiveBinding struct {
	Binding *core.Object
	Role    *core.Object
	// ViaGroupID is the group the binding applies through; "" for a direct (identity) binding.
	ViaGroupID string
	// Activation (id, activatedAt, expiresAt) is present only while the identity holds a live activation.
	Activation *core.Object
	// PendingActivation (id, requestedAt, expiresAt) is an activation request awaiting approval.
	PendingActivation *core.Object
	// InWindow is set for bindings with an access window: whether the window is open right now.
	InWindow *bool
}

// Model is the effective binding as the TypeScript object: the binding's members, then role, via, inWindow,
// activation and pendingActivation.
func (b EffectiveBinding) Model() *core.Object {
	result := b.Binding.Spread()
	if b.Role != nil {
		result.Set("role", b.Role)
	} else {
		result.Set("role", core.Undefined)
	}
	if b.ViaGroupID == "" {
		result.Set("via", "identity")
	} else {
		result.Set("via", core.NewObject("groupId", b.ViaGroupID))
	}
	if b.InWindow != nil {
		result.Set("inWindow", *b.InWindow)
	}
	if b.Activation != nil {
		result.Set("activation", b.Activation)
	}
	if b.PendingActivation != nil {
		result.Set("pendingActivation", b.PendingActivation)
	}
	return result
}

// DecisionService is decisions.ts DecisionService.
type DecisionService interface {
	// RoleGrants is the grant paths of a role: its inline document, its attached policies, and (recursively) the
	// grants of the roles it inherits, each bounded by every authority ceiling on the way down. seen (nil: new)
	// guards against cycles; lapsed (nil: not collected) receives the denies of parts whose authority was revoked.
	RoleGrants(ctx context.Context, tx core.IamStore, role *core.Object, tenantID string, ceilings []any, authorityID string, seen map[string]bool, lapsed *[]GrantPath) ([]GrantPath, error)
	GrantSources(ctx context.Context, tx core.IamStore, identityID, tenantID string) (*GrantSources, error)
	LiveActivations(ctx context.Context, tx core.IamStore, tenantID, identityID string) (map[string]*core.Object, error)
	IdentityGrants(ctx context.Context, tx core.IamStore, identityID, tenantID string, sources *GrantSources, lapsed *[]GrantPath) ([]GrantPath, error)
	EffectiveBindings(ctx context.Context, tx core.IamStore, tenantID, identityID string) ([]EffectiveBinding, error)
	// Resolve loads a resource's trusted attributes from the registry or the application resolver (action "": none).
	Resolve(ctx context.Context, tx core.IamStore, reference core.ResourceRef, internal bool, action string, known *SchemeKnown) (*ResolvedResource, error)
	PrepareDecision(ctx context.Context, tx core.IamStore, principal *Principal, target *core.Object, action string) (*PreparedDecision, error)
	Decide(ctx context.Context, tx core.IamStore, principal *Principal, request AuthorizationRequest, internalResource bool) (core.Decision, error)
	SimulatedPrincipal(identity *core.Object, mfa bool) *Principal
}

// ImpersonatingActor is the administrator behind an impersonation ("view as") session, acting through their own
// source session; nil for every other principal.
func ImpersonatingActor(ctx context.Context, tx core.IamStore, principal *Principal) (*Principal, error) {
	actorID := principal.Session.Get("impersonatorId")
	if !truthy(actorID) {
		return nil, nil
	}
	var session *core.Object
	if sourceID := principal.Session.Get("impersonatorSessionId"); truthy(sourceID) {
		found, err := tx.Get(ctx, "sessions", jsString(sourceID))
		if err != nil {
			return nil, err
		}
		session = found
	}
	identity, err := tx.Get(ctx, "identities", jsString(actorID))
	if err != nil {
		return nil, err
	}
	if session == nil || identity == nil || session.Get("identityId") != identity.Get("id") || identity.Get("status") != "active" {
		return nil, core.NewIamError("UNAUTHENTICATED", "Impersonation has ended", 401)
	}
	// The administrator's side of the decision sees the device this request proves (bound to the "view as" session).
	return WithRequestDevice(&Principal{Identity: identity, Session: session}, principal), nil
}

// ShadowsApplicationType reports whether a type only a tenant registered must not answer for action ("": none)
// from that tenant's registry: tenant types answer for their own actions (`{type}:{verb}`) only.
func ShadowsApplicationType(definition *CatalogResourceType, kind, action string, hasAction, resolver bool) bool {
	return resolver && definition != nil && definition.Source == "tenant" && hasAction && !strings.HasPrefix(action, kind+":")
}

// maxInheritedRoles is how deep an inheritance hierarchy is followed: roles.ts refuses writes past 200 roles.
const maxInheritedRoles = 256

func statementsOf(document any) []any {
	statements, _ := member(document, "statements").([]any)
	return statements
}

// denyOnly is `{ ...document, statements: <deny statements> }`.
func denyOnly(document any) *core.Object {
	var denies []any
	for _, statement := range statementsOf(document) {
		if member(statement, "effect") == "deny" {
			denies = append(denies, statement)
		}
	}
	if denies == nil {
		denies = []any{}
	}
	if object, ok := document.(*core.Object); ok && object != nil {
		return object.Spread(core.NewObject("statements", denies))
	}
	return core.NewObject("statements", denies)
}

// denyPaths are the deny statements of documents as one path that grants nothing.
func denyPaths(documents []any, authorityID string) []GrantPath {
	var grants []any
	for _, document := range documents {
		filtered := denyOnly(document)
		if statements, _ := filtered.Get("statements").([]any); len(statements) > 0 {
			grants = append(grants, filtered)
		}
	}
	if len(grants) == 0 {
		return nil
	}
	return []GrantPath{{Grants: grants, Boundaries: []any{}, AuthorityID: authorityID}}
}

// roleDenies is every deny statement a role carries (inline, attached policies, inherited roles), used where an
// authority behind the role has been revoked: what it granted lapses, what it forbade does not.
func roleDenies(ctx context.Context, tx core.IamStore, role *core.Object, tenantID, authorityID string, seen map[string]bool) ([]GrantPath, error) {
	var documents []any
	seen[jsString(role.Get("id"))] = true
	for queue := []*core.Object{role}; len(queue) > 0; {
		current := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if current.Get("tenantId") != tenantID {
			continue
		}
		if document := current.Get("document"); truthy(document) {
			documents = append(documents, document)
		}
		policyIDs, _ := current.Get("policyIds").([]any)
		for _, policyID := range policyIDs {
			policy, err := tx.Get(ctx, "policies", jsString(policyID))
			if err != nil {
				return nil, err
			}
			if policy != nil && policy.Get("tenantId") == tenantID {
				documents = append(documents, policy.Get("document"))
			}
		}
		inherits, _ := current.Get("inherits").([]any)
		for _, inheritedID := range inherits {
			id := jsString(inheritedID)
			if seen[id] || len(seen) > maxInheritedRoles {
				continue
			}
			seen[id] = true
			inherited, err := tx.Get(ctx, "roles", id)
			if err != nil {
				return nil, err
			}
			if inherited != nil && !truthy(inherited.Get("protected")) {
				queue = append(queue, inherited)
			}
		}
	}
	return denyPaths(documents, authorityID), nil
}

// RoleDenyStatements is every deny statement a role carries, as canonical JSON, whatever the authorities behind
// them: what holders of the role are forbidden.
func RoleDenyStatements(ctx context.Context, tx core.IamStore, role *core.Object) (map[string]bool, error) {
	paths, err := roleDenies(ctx, tx, role, jsString(role.Get("tenantId")), "", map[string]bool{})
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for _, path := range paths {
		for _, document := range path.Grants {
			for _, statement := range statementsOf(document) {
				result[core.CanonicalJSON(statement)] = true
			}
		}
	}
	return result, nil
}

// DocumentDenyStatements is the deny statements of a document, as canonical JSON.
func DocumentDenyStatements(document any) map[string]bool {
	result := map[string]bool{}
	for _, statement := range statementsOf(document) {
		if member(statement, "effect") == "deny" {
			result[core.CanonicalJSON(statement)] = true
		}
	}
	return result
}

// ModuleResourceLabels gives resources a module builds itself (SSH logins and hosts, credential types) their
// classification label exactly as Resolve attaches it; the identity when clearances are off.
func ModuleResourceLabels(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, resources []ResolvedResource) (func(ResolvedResource) ResolvedResource, error) {
	if server.Config.Clearances == nil || len(resources) == 0 {
		return func(resource ResolvedResource) ResolvedResource { return resource }, nil
	}
	scheme, err := SchemeForTenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	labels := map[string]ResolvedResource{}
	for _, resource := range resources {
		key := resource.Type + "/" + resource.ID
		if _, done := labels[key]; resource.TenantID == tenantID && !done {
			labeled, err := AttachLabel(ctx, server, tx, tenantID, resource, AttachLabelOptions{Scheme: scheme})
			if err != nil {
				return nil, err
			}
			labels[key] = labeled
		}
	}
	return func(resource ResolvedResource) ResolvedResource {
		labeled, found := labels[resource.Type+"/"+resource.ID]
		if resource.TenantID != tenantID || !found {
			return resource
		}
		resource.HasClassification, resource.Classification = labeled.HasClassification, labeled.Classification
		return resource
	}, nil
}

func stringIDs(value any) []any {
	list, _ := value.([]any)
	out := []any{}
	for _, item := range list {
		if _, ok := item.(string); ok {
			out = append(out, item)
		}
	}
	return out
}

// classificationKeys are a resource's classification keys as the scheme applies its label.
func classificationKeys(mandatory *MandatoryAccess, resource ResolvedResource) *core.Object {
	var label *core.Object
	if mandatory != nil {
		label = mandatory.Label(resource)
	}
	keys := core.NewObject()
	if level, ok := member(label, "level").(string); ok && label != nil {
		keys.Set("resource.classification", level)
	} else {
		keys.Set("resource.classification", core.Undefined)
	}
	if label != nil {
		if rank := mandatory.Rank(label); rank != nil {
			keys.Set("resource.classificationRank", *rank)
		} else {
			keys.Set("resource.classificationRank", core.Undefined)
		}
	} else {
		keys.Set("resource.classificationRank", -1.0)
	}
	var compartments, releasable any = []any{}, []any{}
	noforn := false
	if label != nil {
		compartments = stringIDs(label.Get("compartments"))
		releasable = stringIDs(label.Get("releasableTo"))
		noforn = label.Get("noforn") == true
	}
	keys.Set("resource.compartments", compartments)
	keys.Set("resource.noforn", noforn)
	keys.Set("resource.releasableTo", releasable)
	return keys
}

// unclearedKeys are the clearance keys when clearances are on but the tenant has no scheme.
func unclearedKeys() *core.Object {
	return core.NewObject(
		"principal.clearanceRank", -1.0, "principal.clearanceStatus", "none",
		"principal.clearanceCompartments", []any{}, "principal.clearanceCitizenship", []any{},
	)
}

// groupLookupLimit: above this many groups one tenant-wide read is cheaper than a lookup per group.
const groupLookupLimit = 24

// subjectBindings are the bindings whose subject is the identity or one of the groups, in id order.
func subjectBindings(ctx context.Context, tx core.IamStore, tenantID, identityID string, groupIDs []string) ([]*core.Object, error) {
	if len(groupIDs) > groupLookupLimit {
		all, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var found []*core.Object
		for _, binding := range all {
			if binding.Get("subjectType") == "identity" {
				if binding.Get("subjectId") == identityID {
					found = append(found, binding)
				}
			} else if containsString(groupIDs, jsString(binding.Get("subjectId"))) {
				found = append(found, binding)
			}
		}
		return found, nil
	}
	found, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, groupID := range groupIDs {
		more, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return nil, err
		}
		found = append(found, more...)
	}
	sortStable(found, func(left, right *core.Object) int {
		return core.CompareIDs(jsString(left.Get("id")), jsString(right.Get("id")))
	})
	return found, nil
}

// isoString is Date#toISOString for an epoch-millisecond time value (years outside 0-9999 as ±YYYYYY).
func isoString(ms float64) string {
	t := time.UnixMilli(int64(ms)).UTC()
	year := t.Year()
	rest := t.Format("-01-02T15:04:05.000Z")
	switch {
	case year < 0:
		return "-" + padNumber(-year, 6) + rest
	case year > 9999:
		return "+" + padNumber(year, 6) + rest
	}
	return padNumber(year, 4) + rest
}

func padNumber(value, width int) string {
	text := core.NumberString(float64(value))
	for len(text) < width {
		text = "0" + text
	}
	return text
}

// isoTime is an ISO-8601 timestamp; a value that is not a usable time reads as the epoch (fails freshness checks
// closed).
func isoTime(value any) string {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.Abs(number) > 8.64e15 {
		number = 0
	}
	return isoString(math.Trunc(number))
}

// sessionContextKeys are the session-aware context keys (see context_keys.go).
func sessionContextKeys(session *core.Object, clientIP string) *core.Object {
	type tag struct {
		key   string
		value string
	}
	var tags []tag
	if stored, ok := session.Get("sessionTags").(*core.Object); ok && stored != nil {
		stored.Entries(func(key string, value any) bool {
			if text, isString := value.(string); isString && SessionTagName(key) != "" {
				tags = append(tags, tag{key, text})
			}
			return true
		})
		sortStable(tags, func(left, right tag) int { return compareUTF16(left.key, right.key) })
	}
	tagKeys := make([]any, len(tags))
	for index, item := range tags {
		tagKeys[index] = item.key
	}
	keys := core.NewObject(
		"principal.sessionId", session.Get("id"),
		"principal.tokenIssueTime", isoTime(session.Get("createdAt")),
		"principal.authTime", isoTime(session.Get("authenticatedAt")),
		"principal.sessionTagKeys", tagKeys,
	)
	if mfaAt, isNumber := session.Get("mfaAuthenticatedAt").(float64); session.Get("mfa") == true && isNumber &&
		!math.IsNaN(mfaAt) && !math.IsInf(mfaAt, 0) && !truthy(session.Get("trustedDeviceId")) && !truthy(session.Get("impersonatorId")) {
		keys.Set("principal.mfaTime", isoTime(mfaAt))
	}
	if source, isString := session.Get("sourceTenantId").(string); session.Get("kind") == "role" && isString {
		keys.Set("principal.sourceTenantId", source)
	}
	if name, isString := session.Get("sessionName").(string); isString {
		keys.Set("principal.sessionName", name)
	}
	if source, isString := session.Get("sourceIdentity").(string); isString {
		keys.Set("principal.sourceIdentity", source)
	}
	for _, item := range tags {
		keys.Set(SessionTagName(item.key), item.value)
	}
	if provider, isString := member(session.Get("webIdentity"), "providerId").(string); isString {
		keys.Set("principal.webIdentityProvider", provider)
	}
	if subject, isString := member(session.Get("webIdentity"), "subject").(string); isString {
		keys.Set("principal.webIdentitySubject", subject)
	}
	if session.Get("id") != "simulation" && clientIP != "" {
		if _, ok := core.IPCounterKey(clientIP); ok {
			keys.Set("request.sourceIp", clientIP)
		}
	}
	return keys
}

type decisions struct {
	server *ServerContext
}

// CreateDecisions builds the decision service (createDecisions).
func CreateDecisions(server *ServerContext) DecisionService {
	return &decisions{server: server}
}

// resolveUnlabeled is Resolve without the classification label.
func (d *decisions) resolveUnlabeled(ctx context.Context, tx core.IamStore, reference core.ResourceRef, internal bool, action string, hasAction bool) (*ResolvedResource, error) {
	server := d.server
	if _, err := Text(reference.Type, "resource type"); err != nil {
		return nil, err
	}
	if _, err := Text(reference.ID, "resource id"); err != nil {
		return nil, err
	}
	plain := &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}
	if internal && InternalResourceTypes.Has(reference.Type) {
		// Vault secrets (`iam/vault/secrets/{name}`) carry their tags and settings (vault.ts).
		secret, err := ResolveSecretResource(ctx, tx, reference)
		if err != nil || secret != nil {
			return secret, err
		}
		// `iam/{type}/{id}` naming a registered managed resource carries that resource's owner, parent and attributes.
		slash := -1
		if reference.Type == "iam" {
			slash = strings.Index(reference.ID, "/")
		}
		if slash > 0 {
			record, err := ManagedResource(ctx, tx, reference.TenantID, reference.ID[:slash], reference.ID[slash+1:])
			if err != nil {
				return nil, err
			}
			if record != nil {
				plain.Attributes = ResolvedManaged(record).Attributes
				return plain, nil
			}
		}
		return plain, nil
	}
	// AI models (`inference` option) resolve from the inference catalog, inherited down the tenant tree.
	if model, err := ResolveModelResource(ctx, server, tx, reference); err != nil || model != nil {
		return model, err
	}
	// SSH logins and hosts (`ssh` option).
	if ssh, err := ResolveSshResource(ctx, server, tx, reference); err != nil || ssh != nil {
		return ssh, err
	}
	// Credential types (`verifiableCredentials` option).
	if credentialType, err := ResolveCredentialTypeResource(ctx, server, tx, reference); err != nil || credentialType != nil {
		return credentialType, err
	}
	definition, err := server.Catalog.ResourceTypeDefinition(ctx, tx, reference.TenantID, reference.Type)
	if err != nil {
		return nil, err
	}
	resolver := server.Options.ResolveResource
	if definition != nil && definition.Managed && !ShadowsApplicationType(definition, reference.Type, action, hasAction, resolver != nil) {
		record, err := ManagedResource(ctx, tx, reference.TenantID, reference.Type, reference.ID)
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, core.NewIamError("NOT_FOUND", "Resource is not registered", 404)
		}
		resolved := ResolvedManaged(record)
		return &resolved, nil
	}
	if resolver == nil {
		return nil, core.NewIamError("RESOURCE_RESOLVER_REQUIRED", "Configure resolveResource for application resources")
	}
	resolved, err := resolver(ctx, reference)
	if err != nil {
		return nil, err
	}
	if resolved == nil || resolved.TenantID != reference.TenantID || resolved.ID != reference.ID || resolved.Type != reference.Type {
		return nil, core.NewIamError("RESOURCE_MISMATCH", "Resource ownership mismatch", 403)
	}
	return resolved, nil
}

// namedResource is, under security clearances, the resource an `iam/{type}/{id}` alias names, as Resolve answers
// for it: nil (with named false) when the alias names nothing beyond IAM's own records; a nil resource with named true
// when resolving it fails (the label then refuses).
func (d *decisions) namedResource(ctx context.Context, tx core.IamStore, reference core.ResourceRef, action string, hasAction bool) (resource *ResolvedResource, named bool, err error) {
	slash := -1
	if reference.Type == "iam" {
		slash = strings.Index(reference.ID, "/")
	}
	if slash <= 0 {
		return nil, false, nil
	}
	target := core.ResourceRef{TenantID: reference.TenantID, Type: reference.ID[:slash], ID: reference.ID[slash+1:]}
	if target.ID == "" || InternalResourceTypes.Has(target.Type) {
		return nil, false, nil
	}
	definition, err := d.server.Catalog.ResourceTypeDefinition(ctx, tx, target.TenantID, target.Type)
	if err != nil {
		return nil, false, err
	}
	if definition != nil && definition.Managed && !ShadowsApplicationType(definition, target.Type, action, hasAction, d.server.Options.ResolveResource != nil) {
		return nil, false, nil
	}
	resolved, err := d.resolveUnlabeled(ctx, tx, target, false, action, hasAction)
	if err != nil {
		var known *core.IamError
		if !errors.As(err, &known) {
			return nil, false, err
		}
		if known.Code == "RESOURCE_RESOLVER_REQUIRED" {
			return nil, false, nil
		}
		return nil, true, nil
	}
	return resolved, true, nil
}

func (d *decisions) RoleGrants(ctx context.Context, tx core.IamStore, role *core.Object, tenantID string, ceilings []any, authorityID string, seen map[string]bool, lapsed *[]GrantPath) ([]GrantPath, error) {
	server := d.server
	if seen == nil {
		seen = map[string]bool{}
	}
	var paths []GrantPath
	roleID := jsString(role.Get("id"))
	// As deep as roles.ts lets a hierarchy grow, so no inherited role (or its denies) is silently left out.
	if role.Get("tenantId") != tenantID || seen[roleID] || len(seen) > maxInheritedRoles {
		return paths, nil
	}
	seen[roleID] = true
	var roleCeilings []any
	known := true
	if authority, isString := role.Get("authorityId").(string); isString {
		chain, ok, err := server.AuthorityChain(ctx, tx, authority)
		if err != nil {
			return nil, err
		}
		roleCeilings, known = chain, ok
	} else if truthy(role.Get("protected")) {
		roleCeilings = []any{}
	} else {
		known = false
	}
	if !known {
		if lapsed != nil {
			denies, err := roleDenies(ctx, tx, role, tenantID, authorityID, seen)
			if err != nil {
				return nil, err
			}
			*lapsed = append(*lapsed, denies...)
		}
		return paths, nil
	}
	join := func(parts ...[]any) []any {
		out := []any{}
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	// Inherited roles are evaluated under this role's ceilings too, so inheriting cannot widen a grant.
	inherits, _ := role.Get("inherits").([]any)
	for _, inheritedID := range inherits {
		inherited, err := tx.Get(ctx, "roles", jsString(inheritedID))
		if err != nil {
			return nil, err
		}
		if inherited == nil || truthy(inherited.Get("protected")) {
			continue
		}
		more, err := d.RoleGrants(ctx, tx, inherited, tenantID, join(ceilings, roleCeilings), authorityID, seen, lapsed)
		if err != nil {
			return nil, err
		}
		paths = append(paths, more...)
	}
	if document := role.Get("document"); truthy(document) {
		paths = append(paths, GrantPath{Grants: []any{document}, Boundaries: join(ceilings, roleCeilings), AuthorityID: authorityID})
	}
	policyIDs, _ := role.Get("policyIds").([]any)
	for _, policyID := range policyIDs {
		policy, err := tx.Get(ctx, "policies", jsString(policyID))
		if err != nil {
			return nil, err
		}
		if policy == nil || policy.Get("tenantId") != tenantID {
			continue
		}
		var policyCeilings []any
		known := true
		if authority, isString := policy.Get("authorityId").(string); isString {
			chain, ok, err := server.AuthorityChain(ctx, tx, authority)
			if err != nil {
				return nil, err
			}
			policyCeilings, known = chain, ok
		} else if policy.Get("uniqueKey") == "system:owner" {
			policyCeilings = []any{}
		} else {
			known = false
		}
		if !known {
			if lapsed != nil {
				*lapsed = append(*lapsed, denyPaths([]any{policy.Get("document")}, authorityID)...)
			}
			continue
		}
		// A higher authority attaching a lower authority's mutable policy cannot silently remove the limits under
		// which that policy was created.
		paths = append(paths, GrantPath{Grants: []any{policy.Get("document")}, Boundaries: join(ceilings, roleCeilings, policyCeilings), AuthorityID: authorityID})
	}
	return paths, nil
}

func (d *decisions) LiveActivations(ctx context.Context, tx core.IamStore, tenantID, identityID string) (map[string]*core.Object, error) {
	activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	result := map[string]*core.Object{}
	now := float64(d.server.Now())
	for _, activation := range activations {
		status := activation.Get("status")
		if jsNumber(activation.Get("expiresAt")) > now && status != "pending" && status != "denied" {
			result[jsString(activation.Get("bindingId"))] = activation
		}
	}
	return result, nil
}

// liveGroups are the identity's live group memberships' group IDs, in membership order (a Set).
func (d *decisions) liveGroups(ctx context.Context, tx core.IamStore, tenantID, identityID string) ([]string, error) {
	memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	var groupIDs []string
	for _, membership := range memberships {
		if !d.server.LiveMembership(membership) {
			continue
		}
		if id := jsString(membership.Get("groupId")); !containsString(groupIDs, id) {
			groupIDs = append(groupIDs, id)
		}
	}
	return groupIDs, nil
}

func (d *decisions) GrantSources(ctx context.Context, tx core.IamStore, identityID, tenantID string) (*GrantSources, error) {
	groupIDs, err := d.liveGroups(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	activations, err := d.LiveActivations(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	candidates, err := subjectBindings(ctx, tx, tenantID, identityID, groupIDs)
	if err != nil {
		return nil, err
	}
	bindings := []*core.Object{}
	for _, binding := range candidates {
		if !d.server.LiveBinding(binding) {
			continue
		}
		inside, err := d.server.WithinWindow(binding)
		if err != nil {
			return nil, err
		}
		_, activated := activations[jsString(binding.Get("id"))]
		if inside && (binding.Get("eligible") != true || activated) {
			bindings = append(bindings, binding)
		}
	}
	return &GrantSources{GroupIDs: groupIDs, Bindings: bindings}, nil
}

func (d *decisions) IdentityGrants(ctx context.Context, tx core.IamStore, identityID, tenantID string, sources *GrantSources, lapsed *[]GrantPath) ([]GrantPath, error) {
	if sources == nil {
		found, err := d.GrantSources(ctx, tx, identityID, tenantID)
		if err != nil {
			return nil, err
		}
		sources = found
	}
	var paths []GrantPath
	for _, binding := range sources.Bindings {
		role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
		if err != nil {
			return nil, err
		}
		if role == nil || role.Get("tenantId") != tenantID {
			continue
		}
		authorityID := jsString(binding.Get("authorityId"))
		ceilings, ok, err := d.server.AuthorityChain(ctx, tx, authorityID)
		if err != nil {
			return nil, err
		}
		if !ok {
			if lapsed != nil {
				denies, err := roleDenies(ctx, tx, role, tenantID, authorityID, map[string]bool{})
				if err != nil {
					return nil, err
				}
				*lapsed = append(*lapsed, denies...)
			}
			continue
		}
		more, err := d.RoleGrants(ctx, tx, role, tenantID, ceilings, authorityID, nil, lapsed)
		if err != nil {
			return nil, err
		}
		paths = append(paths, more...)
	}
	return paths, nil
}

func (d *decisions) EffectiveBindings(ctx context.Context, tx core.IamStore, tenantID, identityID string) ([]EffectiveBinding, error) {
	groupIDs, err := d.liveGroups(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	activations, err := d.LiveActivations(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	all, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	pending := map[string]*core.Object{}
	now := float64(d.server.Now())
	for _, activation := range all {
		if activation.Get("status") == "pending" && jsNumber(activation.Get("expiresAt")) > now {
			pending[jsString(activation.Get("bindingId"))] = activation
		}
	}
	bindings, err := subjectBindings(ctx, tx, tenantID, identityID, groupIDs)
	if err != nil {
		return nil, err
	}
	result := []EffectiveBinding{}
	for _, binding := range bindings {
		// Future-dated bindings are listed (with their start) but grant nothing until then.
		if d.server.ExpiredBinding(binding) {
			continue
		}
		role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
		if err != nil {
			return nil, err
		}
		effective := EffectiveBinding{Binding: binding}
		if role != nil && role.Get("tenantId") == tenantID {
			effective.Role = role
		}
		if binding.Get("subjectType") != "identity" {
			effective.ViaGroupID = jsString(binding.Get("subjectId"))
		}
		if truthy(binding.Get("window")) {
			inside, err := d.server.WithinWindow(binding)
			if err != nil {
				return nil, err
			}
			effective.InWindow = &inside
		}
		if truthy(binding.Get("eligible")) {
			id := jsString(binding.Get("id"))
			if activation := activations[id]; activation != nil {
				effective.Activation = core.NewObject("id", activation.Get("id"), "activatedAt", activation.Get("activatedAt"), "expiresAt", activation.Get("expiresAt"))
			}
			if request := pending[id]; request != nil {
				effective.PendingActivation = core.NewObject("id", request.Get("id"), "requestedAt", request.Get("activatedAt"), "expiresAt", request.Get("expiresAt"))
			}
		}
		result = append(result, effective)
	}
	return result, nil
}

func (d *decisions) Resolve(ctx context.Context, tx core.IamStore, reference core.ResourceRef, internal bool, action string, known *SchemeKnown) (*ResolvedResource, error) {
	hasAction := action != ""
	resolved, err := d.resolveUnlabeled(ctx, tx, reference, internal, action, hasAction)
	if err != nil {
		return nil, err
	}
	// Security clearances: every resource but the platform's own carries its effective classification label, attached
	// at this one exit so no early return skips it.
	if d.server.Config.Clearances == nil || (internal && InternalResourceTypes.Has(reference.Type) && strings.HasPrefix(action, "iam:")) {
		return resolved, nil
	}
	var scheme *core.Object
	if known != nil {
		scheme = known.Scheme
	} else if scheme, err = SchemeForTenant(ctx, tx, reference.TenantID); err != nil {
		return nil, err
	}
	if scheme == nil {
		return resolved, nil
	}
	options := AttachLabelOptions{Scheme: scheme}
	// For anything but administration, `iam/{type}/{id}` also carries what the application answers for the resource
	// it names, so the alias never reads lower than the resource itself.
	if !strings.HasPrefix(action, "iam:") {
		named, isNamed, err := d.namedResource(ctx, tx, reference, action, hasAction)
		if err != nil {
			return nil, err
		}
		options.HasNamed, options.Named = isNamed, named
	}
	labeled, err := AttachLabel(ctx, d.server, tx, reference.TenantID, *resolved, options)
	if err != nil {
		return nil, err
	}
	return &labeled, nil
}

// documentsOf is `[...boundaries, ...paths.flatMap((path) => [...path.grants, ...path.boundaries])]`.
func documentsOf(boundaries []any, paths []GrantPath) []any {
	documents := append([]any(nil), boundaries...)
	for _, path := range paths {
		documents = append(documents, path.Grants...)
		documents = append(documents, path.Boundaries...)
	}
	return documents
}

func (d *decisions) PrepareDecision(ctx context.Context, tx core.IamStore, principal *Principal, target *core.Object, action string) (*PreparedDecision, error) {
	server := d.server
	options := server.Options
	clearances := server.Config.Clearances
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	fixed := func(reason string) *PreparedDecision {
		return &PreparedDecision{Fixed: &core.Decision{Allowed: false, Reason: reason, Matched: []string{}}}
	}
	if root {
		override := core.Decision{Allowed: true, Reason: "ROOT_OVERRIDE", Matched: []string{}}
		if clearances == nil || !clearances.AppliesToRoot {
			return &PreparedDecision{Fixed: &override}, nil
		}
		// Root does not read up (security clearances): a labeled resource needs a clearance of root's own.
		chain, err := server.Ancestry(ctx, tx, target)
		if err != nil {
			return nil, err
		}
		mandatory, err := ClearanceScope(ctx, server, tx, principal, target, chain, nil, server.Now(), true)
		if err != nil {
			return nil, err
		}
		if mandatory == nil {
			return &PreparedDecision{Fixed: &override}, nil
		}
		return &PreparedDecision{
			RootOverride: true,
			Evaluate: func(resource ResolvedResource, evaluated string) (core.Decision, error) {
				if evaluated == "" {
					evaluated = action
				}
				if refused := mandatory.Check(resource, evaluated); refused != nil {
					return *refused, nil
				}
				return override, nil
			},
			Inputs: &DecisionInputs{
				Context: mandatory.Keys.Spread(), Boundaries: []any{},
				Paths:  []GrantPath{{Grants: []any{All()}, Boundaries: []any{}, AuthorityID: ""}},
				Denies: []any{}, Held: map[string][]string{}, Mandatory: mandatory,
			},
		}, nil
	}
	chain, err := server.Ancestry(ctx, tx, target)
	if err != nil {
		return nil, err
	}
	for _, realm := range chain {
		if realm.Get("status") != "active" {
			return fixed("TENANT_INACTIVE"), nil
		}
	}
	session, identity := principal.Session, principal.Identity
	targetID := jsString(target.Get("id"))
	if session.Get("tenantId") != target.Get("id") {
		return fixed("TENANT_MISMATCH"), nil
	}
	roleSession := session.Get("kind") == "role"
	sources := &GrantSources{GroupIDs: []string{}, Bindings: []*core.Object{}}
	if !roleSession {
		if sources, err = d.GrantSources(ctx, tx, jsString(identity.Get("id")), targetID); err != nil {
			return nil, err
		}
	}
	var roleIDs []any
	if roleSession {
		roleIDs = []any{session.Get("roleId")}
	} else {
		var unique []string
		for _, binding := range sources.Bindings {
			if id := jsString(binding.Get("roleId")); !containsString(unique, id) {
				unique = append(unique, id)
			}
		}
		sortStable(unique, compareUTF16)
		roleIDs = stringsOf(unique)
	}
	// A role session's role and trust, read once.
	var role, trust *core.Object
	if roleSession {
		if role, err = tx.Get(ctx, "roles", jsString(session.Get("roleId"))); err != nil {
			return nil, err
		}
		if trust, err = tx.Get(ctx, "trusts", jsString(session.Get("trustId"))); err != nil {
			return nil, err
		}
	}
	// Untrusted or lower-precedence keys first: application context, plugin context, declared identity attributes;
	// the server-derived principal and request keys always win.
	base := core.NewObject()
	if options.ResolveContext != nil {
		extra, err := options.ResolveContext(ctx, principal)
		if err != nil {
			return nil, err
		}
		if extra != nil {
			base.Assign(extra)
		}
	}
	for _, plugin := range server.Plugins {
		if plugin.ResolveContext == nil {
			continue
		}
		extra, err := plugin.ResolveContext(ctx, corePrincipal(principal))
		if err != nil {
			return nil, err
		}
		if extra != nil {
			base.Assign(extra)
		}
	}
	// Keys only the server may set are removed, so an application or plugin value can never stand in for them.
	for _, key := range base.Keys() {
		if IsServerOwnedKey(key, clearances != nil) || key == "principal.sessionTags" {
			base.Delete(key)
		}
	}
	// A trust may keep the source identity's attributes out of its role sessions (read fail-closed).
	passAttributes := !roleSession
	if roleSession && trust != nil {
		passAttributes = TrustPassesSourceAttributes(trust)
	}
	if passAttributes {
		if attributes, ok := identity.Get("attributes").(*core.Object); ok && attributes != nil {
			attributes.Entries(func(key string, value any) bool {
				if !IsServerOwnedKey("principal."+key, clearances != nil) && key != "sessionTags" {
					base.Set("principal."+key, value)
				}
				return true
			})
		}
	}
	// Ownership and root status describe the account in its own tenant; only a session acting in the account's own
	// right is ever the owner or a root admin.
	ownTenant := !roleSession && identity.Get("tenantId") == session.Get("tenantId")
	ownAccount := ownTenant && ActsInOwnRight(session)
	and := func(condition bool, value any) any {
		if !condition {
			return false
		}
		return value
	}
	groups := append([]string(nil), sources.GroupIDs...)
	sortStable(groups, compareUTF16)
	base.Set("principal.id", identity.Get("id"))
	base.Set("principal.tenantId", session.Get("tenantId"))
	base.Set("principal.mfa", session.Get("mfa"))
	base.Set("principal.kind", identity.Get("kind"))
	base.Set("principal.owner", and(ownAccount, identity.Get("owner")))
	base.Set("principal.rootAdmin", and(ownAccount, identity.Get("rootAdmin")))
	base.Set("principal.sessionKind", session.Get("kind"))
	if method := session.Get("method"); truthy(method) {
		base.Set("principal.authMethod", method)
	}
	base.Set("principal.impersonated", truthy(session.Get("impersonatorId")))
	if impersonator := session.Get("impersonatorId"); truthy(impersonator) {
		base.Set("principal.impersonatorId", impersonator)
	}
	base.Set("principal.groups", stringsOf(groups))
	base.Set("principal.roles", roleIDs)
	// B2B guests (guests.ts): `principal.guest` always, the sponsor and home tenant when set.
	base.Assign(GuestContext(identity, ownTenant))
	// Terms of use the person accepted and required ones still owed; nothing for assumed roles.
	if ownTenant {
		agreements, err := AgreementContext(ctx, tx, targetID, jsString(identity.Get("id")), jsString(identity.Get("kind")), server.Now())
		if err != nil {
			return nil, err
		}
		base.Assign(agreements)
	} else {
		base.Assign(core.NewObject("principal.agreements", []any{}, "principal.pendingAgreements", 0.0))
	}
	base.Set("request.time", isoString(float64(server.Now())))
	clientIP := ""
	if client := server.Auth.CurrentClient(ctx); client != nil {
		clientIP = client.IP
	}
	base.Assign(sessionContextKeys(session, clientIP))
	// AI agents (agents.ts): `principal.delegated` always, and the agent's keys and ceilings when an agent acts.
	agentScope, err := AgentDecisionScopeOf(ctx, tx, principal, server.Now())
	if err != nil {
		return nil, err
	}
	if agentScope == nil {
		return fixed("DELEGATION_REVOKED"), nil
	}
	base.Assign(agentScope.Keys)
	// Mandatory access control (security clearances): read whenever clearances are on, never lazily.
	var mandatory *MandatoryAccess
	if clearances != nil {
		if mandatory, err = ClearanceScope(ctx, server, tx, principal, target, chain, agentScope, server.Now(), false); err != nil {
			return nil, err
		}
		if mandatory != nil {
			base.Assign(mandatory.Keys)
		} else {
			base.Assign(unclearedKeys())
		}
	}
	boundaries := []any{}
	for _, realm := range chain {
		if boundary := realm.Get("boundary"); truthy(boundary) {
			boundaries = append(boundaries, boundary)
		}
	}
	boundaries = append(boundaries, agentScope.Boundaries...)
	// Hand-offs (delegations.ts): the key issuers behind the sessions that handed the work on bound it too.
	for _, authorityID := range agentScope.Authorities {
		ceilings, ok, err := server.AuthorityChain(ctx, tx, authorityID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return fixed("CREDENTIAL_AUTHORITY_REVOKED"), nil
		}
		boundaries = append(boundaries, ceilings...)
	}
	principalBoundaries, err := tx.Find(ctx, "principalBoundaries", core.NewObject("tenantId", targetID, "identityId", identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	if len(principalBoundaries) > 0 {
		boundaries = append(boundaries, principalBoundaries[0].Get("document"))
	}
	// A guest stays within the tenant's guest ceiling (`crossTenantAccess.guestBoundary`, guests.ts).
	if ownTenant && truthy(identity.Get("guest")) {
		ceiling, err := GuestBoundary(ctx, tx, targetID)
		if err != nil {
			return nil, err
		}
		if ceiling != nil {
			boundaries = append(boundaries, ceiling)
		}
	}
	if policy := session.Get("policy"); truthy(policy) {
		boundaries = append(boundaries, policy)
	}
	// A session token also stays within its source credential's own policy (such as API-key scopes).
	if policy := session.Get("sourcePolicy"); truthy(policy) {
		boundaries = append(boundaries, policy)
	}
	if authorityID, isString := session.Get("credentialAuthorityId").(string); isString {
		ceilings, ok, err := server.AuthorityChain(ctx, tx, authorityID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return fixed("CREDENTIAL_AUTHORITY_REVOKED"), nil
		}
		boundaries = append(boundaries, ceilings...)
	}
	// A web-identity session is bounded by the authority of whoever registered its OIDC provider as well.
	if web := session.Get("webIdentity"); truthy(web) {
		provider, err := tx.Get(ctx, "oidcProviders", jsString(member(web, "providerId")))
		if err != nil {
			return nil, err
		}
		var ceilings []any
		ok := false
		if authorityID, isString := member(provider, "authorityId").(string); provider != nil && provider.Get("tenantId") == session.Get("tenantId") && isString {
			if ceilings, ok, err = server.AuthorityChain(ctx, tx, authorityID); err != nil {
				return nil, err
			}
		}
		if !ok {
			return fixed("CREDENTIAL_AUTHORITY_REVOKED"), nil
		}
		boundaries = append(boundaries, ceilings...)
	}
	// Denies outlive the authority that issued them: those denies join as paths that grant nothing.
	var paths []GrantPath
	lapsed := []GrantPath{}
	if roleSession {
		// The role's own grant boundary is attached by the root-created trust.
		if role != nil && trust != nil && !truthy(trust.Get("revoked")) {
			ceilings := []any{}
			if ceiling := trust.Get("ceiling"); truthy(ceiling) {
				ceilings = []any{ceiling}
			}
			if paths, err = d.RoleGrants(ctx, tx, role, targetID, ceilings, "", nil, &lapsed); err != nil {
				return nil, err
			}
		}
	} else if paths, err = d.IdentityGrants(ctx, tx, jsString(identity.Get("id")), targetID, sources, &lapsed); err != nil {
		return nil, err
	}
	paths = append(paths, lapsed...)
	documents := documentsOf(boundaries, paths)
	// Feature flags that are on for the tenant, as `tenant.features`: read only when a condition names the key.
	if MentionsFeatures(documents) {
		state, err := FeatureState(ctx, tx, chain, server.Now())
		if err != nil {
			return nil, err
		}
		keys, err := EnabledFeatureKeys(state)
		if err != nil {
			return nil, err
		}
		base.Set(FeatureContextKey, stringsOf(keys))
	}
	// Onboarding flows the person completed and required ones still open, read only when a condition names them.
	if MentionsOnboarding(documents) {
		if ownTenant {
			context, err := OnboardingContext(ctx, tx, chain, identity, server.Now())
			if err != nil {
				return nil, err
			}
			base.Assign(context)
		} else {
			base.Assign(core.NewObject("principal.onboarding", []any{}, "principal.pendingOnboarding", 0.0))
		}
	}
	// Teams and departments (teams.ts, departments.ts), read only when a document names them.
	orgKeys := MentionedOrgKeys(documents)
	if orgKeys.Teams {
		if ownTenant {
			context, err := TeamContext(ctx, tx, targetID, jsString(identity.Get("id")), server.Now())
			if err != nil {
				return nil, err
			}
			base.Assign(context)
		} else {
			base.Set("principal.teams", []any{})
		}
	}
	if orgKeys.Departments {
		if ownTenant {
			context, err := DepartmentContext(ctx, tx, targetID, jsString(identity.Get("id")))
			if err != nil {
				return nil, err
			}
			base.Assign(context)
		} else {
			base.Set("principal.departments", []any{})
		}
	}
	// Spend (billing-service.ts), read only when a document names it; an assumed role sees the tenant's budgets only.
	if MentionsSpend(documents) {
		identityID := ""
		if ownTenant {
			identityID = jsString(identity.Get("id"))
		}
		context, err := BillingServiceOf(server).SpendContext(ctx, tx, target, identityID)
		if err != nil {
			return nil, err
		}
		base.Assign(context)
	}
	// Privacy (privacy.ts): `principal.consents`, read only when a document names it.
	if MentionsConsents(documents) {
		if ownTenant {
			context, err := ConsentContext(ctx, tx, targetID, identity, server.Now())
			if err != nil {
				return nil, err
			}
			base.Assign(context)
		} else {
			base.Set("principal.consents", []any{})
		}
	}
	// License management (licenses.ts): `principal.licenses`, read only when a document names it.
	if MentionsLicenses(documents) {
		if ownTenant {
			context, err := LicenseContext(ctx, tx, targetID, jsString(identity.Get("id")), server.Now())
			if err != nil {
				return nil, err
			}
			base.Assign(context)
		} else {
			base.Set("principal.licenses", []any{})
		}
	}
	// Threat detection (threats.ts): `principal.riskLevel` and `principal.riskScore`, read only when named.
	if MentionsRisk(documents) {
		context, err := RiskContext(ctx, tx, principal, server.Now())
		if err != nil {
			return nil, err
		}
		base.Assign(context)
	}
	// Device posture (devices.ts): the request's verified device, read only when a document names it.
	if MentionsDevice(documents) {
		context, err := DeviceContext(ctx, tx, principal, server.Now())
		if err != nil {
			return nil, err
		}
		base.Assign(context)
	}
	// Deny in any applicable identity policy applies across grant paths.
	denies := []any{}
	for _, path := range paths {
		for _, document := range path.Grants {
			filtered := []any{}
			for _, statement := range statementsOf(document) {
				if member(statement, "effect") == "deny" {
					filtered = append(filtered, statement)
				}
			}
			denies = append(denies, core.NewObject("version", 1.0, "statements", filtered))
		}
	}
	// Relationship tuples the principal holds directly or through a group, keyed by `type/id`.
	held := map[string][]string{}
	var heldOrder []string
	tuples, err := tx.Find(ctx, "relationships", core.NewObject("tenantId", targetID), nil)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	for _, tuple := range tuples {
		expiresAt := tuple.Get("expiresAt")
		applies := !roleSession && (isUndefined(expiresAt) || jsNumber(expiresAt) > now)
		if applies {
			if tuple.Get("subjectType") == "identity" {
				applies = tuple.Get("subjectId") == identity.Get("id")
			} else {
				applies = sources.hasGroup(jsString(tuple.Get("subjectId")))
			}
		}
		if !applies {
			continue
		}
		key := jsString(tuple.Get("type")) + "/" + jsString(tuple.Get("resourceId"))
		if _, seen := held[key]; !seen {
			heldOrder = append(heldOrder, key)
		}
		if relation := jsString(tuple.Get("relation")); !containsString(held[key], relation) {
			held[key] = append(held[key], relation)
		}
	}
	relationsOf := func(kind, id any) []any {
		typeName, typeOK := kind.(string)
		idText, idOK := id.(string)
		if !typeOK || !idOK {
			return []any{}
		}
		key := typeName + "/" + idText
		if typeName == "iam" {
			key = idText
		}
		relations := append([]string(nil), held[key]...)
		sortStable(relations, compareUTF16)
		return stringsOf(relations)
	}
	inputs := &DecisionInputs{
		Context: base, Boundaries: boundaries, Paths: paths, Denies: denies, Held: held, HeldOrder: heldOrder,
		Confirm: agentScope.Confirm, Mandatory: mandatory,
	}
	return &PreparedDecision{
		Inputs: inputs,
		Evaluate: func(resource ResolvedResource, evaluated string) (core.Decision, error) {
			if evaluated == "" {
				evaluated = action
			}
			// Mandatory access control first, keyed on the evaluated action: no grant opens a resource above the
			// session's clearance, and a refusal uses nothing up.
			if mandatory != nil {
				if refused := mandatory.Check(resource, evaluated); refused != nil {
					return *refused, nil
				}
			}
			attributes := resource.Attributes
			if attributes == nil {
				attributes = core.NewObject()
			}
			context := base.Spread()
			attributes.Entries(func(key string, value any) bool {
				context.Set("resource."+key, value)
				return true
			})
			context.Set("resource.tenantId", resource.TenantID)
			// Held on the resource itself; for `iam/{type}/{id}` administration, on the named resource.
			context.Set("resource.relations", relationsOf(resource.Type, resource.ID))
			context.Set("resource.parentRelations", relationsOf(attributes.Get("parentType"), attributes.Get("parentId")))
			// The classification label's keys, after the attributes so an attribute can never stand in for them.
			if clearances != nil {
				context.Assign(classificationKeys(mandatory, resource))
			}
			evaluation := core.EvaluationInput{Action: evaluated, Resource: resource.Type + "/" + resource.ID, Context: context}
			denyInput := evaluation
			denyInput.Grants = append([]any{All()}, denies...)
			denyInput.Boundaries = boundaries
			denyDecision, err := core.EvaluatePolicy(denyInput)
			if err != nil {
				return core.Decision{}, err
			}
			if !denyDecision.Allowed {
				return denyDecision, nil
			}
			for _, path := range paths {
				pathInput := evaluation
				pathInput.Grants = path.Grants
				pathInput.Boundaries = append(append([]any{}, boundaries...), path.Boundaries...)
				decision, err := core.EvaluatePolicy(pathInput)
				if err != nil {
					return core.Decision{}, err
				}
				// A delegation may hold back some actions until the person confirms them (delegations.ts).
				if decision.Allowed {
					if agentScope.Confirm != nil {
						if held := agentScope.Confirm(evaluated, resource.Type, resource.ID); held != nil {
							return *held, nil
						}
					}
					return decision, nil
				}
			}
			return core.Decision{Allowed: false, Reason: "NO_APPLICABLE_GRANT", Matched: []string{}}, nil
		},
	}, nil
}

func (d *decisions) Decide(ctx context.Context, tx core.IamStore, principal *Principal, request AuthorizationRequest, internalResource bool) (core.Decision, error) {
	server := d.server
	target, err := server.Tenant(ctx, tx, request.TenantID)
	if err != nil {
		return core.Decision{}, err
	}
	action, err := Text(request.Action, "action")
	if err != nil {
		return core.Decision{}, err
	}
	targetID := jsString(target.Get("id"))
	// Refusals that do not depend on the resource come first, so an outsider learns nothing about the tenant.
	prepared, err := d.PrepareDecision(ctx, tx, principal, target, action)
	if err != nil {
		return core.Decision{}, err
	}
	if prepared.Fixed != nil && !prepared.Fixed.Allowed {
		return *prepared.Fixed, nil
	}
	known, err := server.Catalog.KnownAction(ctx, tx, targetID, action)
	if err != nil {
		return core.Decision{}, err
	}
	if !known {
		return core.Decision{Allowed: false, Reason: "UNKNOWN_ACTION", Matched: []string{}}, nil
	}
	resource, err := d.Resolve(ctx, tx, core.ResourceRef{TenantID: targetID, Type: request.Resource.Type, ID: request.Resource.ID},
		internalResource || strings.HasPrefix(action, "iam:"), action, PreparedLabeling(prepared))
	if err != nil {
		return core.Decision{}, err
	}
	decision, err := DecideOn(prepared, *resource, "")
	if err != nil || !decision.Allowed {
		return decision, err
	}
	// "View as" never exceeds the administrator behind it: every check must pass for both of them.
	actor, err := ImpersonatingActor(ctx, tx, principal)
	if err != nil || actor == nil {
		return decision, err
	}
	actorPrepared, err := d.PrepareDecision(ctx, tx, actor, target, action)
	if err != nil {
		return core.Decision{}, err
	}
	own, err := DecideOn(actorPrepared, *resource, "")
	if err != nil {
		return core.Decision{}, err
	}
	if own.Allowed {
		return decision, nil
	}
	// The administrator's own clearance refusal stays one, so it is audited with the mandatory marker.
	if own.Reason == "CLEARANCE_REQUIRED" {
		return own, nil
	}
	return core.Decision{Allowed: false, Reason: "IMPERSONATOR_DENIED", Matched: []string{}}, nil
}

func (d *decisions) SimulatedPrincipal(identity *core.Object, mfa bool) *Principal {
	at := float64(d.server.Now())
	kind := "api-key"
	// Machine accounts (service accounts and agents) act through API keys.
	if identity.Get("kind") == "user" {
		kind = "user"
	}
	return &Principal{Identity: identity, Session: core.NewObject(
		"id", "simulation", "tenantId", identity.Get("tenantId"), "identityId", identity.Get("id"), "tokenHash", "",
		"kind", kind, "createdAt", at, "authenticatedAt", at, "lastSeenAt", at, "expiresAt", at+1, "mfa", mfa,
	)}
}

// sortStable is a stable sort with a comparison function (Array#sort is stable).
func sortStable[T any](items []T, compare func(a, b T) int) {
	sort.SliceStable(items, func(i, j int) bool { return compare(items[i], items[j]) < 0 })
}
