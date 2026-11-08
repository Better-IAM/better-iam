package server

// Port of packages/server/src/clearances.ts: security clearances and mandatory access control (the `clearances`
// option). A tenant (normally an organization) defines a classification scheme: ranked levels, compartments and
// dissemination controls (core classification.go). The scheme in force for a tenant is the one defined closest to the
// root of its ancestry, so a child can neither redefine nor re-rank what its ancestors classify. Officers adjudicate
// one clearance per identity (level, adjudicated citizenship, read-ins to compartments backed by NDAs) and label
// resources; the label is IAM-held (`resourceLabels`), inherited down managed parents, and can only be raised by the
// application's resolver. At decision time every party of the session must dominate the resource's label
// (Bell-LaPadula simple security property: no read up), whatever roles, policies and relationships say; `iam:*`
// administration is never subject. Status, expiry, the guest ceiling and NDA acceptance are evaluated at decision
// time, never by a worker.
//
// Records are raw model values (*core.Object): schemes, clearances and labels keep TypeScript's member order. A
// classification label is a *core.Object ({level, compartments?, noforn?, releasableTo?}). A party state (PartyState,
// SessionParties) is a *core.Object {party, status, level?, record?} whose `party` is {identityId, rank, compartments,
// citizenship} with the two sets as string arrays (see ClearancePartyOf).

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const clearanceSchemeKey = "scheme"

// clearanceModuleResourceTypes are the resource types the built-in modules resolve themselves (models and the
// provider tools they run, SSH logins and hosts, credential types); `requireLabels: ['*']` (all application types)
// skips them.
var clearanceModuleResourceTypes = newOrderedSet("model", "model-tool", "ssh-login", "ssh-host", "credential-type")

// clearanceTreeResourceTypes are the resource types one record of which serves a whole subtree: an inference model
// resolves up the tenant tree, so a project uses its organization's models. A label of such a resource written in any
// tenant of the deciding tenant's ancestry applies to it as well, joined like any other.
var clearanceTreeResourceTypes = newOrderedSet("model")

// clearanceContainerTypes: the type of the resource each of these is part of, named by the first segment of their
// ids (containerOf).
var clearanceContainerTypes = map[string]string{"ssh-login": "ssh-host"}

// clearanceRef is a `{ type, id }` reference.
type clearanceRef struct {
	Type string
	ID   string
}

func (r clearanceRef) key() string { return r.Type + "/" + r.ID }

// containerOf is the resource another one is part of, whose own label it always carries (whatever its
// `inheritToChildren`): an SSH login (`ssh-login/{host}/{login}`) is access to its host, so a label on
// `ssh-host/{host}` applies to every login of the host, those added later included.
func containerOf(typeValue, resourceID string) (clearanceRef, bool) {
	container := clearanceContainerTypes[typeValue]
	slash := -1
	if container != "" {
		slash = strings.Index(resourceID, "/")
	}
	if container != "" && slash > 0 {
		return clearanceRef{Type: container, ID: resourceID[:slash]}, true
	}
	return clearanceRef{}, false
}

// invalidClassificationLabel is a label that is valid for no scheme (level ids start with a letter or digit): it
// refuses every party. A fresh copy each time, so nobody can change the shared one.
func invalidClassificationLabel() *core.Object { return core.NewObject("level", "!invalid") }

// AssertClearances (clearances.ts assertClearances): Refuses with FEATURE_DISABLED (403) unless the deployment
// enables clearances.
func AssertClearances(server *ServerContext) (err error) {
	if server.Config.Clearances == nil {
		return core.NewIamError("FEATURE_DISABLED", "Security clearances are not enabled on this deployment", 403)
	}
	return nil
}

// LabelKey (clearances.ts labelKey): The natural key of a resource's label: `{type}/{id}`, hashed when it would
// exceed 512 UTF-8 bytes.
func LabelKey(typeValue string, resourceID string) (result string, err error) {
	return labelKey(typeValue, resourceID), nil
}

func labelKey(typeValue, resourceID string) string {
	key := typeValue + "/" + resourceID
	if len(utf8Bytes(key)) <= 512 {
		return key
	}
	return "sha256:" + Hash(key)
}

// DefinedScheme (clearances.ts definedScheme): The scheme a tenant defines itself, if it does.
func DefinedScheme(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, ClearanceCollections.Schemes, core.NewObject("tenantId", tenantID, "uniqueKey", clearanceSchemeKey), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	if found[0].Get("tenantId") == tenantID {
		return found[0], nil
	}
	return nil, nil
}

// EffectiveScheme (clearances.ts effectiveScheme): The scheme in force for a tenant, given its ancestry (`[tenant,
// parent, ..., root]`): the one defined closest to the root. Undefined when no tenant of the chain defines one.
func EffectiveScheme(ctx context.Context, tx core.IamStore, chain []*core.Object) (result *core.Object, err error) {
	ids := make([]string, len(chain))
	for index, realm := range chain {
		ids[index] = jsString(realm.Get("id"))
	}
	return effectiveSchemeOf(ctx, tx, ids)
}

func effectiveSchemeOf(ctx context.Context, tx core.IamStore, chain []string) (*core.Object, error) {
	for index := len(chain) - 1; index >= 0; index-- {
		scheme, err := DefinedScheme(ctx, tx, chain[index])
		if err != nil {
			return nil, err
		}
		if scheme != nil {
			return scheme, nil
		}
	}
	return nil, nil
}

// clearanceTenantChain is a tenant's ancestor ids from itself to the root, read through the store alone; fails closed
// on a broken chain.
func clearanceTenantChain(ctx context.Context, tx core.IamStore, tenantID string) ([]string, error) {
	chain := []string{}
	seen := map[string]bool{}
	current := tenantID
	for current != "" {
		if seen[current] || len(chain) > 100 {
			return nil, core.NewIamError("INVALID_HIERARCHY", "Invalid tenant hierarchy", 500)
		}
		seen[current] = true
		realm, err := tx.Get(ctx, "tenants", current)
		if err != nil {
			return nil, err
		}
		if realm == nil {
			return nil, core.NewIamError("NOT_FOUND", "Tenant not found", 404)
		}
		chain = append(chain, jsString(realm.Get("id")))
		current, _ = realm.Get("parentId").(string)
	}
	return chain, nil
}

// lapsedSchemeTenantID is the defining tenant of the stand-in scheme enforcedScheme uses where labels outlived the
// scheme they were written under: no label or clearance names it, and its definition has no level, so every label it
// reads is invalid.
const lapsedSchemeTenantID = "!no-scheme-in-force"

// lapsedScheme is the stand-in scheme of a tenant that holds labels while no scheme is in force: every label refuses
// everyone.
func lapsedScheme() *core.Object {
	return core.NewObject(
		"id", lapsedSchemeTenantID,
		"tenantId", lapsedSchemeTenantID,
		"uniqueKey", clearanceSchemeKey,
		"name", "",
		"definition", core.NewObject("levels", []any{}, "compartments", []any{}, "ownerCountries", []any{}, "caveats", []any{}),
		"requireLabels", []any{},
		"guestCeiling", nil,
		"interimAllowed", false,
		"adjudication", "within-own",
		"createdAt", 0.0,
		"createdBy", "",
		"updatedAt", 0.0,
		"updatedBy", "",
		"version", 0.0,
	)
}

// enforcedScheme is the scheme decisions enforce in a tenant, given its ancestry (`[tenant, parent, ..., root]`): the
// scheme in force (effectiveScheme), or, when none is but the tenant still holds labels (written under a scheme that
// no longer applies to it), a stand-in under which each of those labels refuses every party, root included: a label is
// never dropped because its scheme went away. Nil when there is nothing to enforce.
func enforcedScheme(ctx context.Context, tx core.IamStore, tenantID string, chain []string) (*core.Object, error) {
	scheme, err := effectiveSchemeOf(ctx, tx, chain)
	if err != nil || scheme != nil {
		return scheme, err
	}
	one := 1
	held, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", tenantID), &core.FindOptions{Limit: &one})
	if err != nil {
		return nil, err
	}
	for _, item := range held {
		if item.Get("tenantId") == tenantID {
			return lapsedScheme(), nil
		}
	}
	return nil, nil
}

// SchemeForTenant (clearances.ts schemeForTenant): The scheme decisions enforce in a tenant (`enforcedScheme`),
// reading its ancestry from the store.
func SchemeForTenant(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	chain, err := clearanceTenantChain(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	return enforcedScheme(ctx, tx, tenantID, chain)
}

// SchemeLevel (clearances.ts schemeLevel): A level of the scheme by id.
func SchemeLevel(scheme *core.Object, levelID string) (result *core.Object, err error) {
	return schemeLevelOf(scheme, levelID), nil
}

// schemeLevelOf is schemeLevel for any level id value: nil unless it is a string naming a level of the scheme.
func schemeLevelOf(scheme *core.Object, levelID any) *core.Object {
	id, ok := levelID.(string)
	if !ok || scheme == nil {
		return nil
	}
	levels, _ := member(scheme.Get("definition"), "levels").([]any)
	for _, item := range levels {
		if level, ok := item.(*core.Object); ok && level != nil && level.Get("id") == id {
			return level
		}
	}
	return nil
}

// schemeDefinitionOf reads a stored scheme definition into core's form (definitions are validated when written;
// members of another shape are skipped, so they match nothing, as in TypeScript).
func schemeDefinitionOf(value any) *core.ClassificationSchemeDefinition {
	definition := &core.ClassificationSchemeDefinition{Levels: []core.ClassificationLevel{}, Compartments: []core.Compartment{},
		OwnerCountries: []string{}, Caveats: []string{}}
	levels, _ := member(value, "levels").([]any)
	for _, item := range levels {
		level, ok := item.(*core.Object)
		if !ok || level == nil {
			continue
		}
		id, ok := level.Get("id").(string)
		if !ok {
			continue
		}
		name, _ := level.Get("name").(string)
		rank, isNumber := level.Get("rank").(float64)
		if !isNumber {
			rank = math.NaN()
		}
		abbreviation, _ := level.Get("abbreviation").(string)
		definition.Levels = append(definition.Levels, core.ClassificationLevel{ID: id, Name: name, Rank: rank, Abbreviation: abbreviation})
	}
	compartments, _ := member(value, "compartments").([]any)
	for _, item := range compartments {
		compartment, ok := item.(*core.Object)
		if !ok || compartment == nil {
			continue
		}
		id, ok := compartment.Get("id").(string)
		if !ok {
			continue
		}
		name, _ := compartment.Get("name").(string)
		definition.Compartments = append(definition.Compartments, core.Compartment{ID: id, Name: name})
	}
	for _, key := range []string{"ownerCountries", "caveats"} {
		list, _ := member(value, key).([]any)
		for _, item := range list {
			if text, ok := item.(string); ok {
				if key == "ownerCountries" {
					definition.OwnerCountries = append(definition.OwnerCountries, text)
				} else {
					definition.Caveats = append(definition.Caveats, text)
				}
			}
		}
	}
	return definition
}

// clearanceScheme is a scheme record with its definition read once.
type clearanceScheme struct {
	record     *core.Object
	definition *core.ClassificationSchemeDefinition
}

func viewScheme(record *core.Object) *clearanceScheme {
	return &clearanceScheme{record: record, definition: schemeDefinitionOf(record.Get("definition"))}
}

func (s *clearanceScheme) tenantID() any { return s.record.Get("tenantId") }

// labelObject converts what core's label functions return to a label model value (nil: none).
func labelObject(value any) *core.Object {
	switch v := value.(type) {
	case *core.ClassificationLabel:
		if v == nil {
			return nil
		}
		return v.ToValue()
	case core.ClassificationLabel:
		return v.ToValue()
	case *core.Object:
		return v
	}
	return nil
}

// joinClearanceLabels is core joinLabels over label model values.
func joinClearanceLabels(a, b *core.Object, definition *core.ClassificationSchemeDefinition) *core.Object {
	var left, right any
	if a != nil {
		left = a
	}
	if b != nil {
		right = b
	}
	return labelObject(core.JoinLabels(left, right, definition))
}

// validClearanceLabel is core validateLabel of a label known to be valid, as a model value.
func validClearanceLabel(label any, definition *core.ClassificationSchemeDefinition) *core.Object {
	checked, err := core.ValidateLabel(label, definition)
	if err != nil {
		return invalidClassificationLabel()
	}
	return checked.ToValue()
}

// labelRequired is whether the scheme requires a label on resources of `type` (`*` covers application types, not
// built-in ones).
func labelRequired(scheme *core.Object, typeValue string) bool {
	if InternalResourceTypes.Has(typeValue) {
		return false
	}
	required, _ := scheme.Get("requireLabels").([]any)
	includes := func(value string) bool {
		for _, item := range required {
			if item == value {
				return true
			}
		}
		return false
	}
	return includes(typeValue) || (includes("*") && !clearanceModuleResourceTypes.Has(typeValue))
}

// StoredLabel (clearances.ts storedLabel): The stored IAM label of a resource, if it has one.
func StoredLabel(ctx context.Context, tx core.IamStore, tenantID string, typeValue string, resourceID string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", tenantID, "uniqueKey", labelKey(typeValue, resourceID)), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	if found[0].Get("type") == typeValue && found[0].Get("resourceId") == resourceID {
		return found[0], nil
	}
	return nil, nil
}

// schemeLabel is a stored or asserted label as the scheme reads it: normalized when valid, otherwise the invalid
// label.
func schemeLabel(label any, definition *core.ClassificationSchemeDefinition) *core.Object {
	if core.IsValidClassificationLabel(label, definition) {
		return validClearanceLabel(label, definition)
	}
	return invalidClassificationLabel()
}

// storedLabelValid is whether a stored IAM label is valid under the scheme in force: written under that scheme (not
// one a tenant used before it was moved below an ancestor defining its own) and valid for its definition.
func storedLabelValid(stored *core.Object, scheme *clearanceScheme) bool {
	return strictEquals(stored.Get("schemeTenantId"), scheme.tenantID()) &&
		core.IsValidClassificationLabel(stored.Get("label"), scheme.definition)
}

// storedSchemeLabel is a stored IAM label as the scheme in force reads it; one storedLabelValid rejects refuses every
// party.
func storedSchemeLabel(stored *core.Object, scheme *clearanceScheme) *core.Object {
	if storedLabelValid(stored, scheme) {
		return validClearanceLabel(stored.Get("label"), scheme.definition)
	}
	return invalidClassificationLabel()
}

// clearanceParentOf is the managed parent of a registered resource, when it has one.
func clearanceParentOf(record *core.Object) (clearanceRef, bool) {
	if record == nil {
		return clearanceRef{}, false
	}
	parentType, typeOK := record.Get("parentType").(string)
	parentID, idOK := record.Get("parentId").(string)
	if typeOK && idOK {
		return clearanceRef{Type: parentType, ID: parentID}, true
	}
	return clearanceRef{}, false
}

// clearanceParentsOf is every parent a resource inherits labels from: its registration's managed parent, and the
// parent its attributes report (`parentType` / `parentId`: an application resolver's, or what resolvedManaged presents
// for a registration). Both count when they differ, since labels only ever rise: a type only a tenant registered
// answers the application's actions from the application's resolver, so a registration of the tenant's must not stand
// in for the parent the application reports (that would declassify through registering a record).
func clearanceParentsOf(record *core.Object, attributes *core.Object) []clearanceRef {
	parents := []clearanceRef{}
	linked, hasLinked := clearanceParentOf(record)
	if hasLinked {
		parents = append(parents, linked)
	}
	if attributes != nil {
		parentType, typeOK := attributes.Get("parentType").(string)
		parentID, idOK := attributes.Get("parentId").(string)
		if typeOK && idOK {
			reported := clearanceRef{Type: parentType, ID: parentID}
			if !hasLinked || linked.key() != reported.key() {
				parents = append(parents, reported)
			}
		}
	}
	return parents
}

// inheritedChain is what a managed resource passes down: the join of its and its ancestors' inherited labels, and
// its chain's height (the resource and the ancestors above it; +Inf for a cyclic or runaway chain).
type inheritedChain struct {
	label  *core.Object
	height float64
}

// maxParentWalk is how far a walk up managed parents goes at all before it fails closed (inheritance itself stops at
// 16).
const maxParentWalk = 256

// chainFrom is the chain above (and including) one managed resource. It depends only on the resource, never on where
// a walk started, so memo can share it between the resources of one batch. A cycle (which registration never creates)
// or a runaway chain yields the invalid label.
func chainFrom(ctx context.Context, tx core.IamStore, tenantID string, scheme *clearanceScheme, node clearanceRef, visiting map[string]bool, memo map[string]*inheritedChain) (*inheritedChain, error) {
	key := node.key()
	if known, ok := memo[key]; ok {
		return known, nil
	}
	if visiting[key] || len(visiting) >= maxParentWalk {
		return &inheritedChain{label: invalidClassificationLabel(), height: math.Inf(1)}, nil
	}
	visiting[key] = true
	stored, err := StoredLabel(ctx, tx, tenantID, node.Type, node.ID)
	if err != nil {
		return nil, err
	}
	managed, err := ManagedResource(ctx, tx, tenantID, node.Type, node.ID)
	if err != nil {
		return nil, err
	}
	upper := &inheritedChain{height: 0}
	if above, ok := clearanceParentOf(managed); ok {
		if upper, err = chainFrom(ctx, tx, tenantID, scheme, above, visiting, memo); err != nil {
			return nil, err
		}
	}
	delete(visiting, key)
	var here *core.Object
	if stored != nil && truthy(stored.Get("inheritToChildren")) {
		here = storedSchemeLabel(stored, scheme)
	}
	chain := &inheritedChain{label: joinClearanceLabels(here, upper.label, scheme.definition), height: upper.height + 1}
	memo[key] = chain
	return chain, nil
}

// inheritedAt is the labels a resource (`self`, a `{type}/{id}` key) inherits from `parent` and the managed ancestors
// above it: the join of every one of their labels marked `inheritToChildren`. More than maxInheritanceDepth ancestors,
// or a cyclic chain, inherits the invalid label (fail closed). memo shares results between the resources of one batch.
func inheritedAt(ctx context.Context, tx core.IamStore, tenantID string, scheme *clearanceScheme, parent clearanceRef, self string, memo map[string]*inheritedChain) (*core.Object, error) {
	chain, err := chainFrom(ctx, tx, tenantID, scheme, parent, map[string]bool{self: true}, memo)
	if err != nil {
		return nil, err
	}
	if chain.height > ClearanceLimits.MaxInheritanceDepth {
		return invalidClassificationLabel(), nil
	}
	return chain.label, nil
}

// carriedLabel is what a resource carries besides its own label and its managed parents' labels: the labels of the
// same resource in the tenants above the deciding one, for types one record of which serves a subtree
// (clearanceTreeResourceTypes), and the own label of the resource it is part of (containerOf). Nil when there is none.
func carriedLabel(ctx context.Context, tx core.IamStore, tenantID string, scheme *clearanceScheme, typeValue, resourceID string) (*core.Object, error) {
	var label *core.Object
	if clearanceTreeResourceTypes.Has(typeValue) {
		chain, err := clearanceTenantChain(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, realm := range chain[1:] {
			above, err := StoredLabel(ctx, tx, realm, typeValue, resourceID)
			if err != nil {
				return nil, err
			}
			if above != nil {
				label = joinClearanceLabels(label, storedSchemeLabel(above, scheme), scheme.definition)
			}
		}
	}
	if container, ok := containerOf(typeValue, resourceID); ok {
		held, err := StoredLabel(ctx, tx, tenantID, container.Type, container.ID)
		if err != nil {
			return nil, err
		}
		if held != nil {
			label = joinClearanceLabels(label, storedSchemeLabel(held, scheme), scheme.definition)
		}
	}
	return label, nil
}

// iamLabel is the effective IAM-held label of one resource under `scheme`: its own label joined with what it carries
// (carriedLabel) and what it inherits from its managed parents and from the parent its attributes report (see
// clearanceParentsOf), and from the parent `also` reports (what the application resolves for the resource an
// `iam/{type}/{id}` alias names). Nil when unlabeled.
func iamLabel(ctx context.Context, tx core.IamStore, tenantID string, scheme *clearanceScheme, typeValue, resourceID string, attributes, also *core.Object) (*core.Object, error) {
	definition := scheme.definition
	own, err := StoredLabel(ctx, tx, tenantID, typeValue, resourceID)
	if err != nil {
		return nil, err
	}
	record, err := ManagedResource(ctx, tx, tenantID, typeValue, resourceID)
	if err != nil {
		return nil, err
	}
	memo := map[string]*inheritedChain{}
	var label *core.Object
	if own != nil {
		label = storedSchemeLabel(own, scheme)
	}
	carried, err := carriedLabel(ctx, tx, tenantID, scheme, typeValue, resourceID)
	if err != nil {
		return nil, err
	}
	label = joinClearanceLabels(label, carried, definition)
	parents := clearanceParentsOf(record, attributes)
	if also != nil {
		for _, parent := range clearanceParentsOf(record, also) {
			known := false
			for _, existing := range parents {
				if existing.key() == parent.key() {
					known = true
					break
				}
			}
			if !known {
				parents = append(parents, parent)
			}
		}
	}
	self := clearanceRef{Type: typeValue, ID: resourceID}.key()
	for _, parent := range parents {
		inherited, err := inheritedAt(ctx, tx, tenantID, scheme, parent, self, memo)
		if err != nil {
			return nil, err
		}
		label = joinClearanceLabels(label, inherited, definition)
	}
	return label, nil
}

// classificationPresent is `value !== undefined && value !== null` for a resource's classification.
func classificationPresent(resource *ResolvedResource) bool {
	return resource != nil && resource.HasClassification && !nullish(resource.Classification)
}

// AttachLabel (clearances.ts attachLabel): the resource with its effective classification label (the IAM label
// joined with its managed parents' and a resolver's own), `null` (HasClassification, Classification nil) when looked
// up and unlabeled. Labels inherited from managed parents count up to 16 levels; the `classification` the
// application's resolver returned can only raise it, and one that is not valid for the scheme makes the result
// invalid, so every party is refused. Without a scheme to enforce (options.Scheme nil) the resource is returned
// unchanged. Platform-internal resources carry a label only as `iam/{type}/{id}`, labeled as the resource it names,
// with what was resolved for that name (options.Named) joined in; a failed resolution of it refuses every party.
func AttachLabel(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, resource ResolvedResource, options AttachLabelOptions) (result ResolvedResource, err error) {
	if options.Scheme == nil {
		return resource, nil
	}
	scheme := viewScheme(options.Scheme)
	// `iam/{type}/{id}` is labeled as the resource it names, with what was resolved for this name (the parent its
	// attributes report, a resolver's own label) joined in like for the resource itself, so the alias never reads lower.
	labeledType, labeledID, attributes := resource.Type, resource.ID, resource.Attributes
	alias := InternalResourceTypes.Has(resource.Type)
	if alias {
		slash := -1
		if resource.Type == "iam" {
			slash = strings.Index(resource.ID, "/")
		}
		if slash <= 0 {
			return resource, nil
		}
		labeledType, labeledID = resource.ID[:slash], resource.ID[slash+1:]
		if labeledID == "" || InternalResourceTypes.Has(labeledType) {
			return resource, nil
		}
	}
	// named: undefined (hasNamed false), null (Named nil: its resolver failed) or the resource the alias names.
	hasNamed := alias && options.HasNamed
	var named *ResolvedResource
	if hasNamed {
		named = options.Named
	}
	var also *core.Object
	if named != nil {
		also = named.Attributes
	}
	label, err := iamLabel(ctx, tx, tenantID, scheme, labeledType, labeledID, attributes, also)
	if err != nil {
		return resource, err
	}
	if classificationPresent(&resource) {
		label = joinClearanceLabels(label, schemeLabel(resource.Classification, scheme.definition), scheme.definition)
	}
	if hasNamed && named == nil {
		label = invalidClassificationLabel()
	} else if classificationPresent(named) {
		label = joinClearanceLabels(label, schemeLabel(named.Classification, scheme.definition), scheme.definition)
	}
	result = resource
	result.HasClassification = true
	if label != nil {
		result.Classification = label
	} else {
		result.Classification = nil
	}
	return result, nil
}

// InheritedLabel (clearances.ts inheritedLabel): What a resource inherits under `scheme`, without its own label: the
// join of the labels marked `inheritToChildren` of its managed ancestors (through the parents `parentsOf` names for
// its registration) and what it carries (`carriedLabel`: the same model's labels in the tenants above, an SSH
// login's host label); undefined when it inherits nothing.
func InheritedLabel(ctx context.Context, tx core.IamStore, tenantID string, scheme *core.Object, typeValue string, resourceID string) (result *core.Object, err error) {
	return inheritedLabel(ctx, tx, tenantID, viewScheme(scheme), typeValue, resourceID)
}

func inheritedLabel(ctx context.Context, tx core.IamStore, tenantID string, scheme *clearanceScheme, typeValue, resourceID string) (*core.Object, error) {
	record, err := ManagedResource(ctx, tx, tenantID, typeValue, resourceID)
	if err != nil {
		return nil, err
	}
	memo := map[string]*inheritedChain{}
	label, err := carriedLabel(ctx, tx, tenantID, scheme, typeValue, resourceID)
	if err != nil {
		return nil, err
	}
	var attributes *core.Object
	if record != nil {
		attributes = ResolvedManaged(record).Attributes
	}
	self := clearanceRef{Type: typeValue, ID: resourceID}.key()
	for _, parent := range clearanceParentsOf(record, attributes) {
		inherited, err := inheritedAt(ctx, tx, tenantID, scheme, parent, self, memo)
		if err != nil {
			return nil, err
		}
		label = joinClearanceLabels(label, inherited, scheme.definition)
	}
	return label, nil
}

// typeLabels is labelsForType under a scheme already known.
func typeLabels(ctx context.Context, tx core.IamStore, tenantID string, scheme *clearanceScheme, typeValue string) (map[string]*core.Object, error) {
	definition := scheme.definition
	result := map[string]*core.Object{}
	stored, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", tenantID, "type", typeValue), nil)
	if err != nil {
		return nil, err
	}
	for _, item := range stored {
		if item.Get("tenantId") == tenantID && item.Get("type") == typeValue {
			result[jsString(item.Get("resourceId"))] = storedSchemeLabel(item, scheme)
		}
	}
	// Types one record of which serves a subtree carry the labels written above too (see carriedLabel).
	if clearanceTreeResourceTypes.Has(typeValue) {
		chain, err := clearanceTenantChain(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, realm := range chain[1:] {
			above, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", realm, "type", typeValue), nil)
			if err != nil {
				return nil, err
			}
			for _, item := range above {
				if item.Get("tenantId") == realm && item.Get("type") == typeValue {
					resourceID := jsString(item.Get("resourceId"))
					result[resourceID] = joinClearanceLabels(result[resourceID], storedSchemeLabel(item, scheme), definition)
				}
			}
		}
	}
	memo := map[string]*inheritedChain{}
	records, err := tx.Find(ctx, "resources", core.NewObject("tenantId", tenantID, "type", typeValue), nil)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.Get("type") != typeValue {
			continue
		}
		resourceID := jsString(record.Get("resourceId"))
		// The same parents `resolve` follows for the registration (see clearanceParentsOf).
		joined := result[resourceID]
		self := clearanceRef{Type: typeValue, ID: resourceID}.key()
		for _, parent := range clearanceParentsOf(record, ResolvedManaged(record).Attributes) {
			inherited, err := inheritedAt(ctx, tx, tenantID, scheme, parent, self, memo)
			if err != nil {
				return nil, err
			}
			joined = joinClearanceLabels(joined, inherited, definition)
		}
		if joined != nil {
			result[resourceID] = joined
		}
	}
	return result, nil
}

// LabelsForType (clearances.ts labelsForType): The effective IAM-held labels of every labeled resource of one type
// in a tenant, by resource id, for listings: own labels joined with what registered resources inherit from their
// managed parents. Labels an application resolver asserts are not included (decisions still apply them). Empty when
// there is no scheme to enforce; where labels outlived their scheme (`enforcedScheme`), each one is invalid and
// refuses everyone.
func LabelsForType(ctx context.Context, tx core.IamStore, tenantID string, typeValue string) (result map[string]*core.Object, err error) {
	scheme, err := SchemeForTenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if scheme == nil {
		return map[string]*core.Object{}, nil
	}
	return typeLabels(ctx, tx, tenantID, viewScheme(scheme), typeValue)
}

// --- parties ---------------------------------------------------------------------------------------

// clearanceState is a party's clearance as it stands at decision time (TypeScript PartyState).
type clearanceState struct {
	identityID string
	// rank of the level the party counts at; -1 without a clearance.
	rank float64
	// compartments and citizenship are sets in insertion order.
	compartments []string
	citizenship  []string
	// status is the EffectiveClearanceStatus.
	status string
	// level is the level the party counts at (capped for guests); nil without a clearance.
	level  *core.Object
	record *core.Object
}

func unclearedState(identityID, status string, record *core.Object) *clearanceState {
	return &clearanceState{identityID: identityID, rank: -1, compartments: []string{}, citizenship: []string{}, status: status, record: record}
}

func stringSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}

// party is the state's ClearanceParty.
func (s *clearanceState) party() *core.ClearanceParty {
	return &core.ClearanceParty{IdentityID: s.identityID, Rank: s.rank, Compartments: stringSet(s.compartments), Citizenship: stringSet(s.citizenship)}
}

// value is the state as a model value: {party, status, level?, record?}.
func (s *clearanceState) value() *core.Object {
	out := core.NewObject("party", core.NewObject("identityId", s.identityID, "rank", s.rank,
		"compartments", stringsOf(s.compartments), "citizenship", stringsOf(s.citizenship)), "status", s.status)
	if s.level != nil {
		out.Set("level", s.level)
	}
	if s.record != nil {
		out.Set("record", s.record)
	}
	return out
}

// ClearancePartyOf reads a party model value ({identityId, rank, compartments, citizenship}, the `party` of a
// PartyState) into core's ClearanceParty.
func ClearancePartyOf(party *core.Object) *core.ClearanceParty {
	out := &core.ClearanceParty{Rank: math.NaN(), Compartments: map[string]bool{}, Citizenship: map[string]bool{}}
	if party == nil {
		return out
	}
	out.IdentityID, _ = party.Get("identityId").(string)
	if rank, ok := party.Get("rank").(float64); ok {
		out.Rank = rank
	}
	for key, set := range map[string]map[string]bool{"compartments": out.Compartments, "citizenship": out.Citizenship} {
		switch list := party.Get(key).(type) {
		case []any:
			for _, item := range list {
				if text, ok := item.(string); ok {
					set[text] = true
				}
			}
		case []string:
			for _, item := range list {
				set[item] = true
			}
		}
	}
	return out
}

// ReadClearance (clearances.ts readClearance): An identity's clearance record (in the identity's own tenant), if
// any.
func ReadClearance(ctx context.Context, tx core.IamStore, identity *core.Object) (result *core.Object, err error) {
	identityID := jsString(identity.Get("id"))
	record, err := tx.Get(ctx, ClearanceCollections.Clearances, identityID)
	if err != nil || record == nil {
		return nil, err
	}
	if strictEquals(record.Get("tenantId"), identity.Get("tenantId")) && strictEquals(record.Get("identityId"), identity.Get("id")) {
		return record, nil
	}
	return nil, nil
}

// liveCompartments are the compartments a record's read-ins hold right now: known to the scheme, NDA (when named)
// currently accepted.
func liveCompartments(ctx context.Context, tx core.IamStore, scheme *clearanceScheme, record *core.Object, now int64) ([]string, error) {
	known := map[string]bool{}
	for _, compartment := range scheme.definition.Compartments {
		known[compartment.ID] = true
	}
	held := newOrderedSet()
	readIns, _ := record.Get("readIns").([]any)
	for _, item := range readIns {
		compartmentID, ok := member(item, "compartmentId").(string)
		if !ok || !known[compartmentID] {
			continue
		}
		if agreementID := member(item, "agreementId"); !isUndefined(agreementID) {
			agreement, err := tx.Get(ctx, "agreements", jsString(agreementID))
			if err != nil {
				return nil, err
			}
			acceptance, err := tx.Get(ctx, "agreementAcceptances", jsString(agreementID)+":"+jsString(record.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if agreement == nil ||
				!strictEquals(agreement.Get("tenantId"), record.Get("tenantId")) ||
				acceptance == nil ||
				!strictEquals(acceptance.Get("tenantId"), record.Get("tenantId")) ||
				!strictEquals(acceptance.Get("identityId"), record.Get("identityId")) ||
				!strictEquals(acceptance.Get("agreementId"), agreement.Get("id")) ||
				!AcceptanceCurrent(agreement, acceptance, now) {
				continue
			}
		}
		held.Add(compartmentID)
	}
	return held.Values(), nil
}

// PartyState (clearances.ts partyState): One identity's clearance at decision time under `scheme`: the identity must
// be active and unexpired (and, unless `tenantId` is "" (undefined), of that tenant), the record issued under this
// scheme, active (or interim where the scheme allows it) and unexpired, its level known; guests count at most at the
// scheme's guest ceiling and never hold compartments; compartments count only while their NDA acceptance is current.
// Anything else is no clearance. The result is {party, status, level?, record?}.
func PartyState(ctx context.Context, tx core.IamStore, scheme *core.Object, identity *core.Object, identityID string, tenantID string, now int64) (result *core.Object, err error) {
	state, err := partyStateOf(ctx, tx, viewScheme(scheme), identity, identityID, tenantID, now)
	if err != nil {
		return nil, err
	}
	return state.value(), nil
}

func partyStateOf(ctx context.Context, tx core.IamStore, scheme *clearanceScheme, identity *core.Object, identityID, tenantID string, now int64) (*clearanceState, error) {
	none := func(status string, record *core.Object) *clearanceState {
		return unclearedState(identityID, status, record)
	}
	if identity == nil || identity.Get("id") != identityID || (tenantID != "" && identity.Get("tenantId") != tenantID) {
		return none("none", nil), nil
	}
	expiresAt, expires := identity.Get("expiresAt").(float64)
	active := identity.Get("status") == "active" && !(expires && expiresAt <= float64(now))
	// An inactive account never counts; its record is read only to report a suspended or ended clearance as such.
	record, err := ReadClearance(ctx, tx, identity)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return none("none", nil), nil
	}
	if !strictEquals(record.Get("schemeTenantId"), scheme.tenantID()) {
		return none("none", record), nil
	}
	status, _ := record.Get("status").(string)
	if status != "active" && status != "interim" {
		return none(status, record), nil
	}
	if !active {
		return none("none", record), nil
	}
	if status == "interim" && !truthy(scheme.record.Get("interimAllowed")) {
		return none("none", record), nil
	}
	if recordExpiry, ok := record.Get("expiresAt").(float64); ok && recordExpiry <= float64(now) {
		return none("expired", record), nil
	}
	level := schemeLevelOf(scheme.record, record.Get("level"))
	if level == nil {
		return none("none", record), nil
	}
	compartments := []string{}
	if !isUndefined(identity.Get("guest")) {
		ceiling := schemeLevelOf(scheme.record, scheme.record.Get("guestCeiling"))
		if ceiling == nil {
			return none("none", record), nil
		}
		if jsNumber(level.Get("rank")) > jsNumber(ceiling.Get("rank")) {
			level = ceiling
		}
	} else if compartments, err = liveCompartments(ctx, tx, scheme, record, now); err != nil {
		return nil, err
	}
	citizenship := newOrderedSet()
	if list, ok := record.Get("citizenship").([]any); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				citizenship.Add(text)
			}
		}
	}
	return &clearanceState{identityID: identityID, rank: jsNumber(level.Get("rank")), compartments: compartments,
		citizenship: citizenship.Values(), status: status, level: level, record: record}, nil
}

// delegatedAgents are the agents of a delegated session: the acting agent and every agent that handed the work on to
// it.
func delegatedAgents(principal *Principal, agentScope *AgentDecisionScope) []string {
	ids := []string{}
	add := func(value any) {
		if text, ok := value.(string); ok && text != "" && !containsString(ids, text) {
			ids = append(ids, text)
		}
	}
	if agentScope != nil {
		if agentScope.AgentIDs != nil {
			for _, value := range agentScope.AgentIDs {
				add(value)
			}
		} else if chain, ok := member(agentScope.Keys, "principal.delegationChain").([]any); ok {
			for _, value := range chain {
				add(value)
			}
		}
		add(member(agentScope.Keys, "principal.agentId"))
	}
	add(principal.Session.Get("agentId"))
	return ids
}

// SessionParties (clearances.ts sessionParties): The parties of a session in `target`, each with its clearance: a
// person in their own tenant (an impersonation session: the member; the administrator is decided separately); a
// service account's key: the account; an agent's key (or a session token from it): the agent and its sponsor; a
// session token: its source identity; a delegated session: the person, the acting agent and every agent above it in
// the hand-off chain; a role session: nobody cleared; root: the root administrator's record when issued under the
// target's scheme. Unknown session kinds are uncleared. Each state is {party, status, level?, record?}.
func SessionParties(ctx context.Context, tx core.IamStore, principal *Principal, target *core.Object, agentScope *AgentDecisionScope, scheme *core.Object, now int64, root bool) (result []*core.Object, err error) {
	states, err := sessionStates(ctx, tx, principal, target, agentScope, viewScheme(scheme), now, root)
	if err != nil {
		return nil, err
	}
	result = make([]*core.Object, len(states))
	for index, state := range states {
		result[index] = state.value()
	}
	return result, nil
}

func sessionStates(ctx context.Context, tx core.IamStore, principal *Principal, target *core.Object, agentScope *AgentDecisionScope, scheme *clearanceScheme, now int64, root bool) ([]*clearanceState, error) {
	identity, session := principal.Identity, principal.Session
	identityID := jsString(identity.Get("id"))
	uncleared := func(id string) *clearanceState { return unclearedState(id, "none", nil) }
	if root {
		state, err := partyStateOf(ctx, tx, scheme, identity, identityID, "", now)
		if err != nil {
			return nil, err
		}
		return []*clearanceState{state}, nil
	}
	targetID := target.Get("id")
	if !strictEquals(session.Get("tenantId"), targetID) || !strictEquals(identity.Get("tenantId"), targetID) {
		return []*clearanceState{uncleared(identityID)}, nil
	}
	tenantID := jsString(targetID)
	local := func(candidate *core.Object, id string) (*clearanceState, error) {
		return partyStateOf(ctx, tx, scheme, candidate, id, tenantID, now)
	}
	load := func(id string) (*core.Object, error) { return tx.Get(ctx, "identities", id) }
	switch session.Get("kind") {
	case "user":
		state, err := local(identity, identityID)
		if err != nil {
			return nil, err
		}
		return []*clearanceState{state}, nil
	case "api-key", "session-token":
		own, err := local(identity, identityID)
		if err != nil {
			return nil, err
		}
		if identity.Get("kind") != "agent" {
			return []*clearanceState{own}, nil
		}
		sponsorID, ok := member(identity.Get("agent"), "sponsorId").(string)
		if !ok || sponsorID == "" {
			return []*clearanceState{own, uncleared(identityID + "#sponsor")}, nil
		}
		sponsor, err := load(sponsorID)
		if err != nil {
			return nil, err
		}
		if sponsor != nil && sponsor.Get("kind") != "user" {
			sponsor = nil
		}
		sponsorState, err := local(sponsor, sponsorID)
		if err != nil {
			return nil, err
		}
		return []*clearanceState{own, sponsorState}, nil
	case "delegated":
		own, err := local(identity, identityID)
		if err != nil {
			return nil, err
		}
		states := []*clearanceState{own}
		agentIDs := delegatedAgents(principal, agentScope)
		if len(agentIDs) == 0 {
			return append(states, uncleared(identityID+"#agent")), nil
		}
		for _, agentID := range agentIDs {
			agent, err := load(agentID)
			if err != nil {
				return nil, err
			}
			if agent != nil && agent.Get("kind") != "agent" {
				agent = nil
			}
			state, err := local(agent, agentID)
			if err != nil {
				return nil, err
			}
			states = append(states, state)
		}
		return states, nil
	}
	return []*clearanceState{uncleared(identityID)}, nil
}

// clearanceIntersection is the sorted members of every set (the empty list for no sets).
func clearanceIntersection(sets [][]string) []any {
	if len(sets) == 0 {
		return []any{}
	}
	members := make([]map[string]bool, len(sets))
	for index, set := range sets {
		members[index] = stringSet(set)
	}
	shared := []string{}
	for _, value := range sets[0] {
		every := true
		for _, set := range members {
			if !set[value] {
				every = false
				break
			}
		}
		if every {
			shared = append(shared, value)
		}
	}
	sort.SliceStable(shared, func(i, j int) bool { return compareUTF16(shared[i], shared[j]) < 0 })
	return stringsOf(shared)
}

// combinedStatus is the status the parties hold together: the first that does not count, otherwise interim when any
// is interim.
func combinedStatus(states []*clearanceState) string {
	for _, state := range states {
		if state.status != "active" && state.status != "interim" {
			return state.status
		}
	}
	for _, state := range states {
		if state.status == "interim" {
			return "interim"
		}
	}
	return "active"
}

// clearanceKeys are the `principal.clearance*` policy keys of a set of parties.
func clearanceKeys(states []*clearanceState) *core.Object {
	rank := -1.0
	if len(states) > 0 {
		rank = math.Inf(1)
		for _, state := range states {
			rank = math.Min(rank, state.rank)
		}
	}
	var weakest *clearanceState
	for _, state := range states {
		if state.rank == rank {
			weakest = state
			break
		}
	}
	keys := core.NewObject("principal.clearanceRank", rank)
	if rank >= 0 && weakest != nil && weakest.level != nil {
		keys.Set("principal.clearanceLevel", weakest.level.Get("id"))
	}
	status := "none"
	if len(states) > 0 {
		status = combinedStatus(states)
	}
	keys.Set("principal.clearanceStatus", status)
	compartments := make([][]string, len(states))
	citizenship := make([][]string, len(states))
	for index, state := range states {
		compartments[index], citizenship[index] = state.compartments, state.citizenship
	}
	keys.Set("principal.clearanceCompartments", clearanceIntersection(compartments))
	keys.Set("principal.clearanceCitizenship", clearanceIntersection(citizenship))
	return keys
}

func clearanceRefused() *core.Decision {
	return &core.Decision{Allowed: false, Reason: "CLEARANCE_REQUIRED", Matched: []string{}}
}

// ApplicableLabel (clearances.ts applicableLabel): The label the scheme applies to a resource, `undefined` when it
// carries none, or `false` when it must be refused whoever asks: its label was never looked up, or it lacks the
// label its type requires and the scheme sets no default. The result is a label (*core.Object), nil (undefined) or
// false.
func ApplicableLabel(scheme *core.Object, resource ResolvedResource) (result any, err error) {
	label, refuse := applicableLabel(scheme, resource)
	if refuse {
		return false, nil
	}
	if label == nil {
		return nil, nil
	}
	return label, nil
}

// asLabel is a classification value read as a label: an object as itself, an array (an object in JavaScript, with no
// level) as an empty object, so it refuses every party like the array would.
func asLabel(value any) *core.Object {
	if object, ok := value.(*core.Object); ok && object != nil {
		return object
	}
	return core.NewObject()
}

// defaultLabelOr is `scheme.defaultLabel ?? false`: the default label, or refuse.
func defaultLabelOr(scheme *core.Object) (*core.Object, bool) {
	value := scheme.Get("defaultLabel")
	if nullish(value) {
		return nil, true
	}
	return asLabel(value), false
}

// applicableLabel is ApplicableLabel as (label, refuse): refuse true is `false`, a nil label `undefined`.
func applicableLabel(scheme *core.Object, resource ResolvedResource) (*core.Object, bool) {
	// Platform-internal resources are not labeled, except `iam/{type}/{id}` naming a labeled resource (or, once its
	// label was looked up, an unlabeled one of a type that requires a label: refused like the resource itself).
	if InternalResourceTypes.Has(resource.Type) {
		if resource.HasClassification && resource.Classification != nil && typeOf(resource.Classification) == "object" {
			return asLabel(resource.Classification), false
		}
		slash := -1
		if resource.Type == "iam" {
			slash = strings.Index(resource.ID, "/")
		}
		if resource.HasClassification && resource.Classification == nil && slash > 0 && labelRequired(scheme, resource.ID[:slash]) {
			return defaultLabelOr(scheme)
		}
		return nil, false
	}
	if !resource.HasClassification || isUndefined(resource.Classification) {
		return nil, true
	}
	if resource.Classification == nil {
		if labelRequired(scheme, resource.Type) {
			return defaultLabelOr(scheme)
		}
		return nil, false
	}
	label, ok := resource.Classification.(*core.Object)
	if !ok || label == nil {
		return nil, true
	}
	return label, false
}

// PartiesFail (clearances.ts partiesFail): Whether every party dominates the label; undefined ("") when they do, else
// the first failure. `definition` is the scheme's definition (stored form).
func PartiesFail(parties []*core.Object, label *core.Object, definition *core.Object) (result string, err error) {
	converted := make([]*core.ClearanceParty, len(parties))
	for index, party := range parties {
		converted[index] = ClearancePartyOf(party)
	}
	return partiesFail(converted, label, schemeDefinitionOf(definition)), nil
}

func partiesFail(parties []*core.ClearanceParty, label *core.Object, definition *core.ClassificationSchemeDefinition) string {
	if len(parties) == 0 {
		return "level"
	}
	var value any
	if label != nil {
		value = label
	}
	for _, party := range parties {
		if failure := core.Dominates(party, value, definition); failure != "" {
			return failure
		}
	}
	return ""
}

// ClearanceScope (clearances.ts clearanceScope): the mandatory access check of a session in a tenant: nil when
// clearances are off, there is no scheme to enforce there (`enforcedScheme`: none in force and no label left over from
// one), or the principal is a root administrator (`root`) and `clearances.appliesToRoot` is false. Otherwise the
// session's parties (see SessionParties) with their clearances at `now`, their policy keys, and the check every party
// must pass on labeled resources. `chain` is the target's ancestry from itself to the root.
func ClearanceScope(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, target *core.Object, chain []*core.Object, agentScope *AgentDecisionScope, now int64, root bool) (result *MandatoryAccess, err error) {
	clearances := server.Config.Clearances
	if clearances == nil {
		return nil, nil
	}
	if len(chain) == 0 {
		chain = []*core.Object{target}
	}
	ids := make([]string, len(chain))
	for index, realm := range chain {
		ids[index] = jsString(realm.Get("id"))
	}
	targetID := jsString(target.Get("id"))
	record, err := enforcedScheme(ctx, tx, targetID, ids)
	if err != nil || record == nil {
		return nil, err
	}
	if root && !clearances.AppliesToRoot {
		return nil, nil
	}
	scheme := viewScheme(record)
	states, err := sessionStates(ctx, tx, principal, target, agentScope, scheme, now, root)
	if err != nil {
		return nil, err
	}
	parties := make([]*core.ClearanceParty, len(states))
	for index, state := range states {
		parties[index] = state.party()
	}
	definition := scheme.definition
	passes := func(label *core.Object) bool { return partiesFail(parties, label, definition) == "" }
	return &MandatoryAccess{
		Scheme: record,
		Keys:   clearanceKeys(states),
		LabelOf: func(resource ResolvedResource) *core.Object {
			label, refuse := applicableLabel(record, resource)
			if refuse {
				return nil
			}
			return label
		},
		RankOf: func(label *core.Object) *float64 {
			if label == nil {
				return nil
			}
			rank, ok := core.LabelRank(label, definition)
			if !ok {
				return nil
			}
			return &rank
		},
		CheckOf: func(resource ResolvedResource, action string) *core.Decision {
			if strings.HasPrefix(action, "iam:") {
				return nil
			}
			label, refuse := applicableLabel(record, resource)
			if !refuse && label == nil {
				return nil
			}
			if !refuse && passes(label) {
				return nil
			}
			return clearanceRefused()
		},
		FilterOf: func(ctx context.Context, resourceType, action string) (*core.Object, error) {
			filter, err := mandatoryFilter(ctx, server, tx, record, targetID, passes, resourceType, action)
			if err != nil {
				return nil, err
			}
			return filter.ToValue(), nil
		},
	}, nil
}

// mandatoryFilter is MandatoryAccess.filter: for query planning (planResources), the resources of `type` every party
// may read, by id. Refuses (UNSUPPORTED_FILTER) an application (unmanaged) type the scheme requires labels on, and any
// application type while a label in the tenant passes down to children (reported parents are invisible to a filter).
// Always passes `iam:*` actions.
func mandatoryFilter(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, targetID string, passes func(*core.Object) bool, typeValue, action string) (core.ResourceFilter, error) {
	if strings.HasPrefix(action, "iam:") || InternalResourceTypes.Has(typeValue) {
		return core.TrueFilter, nil
	}
	scheme := viewScheme(record)
	required := labelRequired(record, typeValue)
	definitionOfType, err := server.Catalog.ResourceTypeDefinition(ctx, tx, targetID, typeValue)
	if err != nil {
		return core.ResourceFilter{}, err
	}
	// Registered resources answer for the action unless the type is one only a tenant registered and the action is the
	// application's: `resolve` then asks the application's resolver (decisions.ts shadowsApplicationType), so the type
	// is planned as an application type.
	managed := definitionOfType != nil && definitionOfType.Managed &&
		!(server.Options.ResolveResource != nil && definitionOfType.Source == "tenant" && !strings.HasPrefix(action, typeValue+":"))
	if required && !managed {
		return core.ResourceFilter{}, core.NewIamError("UNSUPPORTED_FILTER",
			"Resources of this type must carry a classification label, which a filter cannot check for application resources; check them with authorize")
	}
	one := 1
	// An application resource also inherits the labels of the parent its resolver reports, which no filter can see:
	// while any label in the tenant passes down to children, application types are not planned (fail closed).
	if !managed {
		inheriting, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", targetID, "inheritToChildren", true), &core.FindOptions{Limit: &one})
		if err != nil {
			return core.ResourceFilter{}, err
		}
		if len(inheriting) > 0 {
			return core.ResourceFilter{}, core.NewIamError("UNSUPPORTED_FILTER",
				"Classification labels pass down to application resources through the parents their resolver reports, which a filter cannot check; check them with authorize")
		}
	}
	// Resources part of another carry its label (containerOf: an SSH host's label on its logins), which a filter by id
	// cannot follow: while any of those is labeled, the type is not planned (fail closed).
	if container, ok := clearanceContainerTypes[typeValue]; ok {
		held, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", targetID, "type", container), &core.FindOptions{Limit: &one})
		if err != nil {
			return core.ResourceFilter{}, err
		}
		if len(held) > 0 {
			return core.ResourceFilter{}, core.NewIamError("UNSUPPORTED_FILTER",
				"These resources carry the classification labels of the resources they are part of, which a filter cannot check; check them with authorize")
		}
	}
	labels, err := typeLabels(ctx, tx, targetID, scheme, typeValue)
	if err != nil {
		return core.ResourceFilter{}, err
	}
	sortIDs := func(ids []string) []any {
		sort.SliceStable(ids, func(i, j int) bool { return compareUTF16(ids[i], ids[j]) < 0 })
		return stringsOf(ids)
	}
	if required {
		allowed := newOrderedSet()
		records, err := tx.Find(ctx, "resources", core.NewObject("tenantId", targetID, "type", typeValue), nil)
		if err != nil {
			return core.ResourceFilter{}, err
		}
		for _, resource := range records {
			resourceID := jsString(resource.Get("resourceId"))
			label := labels[resourceID]
			if label == nil {
				if fallback := record.Get("defaultLabel"); !nullish(fallback) {
					label = asLabel(fallback)
				}
			}
			if label != nil && passes(label) {
				allowed.Add(resourceID)
			}
		}
		if allowed.Len() == 0 {
			return core.FalseFilter, nil
		}
		return core.ResourceFilter{Kind: "equals", Field: "id", Values: sortIDs(allowed.Values())}, nil
	}
	denied := []string{}
	for resourceID, label := range labels {
		if !passes(label) {
			denied = append(denied, resourceID)
		}
	}
	if len(denied) == 0 {
		return core.TrueFilter, nil
	}
	return core.NotFilter(core.ResourceFilter{Kind: "equals", Field: "id", Values: sortIDs(denied)}), nil
}

// ClearedFor (clearances.ts clearedFor): Whether the mandatory check alone lets `principal` (every party of its
// session) at `resource` in `tenant` for `action`, whatever roles and policies say: for what is decided on someone's
// behalf rather than by their own decision, such as an administrator's credential offer to them. The resource is
// labeled here as `resolve` would label it. True without the option or a scheme to enforce, and for `iam:` actions.
func ClearedFor(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, resource ResolvedResource, action string) (result bool, err error) {
	if server.Config.Clearances == nil {
		return true, nil
	}
	chain, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return false, err
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return false, err
	}
	mandatory, err := ClearanceScope(ctx, server, tx, principal, tenant, chain, nil, server.Now(), root)
	if err != nil {
		return false, err
	}
	if mandatory == nil {
		return true, nil
	}
	labeled, err := AttachLabel(ctx, server, tx, jsString(tenant.Get("id")), resource, AttachLabelOptions{Scheme: mandatory.Scheme})
	if err != nil {
		return false, err
	}
	return mandatory.Check(labeled, action) == nil, nil
}

// --- lifecycle -------------------------------------------------------------------------------------

// clearanceEnded is whether a clearance already ended: revoked for cause or terminated. Such a record keeps why it
// ended.
func clearanceEnded(record *core.Object) bool {
	status := record.Get("status")
	return status == "terminated" || status == "revoked"
}

// KeepInheritedLabel (clearances.ts keepInheritedLabel): Before a registration is deleted (`resources.delete`): what
// it inherits from its managed parents becomes part of its own label (joined with any it has), because labels
// outlive resources but the parent link does not, so deleting it and registering it again under another parent
// cannot declassify it. Audited as `classification:label` with `reason: 'resource-deleted'`. Refuses
// (RESOURCE_IN_USE) while what it inherits cannot be read under the scheme in force: repair that label first. Does
// nothing (and reads nothing) without the option, and nothing without a scheme to enforce or a label to inherit.
func KeepInheritedLabel(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, record *core.Object) (err error) {
	if server.Config.Clearances == nil {
		return nil
	}
	tenantID := jsString(record.Get("tenantId"))
	typeValue := jsString(record.Get("type"))
	resourceID := jsString(record.Get("resourceId"))
	schemeRecord, err := SchemeForTenant(ctx, tx, tenantID)
	if err != nil || schemeRecord == nil {
		return err
	}
	scheme := viewScheme(schemeRecord)
	definition := scheme.definition
	inherited, err := inheritedLabel(ctx, tx, tenantID, scheme, typeValue, resourceID)
	if err != nil || inherited == nil {
		return err
	}
	if !core.IsValidClassificationLabel(inherited, definition) {
		return core.NewIamError("RESOURCE_IN_USE",
			"This resource inherits a classification label the scheme in force cannot read; repair that label before deleting it", 409)
	}
	existing, err := StoredLabel(ctx, tx, tenantID, typeValue, resourceID)
	if err != nil {
		return err
	}
	// An own label the scheme cannot read already refuses everyone, and outlives the resource as it is.
	if existing != nil && !storedLabelValid(existing, scheme) {
		return nil
	}
	var own *core.Object
	if existing != nil {
		own = validClearanceLabel(existing.Get("label"), definition)
	}
	label := joinClearanceLabels(own, validClearanceLabel(inherited, definition), definition)
	if own != nil && core.MustStringify(own) == core.MustStringify(label) {
		return nil
	}
	now := float64(server.Now())
	id := ID()
	inheritToChildren := any(false)
	version := 0.0
	if existing != nil {
		id = jsString(existing.Get("id"))
		if value := existing.Get("inheritToChildren"); !nullish(value) {
			inheritToChildren = value
		}
		if value := existing.Get("version"); !nullish(value) {
			version = jsNumber(value)
		}
	}
	next := core.NewObject(
		"id", id,
		"tenantId", tenantID,
		"uniqueKey", labelKey(typeValue, resourceID),
		"type", typeValue,
		"resourceId", resourceID,
		"label", label,
		"inheritToChildren", inheritToChildren,
		"schemeTenantId", scheme.tenantID(),
		"labeledBy", principal.Identity.Get("id"),
		"labeledAt", now,
		"version", version+1,
	)
	if existing != nil {
		_, err = tx.Put(ctx, ClearanceCollections.Labels, next)
	} else {
		_, err = tx.Insert(ctx, ClearanceCollections.Labels, next)
	}
	if err != nil {
		return err
	}
	metadata := core.NewObject("type", typeValue, "level", label.Get("level"))
	if compartments, ok := label.Get("compartments").([]any); ok && len(compartments) > 0 {
		metadata.Set("compartments", append([]any{}, compartments...))
	}
	if truthy(label.Get("noforn")) {
		metadata.Set("noforn", true)
	}
	if releasable, ok := label.Get("releasableTo").([]any); ok {
		metadata.Set("releasableTo", append([]any{}, releasable...))
	}
	metadata.Set("inheritToChildren", next.Get("inheritToChildren"))
	if existing != nil {
		metadata.Set("previousLevel", member(existing.Get("label"), "level"))
	}
	metadata.Set("reason", "resource-deleted")
	return server.Events.Audit(ctx, tx, principal, "classification:label", tenantID, jsString(next.Get("uniqueKey")), "allow", false, metadata)
}

// AssertSchemeKept (clearances.ts assertSchemeKept): Refuses moving `tenant` below `parent` (`tenants.reparent`)
// when the move changes the scheme in force for it and `subtree` (the tenant and its descendants) holds
// classification labels or live (interim, active, or suspended) clearances: they were written under the scheme in
// force now, and under another one they would stop counting, or with none in force no longer protect anything.
// Declassify and revoke them first, or keep the tenant under its scheme. Does nothing (and reads nothing) without
// the option.
func AssertSchemeKept(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, parent *core.Object, subtree []string) (err error) {
	if server.Config.Clearances == nil {
		return nil
	}
	// Only the ancestry above the moved tenant changes: a scheme its subtree defines stays in force unless the new
	// ancestry brings one closer to the root.
	ancestry, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return err
	}
	before, err := EffectiveScheme(ctx, tx, ancestry[1:])
	if err != nil {
		return err
	}
	parentAncestry, err := server.Ancestry(ctx, tx, parent)
	if err != nil {
		return err
	}
	after, err := EffectiveScheme(ctx, tx, parentAncestry)
	if err != nil {
		return err
	}
	schemeTenant := func(scheme *core.Object) any {
		if scheme == nil {
			return core.Undefined
		}
		return scheme.Get("tenantId")
	}
	if strictEquals(schemeTenant(before), schemeTenant(after)) {
		return nil
	}
	one := 1
	for _, tenantID := range subtree {
		labels, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("tenantId", tenantID), &core.FindOptions{Limit: &one})
		if err != nil {
			return err
		}
		records, err := tx.Find(ctx, ClearanceCollections.Clearances, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return err
		}
		live := false
		for _, record := range records {
			status := record.Get("status")
			if record.Get("tenantId") == tenantID && (status == "active" || status == "interim" || status == "suspended") {
				live = true
				break
			}
		}
		held := false
		for _, item := range labels {
			if item.Get("tenantId") == tenantID {
				held = true
				break
			}
		}
		if held || live {
			return core.NewIamError("RESOURCE_IN_USE",
				"Moving this tenant changes the classification scheme in force for it while it holds classification labels or clearances; declassify and revoke them first", 409)
		}
	}
	return nil
}

// TerminateClearancesOf (clearances.ts terminateClearancesOf): Offboarding (`identities.offboard`): ends the
// leaver's clearance as `terminated`, debriefing every compartment (audited as `clearance:debrief` and
// `clearance:terminate` with the identity as the resource). The record stays as history; one that already ended
// (revoked for cause, or terminated) is left as it is, so a revocation is never rewritten as an ordinary departure.
// Returns 1 when a clearance was terminated, else 0. Lifecycle cleanup inside the offboarding operation, so it needs
// no clearance permission. Does nothing (and reads nothing) without the `clearances` option.
func TerminateClearancesOf(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object, reason string) (result float64, err error) {
	if server.Config.Clearances == nil {
		return 0, nil
	}
	record, err := ReadClearance(ctx, tx, identity)
	if err != nil {
		return 0, err
	}
	if record == nil || clearanceEnded(record) {
		return 0, nil
	}
	now := float64(server.Now())
	tenantID := jsString(identity.Get("tenantId"))
	identityID := jsString(identity.Get("id"))
	readIns, _ := record.Get("readIns").([]any)
	for _, readIn := range readIns {
		if err := server.Events.Audit(ctx, tx, principal, "clearance:debrief", tenantID, identityID, "allow", false,
			core.NewObject("compartmentId", member(readIn, "compartmentId"), "reason", "terminated")); err != nil {
			return 0, err
		}
	}
	trimmed := orgSlice16(reason, 512)
	next := record.Clone()
	next.Delete("suspended")
	next.Set("status", "terminated")
	next.Set("readIns", []any{})
	next.Set("terminated", core.NewObject("by", principal.Identity.Get("id"), "at", now, "reason", trimmed))
	next.Set("updatedAt", now)
	next.Set("updatedBy", principal.Identity.Get("id"))
	if _, err := tx.Put(ctx, ClearanceCollections.Clearances, next); err != nil {
		return 0, err
	}
	if err := server.Events.Audit(ctx, tx, principal, "clearance:terminate", tenantID, identityID, "allow", false,
		core.NewObject("level", record.Get("level"), "previousStatus", record.Get("status"), "reason", trimmed)); err != nil {
		return 0, err
	}
	return 1, nil
}

// ReleaseClearancesOf (clearances.ts releaseClearancesOf): Identity deletion (`deleteIdentity`): marks the clearance
// `terminated` and releases its read-ins, keeping the record as history. One that already ended keeps its status (a
// revocation for cause stays a revocation) and only loses any read-ins left. Call only with the `clearances` option.
// TypeScript's defaults are `now = Date.now()` and `by = 'identity-deleted'`.
func ReleaseClearancesOf(ctx context.Context, tx core.IamStore, identity *core.Object, now int64, by string) (err error) {
	record, err := ReadClearance(ctx, tx, identity)
	if err != nil || record == nil {
		return err
	}
	readIns, _ := record.Get("readIns").([]any)
	ended := clearanceEnded(record)
	if ended && len(readIns) == 0 {
		return nil
	}
	next := record.Clone()
	next.Delete("suspended")
	if !ended {
		next.Set("status", "terminated")
	}
	next.Set("readIns", []any{})
	if !ended {
		next.Set("terminated", core.NewObject("by", by, "at", float64(now), "reason", "identity deleted"))
	}
	next.Set("updatedAt", float64(now))
	next.Set("updatedBy", by)
	_, err = tx.Put(ctx, ClearanceCollections.Clearances, next)
	return err
}

// SuspendClearance (clearances.ts suspendClearance): Suspends an identity's active or interim clearance (`suspended`
// with who, when, why and the incident), for the clearances API and automatic responses. It records nothing in the
// audit trail and sends nothing: callers do. A suspension is lifted only by `clearances.reinstate`. `input` is {by, at,
// reason, incidentId?}; the result is {outcome: 'suspended' | 'no-clearance' | 'already-applied', record?}.
func SuspendClearance(ctx context.Context, tx core.IamStore, identity *core.Object, input *core.Object) (result *core.Object, err error) {
	record, err := ReadClearance(ctx, tx, identity)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Get("status") == "revoked" || record.Get("status") == "terminated" {
		return core.NewObject("outcome", "no-clearance"), nil
	}
	if record.Get("status") == "suspended" {
		return core.NewObject("outcome", "already-applied", "record", record), nil
	}
	suspended := core.NewObject("by", input.Get("by"), "at", input.Get("at"), "reason", orgSlice16(jsString(input.Get("reason")), 512))
	if incidentID := input.Get("incidentId"); !isUndefined(incidentID) {
		suspended.Set("incidentId", incidentID)
	}
	suspended.Set("previousStatus", record.Get("status"))
	updated := record.Clone()
	updated.Set("status", "suspended")
	updated.Set("suspended", suspended)
	updated.Set("updatedAt", input.Get("at"))
	updated.Set("updatedBy", input.Get("by"))
	next, err := tx.Put(ctx, ClearanceCollections.Clearances, updated)
	if err != nil {
		return nil, err
	}
	return core.NewObject("outcome", "suspended", "record", next), nil
}

// NotifyClearanceStatus (clearances.ts notifyClearanceStatus): Emails the person (template `clearance-status`) that
// their clearance was suspended, revoked or reinstated, naming the level only. Sent only to people with an address,
// and only when the deployment delivers email.
func NotifyClearanceStatus(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, scheme *core.Object, record *core.Object, status string) (err error) {
	options := server.Options
	if options == nil || options.Authentication == nil || options.Authentication.SendEmail == nil ||
		identity.Get("kind") != "user" || !truthy(identity.Get("email")) {
		return nil
	}
	tenantID := jsString(identity.Get("tenantId"))
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return err
	}
	var level *core.Object
	if scheme != nil {
		level = schemeLevelOf(scheme, record.Get("level"))
	}
	payload := core.NewObject("tenantId", tenantID)
	if tenant != nil {
		payload.Set("tenantName", tenant.Get("name"))
	}
	payload.Set("status", status)
	if level != nil {
		payload.Set("levelName", level.Get("name"))
	}
	_, err = server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
		TenantID: tenantID, Kind: "email", To: jsString(identity.Get("email")), Template: "clearance-status", Payload: payload,
	})
	return err
}

// ClearanceCollections is clearances.ts clearanceCollections.
var ClearanceCollections = struct {
	Schemes    string
	Clearances string
	Labels     string
}{"classificationSchemes", "clearances", "resourceLabels"}

// ClearanceLimits is clearances.ts clearanceLimits.
var ClearanceLimits = struct {
	MaxRequiredTypes    float64
	MaxCitizenship      float64
	MaxNotifyEmails     float64
	MaxInheritanceDepth float64
	MaxRetiredLevels    float64
	ReminderDays        float64
}{100, 10, 20, 16, 500, 60}

// MandatoryAccess (clearances.ts MandatoryAccess) is mandatory access control for one session in one tenant: the
// session's clearance against the tenant's scheme. ClearanceScope builds it; the behaviour is closures over the
// session's parties, as in TypeScript.
type MandatoryAccess struct {
	// Scheme is the scheme the check enforces in the tenant (see SchemeForTenant). Read-only.
	Scheme *core.Object
	// Keys are the `principal.clearance*` keys: the lowest rank of the parties, the shared compartments and
	// citizenship.
	Keys *core.Object
	// LabelOf is the label Check applies to a resource (nil: none).
	LabelOf func(resource ResolvedResource) *core.Object
	// RankOf is the rank of a label's level in the scheme (nil: an unknown level).
	RankOf func(label *core.Object) *float64
	// CheckOf refuses a resource above the session's clearance (nil: no refusal).
	CheckOf func(resource ResolvedResource, action string) *core.Decision
	// FilterOf is the resource filter of the labels the session may read, for query planning.
	FilterOf func(ctx context.Context, resourceType, action string) (*core.Object, error)
}

// Label is the label Check applies to a resource, or nil when it carries none.
func (m *MandatoryAccess) Label(resource ResolvedResource) *core.Object {
	if m == nil || m.LabelOf == nil {
		return nil
	}
	return m.LabelOf(resource)
}

// Rank is the rank of a label's level in the scheme (resource.classificationRank); nil for an unknown level.
func (m *MandatoryAccess) Rank(label *core.Object) *float64 {
	if m == nil || m.RankOf == nil {
		return nil
	}
	return m.RankOf(label)
}

// Check is the refusal of a resource the session may not reach for action; nil when it may.
func (m *MandatoryAccess) Check(resource ResolvedResource, action string) *core.Decision {
	if m == nil || m.CheckOf == nil {
		return nil
	}
	return m.CheckOf(resource, action)
}

// Filter is the resource filter of what the session may reach of a type, for query planning.
func (m *MandatoryAccess) Filter(ctx context.Context, resourceType, action string) (*core.Object, error) {
	if m == nil || m.FilterOf == nil {
		return core.TrueFilter.ToValue(), nil
	}
	return m.FilterOf(ctx, resourceType, action)
}

// AttachLabelOptions is attachLabel's `known`: the scheme (nil: none) and, for `iam/{type}/{id}` aliases, the resource
// the alias names (HasNamed; Named nil: resolving it failed, which the label refuses).
type AttachLabelOptions struct {
	Scheme   *core.Object
	HasNamed bool
	Named    *ResolvedResource
}
