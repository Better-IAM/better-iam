package server

// Skeleton of packages/server/src/clearances.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ApplicableLabel (clearances.ts applicableLabel): The label the scheme applies to a resource, `undefined` when it
// carries none, or `false` when it must be refused whoever asks: its label was never looked up, or it lacks the
// label its type requires and the scheme sets no default.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApplicableLabel(scheme *core.Object, resource ResolvedResource) (result any, err error) {
	err = notImplemented("clearances.ts applicableLabel")
	return
}

// AssertClearances (clearances.ts assertClearances): Refuses with FEATURE_DISABLED (403) unless the deployment
// enables clearances.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertClearances(server *ServerContext) (err error) {
	err = notImplemented("clearances.ts assertClearances")
	return
}

// AssertSchemeKept (clearances.ts assertSchemeKept): Refuses moving `tenant` below `parent` (`tenants.reparent`)
// when the move changes the scheme in force for it and `subtree` (the tenant and its descendants) holds
// classification labels or live (interim, active, or suspended) clearances: they were written under the scheme in
// force now, and under another one they would stop counting, or with none in force no longer protect anything.
// Declassify and revoke them first, or keep the tenant under its scheme. Does nothing (and reads nothing) without
// the option.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertSchemeKept(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, parent *core.Object, subtree []string) (err error) {
	err = notImplemented("clearances.ts assertSchemeKept")
	return
}

// AttachLabel (clearances.ts attachLabel): the resource with its effective classification label (the IAM label
// joined with its managed parents' and a resolver's own), `null` (HasClassification, Classification nil) when looked
// up and unlabeled.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AttachLabel(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, resource ResolvedResource, options AttachLabelOptions) (result ResolvedResource, err error) {
	err = notImplemented("clearances.ts attachLabel")
	return
}

// ClearanceScope (clearances.ts clearanceScope): the mandatory access check of a session in a tenant: nil when
// clearances are off, the tenant has no enforced scheme, or root is exempt.
//
// STUB: returns NOT_IMPLEMENTED (whenever clearances are on) until the module is ported.
func ClearanceScope(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, target *core.Object, chain []*core.Object, agentScope *AgentDecisionScope, now int64, root bool) (result *MandatoryAccess, err error) {
	if server.Options.Clearances == nil {
		return nil, nil
	}
	err = notImplemented("clearances.ts clearanceScope")
	return
}

// ClearedFor (clearances.ts clearedFor): Whether the mandatory check alone lets `principal` (every party of its
// session) at `resource` in `tenant` for `action`, whatever roles and policies say: for what is decided on someone's
// behalf rather than by their own decision, such as an administrator's credential offer to them. The resource is
// labeled here as `resolve` would label it. True without the option or a scheme to enforce, and for `iam:` actions.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ClearedFor(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, resource ResolvedResource, action string) (result bool, err error) {
	err = notImplemented("clearances.ts clearedFor")
	return
}

// DefinedScheme (clearances.ts definedScheme): The scheme a tenant defines itself, if it does.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DefinedScheme(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("clearances.ts definedScheme")
	return
}

// EffectiveScheme (clearances.ts effectiveScheme): The scheme in force for a tenant, given its ancestry (`[tenant,
// parent, ..., root]`): the one defined closest to the root. Undefined when no tenant of the chain defines one.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EffectiveScheme(ctx context.Context, tx core.IamStore, chain []*core.Object) (result *core.Object, err error) {
	err = notImplemented("clearances.ts effectiveScheme")
	return
}

// InheritedLabel (clearances.ts inheritedLabel): What a resource inherits under `scheme`, without its own label: the
// join of the labels marked `inheritToChildren` of its managed ancestors (through the parents `parentsOf` names for
// its registration) and what it carries (`carriedLabel`: the same model's labels in the tenants above, an SSH
// login's host label); undefined when it inherits nothing.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InheritedLabel(ctx context.Context, tx core.IamStore, tenantID string, scheme *core.Object, typeValue string, resourceID string) (result *core.Object, err error) {
	err = notImplemented("clearances.ts inheritedLabel")
	return
}

// KeepInheritedLabel (clearances.ts keepInheritedLabel): Before a registration is deleted (`resources.delete`): what
// it inherits from its managed parents becomes part of its own label (joined with any it has), because labels
// outlive resources but the parent link does not, so deleting it and registering it again under another parent
// cannot declassify it. Audited as `classification:label` with `reason: 'resource-deleted'`. Refuses
// (RESOURCE_IN_USE) while what it inherits cannot be read under the scheme in force: repair that label first. Does
// nothing (and reads nothing) without the option, and nothing without a scheme to enforce or a label to inherit.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeepInheritedLabel(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, record *core.Object) (err error) {
	err = notImplemented("clearances.ts keepInheritedLabel")
	return
}

// LabelKey (clearances.ts labelKey): The natural key of a resource's label: `{type}/{id}`, hashed when it would
// exceed 512 UTF-8 bytes.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LabelKey(typeValue string, resourceID string) (result string, err error) {
	err = notImplemented("clearances.ts labelKey")
	return
}

// LabelsForType (clearances.ts labelsForType): The effective IAM-held labels of every labeled resource of one type
// in a tenant, by resource id, for listings: own labels joined with what registered resources inherit from their
// managed parents. Labels an application resolver asserts are not included (decisions still apply them). Empty when
// there is no scheme to enforce; where labels outlived their scheme (`enforcedScheme`), each one is invalid and
// refuses everyone.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LabelsForType(ctx context.Context, tx core.IamStore, tenantID string, typeValue string) (result map[string]*core.Object, err error) {
	err = notImplemented("clearances.ts labelsForType")
	return
}

// NotifyClearanceStatus (clearances.ts notifyClearanceStatus): Emails the person (template `clearance-status`) that
// their clearance was suspended, revoked or reinstated, naming the level only. Sent only to people with an address,
// and only when the deployment delivers email.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func NotifyClearanceStatus(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, scheme *core.Object, record *core.Object, status string) (err error) {
	err = notImplemented("clearances.ts notifyClearanceStatus")
	return
}

// PartiesFail (clearances.ts partiesFail): Whether every party dominates the label; undefined when they do, else the
// first failure.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PartiesFail(parties []*core.Object, label *core.Object, definition *core.Object) (result string, err error) {
	err = notImplemented("clearances.ts partiesFail")
	return
}

// PartyState (clearances.ts partyState): One identity's clearance at decision time under `scheme`: the identity must
// be active and unexpired (and, unless `tenantId` is undefined, of that tenant), the record issued under this
// scheme, active (or interim where the scheme allows it) and unexpired, its level known; guests count at most at the
// scheme's guest ceiling and never hold compartments; compartments count only while their NDA acceptance is current.
// Anything else is no clearance.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PartyState(ctx context.Context, tx core.IamStore, scheme *core.Object, identity *core.Object, identityID string, tenantID string, now int64) (result *core.Object, err error) {
	err = notImplemented("clearances.ts partyState")
	return
}

// ReadClearance (clearances.ts readClearance): An identity's clearance record (in the identity's own tenant), if
// any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReadClearance(ctx context.Context, tx core.IamStore, identity *core.Object) (result *core.Object, err error) {
	err = notImplemented("clearances.ts readClearance")
	return
}

// ReleaseClearancesOf (clearances.ts releaseClearancesOf): Identity deletion (`deleteIdentity`): marks the clearance
// `terminated` and releases its read-ins, keeping the record as history. One that already ended keeps its status (a
// revocation for cause stays a revocation) and only loses any read-ins left. Call only with the `clearances` option.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseClearancesOf(ctx context.Context, tx core.IamStore, identity *core.Object, now int64, by string) (err error) {
	err = notImplemented("clearances.ts releaseClearancesOf")
	return
}

// SchemeForTenant (clearances.ts schemeForTenant): The scheme decisions enforce in a tenant (`enforcedScheme`),
// reading its ancestry from the store.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SchemeForTenant(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("clearances.ts schemeForTenant")
	return
}

// SchemeLevel (clearances.ts schemeLevel): A level of the scheme by id.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SchemeLevel(scheme *core.Object, levelID string) (result *core.Object, err error) {
	err = notImplemented("clearances.ts schemeLevel")
	return
}

// SessionParties (clearances.ts sessionParties): The parties of a session in `target`, each with its clearance: a
// person in their own tenant (an impersonation session: the member; the administrator is decided separately); a
// service account's key: the account; an agent's key (or a session token from it): the agent and its sponsor; a
// session token: its source identity; a delegated session: the person, the acting agent and every agent above it in
// the hand-off chain; a role session: nobody cleared; root: the root administrator's record when issued under the
// target's scheme. Unknown session kinds are uncleared.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SessionParties(ctx context.Context, tx core.IamStore, principal *Principal, target *core.Object, agentScope *AgentDecisionScope, scheme *core.Object, now int64, root bool) (result []*core.Object, err error) {
	err = notImplemented("clearances.ts sessionParties")
	return
}

// StoredLabel (clearances.ts storedLabel): The stored IAM label of a resource, if it has one.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StoredLabel(ctx context.Context, tx core.IamStore, tenantID string, typeValue string, resourceID string) (result *core.Object, err error) {
	err = notImplemented("clearances.ts storedLabel")
	return
}

// SuspendClearance (clearances.ts suspendClearance): Suspends an identity's active or interim clearance (`suspended`
// with who, when, why and the incident), for the clearances API and automatic responses. It records nothing in the
// audit trail and sends nothing: callers do. A suspension is lifted only by `clearances.reinstate`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SuspendClearance(ctx context.Context, tx core.IamStore, identity *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("clearances.ts suspendClearance")
	return
}

// TerminateClearancesOf (clearances.ts terminateClearancesOf): Offboarding (`identities.offboard`): ends the
// leaver's clearance as `terminated`, debriefing every compartment (audited as `clearance:debrief` and
// `clearance:terminate` with the identity as the resource). The record stays as history; one that already ended
// (revoked for cause, or terminated) is left as it is, so a revocation is never rewritten as an ordinary departure.
// Returns 1 when a clearance was terminated, else 0. Lifecycle cleanup inside the offboarding operation, so it needs
// no clearance permission. Does nothing (and reads nothing) without the `clearances` option.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TerminateClearancesOf(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object, reason string) (result float64, err error) {
	err = notImplemented("clearances.ts terminateClearancesOf")
	return
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
		return nil, notImplemented("clearances.ts MandatoryAccess.filter")
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
