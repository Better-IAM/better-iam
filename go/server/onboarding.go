package server

// Skeleton of packages/server/src/onboarding.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// SettingsReader is onboarding.ts SettingsReader.
// TypeScript: (no super call)
type SettingsReader struct {
	Cache map[string]any
	Tx    core.IamStore
}

// CandidateFlows (onboarding.ts candidateFlows): The flows of one audience that reach a tenant, before anything
// about a particular person is known: the tenant's own flows for its members, and its ancestors' flows that reach
// down to it. `chain` is the tenant's ancestry (`ctx.ancestry`: the tenant first, the root last). Disabled flows are
// included with `disabledBy` so administrators can see them; locked flows ignore the switch.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CandidateFlows(ctx context.Context, tx core.IamStore, chain []*core.Object, audience string, settings *SettingsReaderType) (result []*core.Object, err error) {
	err = notImplemented("onboarding.ts candidateFlows")
	return
}

// EvaluateFlow (onboarding.ts evaluateFlow): The state of each step and of the whole flow for one subject.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateFlow(candidate *core.Object, progress *core.Object, facts *core.Object, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts evaluateFlow")
	return
}

// FlowAppliesTo (onboarding.ts flowAppliesTo): Whether a member flow applies to this person: people only, newcomers
// unless `includeExisting`, and the rule.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FlowAppliesTo(flow *core.Object, identity *core.Object, groupIDs []string) (result bool, err error) {
	err = notImplemented("onboarding.ts flowAppliesTo")
	return
}

// FlowsForIdentity (onboarding.ts flowsForIdentity): The member flows a person is asked to complete (switched-off
// flows removed), in platform-first order.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FlowsForIdentity(ctx context.Context, tx core.IamStore, chain []*core.Object, identity *core.Object, now int64, candidates []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("onboarding.ts flowsForIdentity")
	return
}

// LiveGroupIDs (onboarding.ts liveGroupIds): The group IDs an identity is a live member of in its tenant (targeting
// rules test these).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveGroupIDs(ctx context.Context, tx core.IamStore, identity *core.Object, now int64) (result []string, err error) {
	err = notImplemented("onboarding.ts liveGroupIds")
	return
}

// LongText (onboarding.ts longText): Multi-line text: tabs and line breaks allowed, other control characters not.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LongText(value any, name string, maxValue float64) (result string, err error) {
	err = notImplemented("onboarding.ts longText")
	return
}

// MemberFacts (onboarding.ts memberFacts): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MemberFacts(ctx context.Context, tx core.IamStore, identity *core.Object, flows []*core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts memberFacts")
	return
}

// MentionsOnboarding (onboarding.ts mentionsOnboarding): whether any statement of the documents names an onboarding
// context key in a condition.
func MentionsOnboarding(documents []any) bool {
	return anyConditionNames(documents, "principal.onboarding", "principal.pendingOnboarding")
}

// OnboardingContext (onboarding.ts onboardingContext): Policy context for a person in their own tenant:
// `principal.onboarding` names the member flows they have completed, and `principal.pendingOnboarding` counts
// required ones still open. Service accounts are never onboarded.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OnboardingContext(ctx context.Context, tx core.IamStore, chain []*core.Object, identity *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts onboardingContext")
	return
}

// ParseAnswers (onboarding.ts parseAnswers): Validates a form step's answers: every required field present, values
// of the declared type and within bounds. Unknown answer keys are refused. Returns the answers to record (empty
// optional fields left out).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseAnswers(step *core.Object, value any) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts parseAnswers")
	return
}

// ParseRule (onboarding.ts parseRule): Validates a member flow's targeting rule. Group tests (`identity.groups`)
// name groups of the defining tenant, so they are refused on flows that reach only descendant tenants, whose people
// are never members of those groups.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseRule(value any, identityAttributes *core.Object, groups []string) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts parseRule")
	return
}

// ParseSettings (onboarding.ts parseSettings): Validates settings input (replace semantics); `disabledFlowIds` is
// checked against the inherited flows by the caller.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseSettings(input *core.Object) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts parseSettings")
	return
}

// ParseSteps (onboarding.ts parseSteps): Validates a flow's steps (1-25, distinct IDs, kinds allowed for the
// audience).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseSteps(value any, audience string, identityAttributes *core.Object) (result []*core.Object, err error) {
	err = notImplemented("onboarding.ts parseSteps")
	return
}

// ProgressID (onboarding.ts progressId): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProgressID(flowID string, subjectID string) (result string, err error) {
	err = notImplemented("onboarding.ts progressId")
	return
}

// PublicFlow (onboarding.ts publicFlow): A flow record without the fields only the defining tenant needs; what
// descendants and members see.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PublicFlow(flow *core.Object) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts publicFlow")
	return
}

// ResolveSettings (onboarding.ts resolveSettings): Welcome copy and support contacts: for each value, the nearest
// tenant in the chain that set it wins.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveSettings(ctx context.Context, chain []*core.Object, settings *SettingsReaderType) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts resolveSettings")
	return
}

// SettingsID (onboarding.ts settingsId): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SettingsID(tenantID string) (result string, err error) {
	err = notImplemented("onboarding.ts settingsId")
	return
}

// SourceOf (onboarding.ts sourceOf): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SourceOf(tenant *core.Object) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts sourceOf")
	return
}

// TenantFacts (onboarding.ts tenantFacts): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TenantFacts(ctx context.Context, tx core.IamStore, tenant *core.Object, flows []*core.Object) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts tenantFacts")
	return
}

// TenantFlowApplies (onboarding.ts tenantFlowApplies): Whether a tenant flow applies to this tenant: newcomers
// unless `includeExisting`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TenantFlowApplies(flow *core.Object, tenant *core.Object) (result bool, err error) {
	err = notImplemented("onboarding.ts tenantFlowApplies")
	return
}

// AutomaticSteps is onboarding.ts automaticSteps.
var AutomaticSteps = newOrderedSet("agreement", "verify-email", "mfa", "passkey", "check")

// MaxCompletionGroups is onboarding.ts maxCompletionGroups.
const MaxCompletionGroups = 10

// MaxFlowsPerTenant is onboarding.ts maxFlowsPerTenant.
const MaxFlowsPerTenant = 50

// SettingsReaderType is onboarding.ts SettingsReader.
type SettingsReaderType struct {
	server *ServerContext
	Cache  map[string]any
	Tx     core.IamStore
}

// Get (onboarding.ts SettingsReader.get): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SettingsReaderType) Get(ctx context.Context, tenantID string) (result *core.Object, err error) {
	err = notImplemented("onboarding.ts SettingsReader.get")
	return
}
