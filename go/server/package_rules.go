package server

// Skeleton of packages/server/src/package-rules.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"github.com/Better-IAM/better-iam/go/core"
)

// MapRuleGroups (package-rules.ts mapRuleGroups): A copy of a rule with its identity.groups values mapped (IDs to
// names for export, names to IDs for apply).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MapRuleGroups(rule any, mapValue func(string) string) (result any, err error) {
	err = notImplemented("package-rules.ts mapRuleGroups")
	return
}

// MapRuleValues (package-rules.ts mapRuleValues): A copy of a rule with the values it tests an array key for mapped
// (IDs to names for export, names to IDs for apply).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MapRuleValues(rule any, key string, mapValue func(string) string) (result any, err error) {
	err = notImplemented("package-rules.ts mapRuleValues")
	return
}

// ParseAutoAssign (package-rules.ts parseAutoAssign): Validates a rule against the deployment's declared attributes
// and (when known) the tenant's groups. Every error message starts with `path`, so configuration documents point at
// the offending package. Values keep the scalar or array form they were given, so export and plan compare
// canonically.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseAutoAssign(value any, env *core.Object, path string) (result *core.Object, err error) {
	err = notImplemented("package-rules.ts parseAutoAssign")
	return
}

// RuleContext (package-rules.ts ruleContext): The context a rule sees: the identity's declared attributes and fixed
// facts, and its group memberships that no access package created (so rules never chain onto another package or keep
// themselves alive). No session, request, or resource keys: a scheduler cannot replay them, and a preview must equal
// a reconcile. `org` supplies `identity.teams` and `identity.departments` where the caller evaluates them, and
// `identity.licenses` with them.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleContext(identity *core.Object, directGroupIDs []string, org *core.Object) (result *core.Object, err error) {
	err = notImplemented("package-rules.ts ruleContext")
	return
}

// RuleDocument (package-rules.ts ruleDocument): Include clauses become allow statements and exclude clauses deny
// statements of one policy document.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleDocument(rule *core.Object) (result *core.Object, err error) {
	err = notImplemented("package-rules.ts ruleDocument")
	return
}

// RuleGroupIDs (package-rules.ts ruleGroupIds): The group IDs (or names) a rule tests with identity.groups.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleGroupIDs(rule *core.Object) (result []string, err error) {
	err = notImplemented("package-rules.ts ruleGroupIds")
	return
}

// RuleInput (package-rules.ts ruleInput): The administrator-written part of a stored rule (or a rule input), without
// runtime state.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleInput(rule *core.Object) (result *core.Object, err error) {
	err = notImplemented("package-rules.ts ruleInput")
	return
}

// RuleKeys (package-rules.ts ruleKeys): Every key a rule may test, in a stable order: fixed keys first, then the
// declared identity attributes. `org` adds `identity.teams` and `identity.departments` for callers that evaluate
// them.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleKeys(identityAttributes *core.Object, options *core.Object) (result []*core.Object, err error) {
	err = notImplemented("package-rules.ts ruleKeys")
	return
}

// RuleMatch (package-rules.ts ruleMatch): Evaluates a compiled rule for one identity; `matchedBy`/`excludedBy` name
// the clauses that held. Guests (guests.ts) match only rules that test `identity.guest` somewhere: a rule written
// for members (`principal.kind: user`) never reaches people from outside the organization.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleMatch(document *core.Object, identity *core.Object, context *core.Object) (result *core.Object, err error) {
	err = notImplemented("package-rules.ts ruleMatch")
	return
}

// RuleProblem (package-rules.ts ruleProblem): The reason a stored rule no longer validates (an attribute declaration
// removed, a group gone), if any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleProblem(rule *core.Object, env *core.Object) (result string, err error) {
	err = notImplemented("package-rules.ts ruleProblem")
	return
}

// RuleValues (package-rules.ts ruleValues): The values a rule tests an array key (identity.groups, identity.teams,
// identity.departments) for.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleValues(rule *core.Object, key string) (result []string, err error) {
	err = notImplemented("package-rules.ts ruleValues")
	return
}

// RuleWarnings (package-rules.ts ruleWarnings): Advice, not errors: rules that also match service accounts, email
// tests that accept unverified addresses, and clauses on facts that callers with fewer rights than the rule's owner
// control. A rule grants under its owner's authority to whoever matches, so whoever sets those facts picks the
// recipients: declared attributes and identity.managerId (iam:identities:update), and memberships of groups without
// role bindings (iam:groups:update alone; adding to a group with bindings needs their authorities). `boundGroups`
// holds the tenant's groups that have role bindings; without it, groups are not checked.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleWarnings(rule *core.Object, env *core.Object) (result []string, err error) {
	err = notImplemented("package-rules.ts ruleWarnings")
	return
}

// AutomaticJustification is package-rules.ts automaticJustification.
const AutomaticJustification = "Automatic: matches the package rule"

// DefaultMaxGrants is package-rules.ts defaultMaxGrants.
const DefaultMaxGrants = 100

// DefaultMaxRemovals is package-rules.ts defaultMaxRemovals.
const DefaultMaxRemovals = 25

// OrgRuleKeys is package-rules.ts orgRuleKeys.
var OrgRuleKeys = mustObject(`{"identity.teams":"team","identity.departments":"department","identity.licenses":"license"}`)
