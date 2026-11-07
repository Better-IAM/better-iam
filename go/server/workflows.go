package server

// Skeleton of packages/server/src/workflows.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"github.com/Better-IAM/better-iam/go/core"
)

// DateTarget (workflows.ts dateTarget): The instant a date trigger fires for an identity, or undefined when the
// identity carries no usable date.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DateTarget(trigger *core.Object, identity *core.Object) (result *float64, err error) {
	err = notImplemented("workflows.ts dateTarget")
	return
}

// DefaultBrake (workflows.ts defaultBrake): The daily run brake: lower when a workflow takes access away.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DefaultBrake(steps []*core.Object) (result float64, err error) {
	err = notImplemented("workflows.ts defaultBrake")
	return
}

// FillTemplate (workflows.ts fillTemplate): Fills `{name}`, `{email}`, `{organization}`, `{workflow}` and
// `{attribute.<name>}` in an email template.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FillTemplate(template string, values *core.Object) (result string, err error) {
	err = notImplemented("workflows.ts fillTemplate")
	return
}

// ParseScope (workflows.ts parseScope): Validates a scope in the access-package rule language (`include` / `exclude`
// condition sets).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseScope(value any, env *core.Object) (result *core.Object, err error) {
	err = notImplemented("workflows.ts parseScope")
	return
}

// WorkflowsParseSteps (workflows.ts parseSteps): Validates the steps (references to groups and packages are checked
// against the store by the caller).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WorkflowsParseSteps(value any, attributes *core.Object) (result []*core.Object, err error) {
	err = notImplemented("workflows.ts parseSteps")
	return
}

// ParseTrigger (workflows.ts parseTrigger): Validates a trigger against the deployment's declared identity
// attributes.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseTrigger(value any, attributes *core.Object) (result *core.Object, err error) {
	err = notImplemented("workflows.ts parseTrigger")
	return
}

// TriggerOccurrence (workflows.ts triggerOccurrence): Whether the trigger fires for an identity now, and the
// snapshot to keep for mover and leaver triggers. `occurrence` names the firing so each change runs once; the caller
// skips occurrences that already have a run.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TriggerOccurrence(workflow *core.Object, identity *core.Object, snapshot *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("workflows.ts triggerOccurrence")
	return
}

// UtcDay (workflows.ts utcDay): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UtcDay(at int64) (result string, err error) {
	err = notImplemented("workflows.ts utcDay")
	return
}

// WorkflowsDayMs is workflows.ts dayMs.
const WorkflowsDayMs = 86400000

// DestructiveSteps is workflows.ts destructiveSteps.
var DestructiveSteps = newOrderedSet("remove-from-all-groups", "revoke-packages", "revoke-sessions", "disable", "delete")
