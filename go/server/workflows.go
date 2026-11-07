package server

// Port of packages/server/src/workflows.ts: identity lifecycle workflows (joiner, mover, leaver): a trigger, a scope
// in the access-package rule language, and a list of steps that run for each person the trigger fires for, under the
// authority of the administrator who saved the workflow (re-checked when each step runs). Pure: validation and
// trigger computation, no store access.
//
// What starts a run for a person:
//   - `joiner`: the person is active and joined after the workflow was enabled (or already existed, with
//     `includeExisting`);
//   - `mover`: one of the watched attributes (declared identity attributes, or `managerId`) changed;
//   - `leaver`: the person was disabled (by an administrator, offboarding, or account expiry);
//   - `date`: `offsetDays` after (or before, when negative) a date the person carries: a declared string attribute
//     holding an ISO date such as `startDate`, or `createdAt` / `expiresAt`;
//   - `manual`: only `workflows.run`.
//
// Records: `workflows` (Workflow), `workflowRuns` (WorkflowRun: one run of a workflow for one person) and
// `workflowSubjects` (WorkflowSubject: what mover and leaver triggers compare against, uniqueKey
// `{workflowId}:{identityId}`).

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// workflowStepKinds is workflows.ts workflowStepKinds.
var workflowStepKinds = []string{
	"add-to-group",
	"remove-from-group",
	"remove-from-all-groups",
	"assign-package",
	"revoke-packages",
	"send-email",
	"revoke-sessions",
	"disable",
	"enable",
	"set-attributes",
	"set-expiry",
	"delete",
	"emit-event",
	"wait",
}

// DestructiveSteps is workflows.ts destructiveSteps: steps that take something away; workflows with any of them
// default to a lower daily brake.
var DestructiveSteps = newOrderedSet("remove-from-all-groups", "revoke-packages", "revoke-sessions", "disable", "delete")

// workflowMaxSteps is workflows.ts maxSteps.
const workflowMaxSteps = 20

// workflowMaxWaits is workflows.ts maxWaits.
const workflowMaxWaits = 5

// workflowMaxWaitHours is workflows.ts maxWaitHours.
const workflowMaxWaitHours = 365 * 24

// WorkflowsDayMs is workflows.ts dayMs.
const WorkflowsDayMs = 86400000

// workflowDays is workflows.ts days.
func workflowDays(value any, name string) (float64, error) {
	return Integer(value, name, 1, 3650)
}

// ParseTrigger (workflows.ts parseTrigger): Validates a trigger against the deployment's declared identity
// attributes.
func ParseTrigger(value any, attributes *core.Object) (result *core.Object, err error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	kind := input.Get("kind")
	switch kind {
	case "joiner", "leaver", "manual":
		return core.NewObject("kind", kind), nil
	case "mover":
		list, ok := input.Get("attributes").([]any)
		if !ok || len(list) == 0 || len(list) > 20 {
			return nil, invalidInput("trigger.attributes must name 1-20 attributes to watch")
		}
		names := make([]string, len(list))
		for index, name := range list {
			names[index], err = Text(name, "trigger.attributes", 64)
			if err != nil {
				return nil, err
			}
		}
		watched := unique(names)
		for _, name := range watched {
			if name != "managerId" && !attributes.Has(name) {
				return nil, invalidInput("trigger.attributes: " + name + " is not a declared identity attribute (or managerId)")
			}
		}
		sortStable(watched, compareUTF16)
		return core.NewObject("kind", "mover", "attributes", stringsOf(watched)), nil
	case "date":
		attribute, err := Text(input.Get("attribute"), "trigger.attribute", 64)
		if err != nil {
			return nil, err
		}
		if attribute != "createdAt" && attribute != "expiresAt" && !(attributes.Has(attribute) && attributes.Get(attribute) == "string") {
			return nil, invalidInput("trigger.attribute must be createdAt, expiresAt, or a declared string attribute holding an ISO date")
		}
		offsetDays, err := Integer(coalesce(input.Get("offsetDays"), 0.0), "trigger.offsetDays", -365, 3650)
		if err != nil {
			return nil, err
		}
		return core.NewObject("kind", "date", "attribute", attribute, "offsetDays", offsetDays), nil
	}
	return nil, invalidInput("trigger.kind must be joiner, mover, leaver, date or manual")
}

// workflowEventName is the emit-event name pattern.
var workflowEventName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// workflowBodyControl is /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.
func workflowBodyControl(body string) bool {
	for index := 0; index < len(body); index++ {
		c := body[index]
		if c <= 0x08 || c == 0x0b || c == 0x0c || (c >= 0x0e && c <= 0x1f) || c == 0x7f {
			return true
		}
	}
	return false
}

// WorkflowsParseSteps (workflows.ts parseSteps): Validates the steps (references to groups and packages are checked
// against the store by the caller).
func WorkflowsParseSteps(value any, attributes *core.Object) (result []*core.Object, err error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > workflowMaxSteps {
		return nil, invalidInput("steps must list 1-" + strconv.Itoa(workflowMaxSteps) + " steps")
	}
	waits := 0
	steps := make([]*core.Object, 0, len(list))
	for index, item := range list {
		step, err := workflowParseStep(item, index, attributes, &waits)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	if waits > workflowMaxWaits {
		return nil, invalidInput("A workflow may wait at most " + strconv.Itoa(workflowMaxWaits) + " times")
	}
	allWaits := true
	for _, step := range steps {
		if step.Get("kind") != "wait" {
			allWaits = false
			break
		}
	}
	if allWaits {
		return nil, invalidInput("A workflow needs at least one step that does something")
	}
	if steps[len(steps)-1].Get("kind") == "wait" {
		return nil, invalidInput("A workflow cannot end with a wait")
	}
	deleteAt := -1
	for index, step := range steps {
		if step.Get("kind") == "delete" {
			deleteAt = index
			break
		}
	}
	if deleteAt != -1 && deleteAt != len(steps)-1 {
		return nil, invalidInput("delete must be the last step")
	}
	return steps, nil
}

// workflowParseStep is the body of the parseSteps map callback for one step.
func workflowParseStep(item any, index int, attributes *core.Object, waits *int) (*core.Object, error) {
	path := "steps[" + strconv.Itoa(index) + "]"
	raw, ok := item.(*core.Object)
	if !ok || raw == nil {
		return nil, invalidInput(path + " must be an object")
	}
	kind := raw.Get("kind")
	only := func(keys ...string) error {
		for _, key := range raw.Keys() {
			if key != "kind" && !containsString(keys, key) {
				return invalidInput(path + ": unknown field " + key)
			}
		}
		return nil
	}
	switch kind {
	case "add-to-group":
		if err := only("groupId", "days"); err != nil {
			return nil, err
		}
		groupID, err := Text(raw.Get("groupId"), path+".groupId")
		if err != nil {
			return nil, err
		}
		step := core.NewObject("kind", kind, "groupId", groupID)
		if !isUndefined(raw.Get("days")) {
			days, err := workflowDays(raw.Get("days"), path+".days")
			if err != nil {
				return nil, err
			}
			step.Set("days", days)
		}
		return step, nil
	case "remove-from-group":
		if err := only("groupId"); err != nil {
			return nil, err
		}
		groupID, err := Text(raw.Get("groupId"), path+".groupId")
		if err != nil {
			return nil, err
		}
		return core.NewObject("kind", kind, "groupId", groupID), nil
	case "assign-package":
		if err := only("packageId", "days"); err != nil {
			return nil, err
		}
		packageID, err := Text(raw.Get("packageId"), path+".packageId")
		if err != nil {
			return nil, err
		}
		step := core.NewObject("kind", kind, "packageId", packageID)
		if !isUndefined(raw.Get("days")) {
			days, err := workflowDays(raw.Get("days"), path+".days")
			if err != nil {
				return nil, err
			}
			step.Set("days", days)
		}
		return step, nil
	case "revoke-packages":
		if err := only("packageId"); err != nil {
			return nil, err
		}
		step := core.NewObject("kind", kind)
		if !isUndefined(raw.Get("packageId")) {
			packageID, err := Text(raw.Get("packageId"), path+".packageId")
			if err != nil {
				return nil, err
			}
			step.Set("packageId", packageID)
		}
		return step, nil
	case "send-email":
		if err := only("to", "subject", "body"); err != nil {
			return nil, err
		}
		to, err := Text(raw.Get("to"), path+".to", 254)
		if err != nil {
			return nil, err
		}
		to = core.JSLower(core.JSTrim(to))
		if to != "subject" && to != "manager" && !emailPattern.MatchString(to) {
			return nil, invalidInput(path + ".to must be subject, manager, or an email address")
		}
		subject, err := Text(raw.Get("subject"), path+".subject", 200)
		if err != nil {
			return nil, err
		}
		body, ok := raw.Get("body").(string)
		if !ok || core.JSTrim(body) == "" || utf16Len(body) > 5000 || workflowBodyControl(body) {
			return nil, invalidInput(path + ".body must be text of at most 5000 characters")
		}
		return core.NewObject("kind", kind, "to", to, "subject", subject, "body", body), nil
	case "remove-from-all-groups", "revoke-sessions", "disable", "enable", "delete":
		if err := only(); err != nil {
			return nil, err
		}
		return core.NewObject("kind", kind), nil
	case "set-attributes":
		if err := only("attributes"); err != nil {
			return nil, err
		}
		entries, ok := raw.Get("attributes").(*core.Object)
		if !ok || entries == nil || entries.Len() == 0 {
			return nil, invalidInput(path + ".attributes must set at least one attribute")
		}
		result := core.NewObject()
		var failure error
		entries.Entries(func(name string, entry any) bool {
			var declared string
			if attributes.Has(name) {
				declared, _ = attributes.Get(name).(string)
			}
			if declared == "" {
				failure = invalidInput(path + ".attributes: " + name + " is not a declared identity attribute")
				return false
			}
			if entry != nil {
				invalid := typeOf(entry) != declared
				if !invalid && declared == "string" {
					text := entry.(string)
					invalid = utf16Len(text) > 2048 || hasControl(text)
				}
				if !invalid && declared == "number" {
					number := entry.(float64)
					invalid = math.IsNaN(number) || math.IsInf(number, 0)
				}
				if invalid {
					failure = invalidInput(path + ".attributes: " + name + " must be a " + declared + " (or null to clear it)")
					return false
				}
			}
			result.SetRaw(name, entry)
			return true
		})
		if failure != nil {
			return nil, failure
		}
		return core.NewObject("kind", kind, "attributes", result), nil
	case "set-expiry":
		if err := only("days"); err != nil {
			return nil, err
		}
		if raw.Get("days") == nil {
			return core.NewObject("kind", kind, "days", nil), nil
		}
		days, err := workflowDays(raw.Get("days"), path+".days")
		if err != nil {
			return nil, err
		}
		return core.NewObject("kind", kind, "days", days), nil
	case "emit-event":
		if err := only("name"); err != nil {
			return nil, err
		}
		name, err := Text(raw.Get("name"), path+".name", 64)
		if err != nil {
			return nil, err
		}
		if !workflowEventName.MatchString(name) {
			return nil, invalidInput(path + ".name uses lowercase letters, digits, dots, underscores or hyphens")
		}
		return core.NewObject("kind", kind, "name", name), nil
	case "wait":
		if err := only("hours"); err != nil {
			return nil, err
		}
		*waits++
		hours, err := Integer(raw.Get("hours"), path+".hours", 1, workflowMaxWaitHours)
		if err != nil {
			return nil, err
		}
		return core.NewObject("kind", kind, "hours", hours), nil
	}
	return nil, invalidInput(path + ".kind must be one of " + strings.Join(workflowStepKinds, ", "))
}

// ParseScope (workflows.ts parseScope): Validates a scope in the access-package rule language (`include` / `exclude`
// condition sets). Nil when there is no scope.
func ParseScope(value any, env *core.Object) (result *core.Object, err error) {
	if nullish(value) {
		return nil, nil
	}
	input, ok := value.(*core.Object)
	if !ok || input == nil {
		return nil, invalidInput("scope must be an object")
	}
	for _, key := range input.Keys() {
		if key != "include" && key != "exclude" {
			return nil, invalidInput("scope: unknown field " + key + " (use include and exclude)")
		}
	}
	parsed, err := ParseAutoAssign(input, env, "scope")
	if err != nil {
		return nil, err
	}
	scope := core.NewObject("include", parsed.Get("include"))
	if exclude, ok := parsed.Get("exclude").([]any); ok && len(exclude) > 0 {
		scope.Set("exclude", exclude)
	}
	return scope, nil
}

// DefaultBrake (workflows.ts defaultBrake): The daily run brake: lower when a workflow takes access away.
func DefaultBrake(steps []*core.Object) (result float64, err error) {
	for _, step := range steps {
		if DestructiveSteps.Has(jsString(step.Get("kind"))) {
			return 25, nil
		}
	}
	return 200, nil
}

// UtcDay (workflows.ts utcDay): `new Date(at).toISOString().slice(0, 10)`.
func UtcDay(at int64) (result string, err error) {
	if at > 8.64e15 || at < -8.64e15 {
		return "", &rangeError{"Invalid time value"}
	}
	return isoString(float64(at))[:10], nil
}

// workflowWatchedValues (workflows.ts watchedValues): the values a mover trigger watches, as the snapshot stores
// them.
func workflowWatchedValues(trigger *core.Object, identity *core.Object) *core.Object {
	values := core.NewObject()
	names, _ := trigger.Get("attributes").([]any)
	for _, item := range names {
		name := jsString(item)
		var value any
		if name == "managerId" {
			value = identity.Get("managerId")
		} else {
			value = member(identity.Get("attributes"), name)
		}
		if isUndefined(value) {
			value = nil
		}
		values.SetRaw(name, value)
	}
	return values
}

// workflowDigest (workflows.ts digest): the first 16 hex digits of the SHA-256 of the canonical JSON.
func workflowDigest(value any) string {
	sum := sha256.Sum256(utf8Bytes(core.CanonicalJSON(value)))
	return hex.EncodeToString(sum[:])[:16]
}

// workflowDatePattern is a date (read as UTC midnight) or a full timestamp with its offset.
var workflowDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$`)

// workflowDateParse is Date.parse over the strings workflowDatePattern admits (with `T00:00:00Z` appended to a bare
// date), as V8 reads them: days up to 31 roll over into the next month, 24:00 is the end of the day.
func workflowDateParse(raw string) (float64, bool) {
	number := func(text string) int {
		value, _ := strconv.Atoi(text)
		return value
	}
	year, month, day := number(raw[0:4]), number(raw[5:7]), number(raw[8:10])
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return 0, false
	}
	rest := raw[10:]
	hour, minute, second, millis := 0, 0, 0, 0
	offset := 0
	if rest != "" {
		rest = rest[1:]
		hour, minute = number(rest[0:2]), number(rest[3:5])
		rest = rest[5:]
		if strings.HasPrefix(rest, ":") {
			second = number(rest[1:3])
			rest = rest[3:]
			if strings.HasPrefix(rest, ".") {
				end := 1
				for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
					end++
				}
				fraction := rest[1:end]
				for len(fraction) < 3 {
					fraction += "0"
				}
				millis = number(fraction[:3])
				rest = rest[end:]
			}
		}
		if hour > 24 || minute > 59 || second > 59 || (hour == 24 && (minute != 0 || second != 0 || millis != 0)) {
			return 0, false
		}
		if rest != "Z" {
			sign := 1
			if rest[0] == '-' {
				sign = -1
			}
			hours, minutes := number(rest[1:3]), number(rest[4:6])
			if hours > 23 || minutes > 59 {
				return 0, false
			}
			offset = sign * (hours*3600 + minutes*60)
		}
	}
	at := time.Date(year, time.Month(month), day, hour, minute, second, millis*1e6, time.FixedZone("", offset))
	return float64(at.UnixMilli()), true
}

// DateTarget (workflows.ts dateTarget): The instant a date trigger fires for an identity, or nil when the identity
// carries no usable date.
func DateTarget(trigger *core.Object, identity *core.Object) (result *float64, err error) {
	var base *float64
	switch attribute := jsString(trigger.Get("attribute")); attribute {
	case "createdAt", "expiresAt":
		if value := identity.Get(attribute); !isUndefined(value) {
			number := jsNumber(value)
			base = &number
		}
	default:
		raw, ok := member(identity.Get("attributes"), attribute).(string)
		// A date (read as UTC midnight) or a full timestamp with its offset; a local time without one is ambiguous.
		if ok && workflowDatePattern.MatchString(raw) {
			if parsed, valid := workflowDateParse(raw); valid && !math.IsInf(parsed, 0) && !math.IsNaN(parsed) {
				base = &parsed
			}
		}
	}
	if base == nil {
		return nil, nil
	}
	target := *base + jsNumber(trigger.Get("offsetDays"))*WorkflowsDayMs
	return &target, nil
}

// workflowSnapshot is `{ values, status, fired }`.
func workflowSnapshot(values *core.Object, status any, fired float64) *core.Object {
	return core.NewObject("values", values, "status", status, "fired", fired)
}

// TriggerOccurrence (workflows.ts triggerOccurrence): Whether the trigger fires for an identity now, and the
// snapshot to keep for mover and leaver triggers. `occurrence` names the firing so each change runs once; the caller
// skips occurrences that already have a run. snapshot is nil when there is none; the result has `occurrence` and
// `snapshot` members only when they are set.
func TriggerOccurrence(workflow *core.Object, identity *core.Object, snapshot *core.Object, now int64) (result *core.Object, err error) {
	trigger, _ := workflow.Get("trigger").(*core.Object)
	status := identity.Get("status")
	switch member(trigger, "kind") {
	case "joiner":
		if status == "active" && (truthy(workflow.Get("includeExisting")) || jsNumber(identity.Get("createdAt")) >= jsNumber(workflow.Get("activeSince"))) {
			return core.NewObject("occurrence", "joiner"), nil
		}
		return core.NewObject(), nil
	case "mover":
		values := workflowWatchedValues(trigger, identity)
		if snapshot == nil {
			return core.NewObject("snapshot", workflowSnapshot(values, status, 0)), nil
		}
		if workflowDigest(values) == workflowDigest(snapshot.Get("values")) {
			return core.NewObject(), nil
		}
		fired := jsNumber(snapshot.Get("fired")) + 1
		out := core.NewObject()
		if status == "active" {
			out.Set("occurrence", "mover:"+core.NumberString(fired)+":"+workflowDigest(values))
		}
		out.Set("snapshot", workflowSnapshot(values, status, fired))
		return out, nil
	case "leaver":
		if snapshot == nil {
			return core.NewObject("snapshot", workflowSnapshot(core.NewObject(), status, 0)), nil
		}
		if core.StrictEquals(snapshot.Get("status"), status) {
			return core.NewObject(), nil
		}
		leaving := snapshot.Get("status") == "active" && status == "disabled"
		fired := jsNumber(snapshot.Get("fired"))
		if leaving {
			fired++
		}
		out := core.NewObject()
		if leaving {
			out.Set("occurrence", "leaver:"+core.NumberString(fired))
		}
		out.Set("snapshot", workflowSnapshot(core.NewObject(), status, fired))
		return out, nil
	case "date":
		if status != "active" {
			return core.NewObject(), nil
		}
		target, err := DateTarget(trigger, identity)
		if err != nil {
			return nil, err
		}
		// Dates well before the workflow existed never fire; a date that moves fires again.
		if target == nil || *target > float64(now) || *target < jsNumber(workflow.Get("activeSince"))-WorkflowsDayMs {
			return core.NewObject(), nil
		}
		day, err := UtcDay(int64(*target))
		if err != nil {
			return nil, err
		}
		return core.NewObject("occurrence", "date:"+day), nil
	}
	return core.NewObject(), nil
}

// workflowTemplateKey is the placeholder pattern of fillTemplate.
var workflowTemplateKey = regexp.MustCompile(`\{([a-zA-Z][\w.]{0,80})\}`)

// FillTemplate (workflows.ts fillTemplate): Fills `{name}`, `{email}`, `{organization}`, `{workflow}` and
// `{attribute.<name>}` in an email template. values is `{ identity, organization, workflow }`.
func FillTemplate(template string, values *core.Object) (result string, err error) {
	identity := values.Get("identity")
	return workflowTemplateKey.ReplaceAllStringFunc(template, func(match string) string {
		key := match[1 : len(match)-1]
		switch {
		case key == "name":
			return jsString(member(identity, "name"))
		case key == "email":
			email := member(identity, "email")
			if nullish(email) {
				return ""
			}
			return jsString(email)
		case key == "organization":
			return jsString(values.Get("organization"))
		case key == "workflow":
			return jsString(values.Get("workflow"))
		case strings.HasPrefix(key, "attribute."):
			value := member(member(identity, "attributes"), key[len("attribute."):])
			if nullish(value) {
				return ""
			}
			return jsString(value)
		}
		return match
	}), nil
}
