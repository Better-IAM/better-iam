package server

// Port of packages/server/src/api/workflows.ts: identity lifecycle workflows (workflows.go), joiner, mover and leaver
// automation. A workflow has a trigger, a scope (the access-package rule language over the person's attributes,
// groups, teams and departments) and steps (group and package changes, emails, sign-outs, disabling, attribute and
// expiry changes, deletion, events for webhooks, and waits). Steps run under the rights of whoever saved the
// workflow, re-checked at every step. Managing needs `iam:workflows:manage`, reading `iam:workflows:read`, starting
// and retrying runs `iam:workflows:run`.

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// WorkflowsAPI is the `workflows` API group (packages/server/src/api/workflows.ts createWorkflowsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/workflows/{method} onto it.
type WorkflowsAPI struct {
	server *ServerContext
	run    *workflowEngine
}

// CreateWorkflowsAPI builds the `workflows` API group.
func CreateWorkflowsAPI(server *ServerContext) *WorkflowsAPI {
	return &WorkflowsAPI{server: server, run: &workflowEngine{server: server}}
}

// workflowMaxWorkflows is api/workflows.ts maxWorkflows.
const workflowMaxWorkflows = 100

// workflowLeaseMs is api/workflows.ts leaseMs.
const workflowLeaseMs = 5 * 60_000

// workflowRunRetentionMs is api/workflows.ts runRetentionMs: finished runs stay this long for review, then the
// retention sweep removes them.
const workflowRunRetentionMs = 180 * 86_400_000

// workflowSelfChanging is api/workflows.ts selfChanging: steps that change a person's own record; nobody may point
// them at themself through a workflow.
var workflowSelfChanging = newOrderedSet("set-attributes", "set-expiry", "enable")

// workflowSteps reads a stored or parsed step list.
func workflowSteps(value any) []*core.Object {
	list, _ := value.([]any)
	steps := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if step, ok := item.(*core.Object); ok && step != nil {
			steps = append(steps, step)
		} else {
			steps = append(steps, core.NewObject())
		}
	}
	return steps
}

// workflowStepList is a step list as a model array.
func workflowStepList(steps []*core.Object) []any {
	out := make([]any, len(steps))
	for index, step := range steps {
		out[index] = step
	}
	return out
}

// workflowKind is a step's kind.
func workflowKind(step *core.Object) string { return jsString(step.Get("kind")) }

// workflowAnyStep is `steps.some((step) => set.has(step.kind))`.
func workflowAnyStep(steps []*core.Object, set *orderedSet) bool {
	for _, step := range steps {
		if set.Has(workflowKind(step)) {
			return true
		}
	}
	return false
}

// workflowSlice is `text.slice(0, max)` in UTF-16 code units.
func workflowSlice(text string, max int) string {
	units := core.ToUTF16(text)
	if len(units) <= max {
		return text
	}
	return core.FromUTF16(units[:max])
}

// workflowActive is `['pending', 'running', 'waiting', ...].includes(status)`.
func workflowStatusIn(value any, statuses ...string) bool {
	status, ok := value.(string)
	return ok && containsString(statuses, status)
}

// workflowRequirements (api/workflows.ts requirements): the rights a step needs, as the owner would need them by
// hand: [action, resource] pairs. identityID "" stands for undefined.
func workflowRequirements(step *core.Object, tenantID string, identityID string) [][2]string {
	person := identityID
	if person == "" {
		person = tenantID
	}
	switch workflowKind(step) {
	case "add-to-group", "remove-from-group":
		return [][2]string{{"iam:groups:update", jsString(step.Get("groupId"))}}
	case "assign-package":
		return [][2]string{{"iam:packages:assign", jsString(step.Get("packageId"))}}
	case "revoke-packages":
		if truthy(step.Get("packageId")) {
			return [][2]string{{"iam:packages:assign", jsString(step.Get("packageId"))}}
		}
		return nil
	case "revoke-sessions", "disable", "enable", "set-attributes", "set-expiry":
		return [][2]string{{"iam:identities:update", person}}
	case "delete":
		return [][2]string{{"iam:identities:delete", person}}
	// An email carries the person's name, address and attributes: whoever automates it must be able to read them.
	case "send-email":
		return [][2]string{{"iam:identities:read", person}}
	}
	return nil
}

// workflowDecide is `(await ctx.decisions.decide(tx, principal, { tenantId, action, resource: { type: 'iam', id } },
// true)).allowed`.
func workflowDecide(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID, action, resourceID string) (bool, error) {
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
	}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// assertWorkflowRecipients (api/workflows.ts assertRecipients): where a literal `send-email` address may point: an
// address of an active member of the organization, or one at a domain the organization verified, so a workflow
// cannot mail people's details (or phishing) to arbitrary outsiders.
func assertWorkflowRecipients(ctx context.Context, tx core.IamStore, tenantID string, steps []*core.Object) error {
	var literal []string
	for _, step := range steps {
		to := jsString(step.Get("to"))
		if workflowKind(step) == "send-email" && to != "subject" && to != "manager" {
			literal = append(literal, to)
		}
	}
	if len(literal) == 0 {
		return nil
	}
	records, err := tx.Find(ctx, "tenantDomains", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	domains := newOrderedSet()
	for _, record := range records {
		if record.Get("status") == "verified" {
			domains.Add(core.JSLower(jsString(record.Get("domain"))))
		}
	}
	for _, address := range literal {
		at := -1
		for index := len(address) - 1; index >= 0; index-- {
			if address[index] == '@' {
				at = index
				break
			}
		}
		if domains.Has(address[at+1:]) {
			continue
		}
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", address), nil)
		if err != nil {
			return err
		}
		member := false
		for _, identity := range identities {
			if identity.Get("status") == "active" {
				member = true
				break
			}
		}
		if !member {
			return invalidInput("send-email may address subject, manager, a member of the organization, or a verified domain (not " + address + ")")
		}
	}
	return nil
}

// workflowView (api/workflows.ts workflowView).
func workflowView(workflow *core.Object, ownerName string, runs *core.Object) *core.Object {
	view := core.NewObject(
		"id", workflow.Get("id"),
		"tenantId", workflow.Get("tenantId"),
		"name", workflow.Get("name"),
	)
	if description := workflow.Get("description"); truthy(description) {
		view.Set("description", description)
	}
	view.Set("enabled", workflow.Get("enabled"))
	view.Set("trigger", workflow.Get("trigger"))
	if scope := workflow.Get("scope"); truthy(scope) {
		view.Set("scope", scope)
	}
	view.Set("steps", workflow.Get("steps"))
	view.Set("includeExisting", workflow.Get("includeExisting"))
	view.Set("maxRunsPerDay", workflow.Get("maxRunsPerDay"))
	view.Set("ownerId", workflow.Get("ownerId"))
	if ownerName != "" {
		view.Set("ownerName", ownerName)
	}
	view.Set("version", workflow.Get("version"))
	view.Set("activeSince", workflow.Get("activeSince"))
	if braked := workflow.Get("brakedOn"); truthy(braked) {
		view.Set("brakedOn", braked)
	}
	view.Set("createdAt", workflow.Get("createdAt"))
	view.Set("updatedAt", workflow.Get("updatedAt"))
	if runs != nil {
		view.Set("runs", runs)
	}
	return view
}

// workflowRunView (api/workflows.ts runView).
func workflowRunView(run *core.Object, identityName string) *core.Object {
	view := core.NewObject(
		"id", run.Get("id"),
		"workflowId", run.Get("workflowId"),
		"workflowName", run.Get("workflowName"),
		"workflowVersion", run.Get("workflowVersion"),
		"identityId", run.Get("identityId"),
	)
	if identityName != "" {
		view.Set("identityName", identityName)
	}
	view.Set("occurrence", run.Get("occurrence"))
	view.Set("trigger", run.Get("trigger"))
	view.Set("steps", run.Get("steps"))
	view.Set("status", run.Get("status"))
	view.Set("stepIndex", run.Get("stepIndex"))
	view.Set("nextAt", run.Get("nextAt"))
	view.Set("results", run.Get("results"))
	view.Set("startedAt", run.Get("startedAt"))
	if finished := run.Get("finishedAt"); !isUndefined(finished) {
		view.Set("finishedAt", finished)
	}
	if startedBy := run.Get("startedBy"); truthy(startedBy) {
		view.Set("startedBy", startedBy)
	}
	if failure := run.Get("error"); truthy(failure) {
		view.Set("error", failure)
	}
	return view
}

// workflowFields (api/workflows.ts workflowFields): validates a workflow's parts and the groups and packages its
// steps name. input is the request body (the workflow members it carries); previous is nil on create.
func workflowFields(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object) (*core.Object, error) {
	attributes := server.Catalog.IdentityAttributes
	nameValue := input.Get("name")
	if isUndefined(nameValue) || nameValue == nil {
		nameValue = member(previous, "name")
	}
	name, err := Text(nameValue, "name", 120)
	if err != nil {
		return nil, err
	}
	name = core.JSTrim(name)
	if name == "" {
		return nil, invalidInput("name is required")
	}
	var description any = core.Undefined
	switch raw := input.Get("description"); {
	case isUndefined(raw):
		description = member(previous, "description")
	case raw == nil || raw == "":
	default:
		text, err := Text(raw, "description", 1000)
		if err != nil {
			return nil, err
		}
		description = text
	}
	if previous == nil && (isUndefined(input.Get("trigger")) || isUndefined(input.Get("steps"))) {
		return nil, invalidInput("A workflow needs a trigger and steps")
	}
	var trigger any
	if isUndefined(input.Get("trigger")) {
		trigger = previous.Get("trigger")
	} else {
		parsed, err := ParseTrigger(input.Get("trigger"), attributes)
		if err != nil {
			return nil, err
		}
		trigger = parsed
	}
	var steps []*core.Object
	if isUndefined(input.Get("steps")) {
		steps = workflowSteps(previous.Get("steps"))
	} else {
		steps, err = WorkflowsParseSteps(input.Get("steps"), attributes)
		if err != nil {
			return nil, err
		}
	}
	groups, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	groupIDs := newOrderedSet()
	for _, group := range groups {
		groupIDs.Add(jsString(group.Get("id")))
	}
	var scope any = core.Undefined
	if isUndefined(input.Get("scope")) {
		scope = member(previous, "scope")
	} else {
		org, err := OrgRuleEnvironment(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		parsed, err := ParseScope(input.Get("scope"), core.NewObject(
			"identityAttributes", attributes,
			"groups", stringsOf(groupIDs.Values()),
			"org", org,
		))
		if err != nil {
			return nil, err
		}
		if parsed != nil {
			scope = parsed
		}
	}
	for _, step := range steps {
		kind := workflowKind(step)
		if kind == "add-to-group" || kind == "remove-from-group" {
			var group *core.Object
			for _, item := range groups {
				if core.StrictEquals(item.Get("id"), step.Get("groupId")) {
					group = item
					break
				}
			}
			if group == nil {
				return nil, invalidInput("Unknown group " + jsString(step.Get("groupId")))
			}
			if truthy(group.Get("teamId")) {
				return nil, core.NewIamError("TEAM_MANAGED", jsString(group.Get("name"))+" belongs to a team; add people to the team instead", 409)
			}
		}
		if kind == "assign-package" || (kind == "revoke-packages" && truthy(step.Get("packageId"))) {
			if _, err := server.Scoped(ctx, tx, "accessPackages", step.Get("packageId"), tenantID); err != nil {
				return nil, err
			}
		}
	}
	if err := assertWorkflowRecipients(ctx, tx, tenantID, steps); err != nil {
		return nil, err
	}
	includeExisting := coalesce(coalesce(input.Get("includeExisting"), member(previous, "includeExisting")), false)
	if _, ok := includeExisting.(bool); !ok {
		return nil, invalidInput("includeExisting must be a boolean")
	}
	var maxRunsPerDay any
	if isUndefined(input.Get("maxRunsPerDay")) {
		maxRunsPerDay = member(previous, "maxRunsPerDay")
		if nullish(maxRunsPerDay) {
			brake, err := DefaultBrake(steps)
			if err != nil {
				return nil, err
			}
			maxRunsPerDay = brake
		}
	} else {
		maxRunsPerDay, err = Integer(input.Get("maxRunsPerDay"), "maxRunsPerDay", 1, 10_000)
		if err != nil {
			return nil, err
		}
	}
	enabled := coalesce(coalesce(input.Get("enabled"), member(previous, "enabled")), true)
	if _, ok := enabled.(bool); !ok {
		return nil, invalidInput("enabled must be a boolean")
	}
	values := core.NewObject("uniqueKey", "name:"+core.JSLower(name), "name", name)
	if truthy(description) {
		values.Set("description", description)
	}
	values.Set("enabled", enabled)
	values.Set("trigger", trigger)
	if truthy(scope) {
		values.Set("scope", scope)
	}
	values.Set("steps", workflowStepList(steps))
	values.Set("includeExisting", includeExisting)
	values.Set("maxRunsPerDay", maxRunsPerDay)
	return values, nil
}

// assertWorkflowOwnerRights (api/workflows.ts assertOwnerRights): the saver becomes the workflow's owner: they must
// be a person or service account acting in their own right, and hold every right the steps use, so nobody automates
// what they could not do by hand. identityIDs defaults to one undefined person ("").
func assertWorkflowOwnerRights(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, steps []*core.Object, identityIDs []string) error {
	if identityIDs == nil {
		identityIDs = []string{""}
	}
	if !ActsInOwnRight(principal.Session) || truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("ACCESS_DENIED", "Workflows are saved and run from a signed-in session or an API key of their own", 403)
	}
	if !core.StrictEquals(principal.Identity.Get("tenantId"), tenantID) {
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return err
		}
		if !root {
			return core.NewIamError("ACCESS_DENIED", "Workflows are managed from their own organization", 403)
		}
	}
	for _, identityID := range identityIDs {
		for _, step := range steps {
			for _, requirement := range workflowRequirements(step, tenantID, identityID) {
				allowed, err := workflowDecide(ctx, server, tx, principal, tenantID, requirement[0], requirement[1])
				if err != nil {
					return err
				}
				if !allowed {
					return NewOperationDenied("The " + workflowKind(step) + " step needs " + requirement[0] + " on " + requirement[1] + ", which you do not have")
				}
			}
		}
	}
	for _, step := range steps {
		if workflowKind(step) == "assign-package" {
			pkg, err := server.Scoped(ctx, tx, "accessPackages", step.Get("packageId"), tenantID)
			if err != nil {
				return err
			}
			if _, err := AuthorizePackage(ctx, server, tx, principal, pkg, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// rebuildWorkflowSnapshots (api/workflows.ts rebuildSnapshots): baselines for mover and leaver triggers, so only
// changes after this moment fire.
func rebuildWorkflowSnapshots(ctx context.Context, tx core.IamStore, workflow *core.Object, now int64) error {
	tenantID := workflow.Get("tenantId")
	subjects, err := tx.Find(ctx, "workflowSubjects", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
	if err != nil {
		return err
	}
	for _, subject := range subjects {
		if err := tx.Delete(ctx, "workflowSubjects", jsString(subject.Get("id"))); err != nil {
			return err
		}
	}
	kind := member(workflow.Get("trigger"), "kind")
	if kind != "mover" && kind != "leaver" {
		return nil
	}
	identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	for _, identity := range identities {
		if identity.Get("kind") != "user" || identity.Get("status") == "deleted" {
			continue
		}
		occurrence, err := TriggerOccurrence(workflow, identity, nil, now)
		if err != nil {
			return err
		}
		snapshot, ok := occurrence.Get("snapshot").(*core.Object)
		if !ok {
			continue
		}
		record := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", jsString(workflow.Get("id"))+":"+jsString(identity.Get("id")),
			"workflowId", workflow.Get("id"),
			"identityId", identity.Get("id"),
		).Assign(snapshot)
		if _, err := tx.Insert(ctx, "workflowSubjects", record); err != nil {
			return err
		}
	}
	return nil
}

// workflowEngine is api/workflows.ts engine: the run engine, shared by the API and the scheduler runtime.
type workflowEngine struct {
	server *ServerContext
}

// canEmail is `Boolean(ctx.options.authentication?.sendEmail)`.
func (e *workflowEngine) canEmail() bool {
	options := e.server.Options
	return options != nil && options.Authentication != nil && options.Authentication.SendEmail != nil
}

// protect (api/workflows.ts engine protect): a step that takes something away (or rewrites the record) never reaches
// owners, root administrators, or the workflow's owner; nobody changes their own record through a workflow they own
// or started (identities.update refuses that to non-owners by hand); re-enabling a root administrator needs a root
// owner, as setStatus does.
func (e *workflowEngine) protect(ctx context.Context, tx core.IamStore, step *core.Object, target *core.Object, owner *Principal, run *core.Object) error {
	kind := workflowKind(step)
	guarded := DestructiveSteps.Has(kind) || kind == "set-expiry" || kind == "set-attributes"
	if guarded && (truthy(target.Get("owner")) || truthy(target.Get("rootAdmin"))) {
		return core.NewIamError("PROTECTED_RESOURCE", "Workflows never disable, delete, sign out, strip access from, or edit owners or root administrators", 403)
	}
	if guarded && core.StrictEquals(target.Get("id"), owner.Identity.Get("id")) {
		return invalidInput("A workflow does not act against its own owner")
	}
	if workflowSelfChanging.Has(kind) && (core.StrictEquals(target.Get("id"), owner.Identity.Get("id")) || core.StrictEquals(target.Get("id"), run.Get("startedBy"))) {
		return core.NewIamError("ACCESS_DENIED", "Nobody changes their own account through a workflow they own or started", 403)
	}
	if kind == "enable" && truthy(target.Get("rootAdmin")) {
		root, err := e.server.RootPrincipal(ctx, tx, owner)
		if err != nil {
			return err
		}
		if !root {
			return core.NewIamError("ACCESS_DENIED", "Root capability is protected", 403)
		}
	}
	return nil
}

// workflowPerformed is perform's answer: `{ outcome, detail?, changed? }` ("" detail for none).
type workflowPerformed struct {
	outcome string
	detail  string
	changed bool
}

// perform (api/workflows.ts engine perform) runs one step for the run's person.
func (e *workflowEngine) perform(ctx context.Context, tx core.IamStore, owner *Principal, tenant *core.Object, run *core.Object, step *core.Object) (workflowPerformed, error) {
	server := e.server
	tenantID := jsString(tenant.Get("id"))
	target, err := server.ActiveIdentity(ctx, tx, run.Get("identityId"), tenantID)
	if err != nil {
		return workflowPerformed{}, err
	}
	if err := e.protect(ctx, tx, step, target, owner, run); err != nil {
		return workflowPerformed{}, err
	}
	kind := workflowKind(step)
	if kind == "send-email" {
		if err := assertWorkflowRecipients(ctx, tx, tenantID, []*core.Object{step}); err != nil {
			return workflowPerformed{}, err
		}
	}
	targetID := jsString(target.Get("id"))
	for _, requirement := range workflowRequirements(step, tenantID, targetID) {
		if err := Allow(ctx, server, tx, owner, tenantID, requirement[0], requirement[1], "run the "+kind+" step"); err != nil {
			return workflowPerformed{}, err
		}
	}
	now := float64(server.Now())
	audit := func(action string, resourceID string, metadata *core.Object) error {
		return server.Events.Audit(ctx, tx, owner, action, tenantID, resourceID, "allow", false, metadata.Spread(core.NewObject(
			"via", "workflow",
			"workflowId", run.Get("workflowId"),
			"runId", run.Get("id"),
		)))
	}
	done := func(detail string, changed bool) (workflowPerformed, error) {
		return workflowPerformed{outcome: "done", detail: detail, changed: changed}, nil
	}
	skipped := func(detail string) (workflowPerformed, error) {
		return workflowPerformed{outcome: "skipped", detail: detail}, nil
	}
	switch kind {
	case "add-to-group":
		group, err := server.Scoped(ctx, tx, "groups", step.Get("groupId"), tenantID)
		if err != nil {
			return workflowPerformed{}, err
		}
		groupID := jsString(group.Get("id"))
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", targetID), nil)
		if err != nil {
			return workflowPerformed{}, err
		}
		// Already a member (a joiner run for someone who was added by hand, say): nothing to do.
		for _, membership := range members {
			if server.LiveMembership(membership) {
				return skipped("already in " + jsString(group.Get("name")))
			}
		}
		input := core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", targetID)
		if days := step.Get("days"); truthy(days) {
			input.Set("expiresAt", now+jsNumber(days)*WorkflowsDayMs)
		}
		if _, err := AddGroupMember(ctx, server, tx, owner, input); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("iam:groups:update", groupID, core.NewObject("identityId", targetID, "added", true)); err != nil {
			return workflowPerformed{}, err
		}
		return done(jsString(group.Get("name")), true)
	case "remove-from-group":
		group, err := server.Scoped(ctx, tx, "groups", step.Get("groupId"), tenantID)
		if err != nil {
			return workflowPerformed{}, err
		}
		groupID := jsString(group.Get("id"))
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", targetID), nil)
		if err != nil {
			return workflowPerformed{}, err
		}
		if len(members) == 0 {
			return skipped("not in " + jsString(group.Get("name")))
		}
		if err := RemoveGroupMember(ctx, server, tx, owner, core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", targetID)); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("iam:groups:update", groupID, core.NewObject("identityId", targetID, "removed", true)); err != nil {
			return workflowPerformed{}, err
		}
		return done(jsString(group.Get("name")), true)
	case "remove-from-all-groups":
		// Memberships a team or an access package manages are left to them.
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", targetID), nil)
		if err != nil {
			return workflowPerformed{}, err
		}
		set := newOrderedSet()
		for _, membership := range members {
			if !truthy(membership.Get("teamId")) && !truthy(membership.Get("packageAssignmentId")) {
				set.Add(jsString(membership.Get("groupId")))
			}
		}
		groups := set.Values()
		sortStable(groups, compareUTF16)
		for _, groupID := range groups {
			if err := Allow(ctx, server, tx, owner, tenantID, "iam:groups:update", groupID, "remove from a group"); err != nil {
				return workflowPerformed{}, err
			}
			if err := RemoveGroupMember(ctx, server, tx, owner, core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", targetID)); err != nil {
				return workflowPerformed{}, err
			}
			if err := audit("iam:groups:update", groupID, core.NewObject("identityId", targetID, "removed", true)); err != nil {
				return workflowPerformed{}, err
			}
		}
		if len(groups) > 0 {
			return done(strconv.Itoa(len(groups))+" groups", true)
		}
		return skipped("in no groups")
	case "assign-package":
		pkg, err := server.Scoped(ctx, tx, "accessPackages", step.Get("packageId"), tenantID)
		if err != nil {
			return workflowPerformed{}, err
		}
		input := core.NewObject("identityId", targetID)
		if days := step.Get("days"); truthy(days) {
			input.Set("expiresAt", now+jsNumber(days)*WorkflowsDayMs)
		}
		input.Set("justification", "Workflow: "+jsString(run.Get("workflowName")))
		assigned, err := AssignPackage(ctx, server, tx, owner, pkg, input, nil)
		if err != nil {
			return workflowPerformed{}, err
		}
		assignment := assigned.Get("assignment")
		bindingIDs, _ := member(assignment, "bindingIds").([]any)
		membershipIDs, _ := member(assignment, "membershipIds").([]any)
		if err := audit("package:assign", jsString(pkg.Get("id")), core.NewObject(
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"identityId", targetID,
			"bindings", float64(len(bindingIDs)),
			"memberships", float64(len(membershipIDs)),
			"skipped", assigned.Get("skipped"),
		)); err != nil {
			return workflowPerformed{}, err
		}
		return done(jsString(pkg.Get("name")), true)
	case "revoke-packages":
		// Assignments a package rule made belong to the rule (packages.revoke refuses them too): it removes them
		// itself once the person no longer matches.
		records, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID, "identityId", targetID), nil)
		if err != nil {
			return workflowPerformed{}, err
		}
		var assignments []*core.Object
		for _, assignment := range records {
			if (!truthy(step.Get("packageId")) || core.StrictEquals(assignment.Get("packageId"), step.Get("packageId"))) &&
				isUndefined(assignment.Get("ruleRevision")) {
				assignments = append(assignments, assignment)
			}
		}
		for _, assignment := range assignments {
			packageID := jsString(assignment.Get("packageId"))
			if err := Allow(ctx, server, tx, owner, tenantID, "iam:packages:assign", packageID, "revoke a package"); err != nil {
				return workflowPerformed{}, err
			}
			if _, err := RevokeAssignment(ctx, server, tx, assignment); err != nil {
				return workflowPerformed{}, err
			}
			if err := audit("package:revoke", packageID, core.NewObject("packageId", assignment.Get("packageId"), "identityId", targetID)); err != nil {
				return workflowPerformed{}, err
			}
		}
		if len(assignments) > 0 {
			return done(strconv.Itoa(len(assignments))+" packages", true)
		}
		return skipped("no packages")
	case "send-email":
		if !e.canEmail() {
			return skipped("no email delivery configured")
		}
		stepTo := jsString(step.Get("to"))
		var to any = core.Undefined
		switch stepTo {
		case "subject":
			to = target.Get("email")
		case "manager":
			if managerID := target.Get("managerId"); truthy(managerID) {
				manager, err := tx.Get(ctx, "identities", jsString(managerID))
				if err != nil {
					return workflowPerformed{}, err
				}
				if manager != nil && manager.Get("status") == "active" {
					to = manager.Get("email")
				}
			}
		default:
			to = stepTo
		}
		if !truthy(to) {
			return skipped("no address for " + stepTo)
		}
		address := jsString(to)
		values := core.NewObject("identity", target, "organization", tenant.Get("name"), "workflow", run.Get("workflowName"))
		subject, err := FillTemplate(jsString(step.Get("subject")), values)
		if err != nil {
			return workflowPerformed{}, err
		}
		body, err := FillTemplate(jsString(step.Get("body")), values)
		if err != nil {
			return workflowPerformed{}, err
		}
		if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID,
			Kind:     "email",
			To:       address,
			Template: "workflow-message",
			Payload: core.NewObject(
				"tenantId", tenantID,
				"tenantName", tenant.Get("name"),
				"workflowName", run.Get("workflowName"),
				"subject", workflowSlice(subject, 300),
				"body", workflowSlice(body, 10_000),
			),
		}); err != nil {
			return workflowPerformed{}, err
		}
		if stepTo == address {
			return done("sent", false)
		}
		return done("sent to "+stepTo, false)
	case "revoke-sessions":
		if err := server.RevokeAll(ctx, tx, targetID); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("identity:revoke-sessions", targetID, core.NewObject()); err != nil {
			return workflowPerformed{}, err
		}
		return done("", false)
	case "disable":
		if target.Get("status") == "disabled" {
			return skipped("already disabled")
		}
		if err := server.ProtectLastOwner(ctx, tx, target); err != nil {
			return workflowPerformed{}, err
		}
		if _, err := tx.Put(ctx, "identities", target.Spread(core.NewObject("status", "disabled"))); err != nil {
			return workflowPerformed{}, err
		}
		if err := EndContainment(ctx, tx, targetID, server.Now()); err != nil {
			return workflowPerformed{}, err
		}
		if err := server.RevokeAll(ctx, tx, targetID); err != nil {
			return workflowPerformed{}, err
		}
		// As setStatus does: invitations the person sent (or, for guests, sponsors) and nobody redeemed yet are
		// revoked, so re-enabling them later does not bring the tokens back.
		if err := RevokeInvitationsBy(ctx, tx, targetID); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("iam:identities:update", targetID, core.NewObject("status", "disabled")); err != nil {
			return workflowPerformed{}, err
		}
		return done("", true)
	case "enable":
		if target.Get("status") == "active" {
			return skipped("already active")
		}
		if server.IdentityExpired(target) {
			return workflowPerformed{}, core.NewIamError("INVALID_TRANSITION", "The account has expired; extend or clear expiresAt first", 409)
		}
		if _, err := tx.Put(ctx, "identities", target.Spread(core.NewObject("status", "active"))); err != nil {
			return workflowPerformed{}, err
		}
		// As setStatus does: re-enabling ends a threats containment.
		if err := EndContainment(ctx, tx, targetID, server.Now()); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("iam:identities:update", targetID, core.NewObject("status", "active")); err != nil {
			return workflowPerformed{}, err
		}
		return done("", true)
	case "set-attributes":
		next := core.NewObject()
		if current, ok := target.Get("attributes").(*core.Object); ok && current != nil {
			next = current.Spread()
		}
		setting := core.NewObject()
		changes, _ := step.Get("attributes").(*core.Object)
		changes.Entries(func(name string, value any) bool {
			if value == nil {
				next.Delete(name)
			} else {
				setting.SetRaw(name, value)
			}
			return true
		})
		validated, err := AttributeValues(server.Catalog.IdentityAttributes, setting)
		if err != nil {
			return workflowPerformed{}, err
		}
		next.Assign(validated)
		rest := target.Spread()
		rest.Delete("attributes")
		if next.Len() > 0 {
			rest.Set("attributes", next)
		}
		if _, err := tx.Put(ctx, "identities", rest); err != nil {
			return workflowPerformed{}, err
		}
		names := changes.Keys()
		sortStable(names, compareUTF16)
		if err := audit("iam:identities:update", targetID, core.NewObject("attributes", stringsOf(names))); err != nil {
			return workflowPerformed{}, err
		}
		return done("", true)
	case "set-expiry":
		rest := target.Spread()
		rest.Delete("expiresAt")
		var expiresAt any
		if days := step.Get("days"); days != nil {
			expiresAt = now + jsNumber(days)*WorkflowsDayMs
			rest.Set("expiresAt", expiresAt)
		}
		if _, err := tx.Put(ctx, "identities", rest); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("iam:identities:update", targetID, core.NewObject("expiresAt", expiresAt)); err != nil {
			return workflowPerformed{}, err
		}
		return done("", true)
	case "delete":
		if _, err := DeleteIdentity(ctx, server, tx, owner, target); err != nil {
			return workflowPerformed{}, err
		}
		if err := audit("identity:delete", targetID, core.NewObject("kind", target.Get("kind"))); err != nil {
			return workflowPerformed{}, err
		}
		return done("", true)
	case "emit-event":
		if err := audit("workflow:event", targetID, core.NewObject("name", step.Get("name"))); err != nil {
			return workflowPerformed{}, err
		}
		return done(jsString(step.Get("name")), false)
	case "wait":
		return done("", false)
	}
	return workflowPerformed{}, fmt.Errorf("unknown workflow step kind %s", kind)
}

// workflowClearLease is api/workflows.ts clearLease: the run without its lease.
func workflowClearLease(run *core.Object) *core.Object {
	rest := run.Spread()
	rest.Delete("leaseToken")
	rest.Delete("leaseUntil")
	return rest
}

// workflowResults is `[...run.results, ...entries]`.
func workflowResults(run *core.Object, entries ...*core.Object) []any {
	current, _ := run.Get("results").([]any)
	out := make([]any, 0, len(current)+len(entries))
	out = append(out, current...)
	for _, entry := range entries {
		out = append(out, entry)
	}
	return out
}

// workflowLeaseToken is `randomBytes(12).toString('base64url')`.
func workflowLeaseToken() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64url(b[:])
}

// workflowOperatorEvent is an audit event recorded as `deployment-operator`.
func workflowOperatorEvent(tenantID any, action string, resourceID any, now int64, outcome string, metadata *core.Object) *core.Object {
	return core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"actorId", "deployment-operator",
		"action", action,
		"resourceId", resourceID,
		"timestamp", float64(now),
		"outcome", outcome,
		"metadata", metadata,
	)
}

// execute (api/workflows.ts engine execute) runs one run's steps until it waits, finishes or fails. Returns its
// final status (undefined when the run could not be claimed or no longer exists).
func (e *workflowEngine) execute(ctx context.Context, runID string) (any, error) {
	server := e.server
	store := server.Store
	token := workflowLeaseToken()
	claimed, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		run, err := tx.Get(ctx, "workflowRuns", runID)
		if err != nil {
			return false, err
		}
		now := float64(server.Now())
		if run == nil {
			return false, nil
		}
		if run.Get("status") == "running" && jsNumber(coalesce(run.Get("leaseUntil"), 0.0)) > now {
			return false, nil
		}
		if !workflowStatusIn(run.Get("status"), "pending", "waiting", "running") || jsNumber(run.Get("nextAt")) > now {
			return false, nil
		}
		_, err = tx.Put(ctx, "workflowRuns", run.Spread(core.NewObject(
			"status", "running",
			"leaseToken", token,
			"leaseUntil", now+workflowLeaseMs,
		)))
		return err == nil, err
	})
	if err != nil {
		return nil, err
	}
	if !claimed {
		return core.Undefined, nil
	}
	for guard := 0; guard <= 25; guard++ {
		changed := false
		tenantID := ""
		identityID := ""
		next, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (string, error) {
			run, err := tx.Get(ctx, "workflowRuns", runID)
			if err != nil {
				return "", err
			}
			if run == nil || !core.StrictEquals(run.Get("leaseToken"), token) || run.Get("status") != "running" {
				return "stop", nil
			}
			tenantID = jsString(run.Get("tenantId"))
			identityID = jsString(run.Get("identityId"))
			now := server.Now()
			steps, _ := run.Get("steps").([]any)
			stepIndex := jsNumber(run.Get("stepIndex"))
			if stepIndex >= float64(len(steps)) {
				if _, err := tx.Put(ctx, "workflowRuns", workflowClearLease(run).Assign(core.NewObject(
					"status", "completed",
					"finishedAt", float64(now),
					"expiresAt", float64(now)+workflowRunRetentionMs,
				))); err != nil {
					return "", err
				}
				if err := server.Events.RecordAudit(ctx, tx, workflowOperatorEvent(run.Get("tenantId"), "workflow:run:complete", run.Get("id"), now, "allow",
					core.NewObject("workflowId", run.Get("workflowId"), "identityId", run.Get("identityId")))); err != nil {
					return "", err
				}
				return "stop", nil
			}
			workflow, err := tx.Get(ctx, "workflows", jsString(run.Get("workflowId")))
			if err != nil {
				return "", err
			}
			if workflow == nil {
				return "", core.NewIamError("NOT_FOUND", "The workflow was deleted", 404)
			}
			// The rights of the owner who approved these steps: a later editor never lends theirs to old step lists.
			owner, err := tx.Get(ctx, "identities", jsString(run.Get("ownerId")))
			if err != nil {
				return "", err
			}
			if owner == nil || owner.Get("status") != "active" || server.IdentityExpired(owner) {
				return "", core.NewIamError("OWNER_INACTIVE", "The owner of these steps is no longer active; cancel the run, or save the workflow again and start a new one", 409)
			}
			tenant, err := server.Tenant(ctx, tx, run.Get("tenantId"))
			if err != nil {
				return "", err
			}
			if tenant.Get("status") != "active" {
				return "", core.NewIamError("TENANT_INACTIVE", "Tenant inactive", 403)
			}
			index := int(stepIndex)
			step, _ := steps[index].(*core.Object)
			if step == nil {
				step = core.NewObject()
			}
			if workflowKind(step) == "wait" {
				until := float64(now) + jsNumber(step.Get("hours"))*3_600_000
				if _, err := tx.Put(ctx, "workflowRuns", workflowClearLease(run).Assign(core.NewObject(
					"status", "waiting",
					"nextAt", until,
					"stepIndex", stepIndex+1,
					"results", workflowResults(run, core.NewObject(
						"index", stepIndex,
						"kind", "wait",
						"outcome", "done",
						"at", float64(now),
						"detail", "until "+isoString(until),
					)),
				))); err != nil {
					return "", err
				}
				return "stop", nil
			}
			principal := server.Decisions.SimulatedPrincipal(owner, run.Get("ownerMfa") == true)
			result, err := e.perform(ctx, tx, principal, tenant, run, step)
			if err != nil {
				return "", err
			}
			changed = result.changed
			entry := core.NewObject(
				"index", stepIndex,
				"kind", step.Get("kind"),
				"outcome", result.outcome,
				"at", float64(now),
			)
			if result.detail != "" {
				entry.Set("detail", workflowSlice(result.detail, 300))
			}
			if _, err := tx.Put(ctx, "workflowRuns", run.Spread(core.NewObject(
				"stepIndex", stepIndex+1,
				"leaseUntil", float64(now)+workflowLeaseMs,
				"results", workflowResults(run, entry),
			))); err != nil {
				return "", err
			}
			if err := server.Events.RecordAudit(ctx, tx, workflowOperatorEvent(run.Get("tenantId"), "workflow:step", run.Get("id"), now, "allow", core.NewObject(
				"workflowId", run.Get("workflowId"),
				"identityId", run.Get("identityId"),
				"index", stepIndex,
				"kind", step.Get("kind"),
				"outcome", result.outcome,
			))); err != nil {
				return "", err
			}
			return "next", nil
		})
		if err == nil && changed {
			_, err = AfterIdentityChange(ctx, server, tenantID, []string{identityID}, nil)
		}
		if err == nil {
			if next == "stop" {
				break
			}
			continue
		}
		code := "STEP_FAILED"
		if known, ok := asIamError(err); ok {
			code = known.Code
		}
		message := workflowSlice(errorMessage(err), 500)
		if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			run, err := tx.Get(ctx, "workflowRuns", runID)
			if err != nil {
				return err
			}
			if run == nil || !core.StrictEquals(run.Get("leaseToken"), token) {
				return nil
			}
			now := server.Now()
			steps, _ := run.Get("steps").([]any)
			stepIndex := jsNumber(run.Get("stepIndex"))
			var step *core.Object
			if stepIndex >= 0 && stepIndex < float64(len(steps)) {
				step, _ = steps[int(stepIndex)].(*core.Object)
			}
			results := run.Get("results")
			if step != nil {
				results = workflowResults(run, core.NewObject(
					"index", stepIndex,
					"kind", step.Get("kind"),
					"outcome", "failed",
					"at", float64(now),
					"code", code,
					"detail", message,
				))
			}
			if _, err := tx.Put(ctx, "workflowRuns", workflowClearLease(run).Assign(core.NewObject(
				"status", "failed",
				"finishedAt", float64(now),
				"expiresAt", float64(now)+workflowRunRetentionMs,
				"error", core.NewObject("code", code, "message", message),
				"results", results,
			))); err != nil {
				return err
			}
			return server.Events.RecordAudit(ctx, tx, workflowOperatorEvent(run.Get("tenantId"), "workflow:run:fail", run.Get("id"), now, "deny", core.NewObject(
				"workflowId", run.Get("workflowId"),
				"identityId", run.Get("identityId"),
				"index", stepIndex,
				"code", code,
			)))
		}); err != nil {
			return nil, err
		}
		break
	}
	final, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return tx.Get(ctx, "workflowRuns", runID)
	})
	if err != nil {
		return nil, err
	}
	if final == nil {
		return core.Undefined, nil
	}
	return final.Get("status"), nil
}

// workflowCandidate is one person a trigger fired for.
type workflowCandidate struct {
	identity   *core.Object
	occurrence string
	snapshot   *core.Object
}

// workflowOccurrences is a subject's `occurrences` list.
func workflowOccurrences(subject *core.Object) []any {
	list, _ := member(subject, "occurrences").([]any)
	return list
}

// workflowHasOccurrence is `subject?.occurrences?.includes(occurrence)`.
func workflowHasOccurrence(subject *core.Object, occurrence string) bool {
	for _, item := range workflowOccurrences(subject) {
		if item == occurrence {
			return true
		}
	}
	return false
}

// workflowMembers is the live memberships no access package created, per identity (rule contexts).
func workflowMembers(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (map[string][]string, error) {
	records, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	members := map[string][]string{}
	for _, membership := range records {
		if isUndefined(membership.Get("packageAssignmentId")) && server.LiveMembership(membership) {
			identityID := jsString(membership.Get("identityId"))
			members[identityID] = append(members[identityID], jsString(membership.Get("groupId")))
		}
	}
	return members, nil
}

// workflowScopeMatch is `ruleMatch(document, identity, ruleContext(identity, direct, org.of(identity.id, direct))).matched`.
func workflowScopeMatch(document *core.Object, identity *core.Object, direct []string, org *TenantOrgFacts) (bool, error) {
	if direct == nil {
		direct = []string{}
	}
	var facts *core.Object
	if org != nil {
		var err error
		facts, err = org.Of(jsString(identity.Get("id")), direct)
		if err != nil {
			return false, err
		}
	}
	context, err := RuleContext(identity, direct, facts)
	if err != nil {
		return false, err
	}
	match, err := RuleMatch(document, identity, context)
	if err != nil {
		return false, err
	}
	return truthy(match.Get("matched")), nil
}

// evaluateWorkflow (api/workflows.ts engine evaluateWorkflow) starts the runs a workflow's trigger calls for now.
// Returns how many started.
func (e *workflowEngine) evaluateWorkflow(ctx context.Context, workflowID string) (int, error) {
	server := e.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (int, error) {
		workflow, err := tx.Get(ctx, "workflows", workflowID)
		if err != nil {
			return 0, err
		}
		if workflow == nil || !truthy(workflow.Get("enabled")) || member(workflow.Get("trigger"), "kind") == "manual" {
			return 0, nil
		}
		tenant, err := tx.Get(ctx, "tenants", jsString(workflow.Get("tenantId")))
		if err != nil {
			return 0, err
		}
		if tenant == nil || tenant.Get("status") != "active" {
			return 0, nil
		}
		now := server.Now()
		tenantID := jsString(workflow.Get("tenantId"))
		workflowKey := jsString(workflow.Get("id"))
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return 0, err
		}
		var people []*core.Object
		for _, identity := range identities {
			if identity.Get("kind") == "user" && identity.Get("status") != "deleted" {
				people = append(people, identity)
			}
		}
		kind := member(workflow.Get("trigger"), "kind")
		tracked := kind == "mover" || kind == "leaver"
		// Per person: the mover/leaver baseline, and which occurrences already fired (runs themselves expire).
		subjects, err := tx.Find(ctx, "workflowSubjects", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
		if err != nil {
			return 0, err
		}
		snapshots := map[string]*core.Object{}
		for _, subject := range subjects {
			snapshots[jsString(subject.Get("identityId"))] = subject
		}
		var scopeDocument *core.Object
		if scope, ok := workflow.Get("scope").(*core.Object); ok && truthy(scope) {
			scopeDocument, err = RuleDocument(scope)
			if err != nil {
				return 0, err
			}
		}
		var members map[string][]string
		var org *TenantOrgFacts
		loaded := false
		inScope := func(identity *core.Object) (bool, error) {
			if scopeDocument == nil {
				return true, nil
			}
			if !loaded {
				members, err = workflowMembers(ctx, server, tx, tenantID)
				if err != nil {
					return false, err
				}
				org, err = LoadOrgFacts(ctx, tx, tenantID, now)
				if err != nil {
					return false, err
				}
				loaded = true
			}
			return workflowScopeMatch(scopeDocument, identity, members[jsString(identity.Get("id"))], org)
		}
		writeSnapshot := func(identity *core.Object, snapshot *core.Object, occurrence string) error {
			identityID := jsString(identity.Get("id"))
			previous := snapshots[identityID]
			var recordID any = ID()
			if previous != nil {
				recordID = previous.Get("id")
			}
			record := core.NewObject(
				"id", recordID,
				"tenantId", tenantID,
				"uniqueKey", workflowKey+":"+identityID,
				"workflowId", workflow.Get("id"),
				"identityId", identity.Get("id"),
			).Assign(snapshot)
			if occurrence != "" || len(workflowOccurrences(previous)) > 0 {
				occurrences := append([]any{}, workflowOccurrences(previous)...)
				if occurrence != "" {
					occurrences = append(occurrences, occurrence)
				}
				if len(occurrences) > 20 {
					occurrences = occurrences[len(occurrences)-20:]
				}
				record.Set("occurrences", occurrences)
			}
			if previous != nil {
				if _, err := tx.Put(ctx, "workflowSubjects", record); err != nil {
					return err
				}
			} else if _, err := tx.Insert(ctx, "workflowSubjects", record); err != nil {
				return err
			}
			snapshots[identityID] = record
			return nil
		}
		var candidates []workflowCandidate
		for _, identity := range people {
			previous := snapshots[jsString(identity.Get("id"))]
			var base *core.Object
			if tracked {
				base = previous
			}
			fired, err := TriggerOccurrence(workflow, identity, base, now)
			if err != nil {
				return 0, err
			}
			occurrence, _ := fired.Get("occurrence").(string)
			snapshot, _ := fired.Get("snapshot").(*core.Object)
			admit := false
			if occurrence != "" && !workflowHasOccurrence(previous, occurrence) {
				admit, err = inScope(identity)
				if err != nil {
					return 0, err
				}
			}
			if admit {
				candidates = append(candidates, workflowCandidate{identity: identity, occurrence: occurrence, snapshot: snapshot})
			} else if snapshot != nil && tracked {
				// A change outside the scope (or already run) is taken as the new baseline right away.
				if err := writeSnapshot(identity, snapshot, ""); err != nil {
					return 0, err
				}
			}
		}
		if len(candidates) == 0 {
			return 0, nil
		}
		today, err := UtcDay(now)
		if err != nil {
			return 0, err
		}
		startedToday := 0.0
		if workflow.Get("startedOn") == today {
			startedToday = jsNumber(coalesce(workflow.Get("startedToday"), 0.0))
		}
		// The brake admits runs up to the day's allowance and holds the rest (their baselines stay unchanged, so
		// they start on a later day or after someone raises the limit).
		allowance := math.Max(0, jsNumber(workflow.Get("maxRunsPerDay"))-startedToday)
		admitted := candidates
		if float64(len(candidates)) > allowance {
			admitted = candidates[:int(allowance)]
		}
		held := len(candidates) - len(admitted)
		braked := held > 0 && workflow.Get("brakedOn") != today
		update := workflow.Spread(core.NewObject("startedOn", today, "startedToday", startedToday+float64(len(admitted))))
		if braked {
			update.Set("brakedOn", today)
		}
		if _, err := tx.Put(ctx, "workflows", update); err != nil {
			return 0, err
		}
		if braked {
			if err := server.Events.RecordAudit(ctx, tx, workflowOperatorEvent(tenantID, "workflow:brake", workflow.Get("id"), now, "deny", core.NewObject(
				"held", float64(held),
				"startedToday", startedToday+float64(len(admitted)),
				"maxRunsPerDay", workflow.Get("maxRunsPerDay"),
			))); err != nil {
				return 0, err
			}
		}
		for _, candidate := range admitted {
			snapshot := candidate.snapshot
			if snapshot == nil {
				if base := snapshots[jsString(candidate.identity.Get("id"))]; base != nil {
					snapshot = workflowSnapshot2(base.Get("values"), base.Get("status"), base.Get("fired"))
				} else {
					snapshot = workflowSnapshot2(core.NewObject(), candidate.identity.Get("status"), 0.0)
				}
			}
			if err := writeSnapshot(candidate.identity, snapshot, candidate.occurrence); err != nil {
				return 0, err
			}
			// No uniqueKey: which occurrences already ran is kept on the person's workflowSubjects record, which a
			// restart resets, while older runs of the same occurrence may still exist.
			run := core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"workflowId", workflow.Get("id"),
				"workflowName", workflow.Get("name"),
				"workflowVersion", workflow.Get("version"),
				"identityId", candidate.identity.Get("id"),
				"occurrence", candidate.occurrence,
				"trigger", member(workflow.Get("trigger"), "kind"),
				"steps", workflow.Get("steps"),
				"ownerId", workflow.Get("ownerId"),
				"ownerMfa", workflow.Get("ownerMfa") == true,
				"status", "pending",
				"stepIndex", 0.0,
				"nextAt", float64(now),
				"results", []any{},
				"startedAt", float64(now),
			)
			if _, err := tx.Insert(ctx, "workflowRuns", run); err != nil {
				return 0, err
			}
			if err := server.Events.RecordAudit(ctx, tx, workflowOperatorEvent(tenantID, "workflow:run:start", run.Get("id"), now, "allow", core.NewObject(
				"workflowId", workflow.Get("id"),
				"identityId", candidate.identity.Get("id"),
				"occurrence", candidate.occurrence,
			))); err != nil {
				return 0, err
			}
		}
		return len(admitted), nil
	})
}

// workflowSnapshot2 is `{ values, status, fired }` from stored members.
func workflowSnapshot2(values, status, fired any) *core.Object {
	return core.NewObject("values", values, "status", status, "fired", fired)
}

// runDue (api/workflows.ts engine runDue) evaluates every enabled workflow (of one tenant) and runs what is due.
// input is `{ tenantId?, limit? }` (nil for none).
func (e *workflowEngine) runDue(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := e.server
	limit, err := Integer(coalesce(input.Get("limit"), 500.0), "limit", 1, 10_000)
	if err != nil {
		return nil, err
	}
	filter := core.NewObject()
	if !isUndefined(input.Get("tenantId")) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		filter.Set("tenantId", tenantID)
	}
	started, executed, completed, failed, waiting := 0, 0, 0, 0, 0
	workflows, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		return tx.Find(ctx, "workflows", filter, nil)
	})
	if err != nil {
		return nil, err
	}
	for _, workflow := range workflows {
		if truthy(workflow.Get("enabled")) && member(workflow.Get("trigger"), "kind") != "manual" {
			// One workflow's failure (a lock timeout, a record another process changed) never stops the others.
			if count, err := e.evaluateWorkflow(ctx, jsString(workflow.Get("id"))); err == nil {
				started += count
			}
		}
	}
	now := float64(server.Now())
	due, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		var runs []*core.Object
		for _, status := range []string{"pending", "waiting", "running"} {
			found, err := tx.Find(ctx, "workflowRuns", filter.Spread(core.NewObject("status", status)), nil)
			if err != nil {
				return nil, err
			}
			for _, run := range found {
				if status == "running" && jsNumber(coalesce(run.Get("leaseUntil"), 0.0)) > now {
					continue
				}
				runs = append(runs, run)
			}
		}
		var ready []*core.Object
		for _, run := range runs {
			if jsNumber(run.Get("nextAt")) <= now {
				ready = append(ready, run)
			}
		}
		sortStable(ready, func(a, b *core.Object) int {
			if difference := jsNumber(a.Get("nextAt")) - jsNumber(b.Get("nextAt")); difference != 0 && !math.IsNaN(difference) {
				if difference < 0 {
					return -1
				}
				return 1
			}
			if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
				return -1
			}
			return 1
		})
		if len(ready) > int(limit) {
			ready = ready[:int(limit)]
		}
		return ready, nil
	})
	if err != nil {
		return nil, err
	}
	for _, run := range due {
		status, err := e.execute(ctx, jsString(run.Get("id")))
		if err != nil {
			return nil, err
		}
		if !truthy(status) {
			continue
		}
		executed++
		switch status {
		case "completed":
			completed++
		case "failed":
			failed++
		case "waiting":
			waiting++
		}
	}
	return core.NewObject(
		"started", float64(started),
		"executed", float64(executed),
		"completed", float64(completed),
		"failed", float64(failed),
		"waiting", float64(waiting),
	), nil
}

// directory (createWorkflowsApi directory): may the caller see people's names and addresses
// (`iam:identities:read`)? Otherwise views carry IDs only.
func (api *WorkflowsAPI) directory(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (bool, error) {
	return workflowDecide(ctx, api.server, tx, principal, tenantID, "iam:identities:read", tenantID)
}

// names (createWorkflowsApi names): people's addresses (or names) by ID, for callers who may read the directory.
func (api *WorkflowsAPI) names(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, identityIDs []string) (map[string]string, error) {
	result := map[string]string{}
	visible, err := api.directory(ctx, tx, principal, tenantID)
	if err != nil {
		return nil, err
	}
	if !visible {
		return result, nil
	}
	for _, identityID := range unique(identityIDs) {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			result[identityID] = jsString(coalesce(identity.Get("email"), identity.Get("name")))
		}
	}
	return result, nil
}

// workflowRunStats (createWorkflowsApi runStats).
func workflowRunStats(runs []*core.Object, now int64) *core.Object {
	last := 0.0
	last30, active, failed := 0, 0, 0
	for _, item := range runs {
		started := jsNumber(item.Get("startedAt"))
		last = math.Max(last, started)
		if started > float64(now)-30*WorkflowsDayMs {
			last30++
		}
		if workflowStatusIn(item.Get("status"), "pending", "running", "waiting") {
			active++
		}
		if item.Get("status") == "failed" {
			failed++
		}
	}
	stats := core.NewObject("last30Days", float64(last30), "active", float64(active), "failed", float64(failed))
	if last != 0 && !math.IsNaN(last) {
		stats.Set("lastRunAt", last)
	}
	return stats
}

// startManual (createWorkflowsApi startManual): starts manual runs for people (the caller needs the steps' rights
// over each of them).
func (api *WorkflowsAPI) startManual(ctx context.Context, tx core.IamStore, principal *Principal, workflow *core.Object, identityIDs []string) ([]*core.Object, error) {
	server := api.server
	tenantID := jsString(workflow.Get("tenantId"))
	steps := workflowSteps(workflow.Get("steps"))
	if err := assertWorkflowOwnerRights(ctx, server, tx, principal, tenantID, steps, identityIDs); err != nil {
		return nil, err
	}
	if containsString(identityIDs, jsString(principal.Identity.Get("id"))) && workflowAnyStep(steps, workflowSelfChanging) {
		return nil, core.NewIamError("ACCESS_DENIED", "Nobody changes their own account through a workflow they start", 403)
	}
	now := float64(server.Now())
	var created []*core.Object
	for _, identityID := range identityIDs {
		identity, err := server.ActiveIdentity(ctx, tx, identityID, tenantID)
		if err != nil {
			return nil, err
		}
		if identity.Get("kind") != "user" {
			return nil, invalidInput("Workflows run for people")
		}
		occurrence := "manual:" + ID()
		record := core.NewObject(
			"id", ID(),
			"tenantId", workflow.Get("tenantId"),
			"workflowId", workflow.Get("id"),
			"workflowName", workflow.Get("name"),
			"workflowVersion", workflow.Get("version"),
			"identityId", identity.Get("id"),
			"occurrence", occurrence,
			"trigger", member(workflow.Get("trigger"), "kind"),
			"steps", workflow.Get("steps"),
			"ownerId", workflow.Get("ownerId"),
			"ownerMfa", workflow.Get("ownerMfa") == true,
			"status", "pending",
			"stepIndex", 0.0,
			"nextAt", now,
			"results", []any{},
			"startedAt", now,
			"startedBy", principal.Identity.Get("id"),
		)
		if _, err := tx.Insert(ctx, "workflowRuns", record); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "workflow:run:start", tenantID, jsString(record.Get("id")), "allow", false, core.NewObject(
			"workflowId", workflow.Get("id"),
			"identityId", identity.Get("id"),
			"occurrence", occurrence,
		)); err != nil {
			return nil, err
		}
		created = append(created, record)
	}
	return created, nil
}

// settle (createWorkflowsApi settle) runs the runs until they wait, finish or fail, and lists them by ID (the
// caller may run steps without being allowed to read the directory).
func (api *WorkflowsAPI) settle(ctx context.Context, tenantID any, runIDs []string) ([]any, error) {
	for _, runID := range runIDs {
		if _, err := api.run.execute(ctx, runID); err != nil {
			return nil, err
		}
	}
	return core.Transact(ctx, api.server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		views := []any{}
		for _, runID := range runIDs {
			item, err := tx.Get(ctx, "workflowRuns", runID)
			if err != nil {
				return nil, err
			}
			if item != nil && core.StrictEquals(item.Get("tenantId"), tenantID) {
				views = append(views, workflowRunView(item, ""))
			}
		}
		return views, nil
	})
}

// ownerName is `principal.identity.email ?? principal.identity.name`.
func workflowOwnerName(principal *Principal) string {
	return jsString(coalesce(principal.Identity.Get("email"), principal.Identity.Get("name")))
}

// workflowCancelled is a run cancelled now: `{ ...rest, status: 'cancelled', finishedAt, expiresAt }` without its
// lease.
func workflowCancelled(item *core.Object, now int64) *core.Object {
	return workflowClearLease(item).Assign(core.NewObject(
		"status", "cancelled",
		"finishedAt", float64(now),
		"expiresAt", float64(now)+workflowRunRetentionMs,
	))
}

// CancelRun is POST {basePath}/workflows/cancelRun. Stops a pending, running, waiting or failed run; steps already
// done stay done.
func (api *WorkflowsAPI) CancelRun(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsCancelRunInput]) (Out[apitypes.WorkflowsCancelRunOutput], error) {
	server := api.server
	runID, err := Text(input.Get("runId"), "runId")
	if err != nil {
		return Out[apitypes.WorkflowsCancelRunOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:run", runID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		item, err := server.Scoped(ctx, call.Tx, "workflowRuns", input.Get("runId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if !workflowStatusIn(item.Get("status"), "pending", "waiting", "failed", "running") {
			return nil, core.NewIamError("INVALID_TRANSITION", "This run already finished", 409)
		}
		cancelled, err := call.Tx.Put(ctx, "workflowRuns", workflowCancelled(item, server.Now()))
		if err != nil {
			return nil, err
		}
		return workflowRunView(cancelled, ""), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsCancelRunOutput]{}, err
	}
	return Out[apitypes.WorkflowsCancelRunOutput]{Value: view}, nil
}

// Create is POST {basePath}/workflows/create. Creates a workflow owned by the caller, who must hold every right its
// steps use. Mover and leaver workflows take everyone's current values as their baseline, so only later changes
// fire.
func (api *WorkflowsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsCreateInput]) (Out[apitypes.WorkflowsCreateOutput], error) {
	server := api.server
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:manage", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		values, err := workflowFields(ctx, server, tx, tenantID, input.Body, nil)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, "workflows", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, workflow := range existing {
			if core.StrictEquals(workflow.Get("uniqueKey"), values.Get("uniqueKey")) {
				return nil, core.NewIamError("CONFLICT", "A workflow with this name exists", 409)
			}
		}
		if len(existing) >= workflowMaxWorkflows {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+strconv.Itoa(workflowMaxWorkflows)+" workflows", 409)
		}
		steps := workflowSteps(values.Get("steps"))
		if err := assertWorkflowOwnerRights(ctx, server, tx, principal, tenantID, steps, nil); err != nil {
			return nil, err
		}
		if workflowAnyStep(steps, DestructiveSteps) {
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
		}
		now := server.Now()
		workflow, err := tx.Insert(ctx, "workflows", values.Spread(core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"ownerId", principal.Identity.Get("id"),
			"ownerMfa", principal.Session.Get("mfa"),
			"version", 1.0,
			"activeSince", float64(now),
			"createdAt", float64(now),
			"updatedAt", float64(now),
		)))
		if err != nil {
			return nil, err
		}
		if err := rebuildWorkflowSnapshots(ctx, tx, workflow, now); err != nil {
			return nil, err
		}
		return workflowView(workflow, workflowOwnerName(principal), nil), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsCreateOutput]{}, err
	}
	return Out[apitypes.WorkflowsCreateOutput]{Value: view}, nil
}

// Delete is POST {basePath}/workflows/delete. Deletes a workflow and cancels its pending, running and waiting runs;
// finished runs stay as history.
func (api *WorkflowsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsDeleteInput]) (Out[apitypes.WorkflowsDeleteOutput], error) {
	server := api.server
	workflowID, err := Text(input.Get("workflowId"), "workflowId")
	if err != nil {
		return Out[apitypes.WorkflowsDeleteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:manage", workflowID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		workflow, err := server.Scoped(ctx, tx, "workflows", input.Get("workflowId"), tenantID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		cancelled := 0
		runs, err := tx.Find(ctx, "workflowRuns", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, item := range runs {
			if workflowStatusIn(item.Get("status"), "pending", "waiting", "running") {
				if _, err := tx.Put(ctx, "workflowRuns", workflowCancelled(item, now)); err != nil {
					return nil, err
				}
				cancelled++
			}
		}
		subjects, err := tx.Find(ctx, "workflowSubjects", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, subject := range subjects {
			if err := tx.Delete(ctx, "workflowSubjects", jsString(subject.Get("id"))); err != nil {
				return nil, err
			}
		}
		if err := tx.Delete(ctx, "workflows", jsString(workflow.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true, "runsCancelled", float64(cancelled)), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsDeleteOutput]{}, err
	}
	return Out[apitypes.WorkflowsDeleteOutput]{Value: result}, nil
}

// Evaluate is POST {basePath}/workflows/evaluate. Evaluates this organization's workflows and runs whatever is due
// now, instead of waiting for the scheduler.
func (api *WorkflowsAPI) Evaluate(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsEvaluateInput]) (Out[apitypes.WorkflowsEvaluateOutput], error) {
	if _, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:workflows:run", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (bool, error) {
		return true, nil
	}, false); err != nil {
		return Out[apitypes.WorkflowsEvaluateOutput]{}, err
	}
	result, err := api.run.runDue(ctx, core.NewObject("tenantId", input.Get("tenantId")))
	if err != nil {
		return Out[apitypes.WorkflowsEvaluateOutput]{}, err
	}
	return Out[apitypes.WorkflowsEvaluateOutput]{Value: result}, nil
}

// workflowRunsNewestFirst sorts runs by startedAt descending, then ID.
func workflowRunsNewestFirst(runs []*core.Object) {
	sortStable(runs, func(a, b *core.Object) int {
		if difference := jsNumber(b.Get("startedAt")) - jsNumber(a.Get("startedAt")); difference != 0 && !math.IsNaN(difference) {
			if difference < 0 {
				return -1
			}
			return 1
		}
		if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
			return -1
		}
		return 1
	})
}

// Get is POST {basePath}/workflows/get. Returns one workflow with run statistics and its 50 most recent runs.
func (api *WorkflowsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsGetInput]) (Out[apitypes.WorkflowsGetOutput], error) {
	server := api.server
	workflowID, err := Text(input.Get("workflowId"), "workflowId")
	if err != nil {
		return Out[apitypes.WorkflowsGetOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:read", workflowID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		workflow, err := server.Scoped(ctx, tx, "workflows", input.Get("workflowId"), tenantID)
		if err != nil {
			return nil, err
		}
		runs, err := tx.Find(ctx, "workflowRuns", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		workflowRunsNewestFirst(runs)
		recent := runs
		if len(recent) > 50 {
			recent = recent[:50]
		}
		ids := []string{jsString(workflow.Get("ownerId"))}
		for _, item := range recent {
			ids = append(ids, jsString(item.Get("identityId")))
		}
		known, err := api.names(ctx, tx, call.Principal, tenantID, ids)
		if err != nil {
			return nil, err
		}
		recentRuns := make([]any, len(recent))
		for index, item := range recent {
			recentRuns[index] = workflowRunView(item, known[jsString(item.Get("identityId"))])
		}
		view := workflowView(workflow, known[jsString(workflow.Get("ownerId"))], workflowRunStats(runs, server.Now()))
		view.Set("recentRuns", recentRuns)
		return view, nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsGetOutput]{}, err
	}
	return Out[apitypes.WorkflowsGetOutput]{Value: view}, nil
}

// GetRun is POST {basePath}/workflows/getRun. Returns one run with its steps and results.
func (api *WorkflowsAPI) GetRun(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsGetRunInput]) (Out[apitypes.WorkflowsGetRunOutput], error) {
	server := api.server
	runID, err := Text(input.Get("runId"), "runId")
	if err != nil {
		return Out[apitypes.WorkflowsGetRunOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:read", runID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		item, err := server.Scoped(ctx, call.Tx, "workflowRuns", input.Get("runId"), tenantID)
		if err != nil {
			return nil, err
		}
		identityID := jsString(item.Get("identityId"))
		known, err := api.names(ctx, call.Tx, call.Principal, tenantID, []string{identityID})
		if err != nil {
			return nil, err
		}
		return workflowRunView(item, known[identityID]), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsGetRunOutput]{}, err
	}
	return Out[apitypes.WorkflowsGetRunOutput]{Value: view}, nil
}

// List is POST {basePath}/workflows/list. Lists the tenant's workflows by name, with run statistics.
func (api *WorkflowsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsListInput]) (Out[apitypes.WorkflowsListOutput], error) {
	server := api.server
	views, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		workflows, err := tx.Find(ctx, "workflows", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		runs, err := tx.Find(ctx, "workflowRuns", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		ownerIDs := make([]string, len(workflows))
		for index, workflow := range workflows {
			ownerIDs[index] = jsString(workflow.Get("ownerId"))
		}
		owners, err := api.names(ctx, tx, call.Principal, tenantID, ownerIDs)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		sortStable(workflows, func(a, b *core.Object) int {
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
		})
		views := make([]any, len(workflows))
		for index, workflow := range workflows {
			var own []*core.Object
			for _, item := range runs {
				if core.StrictEquals(item.Get("workflowId"), workflow.Get("id")) {
					own = append(own, item)
				}
			}
			views[index] = workflowView(workflow, owners[jsString(workflow.Get("ownerId"))], workflowRunStats(own, now))
		}
		return views, nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsListOutput]{}, err
	}
	return Out[apitypes.WorkflowsListOutput]{Value: views}, nil
}

// ListRuns is POST {basePath}/workflows/listRuns. Lists runs, newest first, optionally of one workflow, one person or
// one status.
func (api *WorkflowsAPI) ListRuns(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsListRunsInput]) (Out[apitypes.WorkflowsListRunsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 10_000_000)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID)
		if value := input.Get("workflowId"); !isUndefined(value) {
			text, err := Text(value, "workflowId")
			if err != nil {
				return nil, err
			}
			filter.Set("workflowId", text)
		}
		if value := input.Get("identityId"); !isUndefined(value) {
			text, err := Text(value, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", text)
		}
		if value := input.Get("status"); !isUndefined(value) {
			text, err := Text(value, "status", 32)
			if err != nil {
				return nil, err
			}
			filter.Set("status", text)
		}
		rows, err := tx.Find(ctx, "workflowRuns", filter, nil)
		if err != nil {
			return nil, err
		}
		workflowRunsNewestFirst(rows)
		start := int(math.Min(offset, float64(len(rows))))
		end := int(math.Min(offset+limit, float64(len(rows))))
		page := rows[start:end]
		ids := make([]string, len(page))
		for index, item := range page {
			ids[index] = jsString(item.Get("identityId"))
		}
		known, err := api.names(ctx, tx, call.Principal, tenantID, ids)
		if err != nil {
			return nil, err
		}
		views := make([]any, len(page))
		for index, item := range page {
			views[index] = workflowRunView(item, known[jsString(item.Get("identityId"))])
		}
		return core.NewObject("total", float64(len(rows)), "runs", views), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsListRunsOutput]{}, err
	}
	return Out[apitypes.WorkflowsListRunsOutput]{Value: result}, nil
}

// Preview is POST {basePath}/workflows/preview. What the workflow would do right now: who its scope matches, who a
// run would start for at the next evaluation, upcoming dates (30 days), and whether the owner still holds each step's
// rights. Changes nothing.
func (api *WorkflowsAPI) Preview(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsPreviewInput]) (Out[apitypes.WorkflowsPreviewOutput], error) {
	server := api.server
	workflowID, err := Text(input.Get("workflowId"), "workflowId")
	if err != nil {
		return Out[apitypes.WorkflowsPreviewOutput]{}, err
	}
	preview, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:read", workflowID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		workflow, err := server.Scoped(ctx, tx, "workflows", input.Get("workflowId"), tenantID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		visible, err := api.directory(ctx, tx, call.Principal, tenantID)
		if err != nil {
			return nil, err
		}
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var people []*core.Object
		for _, identity := range identities {
			if identity.Get("kind") == "user" && identity.Get("status") == "active" {
				people = append(people, identity)
			}
		}
		members, err := workflowMembers(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		org, err := LoadOrgFacts(ctx, tx, tenantID, now)
		if err != nil {
			return nil, err
		}
		var document *core.Object
		if scope, ok := workflow.Get("scope").(*core.Object); ok && truthy(scope) {
			document, err = RuleDocument(scope)
			if err != nil {
				return nil, err
			}
		}
		subjects, err := tx.Find(ctx, "workflowSubjects", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		snapshots := map[string]*core.Object{}
		for _, subject := range subjects {
			snapshots[jsString(subject.Get("identityId"))] = subject
		}
		trigger, _ := workflow.Get("trigger").(*core.Object)
		kind := member(trigger, "kind")
		tracked := kind == "mover" || kind == "leaver"
		inScope, wouldStart := []any{}, []any{}
		type upcomingEntry struct {
			entry *core.Object
			at    float64
		}
		var upcoming []upcomingEntry
		for _, identity := range people {
			identityID := jsString(identity.Get("id"))
			if document != nil {
				matched, err := workflowScopeMatch(document, identity, members[identityID], org)
				if err != nil {
					return nil, err
				}
				if !matched {
					continue
				}
			}
			// Names and addresses only for callers who may read the directory; IDs otherwise.
			name := identity.Get("id")
			if visible {
				name = identity.Get("name")
			}
			entry := core.NewObject("id", identity.Get("id"), "name", name)
			if email := identity.Get("email"); visible && truthy(email) {
				entry.Set("email", email)
			}
			inScope = append(inScope, entry)
			subject := snapshots[identityID]
			var base *core.Object
			if tracked {
				base = subject
			}
			fired, err := TriggerOccurrence(workflow, identity, base, now)
			if err != nil {
				return nil, err
			}
			occurrence, _ := fired.Get("occurrence").(string)
			if truthy(workflow.Get("enabled")) && occurrence != "" && !workflowHasOccurrence(subject, occurrence) {
				wouldStart = append(wouldStart, core.NewObject("id", identity.Get("id"), "name", name, "occurrence", occurrence))
			}
			if kind == "date" {
				at, err := DateTarget(trigger, identity)
				if err != nil {
					return nil, err
				}
				if at != nil && *at > float64(now) && *at <= float64(now)+30*WorkflowsDayMs {
					upcoming = append(upcoming, upcomingEntry{entry: core.NewObject("id", identity.Get("id"), "name", name, "at", *at), at: *at})
				}
			}
		}
		sortStable(upcoming, func(a, b upcomingEntry) int {
			switch {
			case a.at < b.at:
				return -1
			case a.at > b.at:
				return 1
			}
			return 0
		})
		upcomingList := make([]any, len(upcoming))
		for index, item := range upcoming {
			upcomingList[index] = item.entry
		}
		owner, err := tx.Get(ctx, "identities", jsString(workflow.Get("ownerId")))
		if err != nil {
			return nil, err
		}
		var ownerPrincipal *Principal
		if owner != nil && owner.Get("status") == "active" {
			ownerPrincipal = server.Decisions.SimulatedPrincipal(owner, workflow.Get("ownerMfa") == true)
		}
		stepViews := []any{}
		for index, step := range workflowSteps(workflow.Get("steps")) {
			allowed := ownerPrincipal != nil
			reason := ""
			if ownerPrincipal == nil {
				reason = "The owner is no longer active"
			} else {
				for _, requirement := range workflowRequirements(step, tenantID, "") {
					ok, err := workflowDecide(ctx, server, tx, ownerPrincipal, tenantID, requirement[0], requirement[1])
					if err != nil {
						return nil, err
					}
					if !ok {
						allowed = false
						reason = "The owner lacks " + requirement[0] + " on " + requirement[1]
						break
					}
				}
			}
			view := core.NewObject("index", float64(index), "kind", step.Get("kind"), "allowed", allowed)
			if reason != "" {
				view.Set("reason", reason)
			}
			stepViews = append(stepViews, view)
		}
		return core.NewObject("inScope", inScope, "wouldStart", wouldStart, "upcoming", upcomingList, "steps", stepViews), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsPreviewOutput]{}, err
	}
	return Out[apitypes.WorkflowsPreviewOutput]{Value: preview}, nil
}

// RetryRun is POST {basePath}/workflows/retryRun. Resumes a failed run at the step that failed (after fixing the
// cause: a deleted group, an owner who left). The caller needs the remaining steps' rights over the person, and the
// remaining steps then run with the caller's rights: retrying is approving them.
func (api *WorkflowsAPI) RetryRun(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsRetryRunInput]) (Out[apitypes.WorkflowsRetryRunOutput], error) {
	server := api.server
	runID, err := Text(input.Get("runId"), "runId")
	if err != nil {
		return Out[apitypes.WorkflowsRetryRunOutput]{}, err
	}
	retried, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:run", runID, func(ctx context.Context, call MutationContext) (string, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		item, err := server.Scoped(ctx, tx, "workflowRuns", input.Get("runId"), tenantID)
		if err != nil {
			return "", err
		}
		if item.Get("status") != "failed" {
			return "", core.NewIamError("INVALID_TRANSITION", "Only failed runs can be retried", 409)
		}
		steps := workflowSteps(item.Get("steps"))
		from := int(math.Max(0, math.Min(jsNumber(item.Get("stepIndex")), float64(len(steps)))))
		remaining := steps[from:]
		identityID := jsString(item.Get("identityId"))
		if err := assertWorkflowOwnerRights(ctx, server, tx, principal, tenantID, remaining, []string{identityID}); err != nil {
			return "", err
		}
		if workflowAnyStep(remaining, DestructiveSteps) {
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return "", err
			}
		}
		if identityID == jsString(principal.Identity.Get("id")) && workflowAnyStep(remaining, workflowSelfChanging) {
			return "", core.NewIamError("ACCESS_DENIED", "Nobody changes their own account through a workflow they retry", 403)
		}
		rest := item.Spread()
		rest.Delete("error")
		rest.Delete("finishedAt")
		rest.Delete("expiresAt")
		if _, err := tx.Put(ctx, "workflowRuns", rest.Assign(core.NewObject(
			"status", "pending",
			"nextAt", float64(server.Now()),
			"ownerId", principal.Identity.Get("id"),
			"ownerMfa", principal.Session.Get("mfa"),
			"startedBy", principal.Identity.Get("id"),
		))); err != nil {
			return "", err
		}
		return jsString(item.Get("id")), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsRetryRunOutput]{}, err
	}
	views, err := api.settle(ctx, input.Get("tenantId"), []string{retried})
	if err != nil {
		return Out[apitypes.WorkflowsRetryRunOutput]{}, err
	}
	if len(views) == 0 {
		return Out[apitypes.WorkflowsRetryRunOutput]{Value: core.Undefined}, nil
	}
	return Out[apitypes.WorkflowsRetryRunOutput]{Value: views[0]}, nil
}

// Run is POST {basePath}/workflows/run. Runs a workflow now for up to 100 people, whatever its trigger (the scope is
// not applied: you choose the people). The caller needs the steps' rights over each of them. Steps run until the
// first wait before this returns.
func (api *WorkflowsAPI) Run(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsRunInput]) (Out[apitypes.WorkflowsRunOutput], error) {
	server := api.server
	listed, err := Strings(input.Get("identityIds"), "identityIds")
	if err != nil {
		return Out[apitypes.WorkflowsRunOutput]{}, err
	}
	identityIDs := unique(listed)
	if len(identityIDs) == 0 {
		return Out[apitypes.WorkflowsRunOutput]{}, invalidInput("Provide 1-100 identityIds")
	}
	workflowID, err := Text(input.Get("workflowId"), "workflowId")
	if err != nil {
		return Out[apitypes.WorkflowsRunOutput]{}, err
	}
	created, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:run", workflowID, func(ctx context.Context, call MutationContext) ([]*core.Object, error) {
		workflow, err := server.Scoped(ctx, call.Tx, "workflows", input.Get("workflowId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if workflowAnyStep(workflowSteps(workflow.Get("steps")), DestructiveSteps) {
			if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
				return nil, err
			}
		}
		return api.startManual(ctx, call.Tx, call.Principal, workflow, identityIDs)
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsRunOutput]{}, err
	}
	runIDs := make([]string, len(created))
	for index, item := range created {
		runIDs[index] = jsString(item.Get("id"))
	}
	views, err := api.settle(ctx, input.Get("tenantId"), runIDs)
	if err != nil {
		return Out[apitypes.WorkflowsRunOutput]{}, err
	}
	return Out[apitypes.WorkflowsRunOutput]{Value: views}, nil
}

// Update is POST {basePath}/workflows/update. Edits a workflow; the caller becomes its owner (and must hold the
// steps' rights). Changing the trigger or enabling it again starts it afresh: joiners and dates count from now, and
// mover and leaver baselines are retaken. Runs already started keep the steps they started with, and the rights of
// the owner who approved them, unless `activeRuns: 'cancel'` stops them.
func (api *WorkflowsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsUpdateInput]) (Out[apitypes.WorkflowsUpdateOutput], error) {
	server := api.server
	workflowID, err := Text(input.Get("workflowId"), "workflowId")
	if err != nil {
		return Out[apitypes.WorkflowsUpdateOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:workflows:manage", workflowID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		previous, err := server.Scoped(ctx, tx, "workflows", input.Get("workflowId"), tenantID)
		if err != nil {
			return nil, err
		}
		values, err := workflowFields(ctx, server, tx, tenantID, input.Body, previous)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, "workflows", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, workflow := range existing {
			if !core.StrictEquals(workflow.Get("id"), previous.Get("id")) && core.StrictEquals(workflow.Get("uniqueKey"), values.Get("uniqueKey")) {
				return nil, core.NewIamError("CONFLICT", "A workflow with this name exists", 409)
			}
		}
		steps := workflowSteps(values.Get("steps"))
		if err := assertWorkflowOwnerRights(ctx, server, tx, principal, tenantID, steps, nil); err != nil {
			return nil, err
		}
		if workflowAnyStep(steps, DestructiveSteps) {
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
		}
		now := server.Now()
		nextTrigger, _, _ := core.Stringify(values.Get("trigger"))
		previousTrigger, _, _ := core.Stringify(previous.Get("trigger"))
		restart := nextTrigger != previousTrigger || (values.Get("enabled") == true && !truthy(previous.Get("enabled")))
		kept := previous.Spread()
		kept.Delete("description")
		kept.Delete("scope")
		kept.Delete("brakedOn")
		activeRuns := input.Get("activeRuns")
		if !isUndefined(activeRuns) && activeRuns != "keep" && activeRuns != "cancel" {
			return nil, invalidInput("activeRuns must be 'keep' or 'cancel'")
		}
		activeSince := previous.Get("activeSince")
		if restart {
			activeSince = float64(now)
		}
		record := kept.Assign(values, core.NewObject(
			"ownerId", principal.Identity.Get("id"),
			"ownerMfa", principal.Session.Get("mfa"),
			"version", jsNumber(previous.Get("version"))+1,
			"activeSince", activeSince,
			"updatedAt", float64(now),
		))
		if braked := previous.Get("brakedOn"); truthy(braked) && isUndefined(input.Get("maxRunsPerDay")) {
			record.Set("brakedOn", braked)
		}
		workflow, err := tx.Put(ctx, "workflows", record)
		if err != nil {
			return nil, err
		}
		if restart {
			if err := rebuildWorkflowSnapshots(ctx, tx, workflow, now); err != nil {
				return nil, err
			}
		}
		if activeRuns == "cancel" {
			runs, err := tx.Find(ctx, "workflowRuns", core.NewObject("tenantId", tenantID, "workflowId", workflow.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, item := range runs {
				if workflowStatusIn(item.Get("status"), "pending", "waiting", "running", "failed") {
					if _, err := tx.Put(ctx, "workflowRuns", workflowCancelled(item, now)); err != nil {
						return nil, err
					}
				}
			}
		}
		return workflowView(workflow, workflowOwnerName(principal), nil), nil
	}, false)
	if err != nil {
		return Out[apitypes.WorkflowsUpdateOutput]{}, err
	}
	return Out[apitypes.WorkflowsUpdateOutput]{Value: view}, nil
}

// workflowReactingPrefixes are the audit actions that can change who a workflow fires for: people, their groups,
// teams and departments, and workflows.
var workflowReactingPrefixes = []string{
	"iam:identities:",
	"identity:",
	"iam:groups:",
	"iam:teams:",
	"iam:departments:",
	"iam:workflows:",
	"iam:scim",
	"scim:",
}

// workflowCacheEntry is one enabledCache entry.
type workflowCacheEntry struct {
	at    int64
	value bool
}

// WorkflowsRuntime is api/workflows.ts createWorkflowsRuntime(): workflows for the deployment's own code
// (`iam.workflows`): the scheduler job `runDue` (every few minutes), and `subscribe()`, which evaluates an
// organization's workflows shortly after a change to its people is recorded in the audit log (it needs
// `iam.dispatchAuditHooks()` to be running, as the console does). Evaluations run in the background, debounced per
// organization, so audit dispatch never waits for them; `idle()` resolves once the scheduled ones have finished.
type WorkflowsRuntime struct {
	server       *ServerContext
	run          *workflowEngine
	mu           sync.Mutex
	busy         map[string]bool
	dirty        map[string]bool
	pending      map[string]chan struct{}
	enabledCache map[string]workflowCacheEntry
}

// RunDue (api/workflows.ts createWorkflowsRuntime().runDue): Evaluates every enabled workflow and runs the steps
// that are due (a scheduler job, every few minutes). input is `{ tenantId?, limit? }` (nil for none).
func (s *WorkflowsRuntime) RunDue(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return s.run.runDue(ctx, input)
}

// hasWorkflows (createWorkflowsRuntime hasWorkflows): whether the tenant has an enabled automatic workflow, cached
// for 15 seconds.
func (s *WorkflowsRuntime) hasWorkflows(ctx context.Context, tenantID string) (bool, error) {
	s.mu.Lock()
	cached, ok := s.enabledCache[tenantID]
	s.mu.Unlock()
	if ok && cached.at > s.server.Wall()-15_000 {
		return cached.value, nil
	}
	workflows, err := core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		return tx.Find(ctx, "workflows", core.NewObject("tenantId", tenantID), nil)
	})
	if err != nil {
		return false, err
	}
	value := false
	for _, workflow := range workflows {
		if truthy(workflow.Get("enabled")) && member(workflow.Get("trigger"), "kind") != "manual" {
			value = true
			break
		}
	}
	s.mu.Lock()
	s.enabledCache[tenantID] = workflowCacheEntry{at: s.server.Wall(), value: value}
	if len(s.enabledCache) > 10_000 {
		s.enabledCache = map[string]workflowCacheEntry{}
	}
	s.mu.Unlock()
	return value, nil
}

// evaluate (createWorkflowsRuntime evaluate) runs the tenant's due workflows until no change arrived meanwhile. The
// scheduler catches up; a background evaluation never surfaces.
func (s *WorkflowsRuntime) evaluate(tenantID string) {
	s.mu.Lock()
	s.busy[tenantID] = true
	s.mu.Unlock()
	defer func() {
		_ = recover()
		s.mu.Lock()
		delete(s.busy, tenantID)
		delete(s.pending, tenantID)
		s.mu.Unlock()
	}()
	ctx := context.Background()
	for {
		s.mu.Lock()
		delete(s.dirty, tenantID)
		s.mu.Unlock()
		has, err := s.hasWorkflows(ctx, tenantID)
		if err != nil || !has {
			return
		}
		if _, err := s.run.runDue(ctx, core.NewObject("tenantId", tenantID)); err != nil {
			return
		}
		s.mu.Lock()
		again := s.dirty[tenantID]
		s.mu.Unlock()
		if !again {
			return
		}
	}
}

// react (createWorkflowsRuntime react) schedules an evaluation of the event's tenant.
func (s *WorkflowsRuntime) react(_ context.Context, event *core.Object) error {
	// A workflow's own steps (and the run events) never retrigger evaluation; other workflows see them on schedule.
	if member(event.Get("metadata"), "via") == "workflow" {
		return nil
	}
	action := jsString(event.Get("action"))
	reacting := false
	for _, prefix := range workflowReactingPrefixes {
		if len(action) >= len(prefix) && action[:len(prefix)] == prefix {
			reacting = true
			break
		}
	}
	if !reacting {
		return nil
	}
	tenantID := jsString(event.Get("tenantId"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(action) >= len("iam:workflows:") && action[:len("iam:workflows:")] == "iam:workflows:" {
		delete(s.enabledCache, tenantID)
	}
	if _, pending := s.pending[tenantID]; s.busy[tenantID] || pending {
		s.dirty[tenantID] = true
		return nil
	}
	done := make(chan struct{})
	s.pending[tenantID] = done
	go func() {
		defer close(done)
		time.Sleep(200 * time.Millisecond)
		s.evaluate(tenantID)
	}()
	return nil
}

// Subscribe (api/workflows.ts createWorkflowsRuntime().subscribe): Reacts to changes to each organization's people
// (see above); returns the unsubscribe function.
func (s *WorkflowsRuntime) Subscribe() (result func(), err error) {
	return s.server.Events.Subscribe("*", s.react)
}

// Idle (api/workflows.ts createWorkflowsRuntime().idle): Resolves once every evaluation `subscribe()` scheduled has
// finished (for tests and graceful shutdown).
func (s *WorkflowsRuntime) Idle(ctx context.Context) (err error) {
	for {
		s.mu.Lock()
		waits := make([]chan struct{}, 0, len(s.pending))
		for _, done := range s.pending {
			waits = append(waits, done)
		}
		s.mu.Unlock()
		if len(waits) == 0 {
			return nil
		}
		for _, done := range waits {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// CreateWorkflowsRuntime builds the WorkflowsRuntime (api/workflows.ts createWorkflowsRuntime).
func CreateWorkflowsRuntime(server *ServerContext) *WorkflowsRuntime {
	return &WorkflowsRuntime{
		server:       server,
		run:          &workflowEngine{server: server},
		busy:         map[string]bool{},
		dirty:        map[string]bool{},
		pending:      map[string]chan struct{}{},
		enabledCache: map[string]workflowCacheEntry{},
	}
}
