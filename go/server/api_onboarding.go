package server

// Port of packages/server/src/api/onboarding.ts. Onboarding: checklists for newcomers, customized at every level of
// the tenant hierarchy. `member` flows walk people through their first days (forms, acknowledgements, tasks,
// accepting terms, verifying their email, enrolling MFA or a passkey); `tenant` flows walk a new organization's or
// project's administrators through setup (a verified domain, enough owners and members, an MFA policy, SSO, directory
// sync). Flows defined at the platform root reach every tenant below; organizations add their own and switch off the
// platform's unlocked ones; projects do the same. Policies see `principal.onboarding` and
// `principal.pendingOnboarding`. Managing needs `iam:onboarding:manage`, reports `iam:onboarding:read`; people work
// through their own flows without a permission.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// OnboardingAPI is the `onboarding` API group (packages/server/src/api/onboarding.ts createOnboardingApi): every method runs through the
// operation envelope; the router maps POST {basePath}/onboarding/{method} onto it.
type OnboardingAPI struct {
	server *ServerContext
}

// CreateOnboardingAPI builds the `onboarding` API group.
func CreateOnboardingAPI(server *ServerContext) *OnboardingAPI {
	return &OnboardingAPI{server: server}
}

const onboardingMaxDescendants = 1000

// onboardingSubject is the person or tenant a progress record belongs to.
type onboardingSubject struct {
	Type     string // identity | tenant
	ID       string
	TenantID string
}

// onboardingStatus is one evaluated flow with the candidate it came from.
type onboardingStatus struct {
	candidate *core.Object
	status    *core.Object
}

// onboardingSelfSession is selfSession: onboarding is the caller's own business, from an ordinary session (or API
// key) of the tenant.
func onboardingSelfSession(principal *Principal, tenantID string) error {
	if !ActsInOwnRight(principal.Session) || principal.Session.Get("tenantId") != tenantID || principal.Identity.Get("tenantId") != tenantID {
		return core.NewIamError("ACCESS_DENIED", "Onboarding is completed from an ordinary session of its tenant", 403)
	}
	return nil
}

// onboardingNotImpersonating is notImpersonating.
func onboardingNotImpersonating(principal *Principal, what string) error {
	if truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", what+" while impersonating", 403)
	}
	return nil
}

func onboardingFlowNotFound() error {
	return core.NewIamError("NOT_FOUND", "Onboarding flow not found", 404)
}

func onboardingStepNotFound() error {
	return core.NewIamError("NOT_FOUND", "Onboarding step not found", 404)
}

// onboardingFlowRecord is flowRecord.
func onboardingFlowRecord(ctx context.Context, tx core.IamStore, flowID any) (*core.Object, error) {
	id, err := Text(flowID, "flowId", 128)
	if err != nil {
		return nil, err
	}
	flow, err := tx.Get(ctx, "onboardingFlows", id)
	if err != nil {
		return nil, err
	}
	if flow == nil {
		return nil, onboardingFlowNotFound()
	}
	return flow, nil
}

// onboardingDescendantsOf is descendantsOf: every tenant below `root`, breadth first, at most 1000.
func onboardingDescendantsOf(ctx context.Context, tx core.IamStore, root *core.Object) ([]*core.Object, bool, error) {
	tenants := []*core.Object{}
	frontier := []any{root.Get("id")}
	for len(frontier) > 0 {
		next := []any{}
		for _, parentID := range frontier {
			children, err := tx.Find(ctx, "tenants", core.NewObject("parentId", parentID), nil)
			if err != nil {
				return nil, false, err
			}
			sort.SliceStable(children, func(i, j int) bool {
				return jsNumber(children[i].Get("createdAt"))-jsNumber(children[j].Get("createdAt")) < 0
			})
			for _, child := range children {
				if len(tenants) >= onboardingMaxDescendants {
					return tenants, true, nil
				}
				tenants = append(tenants, child)
				next = append(next, child.Get("id"))
			}
		}
		frontier = next
	}
	return tenants, false, nil
}

// onboardingDescendantTypes is descendantTypes: the tenant types that can appear below a tenant of `type`,
// following the hierarchy's allowed children.
func onboardingDescendantTypes(server *ServerContext, tenantType string) *orderedSet {
	children := func(name string) []string {
		for _, entry := range server.Config.Hierarchy.Types {
			if entry.Name == name {
				return entry.Type.AllowedChildren
			}
		}
		return nil
	}
	found := newOrderedSet()
	queue := append([]string(nil), children(tenantType)...)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if found.Has(next) {
			continue
		}
		found.Add(next)
		queue = append(queue, children(next)...)
	}
	return found
}

// onboardingSameJSON is sameJson: JSON.stringify(a) === JSON.stringify(b).
func onboardingSameJSON(a, b any) bool {
	textA, okA, errA := core.Stringify(a)
	textB, okB, errB := core.Stringify(b)
	return errA == nil && errB == nil && okA == okB && textA == textB
}

// onboardingSortFlows sorts flows oldest first, then by name.
func onboardingSortFlows(flows []*core.Object) {
	sort.SliceStable(flows, func(i, j int) bool {
		a, b := flows[i], flows[j]
		if difference := jsNumber(a.Get("createdAt")) - jsNumber(b.Get("createdAt")); difference != 0 {
			return difference < 0
		}
		return localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))) < 0
	})
}

// onboardingAuthorizeCompletionGroup is authorizeCompletionGroup: whether `principal` may put people into a
// completion group: iam:groups:update on it and the use of the grant authority behind each of its bindings, and
// behind those of the teams that sync from it (and of the teams above them), since team sync copies the group's
// members there; and iam:licenses:assign when a license product is assigned to the group or to one of those teams,
// since the people who finish the flow claim its seats (api/groups.ts).
func onboardingAuthorizeCompletionGroup(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID, groupID string) error {
	if err := Allow(ctx, server, tx, principal, tenantID, "iam:groups:update", groupID, "add people to a completion group"); err != nil {
		return err
	}
	teams, err := TeamsSyncingFrom(ctx, tx, tenantID, groupID)
	if err != nil {
		return err
	}
	syncing := make([]string, len(teams))
	for index, team := range teams {
		syncing[index] = jsString(team.Get("id"))
	}
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
	if err != nil {
		return err
	}
	chained, err := TeamChainBindings(ctx, tx, tenantID, syncing)
	if err != nil {
		return err
	}
	for _, binding := range append(bindings, chained...) {
		if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, jsString(binding.Get("authorityId"))); err != nil {
			return err
		}
	}
	return AssertMayClaimLicenses(ctx, server, tx, principal, tenantID, groupID,
		"A completion group carries license seats; adding people to it needs iam:licenses:assign")
}

// onboardingOwnerMayGrant is ownerMayGrant: whether the flow's owner (`groupsOwnerId`) may still put people into a
// completion group: active, and passing the check saveFlow made. Groups whose authority the owner lost (demoted,
// revoked, left) are skipped, like the automatic rules of access packages whose owner lost the rights.
func onboardingOwnerMayGrant(ctx context.Context, server *ServerContext, tx core.IamStore, owner *core.Object, tenantID, groupID string) bool {
	if owner == nil || owner.Get("status") != "active" || server.IdentityExpired(owner) {
		return false
	}
	return onboardingAuthorizeCompletionGroup(ctx, server, tx, server.Decisions.SimulatedPrincipal(owner, true), tenantID, groupID) == nil
}

// onboardingLengthTruthy is `value.length` truthiness for any value.
func onboardingLengthTruthy(value any) bool {
	switch v := value.(type) {
	case []any:
		return len(v) > 0
	case string:
		return v != ""
	case *core.Object:
		return v != nil && truthy(v.Get("length"))
	}
	return false
}

// onboardingSaveFlow is saveFlow: validates and stores a flow (a new one without `previous`). Answers that fill
// identity attributes need iam:identities:update, and completion groups need iam:groups:update on each group plus the
// use of the grant authorities behind the group's bindings, because finishing the flow makes the person a member.
// Every completion group is checked again whenever a change alters who completes the flow or when (steps, rule,
// scope, includeExisting, new groups), and the editor then becomes the owner the groups are applied under.
func onboardingSaveFlow(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object, previous *core.Object) (*core.Object, error) {
	if input == nil {
		input = core.NewObject()
	}
	prev := func(key string) any {
		if previous == nil {
			return core.Undefined
		}
		return previous.Get(key)
	}
	tenantID := jsString(tenant.Get("id"))
	audienceValue := coalesce(prev("audience"), input.Get("audience"))
	if audienceValue != "member" && audienceValue != "tenant" {
		return nil, invalidInput("audience must be member or tenant")
	}
	audience := audienceValue.(string)
	if previous != nil && !isUndefined(input.Get("audience")) && input.Get("audience") != previous.Get("audience") {
		return nil, invalidInput("A flow keeps its audience; create a new flow instead")
	}
	nameText, err := Text(coalesce(input.Get("name"), prev("name")), "name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(nameText)
	var description any
	switch raw := input.Get("description"); {
	case isUndefined(raw):
		description = prev("description")
	case raw == nil || raw == "":
		description = core.Undefined
	default:
		if description, err = onboardingLongText(raw, "description", 2_000); err != nil {
			return nil, err
		}
	}
	below := onboardingDescendantTypes(server, jsString(tenant.Get("type")))
	appliesTo := coalesce(input.Get("appliesTo"), prev("appliesTo"))
	if nullish(appliesTo) {
		if audience == "tenant" || tenant.Get("parentId") == nil {
			appliesTo = "descendants"
		} else {
			appliesTo = "tenant"
		}
	}
	if appliesTo != "tenant" && appliesTo != "descendants" && appliesTo != "subtree" {
		return nil, invalidInput("appliesTo must be tenant, descendants or subtree")
	}
	if audience == "tenant" && appliesTo != "descendants" {
		return nil, invalidInput("Tenant setup flows apply to descendant tenants")
	}
	if appliesTo != "tenant" && below.Len() == 0 {
		return nil, invalidInput(jsString(tenant.Get("type")) + " tenants have no descendants; use appliesTo: tenant")
	}
	var tenantTypes any
	switch raw := input.Get("tenantTypes"); {
	case isUndefined(raw):
		tenantTypes = prev("tenantTypes")
	case raw == nil:
		tenantTypes = core.Undefined
	default:
		tenantTypes = raw
	}
	if !isUndefined(tenantTypes) {
		if appliesTo == "tenant" {
			return nil, invalidInput("tenantTypes applies to flows that reach descendants")
		}
		list, ok := tenantTypes.([]any)
		if !ok || len(list) < 1 || len(list) > 20 {
			return nil, invalidInput("tenantTypes must list 1-20 tenant types")
		}
		types := make([]string, len(list))
		for index, item := range list {
			text, err := Text(item, "tenantTypes", 64)
			if err != nil {
				return nil, err
			}
			types[index] = text
		}
		types = unique(types)
		sortStrings(types)
		for _, kind := range types {
			if !below.Has(kind) {
				return nil, invalidInput("tenantTypes: " + kind + " tenants cannot exist below a " + jsString(tenant.Get("type")) + " tenant")
			}
		}
		tenantTypes = stringsOf(types)
	}
	tenantGroups, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	groups := newOrderedSet()
	for _, group := range tenantGroups {
		groups.Add(jsString(group.Get("id")))
	}
	var ruleInput any
	switch raw := input.Get("rule"); {
	case isUndefined(raw):
		ruleInput = prev("rule")
	case raw == nil:
		ruleInput = core.Undefined
	default:
		ruleInput = raw
	}
	if !isUndefined(ruleInput) && audience != "member" {
		return nil, invalidInput("rule applies to member flows only")
	}
	var rule any = core.Undefined
	if !isUndefined(ruleInput) {
		ruleGroups := groups.Values()
		if appliesTo == "descendants" {
			ruleGroups = []string{}
		}
		parsed, err := ParseRule(ruleInput, server.Catalog.IdentityAttributes, ruleGroups)
		if err != nil {
			return nil, err
		}
		rule = parsed
	}
	fallback := func(key string, value bool) bool {
		if b, ok := prev(key).(bool); ok {
			return b
		}
		if nullish(prev(key)) {
			return value
		}
		return truthy(prev(key))
	}
	required, err := onboardingFlag(input.Get("required"), "required", fallback("required", true))
	if err != nil {
		return nil, err
	}
	locked, err := onboardingFlag(input.Get("locked"), "locked", fallback("locked", false))
	if err != nil {
		return nil, err
	}
	includeExisting, err := onboardingFlag(input.Get("includeExisting"), "includeExisting", fallback("includeExisting", false))
	if err != nil {
		return nil, err
	}
	enabled, err := onboardingFlag(input.Get("enabled"), "enabled", fallback("enabled", true))
	if err != nil {
		return nil, err
	}
	if isUndefined(input.Get("steps")) && previous == nil {
		return nil, invalidInput("steps are required")
	}
	var steps []any
	if isUndefined(input.Get("steps")) {
		steps, _ = previous.Get("steps").([]any)
	} else {
		parsed, err := ParseSteps(input.Get("steps"), audience, server.Catalog.IdentityAttributes)
		if err != nil {
			return nil, err
		}
		steps = onboardingList(parsed)
	}
	var groupInput any
	switch raw := input.Get("completionGroupIds"); {
	case isUndefined(raw):
		groupInput = prev("completionGroupIds")
	case raw == nil:
		groupInput = core.Undefined
	default:
		groupInput = raw
	}
	var completionGroupIDs []string
	if !isUndefined(groupInput) && onboardingLengthTruthy(groupInput) {
		if audience != "member" || appliesTo == "descendants" {
			return nil, invalidInput("completionGroupIds apply to member flows that reach the defining tenant’s own people")
		}
		list, ok := groupInput.([]any)
		if !ok || len(list) > MaxCompletionGroups {
			return nil, invalidInput("completionGroupIds must list at most " + jsString(float64(MaxCompletionGroups)) + " groups")
		}
		ids := make([]string, len(list))
		for index, item := range list {
			text, err := Text(item, "groupId", 128)
			if err != nil {
				return nil, err
			}
			ids[index] = text
		}
		completionGroupIDs = unique(ids)
		for _, groupID := range completionGroupIDs {
			if !groups.Has(groupID) {
				return nil, core.NewIamError("NOT_FOUND", "Group "+groupID+" not found", 404)
			}
			// A team's backing group takes its members from the team only (teams.ts).
			group, err := tx.Get(ctx, "groups", groupID)
			if err != nil {
				return nil, err
			}
			if err := AssertNotTeamGroup(group); err != nil {
				return nil, err
			}
		}
	}
	mapped := false
	for _, step := range onboardingObjects(steps) {
		for _, field := range onboardingObjects(step.Get("fields")) {
			if !isUndefined(field.Get("attribute")) {
				mapped = true
			}
		}
	}
	// Answers fill attributes only for the defining tenant's own people: a tenant has no authority over the identities
	// of the tenants below it, whose policies may grant access by those attributes.
	if mapped && appliesTo == "descendants" {
		return nil, invalidInput("Answers fill identity attributes only for the defining tenant’s own people; a flow that reaches only tenants below cannot map fields to attributes")
	}
	mapsAttributes := !isUndefined(input.Get("steps")) && mapped
	previousGroups := onboardingStrings(prev("completionGroupIds"))
	newGroups := 0
	for _, groupID := range completionGroupIDs {
		if previous == nil || !containsString(previousGroups, groupID) {
			newGroups++
		}
	}
	// Finishing the flow puts people into its completion groups, so a change to who finishes it or when (easier steps,
	// a wider rule or scope, existing people, resuming it, another group) re-checks every group, not only new ones.
	reauthorize := len(completionGroupIDs) > 0 &&
		(previous == nil ||
			newGroups > 0 ||
			!onboardingSameJSON(previous.Get("steps"), steps) ||
			!onboardingSameJSON(previous.Get("rule"), rule) ||
			previous.Get("appliesTo") != appliesTo ||
			previous.Get("includeExisting") != includeExisting ||
			(enabled && !truthy(previous.Get("enabled"))))
	if mapsAttributes || reauthorize {
		if !ActsInOwnRight(principal.Session) {
			return nil, invalidInput("Attribute answers and completion groups are set from an ordinary session or API key")
		}
		if err := onboardingNotImpersonating(principal, "Attribute answers and completion groups cannot be set"); err != nil {
			return nil, err
		}
	}
	if mapsAttributes {
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:identities:update", tenantID, "let answers fill identity attributes"); err != nil {
			return nil, err
		}
	}
	if reauthorize {
		for _, groupID := range completionGroupIDs {
			if err := onboardingAuthorizeCompletionGroup(ctx, server, tx, principal, tenantID, groupID); err != nil {
				return nil, err
			}
		}
	}
	principalID := principal.Identity.Get("id")
	// The groups stand on the authority of whoever last passed that check (kept by edits that change nothing of it).
	var groupsOwnerID any
	if reauthorize {
		groupsOwnerID = principalID
	} else {
		groupsOwnerID = coalesce(prev("groupsOwnerId"), prev("authorId"))
	}
	// Naming the groups again hands them to an editor who passes the check (how an administrator takes over the groups
	// of an owner who lost the authority); an editor who does not pass it leaves the owner as it was.
	if !reauthorize && len(completionGroupIDs) > 0 && !isUndefined(input.Get("completionGroupIds")) &&
		groupsOwnerID != principalID && ActsInOwnRight(principal.Session) && !truthy(principal.Session.Get("impersonatorId")) {
		passed := true
		for _, groupID := range completionGroupIDs {
			if onboardingAuthorizeCompletionGroup(ctx, server, tx, principal, tenantID, groupID) != nil {
				passed = false
				break
			}
		}
		if passed {
			groupsOwnerID = principalID
		}
	}
	all, err := tx.Find(ctx, "onboardingFlows", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	others := []*core.Object{}
	for _, flow := range all {
		if previous == nil || flow.Get("id") != previous.Get("id") {
			others = append(others, flow)
		}
	}
	uniqueKey := "name:" + core.JSLower(name)
	if name == "" {
		return nil, invalidInput("name is required")
	}
	for _, flow := range others {
		if flow.Get("uniqueKey") == uniqueKey {
			return nil, core.NewIamError("CONFLICT", "An onboarding flow with this name exists", 409)
		}
	}
	if previous == nil && len(others) >= MaxFlowsPerTenant {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+jsString(float64(MaxFlowsPerTenant))+" onboarding flows", 409)
	}
	now := float64(server.Now())
	var id any = ID()
	if previous != nil {
		id = previous.Get("id")
	}
	record := core.NewObject("id", id, "tenantId", tenantID, "uniqueKey", uniqueKey, "name", name)
	if !isUndefined(description) {
		record.Set("description", description)
	}
	record.Set("audience", audience)
	record.Set("appliesTo", appliesTo)
	if !isUndefined(tenantTypes) {
		record.Set("tenantTypes", tenantTypes)
	}
	if !isUndefined(rule) {
		record.Set("rule", rule)
	}
	record.Set("required", required)
	record.Set("locked", locked)
	record.Set("includeExisting", includeExisting)
	record.Set("enabled", enabled)
	if effectiveFrom := prev("effectiveFrom"); !isUndefined(effectiveFrom) {
		record.Set("effectiveFrom", effectiveFrom)
	} else if enabled {
		record.Set("effectiveFrom", now)
	}
	record.Set("steps", steps)
	if len(completionGroupIDs) > 0 {
		record.Set("completionGroupIds", stringsOf(completionGroupIDs))
		if !isUndefined(groupsOwnerID) {
			record.Set("groupsOwnerId", groupsOwnerID)
		}
	}
	version := 1.0
	if previous != nil {
		version = jsNumber(previous.Get("version"))
		if !onboardingSameJSON(previous.Get("steps"), steps) {
			version++
		}
	}
	record.Set("version", version)
	record.Set("authorId", principalID)
	createdAt := any(now)
	if previous != nil {
		createdAt = coalesce(previous.Get("createdAt"), now)
	}
	record.Set("createdAt", createdAt)
	record.Set("updatedAt", now)
	if previous != nil {
		return tx.Put(ctx, "onboardingFlows", record)
	}
	return tx.Insert(ctx, "onboardingFlows", record)
}

// DeleteOnboardingFlow (api/onboarding.ts deleteOnboardingFlow): Deletes a flow with every progress record of it, in
// every tenant it reached, and removes it from tenants' disabledFlowIds. Returns how many progress records went.
func DeleteOnboardingFlow(ctx context.Context, tx core.IamStore, flow *core.Object) (int, error) {
	flowID := jsString(flow.Get("id"))
	progress, err := tx.Find(ctx, "onboardingProgress", core.NewObject("flowId", flowID), nil)
	if err != nil {
		return 0, err
	}
	for _, record := range progress {
		if err := tx.Delete(ctx, "onboardingProgress", jsString(record.Get("id"))); err != nil {
			return 0, err
		}
	}
	settings, err := tx.Find(ctx, "onboardingSettings", core.NewObject(), nil)
	if err != nil {
		return 0, err
	}
	for _, record := range settings {
		if !onboardingArrayIncludes(record.Get("disabledFlowIds"), flowID) {
			continue
		}
		kept := []any{}
		for _, item := range onboardingStrings(record.Get("disabledFlowIds")) {
			if item != flowID {
				kept = append(kept, item)
			}
		}
		if _, err := tx.Put(ctx, "onboardingSettings", record.Spread().Set("disabledFlowIds", kept)); err != nil {
			return 0, err
		}
	}
	if err := tx.Delete(ctx, "onboardingFlows", flowID); err != nil {
		return 0, err
	}
	return len(progress), nil
}

// onboardingProgressFor is progressFor: a subject's progress records by flow ID.
func onboardingProgressFor(ctx context.Context, tx core.IamStore, tenantID, subjectID any) (map[string]*core.Object, error) {
	records, err := tx.Find(ctx, "onboardingProgress", core.NewObject("tenantId", tenantID, "subjectId", subjectID), nil)
	if err != nil {
		return nil, err
	}
	progress := map[string]*core.Object{}
	for _, record := range records {
		progress[jsString(record.Get("flowId"))] = record
	}
	return progress, nil
}

func onboardingUpsertProgress(ctx context.Context, tx core.IamStore, record *core.Object, existed bool) (*core.Object, error) {
	if existed {
		return tx.Put(ctx, "onboardingProgress", record)
	}
	return tx.Insert(ctx, "onboardingProgress", record)
}

func onboardingNewProgress(flow *core.Object, subject onboardingSubject, now float64) *core.Object {
	return core.NewObject(
		"id", onboardingProgressID(jsString(flow.Get("id")), subject.ID),
		"tenantId", subject.TenantID,
		"flowId", flow.Get("id"),
		"flowTenantId", flow.Get("tenantId"),
		"subjectType", subject.Type,
		"subjectId", subject.ID,
		"steps", []any{},
		"startedAt", now,
		"updatedAt", now,
	)
}

// onboardingWithStep is withStep: the progress with the step's record replaced.
func onboardingWithStep(progress *core.Object, record *core.Object) *core.Object {
	steps := []any{}
	for _, step := range onboardingObjects(progress.Get("steps")) {
		if step.Get("stepId") != record.Get("stepId") {
			steps = append(steps, step)
		}
	}
	return progress.Spread().Set("steps", append(steps, record))
}

// onboardingRecordCompletions is recordCompletions: records flows seen complete that are not yet recorded in their
// current version (audited `onboarding:complete`), and returns the member flows whose completion groups still need
// applying.
func onboardingRecordCompletions(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, subject onboardingSubject, statuses []onboardingStatus, progress map[string]*core.Object) ([]string, error) {
	pendingGroups := []string{}
	now := float64(server.Now())
	for _, entry := range statuses {
		if entry.status.Get("complete") != true {
			continue
		}
		flow := onboardingCandidateFlow(entry.candidate)
		flowID := jsString(flow.Get("id"))
		existing := progress[flowID]
		record := existing
		if existing == nil || isUndefined(existing.Get("completedAt")) || existing.Get("completedVersion") != flow.Get("version") {
			base := existing
			if base == nil {
				base = onboardingNewProgress(flow, subject, now)
			}
			updated, err := onboardingUpsertProgress(ctx, tx, base.Spread().Set("completedAt", now).Set("completedVersion", flow.Get("version")).Set("updatedAt", now), existing != nil)
			if err != nil {
				return nil, err
			}
			record = updated
			progress[flowID] = record
			entry.status.Set("completedAt", now)
			if err := server.Events.Audit(ctx, tx, principal, "onboarding:complete", subject.TenantID, subject.ID, "allow", false,
				core.NewObject("flowId", flow.Get("id"), "flow", flow.Get("name"), "version", flow.Get("version"), "subjectType", subject.Type)); err != nil {
				return nil, err
			}
		}
		if subject.Type == "identity" && onboardingLengthTruthy(flow.Get("completionGroupIds")) && record.Get("groupsAppliedVersion") != flow.Get("version") {
			pendingGroups = append(pendingGroups, flowID)
		}
	}
	return pendingGroups, nil
}

// onboardingSlice is `text.slice(0, max)` in UTF-16 code units.
func onboardingSlice(text string, max int) string {
	units := core.ToUTF16(text)
	if len(units) <= max {
		return text
	}
	return core.FromUTF16(units[:max])
}

// onboardingApplyCompletionGroups is applyCompletionGroups: makes a person a member of the completion groups of
// flows they finished, one transaction per flow so a separation-of-duties or invariant refusal in one leaves the
// others (and the recorded completion) in place. A refusal is kept on the progress record as `completionError` and
// retried the next time the person's onboarding is read, and so is a group the flow's owner may no longer add people
// to (audited once as `onboarding:groups-skipped`).
func onboardingApplyCompletionGroups(ctx context.Context, server *ServerContext, tenantID, identityID string, flowIDs []string) error {
	changed := false
	for _, flowID := range flowIDs {
		added, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
			flow, err := tx.Get(ctx, "onboardingFlows", flowID)
			if err != nil {
				return false, err
			}
			progress, err := tx.Get(ctx, "onboardingProgress", onboardingProgressID(flowID, identityID))
			if err != nil {
				return false, err
			}
			identity, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return false, err
			}
			if flow == nil || !onboardingLengthTruthy(flow.Get("completionGroupIds")) || progress == nil ||
				progress.Get("completedVersion") != flow.Get("version") ||
				progress.Get("groupsAppliedVersion") == flow.Get("version") ||
				identity == nil || identity.Get("status") != "active" || identity.Get("tenantId") != tenantID {
				return false, nil
			}
			now := float64(server.Now())
			// The groups are applied under the authority of the flow's owner (saveFlow), checked again now: a group
			// they can no longer add people to is skipped, reported, and retried on the next read.
			ownerID := coalesce(flow.Get("groupsOwnerId"), flow.Get("authorId"))
			var owner *core.Object
			if truthy(ownerID) {
				if owner, err = tx.Get(ctx, "identities", jsString(ownerID)); err != nil {
					return false, err
				}
			}
			type plannedMember struct {
				groupID, uniqueKey string
				existing           *core.Object
			}
			planned := []plannedMember{}
			skipped := []string{}
			for _, groupID := range onboardingStrings(flow.Get("completionGroupIds")) {
				group, err := tx.Get(ctx, "groups", groupID)
				if err != nil {
					return false, err
				}
				if group == nil || group.Get("tenantId") != tenantID {
					continue
				}
				uniqueKey := groupID + ":" + identityID
				members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
				if err != nil {
					return false, err
				}
				var existing *core.Object
				if len(members) > 0 {
					existing = members[0]
				}
				if existing != nil && (isUndefined(existing.Get("expiresAt")) || jsNumber(existing.Get("expiresAt")) > now) {
					continue
				}
				if !onboardingOwnerMayGrant(ctx, server, tx, owner, tenantID, groupID) {
					skipped = append(skipped, groupID)
				} else {
					planned = append(planned, plannedMember{groupID: groupID, uniqueKey: uniqueKey, existing: existing})
				}
			}
			// Enforced invariants and separation of duties hold for completion groups as for groups.addMember.
			var guardrails *InvariantSnapshotState
			if len(planned) > 0 {
				if guardrails, err = InvariantSnapshot(ctx, server, tx, tenantID, "iam:groups:update"); err != nil {
					return false, err
				}
			}
			added := []string{}
			for _, item := range planned {
				if item.existing != nil {
					kept := item.existing.Spread()
					kept.Delete("expiresAt")
					kept.Delete("packageAssignmentId")
					if _, err := tx.Put(ctx, "groupMembers", kept); err != nil {
						return false, err
					}
				} else if _, err := tx.Insert(ctx, "groupMembers", core.NewObject(
					"id", ID(), "tenantId", tenantID, "uniqueKey", item.uniqueKey, "groupId", item.groupID, "identityId", identityID,
				)); err != nil {
					return false, err
				}
				added = append(added, item.groupID)
			}
			if len(added) > 0 {
				if err := SodAssertIdentity(ctx, server, tx, tenantID, identityID); err != nil {
					return false, err
				}
				if err := InvariantVerify(ctx, server, tx, tenantID, guardrails); err != nil {
					return false, err
				}
			}
			previousError := progress.Get("completionError")
			rest := progress.Spread()
			rest.Delete("completionError")
			refusal := ""
			if len(skipped) > 0 {
				noun := "groups"
				if len(skipped) == 1 {
					noun = "group"
				}
				refusal = "Completion groups skipped: the flow's owner can no longer add people to " + noun + " " + joinStrings(skipped, ", ") +
					"; an administrator who can should save the flow's completion groups again"
			}
			if refusal != "" {
				rest.Set("completionError", refusal)
			} else {
				rest.Set("groupsAppliedVersion", flow.Get("version"))
			}
			if _, err := tx.Put(ctx, "onboardingProgress", rest); err != nil {
				return false, err
			}
			if refusal != "" && refusal != previousError {
				metadata := core.NewObject("flowId", flowID, "flow", flow.Get("name"), "groupIds", stringsOf(skipped))
				if truthy(ownerID) {
					metadata.Set("ownerId", ownerID)
				}
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(), "tenantId", tenantID, "actorId", identityID, "action", "onboarding:groups-skipped",
					"resourceId", identityID, "timestamp", float64(server.Wall()), "outcome", "deny", "metadata", metadata,
				)); err != nil {
					return false, err
				}
			}
			if len(added) > 0 {
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(), "tenantId", tenantID, "actorId", identityID, "action", "onboarding:groups",
					"resourceId", identityID, "timestamp", float64(server.Wall()), "outcome", "allow",
					"metadata", core.NewObject("flowId", flowID, "flow", flow.Get("name"), "groupIds", stringsOf(added)),
				)); err != nil {
					return false, err
				}
			}
			return len(added) > 0, nil
		})
		if err != nil {
			message := onboardingSlice(errorMessage(err), 500)
			// Bookkeeping never masks the completion.
			_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				progress, err := tx.Get(ctx, "onboardingProgress", onboardingProgressID(flowID, identityID))
				if err != nil {
					return err
				}
				if progress != nil && progress.Get("completionError") != message {
					_, err = tx.Put(ctx, "onboardingProgress", progress.Spread().Set("completionError", message))
				}
				return err
			})
			continue
		}
		changed = added || changed
	}
	if changed {
		if _, err := AfterIdentityChange(ctx, server, tenantID, []string{identityID}, core.Undefined); err != nil {
			return err
		}
	}
	return nil
}

// joinStrings is `items.join(separator)`.
func joinStrings(items []string, separator string) string {
	out := ""
	for index, item := range items {
		if index > 0 {
			out += separator
		}
		out += item
	}
	return out
}

// onboardingMemberStatuses is memberStatuses: evaluates a person's member flows (optionally with their answers).
func onboardingMemberStatuses(ctx context.Context, server *ServerContext, tx core.IamStore, chain []*core.Object, identity *core.Object, answers bool, candidates []*core.Object) ([]onboardingStatus, map[string]*core.Object, error) {
	now := server.Now()
	flows, err := FlowsForIdentity(ctx, tx, chain, identity, now, candidates)
	if err != nil {
		return nil, nil, err
	}
	progress, err := onboardingProgressFor(ctx, tx, identity.Get("tenantId"), identity.Get("id"))
	if err != nil {
		return nil, nil, err
	}
	defined := make([]*core.Object, len(flows))
	for index, candidate := range flows {
		defined[index] = onboardingCandidateFlow(candidate)
	}
	facts, err := MemberFacts(ctx, tx, identity, defined, now)
	if err != nil {
		return nil, nil, err
	}
	statuses := make([]onboardingStatus, 0, len(flows))
	for _, candidate := range flows {
		status, err := EvaluateFlow(candidate, progress[jsString(onboardingCandidateFlow(candidate).Get("id"))],
			core.NewObject("member", core.NewObject("identity", identity, "facts", facts)), core.NewObject("answers", answers))
		if err != nil {
			return nil, nil, err
		}
		statuses = append(statuses, onboardingStatus{candidate: candidate, status: status})
	}
	return statuses, progress, nil
}

// onboardingTenantStatuses is tenantStatuses: evaluates a tenant's setup flows (always with answers: the tenant's
// administrators and the definer see them).
func onboardingTenantStatuses(ctx context.Context, tx core.IamStore, chain []*core.Object, candidates []*core.Object) ([]onboardingStatus, map[string]*core.Object, error) {
	tenant := chain[0]
	if candidates == nil {
		var err error
		if candidates, err = CandidateFlows(ctx, tx, chain, "tenant", nil); err != nil {
			return nil, nil, err
		}
	}
	flows := []*core.Object{}
	for _, candidate := range candidates {
		if onboardingTenantFlowApplies(onboardingCandidateFlow(candidate), tenant) {
			flows = append(flows, candidate)
		}
	}
	progress, err := onboardingProgressFor(ctx, tx, tenant.Get("id"), tenant.Get("id"))
	if err != nil {
		return nil, nil, err
	}
	defined := make([]*core.Object, len(flows))
	for index, candidate := range flows {
		defined[index] = onboardingCandidateFlow(candidate)
	}
	facts, err := TenantFacts(ctx, tx, tenant, defined)
	if err != nil {
		return nil, nil, err
	}
	statuses := make([]onboardingStatus, 0, len(flows))
	for _, candidate := range flows {
		status, err := EvaluateFlow(candidate, progress[jsString(onboardingCandidateFlow(candidate).Get("id"))],
			core.NewObject("tenant", facts), core.NewObject("answers", true))
		if err != nil {
			return nil, nil, err
		}
		statuses = append(statuses, onboardingStatus{candidate: candidate, status: status})
	}
	return statuses, progress, nil
}

// onboardingSummarize is summarize: what a person (or a tenant being set up) sees.
func onboardingSummarize(tenant, welcome *core.Object, statuses []onboardingStatus) *core.Object {
	flows := make([]any, len(statuses))
	pending := 0
	for index, entry := range statuses {
		flows[index] = entry.status
		if truthy(entry.status.Get("required")) && entry.status.Get("complete") != true {
			pending++
		}
	}
	return core.NewObject("tenant", onboardingSource(tenant), "welcome", welcome, "flows", flows, "pending", float64(pending), "complete", pending == 0)
}

// onboardingSubjectProgress is subjectProgress.
func onboardingSubjectProgress(status, record *core.Object, answers bool) *core.Object {
	awaiting := []any{}
	for _, step := range onboardingObjects(status.Get("steps")) {
		if step.Get("state") == "submitted" {
			awaiting = append(awaiting, step.Get("id"))
		}
	}
	result := core.NewObject("complete", status.Get("complete"), "done", status.Get("done"), "total", status.Get("total"), "awaiting", awaiting)
	if completedAt := status.Get("completedAt"); !isUndefined(completedAt) {
		result.Set("completedAt", completedAt)
	}
	if record != nil {
		result.Set("startedAt", record.Get("startedAt"))
		if completionError := record.Get("completionError"); truthy(completionError) {
			result.Set("completionError", completionError)
		}
	}
	if answers {
		collected := core.NewObject()
		if record != nil {
			for _, step := range onboardingObjects(record.Get("steps")) {
				if stepAnswers, ok := step.Get("answers").(*core.Object); ok && stepAnswers != nil && stepAnswers.Len() > 0 {
					collected.Set(jsString(step.Get("stepId")), stepAnswers)
				}
			}
		}
		if collected.Len() > 0 {
			result.Set("answers", collected)
		}
	}
	return result
}

// onboardingCompleteStep is completeStep: records one step the subject completed by hand: form answers, an
// acknowledgement, or a task (done, or submitted for verification). Steps that complete on their own are refused.
func onboardingCompleteStep(step *core.Object, answers, acknowledged any, actorID any, now float64) (*core.Object, error) {
	kind := jsString(step.Get("kind"))
	if AutomaticSteps.Has(kind) {
		if kind == "check" {
			return nil, invalidInput("This step completes when the organization’s setup meets it")
		}
		return nil, invalidInput("This step completes on its own once you have done it")
	}
	if kind == "form" {
		parsed, err := ParseAnswers(step, answers)
		if err != nil {
			return nil, err
		}
		return core.NewObject("stepId", step.Get("id"), "completedAt", now, "completedBy", actorID, "answers", parsed), nil
	}
	if !isUndefined(answers) {
		return nil, invalidInput("answers apply to form steps only")
	}
	if kind == "acknowledge" && acknowledged != true {
		return nil, invalidInput("Confirm that you have read this (acknowledged: true)")
	}
	if kind == "task" && step.Get("verification") == "admin" {
		return core.NewObject("stepId", step.Get("id"), "submittedAt", now, "completedBy", actorID), nil
	}
	return core.NewObject("stepId", step.Get("id"), "completedAt", now, "completedBy", actorID), nil
}

// onboardingFindStep is `flow.steps.find((item) => item.id === stepId)`.
func onboardingFindStep(flow *core.Object, stepID any) *core.Object {
	for _, step := range onboardingObjects(flow.Get("steps")) {
		if step.Get("id") == stepID {
			return step
		}
	}
	return nil
}

// onboardingFindCandidate is `candidates.find((item) => item.flow.id === flowId && keep(item))`.
func onboardingFindCandidate(candidates []*core.Object, flowID any, keep func(candidate *core.Object) bool) *core.Object {
	for _, candidate := range candidates {
		if onboardingCandidateFlow(candidate).Get("id") == flowID && (keep == nil || keep(candidate)) {
			return candidate
		}
	}
	return nil
}

// onboardingIdentityRef is `{ id, name, email? }` of an identity.
func onboardingIdentityRef(identity *core.Object) *core.Object {
	ref := core.NewObject("id", identity.Get("id"), "name", identity.Get("name"))
	if email := identity.Get("email"); truthy(email) {
		ref.Set("email", email)
	}
	return ref
}

// scopedFlow is a flow this tenant defines.
func (api *OnboardingAPI) scopedFlow(ctx context.Context, tx core.IamStore, flowID any, tenantID any) (*core.Object, error) {
	flow, err := onboardingFlowRecord(ctx, tx, flowID)
	if err != nil {
		return nil, err
	}
	if flow.Get("tenantId") != tenantID {
		return nil, onboardingFlowNotFound()
	}
	return flow, nil
}

// CreateFlow is POST {basePath}/onboarding/createFlow. Creates a flow at this tenant's level (member onboarding for
// its people or those below; setup for tenants below).
func (api *OnboardingAPI) CreateFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingCreateFlowInput]) (Out[apitypes.OnboardingCreateFlowOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:onboarding:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return onboardingSaveFlow(ctx, api.server, call.Tx, call.Principal, call.Tenant, input.Body, nil)
	}, false)
	return Out[apitypes.OnboardingCreateFlowOutput]{Value: result}, err
}

// DeleteFlow is POST {basePath}/onboarding/deleteFlow. Deletes a flow and everyone's progress through it.
func (api *OnboardingAPI) DeleteFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingDeleteFlowInput]) (Out[apitypes.OnboardingDeleteFlowOutput], error) {
	resourceID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingDeleteFlowOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:onboarding:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		flow, err := api.scopedFlow(ctx, call.Tx, input.Get("flowId"), call.Tenant.Get("id"))
		if err != nil {
			return nil, err
		}
		removed, err := DeleteOnboardingFlow(ctx, call.Tx, flow)
		if err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true, "progressRemoved", float64(removed)), nil
	}, false)
	return Out[apitypes.OnboardingDeleteFlowOutput]{Value: result}, err
}

// Effective is POST {basePath}/onboarding/effective. Everything onboarding looks like from this tenant: the member
// flows that reach its people (own and inherited, with where each comes from and whether it is switched off), the
// setup flows its administrators complete, the flows it defines for tenants below, and its welcome settings with the
// level each value comes from.
func (api *OnboardingAPI) Effective(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingEffectiveInput]) (Out[apitypes.OnboardingEffectiveOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:onboarding:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		settings := newSettingsReader(tx)
		describe := func(candidate *core.Object) *core.Object {
			flow := onboardingCandidateFlow(candidate)
			inherited := candidate.Get("inherited") == true
			shown := flow
			if inherited {
				shown = onboardingPublicFlow(flow)
			}
			disabledBy := onboardingCandidateDisabledBy(candidate)
			entry := core.NewObject("flow", shown, "source", onboardingSource(onboardingCandidateSource(candidate)), "inherited", inherited)
			if disabledBy != nil {
				entry.Set("disabledBy", onboardingSource(disabledBy))
			}
			entry.Set("canDisable", inherited && flow.Get("audience") == "member" && !truthy(flow.Get("locked")) &&
				(disabledBy == nil || disabledBy.Get("id") == tenant.Get("id")))
			return entry
		}
		levels := make([]any, len(chain))
		for index := range chain {
			levels[index] = onboardingSource(chain[len(chain)-1-index])
		}
		memberCandidates, err := CandidateFlows(ctx, tx, chain, "member", settings)
		if err != nil {
			return nil, err
		}
		memberFlows := make([]any, len(memberCandidates))
		for index, candidate := range memberCandidates {
			memberFlows[index] = describe(candidate)
		}
		setupCandidates, err := CandidateFlows(ctx, tx, chain, "tenant", settings)
		if err != nil {
			return nil, err
		}
		setupFlows := []any{}
		for _, candidate := range setupCandidates {
			if onboardingTenantFlowApplies(onboardingCandidateFlow(candidate), tenant) {
				setupFlows = append(setupFlows, describe(candidate))
			}
		}
		own, err := tx.Find(ctx, "onboardingFlows", core.NewObject("tenantId", tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		onboardingSortFlows(own)
		types := onboardingDescendantTypes(server, jsString(tenant.Get("type"))).Values()
		sortStrings(types)
		attributes := core.NewObject()
		if server.Catalog.IdentityAttributes != nil {
			attributes = server.Catalog.IdentityAttributes.Spread()
		}
		ownSettings, err := settings.Get(ctx, jsString(tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		settingsEntry := core.NewObject()
		if ownSettings != nil {
			settingsEntry.Set("own", ownSettings)
		}
		resolved, err := ResolveSettings(ctx, chain, settings)
		if err != nil {
			return nil, err
		}
		settingsEntry.Set("resolved", resolved)
		return core.NewObject(
			"tenant", onboardingSource(tenant),
			"levels", levels,
			"memberFlows", memberFlows,
			"setupFlows", setupFlows,
			"ownFlows", onboardingList(own),
			"descendantTypes", stringsOf(types),
			"identityAttributes", attributes,
			"settings", settingsEntry,
		), nil
	}, false)
	return Out[apitypes.OnboardingEffectiveOutput]{Value: result}, err
}

// GetFlow is POST {basePath}/onboarding/getFlow. Returns one flow this tenant defines.
func (api *OnboardingAPI) GetFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingGetFlowInput]) (Out[apitypes.OnboardingGetFlowOutput], error) {
	resourceID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingGetFlowOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:onboarding:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return api.scopedFlow(ctx, call.Tx, input.Get("flowId"), call.Tenant.Get("id"))
	}, false)
	return Out[apitypes.OnboardingGetFlowOutput]{Value: result}, err
}

// ListFlows is POST {basePath}/onboarding/listFlows. Lists the flows this tenant defines, oldest first, optionally
// for one audience.
func (api *OnboardingAPI) ListFlows(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingListFlowsInput]) (Out[apitypes.OnboardingListFlowsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:onboarding:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		flows, err := call.Tx.Find(ctx, "onboardingFlows", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		audience := input.Get("audience")
		kept := []*core.Object{}
		for _, flow := range flows {
			if isUndefined(audience) || flow.Get("audience") == audience {
				kept = append(kept, flow)
			}
		}
		onboardingSortFlows(kept)
		return onboardingList(kept), nil
	}, false)
	return Out[apitypes.OnboardingListFlowsOutput]{Value: result}, err
}

// MemberProgress is POST {basePath}/onboarding/memberProgress. One person's onboarding in this tenant, with their
// answers (for member pages).
func (api *OnboardingAPI) MemberProgress(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingMemberProgressInput]) (Out[apitypes.OnboardingMemberProgressOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.OnboardingMemberProgressOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:onboarding:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), jsString(tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		statuses, _, err := onboardingMemberStatuses(ctx, server, tx, chain, identity, true, nil)
		if err != nil {
			return nil, err
		}
		flows := make([]any, len(statuses))
		pending := 0
		for index, entry := range statuses {
			flows[index] = entry.status
			if truthy(entry.status.Get("required")) && entry.status.Get("complete") != true {
				pending++
			}
		}
		return core.NewObject("identity", onboardingIdentityRef(identity), "flows", flows, "pending", float64(pending)), nil
	}, false)
	return Out[apitypes.OnboardingMemberProgressOutput]{Value: result}, err
}

// Mine is POST {basePath}/onboarding/mine. The caller's own onboarding: welcome copy and their member flows; needs
// only an ordinary session of the tenant.
func (api *OnboardingAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingMineInput]) (Out[apitypes.OnboardingMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.OnboardingMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.OnboardingMineOutput]{}, err
	}
	var pendingGroups []string
	var identityID string
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := onboardingSelfSession(principal, tenantID); err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		statuses, progress, err := onboardingMemberStatuses(ctx, server, tx, chain, principal.Identity, true, nil)
		if err != nil {
			return nil, err
		}
		identityID = jsString(principal.Identity.Get("id"))
		// Completions are recorded for the person themselves, never while an administrator views as them.
		pendingGroups = nil
		if !truthy(principal.Session.Get("impersonatorId")) {
			if pendingGroups, err = onboardingRecordCompletions(ctx, server, tx, principal,
				onboardingSubject{Type: "identity", ID: identityID, TenantID: tenantID}, statuses, progress); err != nil {
				return nil, err
			}
		}
		welcome, err := ResolveSettings(ctx, chain, newSettingsReader(tx))
		if err != nil {
			return nil, err
		}
		return onboardingSummarize(tenant, welcome, statuses), nil
	})
	if err != nil {
		return Out[apitypes.OnboardingMineOutput]{}, err
	}
	if len(pendingGroups) > 0 {
		if err := onboardingApplyCompletionGroups(ctx, server, tenantID, identityID, pendingGroups); err != nil {
			return Out[apitypes.OnboardingMineOutput]{}, err
		}
	}
	return Out[apitypes.OnboardingMineOutput]{Value: result}, nil
}

// Progress is POST {basePath}/onboarding/progress. Progress through one flow as seen from this tenant. Member flows
// (own or inherited) list this tenant's people the flow applies to, with their answers; a flow defined here that
// reaches descendant tenants adds per-tenant counts (never names). Tenant setup flows defined here list every
// descendant tenant they apply to, with its answers.
func (api *OnboardingAPI) Progress(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingProgressInput]) (Out[apitypes.OnboardingProgressOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingProgressOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:onboarding:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		flow, err := onboardingFlowRecord(ctx, tx, input.Get("flowId"))
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		settings := newSettingsReader(tx)
		now := server.Now()
		var candidate *core.Object
		if flow.Get("tenantId") == tenant.Get("id") {
			candidate = onboardingCandidate(flow, tenant, false, 0)
		} else {
			candidates, err := CandidateFlows(ctx, tx, chain, jsString(flow.Get("audience")), settings)
			if err != nil {
				return nil, err
			}
			candidate = onboardingFindCandidate(candidates, flow.Get("id"), nil)
		}
		if candidate == nil || (flow.Get("audience") == "tenant" && flow.Get("tenantId") != tenant.Get("id")) {
			return nil, onboardingFlowNotFound()
		}
		summary := core.NewObject("flow", core.NewObject(
			"id", flow.Get("id"),
			"name", flow.Get("name"),
			"audience", flow.Get("audience"),
			"version", flow.Get("version"),
			"required", flow.Get("required"),
			"source", onboardingSource(onboardingCandidateSource(candidate)),
			"inherited", candidate.Get("inherited"),
		))
		disabledBy := onboardingCandidateDisabledBy(candidate)
		if disabledBy != nil {
			summary.Get("flow").(*core.Object).Set("disabledBy", onboardingSource(disabledBy))
		}
		report := summary
		report.Set("summary", core.NewObject("subjects", 0.0, "complete", 0.0))
		countComplete := func(rows []any) float64 {
			complete := 0
			for _, row := range rows {
				if member(row, "complete") == true {
					complete++
				}
			}
			return float64(complete)
		}
		if flow.Get("audience") == "tenant" {
			tenants, truncated, err := onboardingDescendantsOf(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			rows := []any{}
			report.Set("tenants", rows)
			for _, target := range tenants {
				if target.Get("status") == "deleted" {
					continue
				}
				targetChain, err := server.Ancestry(ctx, tx, target)
				if err != nil {
					return nil, err
				}
				candidates, err := CandidateFlows(ctx, tx, targetChain, "tenant", settings)
				if err != nil {
					return nil, err
				}
				found := onboardingFindCandidate(candidates, flow.Get("id"), func(item *core.Object) bool {
					return onboardingTenantFlowApplies(onboardingCandidateFlow(item), target)
				})
				if found == nil {
					continue
				}
				statuses, progress, err := onboardingTenantStatuses(ctx, tx, targetChain, []*core.Object{found})
				if err != nil {
					return nil, err
				}
				status := statuses[0].status
				ref := onboardingSource(target).Set("status", target.Get("status"))
				rows = append(rows, core.NewObject("tenant", ref).Assign(onboardingSubjectProgress(status, progress[jsString(flow.Get("id"))], true)))
			}
			report.Set("tenants", rows)
			report.Set("summary", core.NewObject("subjects", float64(len(rows)), "complete", countComplete(rows)))
			if truncated {
				report.Set("truncated", true)
			}
			return report, nil
		}
		members := []any{}
		report.Set("members", members)
		reachesHere := false
		if candidate.Get("inherited") == true || flow.Get("appliesTo") != "descendants" {
			reachesHere = disabledBy == nil
		}
		if reachesHere {
			identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			people := []*core.Object{}
			for _, identity := range identities {
				if identity.Get("kind") == "user" && identity.Get("status") == "active" {
					people = append(people, identity)
				}
			}
			label := func(identity *core.Object) string {
				return jsString(coalesce(identity.Get("email"), identity.Get("name")))
			}
			sort.SliceStable(people, func(i, j int) bool { return localeCompare(label(people[i]), label(people[j])) < 0 })
			for _, identity := range people {
				var groupIDs []string
				if truthy(flow.Get("rule")) {
					if groupIDs, err = LiveGroupIDs(ctx, tx, identity, now); err != nil {
						return nil, err
					}
				}
				applies, err := FlowAppliesTo(flow, identity, groupIDs)
				if err != nil {
					return nil, err
				}
				if !applies {
					continue
				}
				statuses, progress, err := onboardingMemberStatuses(ctx, server, tx, chain, identity, true, []*core.Object{candidate})
				if err != nil {
					return nil, err
				}
				if len(statuses) == 0 {
					continue
				}
				members = append(members, core.NewObject("identity", onboardingIdentityRef(identity)).
					Assign(onboardingSubjectProgress(statuses[0].status, progress[jsString(flow.Get("id"))], true)))
			}
		}
		report.Set("members", members)
		report.Set("summary", core.NewObject("subjects", float64(len(members)), "complete", countComplete(members)))
		if flow.Get("tenantId") == tenant.Get("id") && flow.Get("appliesTo") != "tenant" {
			tenants, truncated, err := onboardingDescendantsOf(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			descendants := []any{}
			for _, target := range tenants {
				if target.Get("status") != "active" {
					continue
				}
				targetChain, err := server.Ancestry(ctx, tx, target)
				if err != nil {
					return nil, err
				}
				candidates, err := CandidateFlows(ctx, tx, targetChain, "member", settings)
				if err != nil {
					return nil, err
				}
				found := onboardingFindCandidate(candidates, flow.Get("id"), func(item *core.Object) bool {
					return onboardingCandidateDisabledBy(item) == nil
				})
				if found == nil {
					continue
				}
				people, complete := 0, 0
				identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", target.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				for _, identity := range identities {
					if identity.Get("kind") != "user" || identity.Get("status") != "active" {
						continue
					}
					statuses, _, err := onboardingMemberStatuses(ctx, server, tx, targetChain, identity, false, []*core.Object{found})
					if err != nil {
						return nil, err
					}
					if len(statuses) == 0 {
						continue
					}
					people++
					if statuses[0].status.Get("complete") == true {
						complete++
					}
				}
				descendants = append(descendants, core.NewObject("tenant", onboardingSource(target), "people", float64(people), "complete", float64(complete)))
			}
			report.Set("descendants", descendants)
			if truncated {
				report.Set("truncated", true)
			}
		}
		return report, nil
	}, false)
	return Out[apitypes.OnboardingProgressOutput]{Value: result}, err
}

// ResetProgress is POST {basePath}/onboarding/resetProgress. Clears progress so people (or tenants) go through a
// flow, or one step of it, again. The tenant that defines the flow may reset anyone it reaches (everyone when
// `subjectId` is omitted); a tenant the flow reaches may reset its own people. Resetting one's own progress through a
// flow with completion groups needs the right to add oneself to those groups. Audited as `onboarding:reset`.
func (api *OnboardingAPI) ResetProgress(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingResetProgressInput]) (Out[apitypes.OnboardingResetProgressOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingResetProgressOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:onboarding:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		flow, err := onboardingFlowRecord(ctx, tx, input.Get("flowId"))
		if err != nil {
			return nil, err
		}
		var stepID any = core.Undefined
		if raw := input.Get("stepId"); !isUndefined(raw) {
			text, err := Text(raw, "stepId", 64)
			if err != nil {
				return nil, err
			}
			stepID = text
		}
		if !isUndefined(stepID) && onboardingFindStep(flow, stepID) == nil {
			return nil, onboardingStepNotFound()
		}
		definer := flow.Get("tenantId") == tenant.Get("id")
		if !definer {
			if flow.Get("audience") != "member" {
				return nil, onboardingFlowNotFound()
			}
			chain, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			candidates, err := CandidateFlows(ctx, tx, chain, "member", nil)
			if err != nil {
				return nil, err
			}
			if onboardingFindCandidate(candidates, flow.Get("id"), nil) == nil {
				return nil, onboardingFlowNotFound()
			}
		}
		var subjectID any = core.Undefined
		if raw := input.Get("subjectId"); !isUndefined(raw) {
			text, err := Text(raw, "subjectId", 128)
			if err != nil {
				return nil, err
			}
			subjectID = text
		}
		filter := core.NewObject("flowId", flow.Get("id"))
		if !isUndefined(subjectID) {
			filter.Set("subjectId", subjectID)
		}
		found, err := tx.Find(ctx, "onboardingProgress", filter, nil)
		if err != nil {
			return nil, err
		}
		records := []*core.Object{}
		for _, record := range found {
			if definer || record.Get("tenantId") == tenant.Get("id") {
				records = append(records, record)
			}
		}
		// Finishing the flow again would put the caller back into its completion groups (after an administrator took
		// them out, say), so resetting one's own progress needs the right to add oneself to them.
		if onboardingLengthTruthy(flow.Get("completionGroupIds")) {
			own := false
			for _, record := range records {
				if record.Get("subjectId") == principal.Identity.Get("id") && record.Get("tenantId") == flow.Get("tenantId") {
					own = true
				}
			}
			if own {
				for _, groupID := range onboardingStrings(flow.Get("completionGroupIds")) {
					if onboardingAuthorizeCompletionGroup(ctx, server, tx, principal, jsString(flow.Get("tenantId")), groupID) != nil {
						return nil, core.NewIamError("ACCESS_DENIED", "Resetting your own progress through a flow with completion groups needs the right to add yourself to them", 403)
					}
				}
			}
		}
		for _, record := range records {
			if isUndefined(stepID) {
				if err := tx.Delete(ctx, "onboardingProgress", jsString(record.Get("id"))); err != nil {
					return nil, err
				}
				continue
			}
			rest := record.Spread()
			rest.Delete("completedAt")
			rest.Delete("completedVersion")
			steps := []any{}
			for _, step := range onboardingObjects(record.Get("steps")) {
				if step.Get("stepId") != stepID {
					steps = append(steps, step)
				}
			}
			rest.Set("steps", steps)
			rest.Set("updatedAt", float64(server.Now()))
			if _, err := tx.Put(ctx, "onboardingProgress", rest); err != nil {
				return nil, err
			}
		}
		metadata := core.NewObject("flowId", flow.Get("id"), "flow", flow.Get("name"), "reset", float64(len(records)))
		if !isUndefined(subjectID) {
			metadata.Set("subjectId", subjectID)
		}
		if !isUndefined(stepID) {
			metadata.Set("stepId", stepID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "onboarding:reset", jsString(tenant.Get("id")), jsString(flow.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject("reset", float64(len(records))), nil
	}, false)
	return Out[apitypes.OnboardingResetProgressOutput]{Value: result}, err
}

// SetSettings is POST {basePath}/onboarding/setSettings. Replaces this tenant's onboarding settings: welcome title
// and message, support contacts, and the inherited (unlocked) member flows switched off for this tenant and every
// tenant below it. `null` values clear a field.
func (api *OnboardingAPI) SetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSetSettingsInput]) (Out[apitypes.OnboardingSetSettingsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:onboarding:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		values, err := ParseSettings(input.Body)
		if err != nil {
			return nil, err
		}
		id := onboardingSettingsID(jsString(tenant.Get("id")))
		previous, err := tx.Get(ctx, "onboardingSettings", id)
		if err != nil {
			return nil, err
		}
		disabled := onboardingStrings(values.Get("disabledFlowIds"))
		if len(disabled) > 0 {
			chain, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			candidates, err := CandidateFlows(ctx, tx, chain, "member", newSettingsReader(tx))
			if err != nil {
				return nil, err
			}
			switchable := map[string]*core.Object{}
			for _, candidate := range candidates {
				if candidate.Get("inherited") == true {
					flow := onboardingCandidateFlow(candidate)
					switchable[jsString(flow.Get("id"))] = flow
				}
			}
			// A switch kept from before whose flow no longer reaches here (deleted, retargeted, or now locked) is
			// dropped quietly, so re-saving the settings never fails on someone else's change.
			kept := []string{}
			for _, flowID := range disabled {
				flow := switchable[flowID]
				if (flow != nil && !truthy(flow.Get("locked"))) || previous == nil || !onboardingArrayIncludes(previous.Get("disabledFlowIds"), flowID) {
					kept = append(kept, flowID)
				}
			}
			disabled = kept
			values.Set("disabledFlowIds", stringsOf(disabled))
			for _, flowID := range disabled {
				flow := switchable[flowID]
				if flow == nil {
					return nil, invalidInput("disabledFlowIds: " + flowID + " is not an inherited member flow of this tenant")
				}
				if truthy(flow.Get("locked")) {
					return nil, invalidInput("disabledFlowIds: " + jsString(flow.Get("name")) + " is locked by the tenant that defines it")
				}
			}
		}
		record := core.NewObject("id", id, "tenantId", tenant.Get("id")).Assign(values)
		record.Set("updatedAt", float64(server.Now()))
		if previous != nil {
			return tx.Put(ctx, "onboardingSettings", record)
		}
		return tx.Insert(ctx, "onboardingSettings", record)
	}, false)
	return Out[apitypes.OnboardingSetSettingsOutput]{Value: result}, err
}

// Setup is POST {basePath}/onboarding/setup. This tenant's own setup checklists (defined by the tenants above it),
// with the state of every step.
func (api *OnboardingAPI) Setup(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSetupInput]) (Out[apitypes.OnboardingSetupOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:onboarding:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		statuses, progress, err := onboardingTenantStatuses(ctx, tx, chain, nil)
		if err != nil {
			return nil, err
		}
		if !truthy(principal.Session.Get("impersonatorId")) {
			id := jsString(tenant.Get("id"))
			if _, err := onboardingRecordCompletions(ctx, server, tx, principal, onboardingSubject{Type: "tenant", ID: id, TenantID: id}, statuses, progress); err != nil {
				return nil, err
			}
		}
		welcome, err := ResolveSettings(ctx, chain, newSettingsReader(tx))
		if err != nil {
			return nil, err
		}
		return onboardingSummarize(tenant, welcome, statuses), nil
	}, false)
	return Out[apitypes.OnboardingSetupOutput]{Value: result}, err
}

// SubmitSetupStep is POST {basePath}/onboarding/submitSetupStep. Completes a form, acknowledgement or task step of
// this tenant's setup; check steps follow the tenant's state.
func (api *OnboardingAPI) SubmitSetupStep(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSubmitSetupStepInput]) (Out[apitypes.OnboardingSubmitSetupStepOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingSubmitSetupStepOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:onboarding:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		if err := onboardingNotImpersonating(principal, "Setup steps cannot be completed"); err != nil {
			return nil, err
		}
		stepID, err := Text(input.Get("stepId"), "stepId", 64)
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		candidates, err := CandidateFlows(ctx, tx, chain, "tenant", nil)
		if err != nil {
			return nil, err
		}
		candidate := onboardingFindCandidate(candidates, input.Get("flowId"), func(item *core.Object) bool {
			return onboardingTenantFlowApplies(onboardingCandidateFlow(item), tenant)
		})
		if candidate == nil {
			return nil, onboardingFlowNotFound()
		}
		flow := onboardingCandidateFlow(candidate)
		step := onboardingFindStep(flow, stepID)
		if step == nil {
			return nil, onboardingStepNotFound()
		}
		now := float64(server.Now())
		record, err := onboardingCompleteStep(step, input.Get("answers"), input.Get("acknowledged"), principal.Identity.Get("id"), now)
		if err != nil {
			return nil, err
		}
		id := jsString(tenant.Get("id"))
		subject := onboardingSubject{Type: "tenant", ID: id, TenantID: id}
		progress, err := onboardingProgressFor(ctx, tx, id, id)
		if err != nil {
			return nil, err
		}
		flowID := jsString(flow.Get("id"))
		existing := progress[flowID]
		base := existing
		if base == nil {
			base = onboardingNewProgress(flow, subject, now)
		}
		saved, err := onboardingUpsertProgress(ctx, tx, onboardingWithStep(base, record).Set("updatedAt", now), existing != nil)
		if err != nil {
			return nil, err
		}
		progress[flowID] = saved
		metadata := core.NewObject("flowId", flow.Get("id"), "flow", flow.Get("name"), "stepId", stepID, "kind", step.Get("kind"))
		if !isUndefined(record.Get("submittedAt")) {
			metadata.Set("awaitingVerification", true)
		}
		if err := server.Events.Audit(ctx, tx, principal, "onboarding:step", id, id, "allow", false, metadata); err != nil {
			return nil, err
		}
		facts, err := TenantFacts(ctx, tx, tenant, []*core.Object{flow})
		if err != nil {
			return nil, err
		}
		status, err := EvaluateFlow(candidate, progress[flowID], core.NewObject("tenant", facts), core.NewObject("answers", true))
		if err != nil {
			return nil, err
		}
		if _, err := onboardingRecordCompletions(ctx, server, tx, principal, subject, []onboardingStatus{{candidate: candidate, status: status}}, progress); err != nil {
			return nil, err
		}
		return core.NewObject("flow", status), nil
	}, false)
	return Out[apitypes.OnboardingSubmitSetupStepOutput]{Value: result}, err
}

// SubmitStep is POST {basePath}/onboarding/submitStep. Completes one step of the caller's own flow: `answers` for a
// form, `acknowledged: true` for an acknowledgement, nothing for a task (an admin-verified task waits for an
// administrator). Answers mapped to identity attributes fill only empty attributes. Impersonating administrators
// cannot complete steps on someone's behalf. Audited as `onboarding:step`, and `onboarding:complete` when the flow is
// done.
func (api *OnboardingAPI) SubmitStep(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSubmitStepInput]) (Out[apitypes.OnboardingSubmitStepOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.OnboardingSubmitStepOutput]{}, err
	}
	flowID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingSubmitStepOutput]{}, err
	}
	stepID, err := Text(input.Get("stepId"), "stepId", 64)
	if err != nil {
		return Out[apitypes.OnboardingSubmitStepOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.OnboardingSubmitStepOutput]{}, err
	}
	var status *core.Object
	var filled, pendingGroups []string
	var identityID string
	err = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return err
		}
		if err := onboardingSelfSession(principal, tenantID); err != nil {
			return err
		}
		if err := onboardingNotImpersonating(principal, "Onboarding steps cannot be completed"); err != nil {
			return err
		}
		if principal.Identity.Get("kind") != "user" {
			return invalidInput("Only people complete onboarding")
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return err
		}
		now := server.Now()
		flows, err := FlowsForIdentity(ctx, tx, chain, principal.Identity, now, nil)
		if err != nil {
			return err
		}
		candidate := onboardingFindCandidate(flows, flowID, nil)
		if candidate == nil {
			return onboardingFlowNotFound()
		}
		flow := onboardingCandidateFlow(candidate)
		step := onboardingFindStep(flow, stepID)
		if step == nil {
			return onboardingStepNotFound()
		}
		record, err := onboardingCompleteStep(step, input.Get("answers"), input.Get("acknowledged"), principal.Identity.Get("id"), float64(now))
		if err != nil {
			return err
		}
		// Answers fill the person's empty declared attributes, and only in the tenant that defines the flow (a flow
		// inherited from above records answers but never writes this tenant's identities); values someone else set are
		// kept, and every value passes the same validation as identities.update.
		filled = []string{}
		identity := principal.Identity
		if step.Get("kind") == "form" && flow.Get("tenantId") == tenantID {
			attributes := core.NewObject()
			if existing, ok := identity.Get("attributes").(*core.Object); ok && existing != nil {
				attributes = existing.Spread()
			}
			answers, _ := record.Get("answers").(*core.Object)
			for _, field := range onboardingObjects(step.Get("fields")) {
				var value any = core.Undefined
				if answers != nil {
					if found, ok := answers.Lookup(jsString(field.Get("name"))); ok {
						value = found
					}
				}
				attribute := field.Get("attribute")
				if !truthy(attribute) || isUndefined(value) || attributes.Has(jsString(attribute)) {
					continue
				}
				if field.Get("type") == "boolean" && value == false && !truthy(field.Get("required")) {
					continue
				}
				parsed, err := AttributeValues(server.Catalog.IdentityAttributes, core.NewObject(jsString(attribute), value))
				if err != nil {
					return err
				}
				attributes.Assign(parsed)
				filled = append(filled, jsString(attribute))
			}
			if len(filled) > 0 {
				if identity, err = tx.Put(ctx, "identities", identity.Spread().Set("attributes", attributes)); err != nil {
					return err
				}
			}
		}
		identityID = jsString(identity.Get("id"))
		progress, err := onboardingProgressFor(ctx, tx, tenantID, identityID)
		if err != nil {
			return err
		}
		existing := progress[flowID]
		base := existing
		if base == nil {
			base = onboardingNewProgress(flow, onboardingSubject{Type: "identity", ID: identityID, TenantID: tenantID}, float64(now))
		}
		saved, err := onboardingUpsertProgress(ctx, tx, onboardingWithStep(base, record).Set("updatedAt", float64(now)), existing != nil)
		if err != nil {
			return err
		}
		progress[flowID] = saved
		metadata := core.NewObject("flowId", flowID, "flow", flow.Get("name"), "stepId", stepID, "kind", step.Get("kind"))
		if !isUndefined(record.Get("submittedAt")) {
			metadata.Set("awaitingVerification", true)
		}
		if len(filled) > 0 {
			metadata.Set("attributes", stringsOf(filled))
		}
		if err := server.Events.Audit(ctx, tx, principal, "onboarding:step", tenantID, identityID, "allow", false, metadata); err != nil {
			return err
		}
		facts, err := MemberFacts(ctx, tx, identity, []*core.Object{flow}, now)
		if err != nil {
			return err
		}
		if status, err = EvaluateFlow(candidate, progress[flowID], core.NewObject("member", core.NewObject("identity", identity, "facts", facts)), core.NewObject("answers", true)); err != nil {
			return err
		}
		acting := *principal
		acting.Identity = identity
		pendingGroups, err = onboardingRecordCompletions(ctx, server, tx, &acting, onboardingSubject{Type: "identity", ID: identityID, TenantID: tenantID},
			[]onboardingStatus{{candidate: candidate, status: status}}, progress)
		return err
	})
	if err != nil {
		return Out[apitypes.OnboardingSubmitStepOutput]{}, err
	}
	if len(pendingGroups) > 0 {
		if err := onboardingApplyCompletionGroups(ctx, server, tenantID, identityID, pendingGroups); err != nil {
			return Out[apitypes.OnboardingSubmitStepOutput]{}, err
		}
	} else if len(filled) > 0 {
		if _, err := AfterIdentityChange(ctx, server, tenantID, []string{identityID}, core.Undefined); err != nil {
			return Out[apitypes.OnboardingSubmitStepOutput]{}, err
		}
	}
	return Out[apitypes.OnboardingSubmitStepOutput]{Value: core.NewObject("flow", status, "attributesFilled", stringsOf(filled))}, nil
}

// UpdateFlow is POST {basePath}/onboarding/updateFlow. Edits a flow. Changing the steps bumps the version: finished
// steps stay finished (progress is kept per step ID), and a new required step reopens the flow for everyone it
// applies to.
func (api *OnboardingAPI) UpdateFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingUpdateFlowInput]) (Out[apitypes.OnboardingUpdateFlowOutput], error) {
	resourceID, err := Text(input.Get("flowId"), "flowId", 128)
	if err != nil {
		return Out[apitypes.OnboardingUpdateFlowOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:onboarding:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		previous, err := api.scopedFlow(ctx, call.Tx, input.Get("flowId"), call.Tenant.Get("id"))
		if err != nil {
			return nil, err
		}
		changes := input.Body.Spread()
		changes.Delete("tenantId")
		changes.Delete("flowId")
		return onboardingSaveFlow(ctx, api.server, call.Tx, call.Principal, call.Tenant, changes, previous)
	}, false)
	return Out[apitypes.OnboardingUpdateFlowOutput]{Value: result}, err
}

// VerifyStep is POST {basePath}/onboarding/verifyStep. Approves (the default) or sends back an
// administrator-verified task. For member flows the caller administers the person's tenant (`tenantId` is the
// person's tenant); for setup flows the caller administers the tenant that defines the flow and names the tenant
// being set up as `subjectId`. Audited as `onboarding:verify` or `onboarding:reject`.
func (api *OnboardingAPI) VerifyStep(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingVerifyStepInput]) (Out[apitypes.OnboardingVerifyStepOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("subjectId"), "subjectId", 128)
	if err != nil {
		return Out[apitypes.OnboardingVerifyStepOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:onboarding:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		if err := onboardingNotImpersonating(principal, "Onboarding steps cannot be verified"); err != nil {
			return nil, err
		}
		approveValue := coalesce(input.Get("approve"), true)
		approve, ok := approveValue.(bool)
		if !ok {
			return nil, invalidInput("approve must be a boolean")
		}
		var note any = core.Undefined
		if raw := input.Get("note"); !isUndefined(raw) && raw != "" {
			text, err := Text(raw, "note", 500)
			if err != nil {
				return nil, err
			}
			note = core.JSTrim(text)
		}
		flow, err := onboardingFlowRecord(ctx, tx, input.Get("flowId"))
		if err != nil {
			return nil, err
		}
		now := server.Now()
		var candidate *core.Object
		var subject onboardingSubject
		var evaluate func(progress *core.Object) (*core.Object, error)
		if flow.Get("audience") == "member" {
			identity, err := server.ActiveIdentity(ctx, tx, input.Get("subjectId"), jsString(tenant.Get("id")))
			if err != nil {
				return nil, err
			}
			if identity.Get("id") == principal.Identity.Get("id") {
				return nil, invalidInput("People cannot verify their own onboarding")
			}
			chain, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			flows, err := FlowsForIdentity(ctx, tx, chain, identity, now, nil)
			if err != nil {
				return nil, err
			}
			candidate = onboardingFindCandidate(flows, flow.Get("id"), nil)
			subject = onboardingSubject{Type: "identity", ID: jsString(identity.Get("id")), TenantID: jsString(tenant.Get("id"))}
			evaluate = func(progress *core.Object) (*core.Object, error) {
				facts, err := MemberFacts(ctx, tx, identity, []*core.Object{flow}, now)
				if err != nil {
					return nil, err
				}
				return EvaluateFlow(candidate, progress, core.NewObject("member", core.NewObject("identity", identity, "facts", facts)), core.NewObject("answers", true))
			}
		} else {
			if flow.Get("tenantId") != tenant.Get("id") {
				return nil, onboardingFlowNotFound()
			}
			subjectID, err := Text(input.Get("subjectId"), "subjectId", 128)
			if err != nil {
				return nil, err
			}
			target, err := server.Tenant(ctx, tx, subjectID)
			if err != nil {
				return nil, err
			}
			targetChain, err := server.Ancestry(ctx, tx, target)
			if err != nil {
				return nil, err
			}
			below := false
			for _, item := range targetChain[1:] {
				if item.Get("id") == tenant.Get("id") {
					below = true
				}
			}
			if !below {
				return nil, core.NewIamError("NOT_FOUND", "Tenant not found", 404)
			}
			candidates, err := CandidateFlows(ctx, tx, targetChain, "tenant", nil)
			if err != nil {
				return nil, err
			}
			candidate = onboardingFindCandidate(candidates, flow.Get("id"), func(item *core.Object) bool {
				return onboardingTenantFlowApplies(onboardingCandidateFlow(item), target)
			})
			subject = onboardingSubject{Type: "tenant", ID: jsString(target.Get("id")), TenantID: jsString(target.Get("id"))}
			evaluate = func(progress *core.Object) (*core.Object, error) {
				facts, err := TenantFacts(ctx, tx, target, []*core.Object{flow})
				if err != nil {
					return nil, err
				}
				return EvaluateFlow(candidate, progress, core.NewObject("tenant", facts), core.NewObject("answers", true))
			}
		}
		if candidate == nil {
			return nil, onboardingFlowNotFound()
		}
		step := onboardingFindStep(flow, input.Get("stepId"))
		if step == nil || step.Get("kind") != "task" || step.Get("verification") != "admin" {
			return nil, invalidInput("Only administrator-verified tasks are verified")
		}
		progress, err := onboardingProgressFor(ctx, tx, subject.TenantID, subject.ID)
		if err != nil {
			return nil, err
		}
		flowID := jsString(flow.Get("id"))
		existing := progress[flowID]
		var record *core.Object
		if approve {
			record = core.NewObject("stepId", step.Get("id"), "completedAt", float64(now), "completedBy", subject.ID, "verifiedBy", principal.Identity.Get("id"))
		} else {
			record = core.NewObject("stepId", step.Get("id"), "rejectedAt", float64(now), "verifiedBy", principal.Identity.Get("id"))
		}
		if truthy(note) {
			record.Set("note", note)
		}
		base := existing
		if base == nil {
			base = onboardingNewProgress(flow, subject, float64(now))
		}
		saved, err := onboardingUpsertProgress(ctx, tx, onboardingWithStep(base, record).Set("updatedAt", float64(now)), existing != nil)
		if err != nil {
			return nil, err
		}
		progress[flowID] = saved
		action := "onboarding:reject"
		if approve {
			action = "onboarding:verify"
		}
		metadata := core.NewObject("flowId", flow.Get("id"), "flow", flow.Get("name"), "stepId", step.Get("id"), "subjectType", subject.Type)
		if truthy(note) {
			metadata.Set("note", note)
		}
		if err := server.Events.Audit(ctx, tx, principal, action, jsString(tenant.Get("id")), subject.ID, "allow", false, metadata); err != nil {
			return nil, err
		}
		status, err := evaluate(progress[flowID])
		if err != nil {
			return nil, err
		}
		// Completion is recorded here; completion groups are applied the next time the person reads their onboarding.
		if _, err := onboardingRecordCompletions(ctx, server, tx, principal, subject, []onboardingStatus{{candidate: candidate, status: status}}, progress); err != nil {
			return nil, err
		}
		return core.NewObject("flow", status), nil
	}, false)
	return Out[apitypes.OnboardingVerifyStepOutput]{Value: result}, err
}
