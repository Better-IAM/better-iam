package server

// Port of packages/server/src/api/reports.ts: the access report (the access-hygiene picture of a tenant: what is
// about to end, what is elevated right now, and what nobody uses) and the `reports` API group.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const reportDay = 86400_000.0

// ReportsAPI is the `reports` API group (packages/server/src/api/reports.ts createReportsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/reports/{method} onto it.
type ReportsAPI struct {
	server *ServerContext
}

// CreateReportsAPI builds the `reports` API group.
func CreateReportsAPI(server *ServerContext) *ReportsAPI {
	return &ReportsAPI{server: server}
}

// may is whether the principal may take action on the tenant (an unrecorded decision).
func (api *ReportsAPI) may(ctx context.Context, tx core.IamStore, principal *Principal, tenantID, action string) (bool, error) {
	decision, err := api.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: tenantID},
	}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// Access is POST {basePath}/reports/access. Returns the tenant's access report: identities and grants ending soon, live elevations, pending requests, and unused or expiring API keys.
// Identities and bindings ending within `withinMs` (30 days by default), keys unused for `unusedForMs` (30 days) or
// ending soon, live activations, and pending activation requests. Requires iam:identities:read; the binding and
// credential sections additionally need iam:bindings:read and iam:credentials:read and are omitted otherwise.
func (api *ReportsAPI) Access(ctx context.Context, credential core.CredentialInput, input In[apitypes.ReportsAccessInput]) (Out[apitypes.ReportsAccessOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:identities:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenant := jsString(tenantID)
		windows, err := ReportWindows(input.Body)
		if err != nil {
			return nil, err
		}
		bindings, err := api.may(ctx, call.Tx, call.Principal, tenant, "iam:bindings:read")
		if err != nil {
			return nil, err
		}
		credentials, err := api.may(ctx, call.Tx, call.Principal, tenant, "iam:credentials:read")
		if err != nil {
			return nil, err
		}
		return BuildAccessReport(ctx, api.server, call.Tx, tenant, windows, core.NewObject("bindings", bindings, "credentials", credentials))
	}, false)
	return Out[apitypes.ReportsAccessOutput]{Value: result}, err
}

// byEndThenID orders by a numeric member, then by id (`a[field] - b[field] || (a.id < b.id ? -1 : 1)`).
func byEndThenID(field string) func(a, b *core.Object) bool {
	return func(a, b *core.Object) bool {
		if difference := jsNumber(a.Get(field)) - jsNumber(b.Get(field)); difference != 0 && difference == difference {
			return difference < 0
		}
		return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
	}
}

func sortedObjects(records []*core.Object, less func(a, b *core.Object) bool) []any {
	sort.SliceStable(records, func(i, j int) bool { return less(records[i], records[j]) })
	return recordList(records)
}

// BuildAccessReport (api/reports.ts buildAccessReport): Builds the access report of one tenant inside a transaction.
// The API decides per caller which sections to include; deployment operations (the digest) include every section.
// windows holds withinMs and unusedForMs; sections holds the bindings and credentials flags.
func BuildAccessReport(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, windows *core.Object, sections *core.Object) (result *core.Object, err error) {
	now := float64(server.Now())
	withinMs, unusedForMs := jsNumber(windows.Get("withinMs")), jsNumber(windows.Get("unusedForMs"))
	horizon := now + withinMs
	byName := func(a, b *core.Object) int {
		return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
	}
	stored, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	identities := make([]*core.Object, 0, len(stored))
	for _, identity := range stored {
		if identity.Get("status") != "deleted" {
			identities = append(identities, identity)
		}
	}
	names := map[string]any{}
	disabled := 0
	var expiringIdentities []*core.Object
	for _, identity := range identities {
		names[jsString(identity.Get("id"))] = identity.Get("name")
		if identity.Get("status") == "disabled" {
			disabled++
		}
		expiresAt, isNumber := identity.Get("expiresAt").(float64)
		// Past its deadline an identity is a finding only until the worker has disabled it.
		if isNumber && expiresAt <= horizon && (expiresAt > now || identity.Get("status") == "active") {
			expiringIdentities = append(expiringIdentities, identity)
		}
	}
	sort.SliceStable(expiringIdentities, func(i, j int) bool {
		a, b := expiringIdentities[i], expiringIdentities[j]
		if difference := jsNumber(a.Get("expiresAt")) - jsNumber(b.Get("expiresAt")); difference != 0 {
			return difference < 0
		}
		return byName(a, b) < 0
	})
	expiring := make([]any, len(expiringIdentities))
	for index, identity := range expiringIdentities {
		summary := core.NewObject("id", identity.Get("id"), "name", identity.Get("name"))
		if email := identity.Get("email"); truthy(email) {
			summary.Set("email", email)
		}
		expiresAt := jsNumber(identity.Get("expiresAt"))
		summary.Set("kind", identity.Get("kind"))
		summary.Set("status", identity.Get("status"))
		summary.Set("expiresAt", expiresAt)
		summary.Set("expired", expiresAt <= now)
		expiring[index] = summary
	}
	nameOf := func(names map[string]any, id any) any {
		if name, ok := names[jsString(id)]; ok {
			return name
		}
		return core.Undefined
	}
	omitted := []any{}
	report := core.NewObject(
		"generatedAt", now,
		"withinMs", withinMs,
		"unusedForMs", unusedForMs,
		"identities", core.NewObject("total", len(identities), "disabled", disabled, "expiring", expiring),
		"omitted", omitted,
	)
	if truthy(sections.Get("bindings")) {
		roles := map[string]any{}
		roleRecords, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, role := range roleRecords {
			roles[jsString(role.Get("id"))] = role.Get("name")
		}
		groups := map[string]any{}
		groupRecords, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, group := range groupRecords {
			groups[jsString(group.Get("id"))] = group.Get("name")
		}
		allBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var bindings []*core.Object
		for _, binding := range allBindings {
			if !server.ExpiredBinding(binding) {
				bindings = append(bindings, binding)
			}
		}
		memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		// An activation or request counts only while it could grant: its binding is still live and eligible, its
		// holder is active, and (for a group binding) still a member.
		activeIDs := map[string]bool{}
		for _, identity := range identities {
			if identity.Get("status") == "active" {
				activeIDs[jsString(identity.Get("id"))] = true
			}
		}
		eligibleBindings := map[string]*core.Object{}
		for _, binding := range bindings {
			if truthy(binding.Get("eligible")) && server.LiveBinding(binding) {
				eligibleBindings[jsString(binding.Get("id"))] = binding
			}
		}
		applies := func(activation *core.Object) bool {
			binding, ok := eligibleBindings[jsString(activation.Get("bindingId"))]
			if !ok || !activeIDs[jsString(activation.Get("identityId"))] {
				return false
			}
			if binding.Get("subjectType") == "identity" {
				return true
			}
			for _, member := range memberships {
				if member.Get("groupId") == binding.Get("subjectId") && member.Get("identityId") == activation.Get("identityId") && server.LiveMembership(member) {
					return true
				}
			}
			return false
		}
		storedActivations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var activations []*core.Object
		for _, activation := range storedActivations {
			if applies(activation) {
				activations = append(activations, activation)
			}
		}
		subjectName := func(binding *core.Object) any {
			if binding.Get("subjectType") == "identity" {
				return nameOf(names, binding.Get("subjectId"))
			}
			return nameOf(groups, binding.Get("subjectId"))
		}
		summarize := func(binding *core.Object, at any) *core.Object {
			roleName := nameOf(roles, binding.Get("roleId"))
			subject := subjectName(binding)
			summary := core.NewObject("id", binding.Get("id"), "roleId", binding.Get("roleId"))
			if truthy(roleName) {
				summary.Set("roleName", roleName)
			}
			summary.Set("subjectType", binding.Get("subjectType"))
			summary.Set("subjectId", binding.Get("subjectId"))
			if truthy(subject) {
				summary.Set("subjectName", subject)
			}
			summary.Set("expiresAt", at)
			summary.Set("eligible", binding.Get("eligible") == true)
			return summary
		}
		scheduledBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var scheduled []*core.Object
		for _, binding := range scheduledBindings {
			startsAt, isNumber := binding.Get("startsAt").(float64)
			if isNumber && startsAt > now && startsAt <= horizon && !server.ExpiredBinding(binding) {
				scheduled = append(scheduled, binding)
			}
		}
		eligible, windowed := 0, 0
		var expiringBindings []*core.Object
		for _, binding := range bindings {
			if truthy(binding.Get("eligible")) {
				eligible++
			}
			if truthy(binding.Get("window")) {
				windowed++
			}
			if expiresAt, isNumber := binding.Get("expiresAt").(float64); isNumber && expiresAt <= horizon {
				expiringBindings = append(expiringBindings, binding)
			}
		}
		sort.SliceStable(expiringBindings, func(i, j int) bool { return byEndThenID("expiresAt")(expiringBindings[i], expiringBindings[j]) })
		expiringSummaries := make([]any, len(expiringBindings))
		for index, binding := range expiringBindings {
			expiringSummaries[index] = summarize(binding, binding.Get("expiresAt"))
		}
		sort.SliceStable(scheduled, func(i, j int) bool { return byEndThenID("startsAt")(scheduled[i], scheduled[j]) })
		starting := make([]any, len(scheduled))
		for index, binding := range scheduled {
			starting[index] = summarize(binding, binding.Get("startsAt"))
		}
		var endingMemberships []*core.Object
		for _, member := range memberships {
			if expiresAt, isNumber := member.Get("expiresAt").(float64); isNumber && expiresAt <= horizon && server.LiveMembership(member) {
				endingMemberships = append(endingMemberships, member)
			}
		}
		sort.SliceStable(endingMemberships, func(i, j int) bool { return byEndThenID("expiresAt")(endingMemberships[i], endingMemberships[j]) })
		expiringMemberships := make([]any, len(endingMemberships))
		for index, member := range endingMemberships {
			groupName := nameOf(groups, member.Get("groupId"))
			identityName := nameOf(names, member.Get("identityId"))
			summary := core.NewObject("groupId", member.Get("groupId"))
			if truthy(groupName) {
				summary.Set("groupName", groupName)
			}
			summary.Set("identityId", member.Get("identityId"))
			if truthy(identityName) {
				summary.Set("identityName", identityName)
			}
			summary.Set("expiresAt", member.Get("expiresAt"))
			expiringMemberships[index] = summary
		}
		var live []*core.Object
		pendingRequests := 0
		for _, activation := range activations {
			status := activation.Get("status")
			ends := jsNumber(activation.Get("expiresAt"))
			if ends > now && status != "pending" && status != "denied" {
				live = append(live, activation)
			}
			if status == "pending" && ends > now {
				pendingRequests++
			}
		}
		sort.SliceStable(live, func(i, j int) bool { return byEndThenID("expiresAt")(live[i], live[j]) })
		liveActivations := make([]any, len(live))
		for index, activation := range live {
			identityName := nameOf(names, activation.Get("identityId"))
			roleName := nameOf(roles, activation.Get("roleId"))
			summary := core.NewObject("id", activation.Get("id"), "identityId", activation.Get("identityId"))
			if truthy(identityName) {
				summary.Set("identityName", identityName)
			}
			summary.Set("roleId", activation.Get("roleId"))
			if truthy(roleName) {
				summary.Set("roleName", roleName)
			}
			summary.Set("activatedAt", activation.Get("activatedAt"))
			summary.Set("expiresAt", activation.Get("expiresAt"))
			if justification := activation.Get("justification"); truthy(justification) {
				summary.Set("justification", justification)
			}
			liveActivations[index] = summary
		}
		report.Set("bindings", core.NewObject(
			"total", len(bindings),
			"eligible", eligible,
			"windowed", windowed,
			"expiring", expiringSummaries,
			"starting", starting,
			"expiringMemberships", expiringMemberships,
			"activations", liveActivations,
			"pendingRequests", pendingRequests,
		))
	} else {
		omitted = append(omitted, "bindings")
	}
	if truthy(sections.Get("credentials")) {
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("tenantId", tenantID, "kind", "api-key"), nil)
		if err != nil {
			return nil, err
		}
		var keys []*core.Object
		for _, session := range sessions {
			summary, err := CredentialSummary(session, int64(now))
			if err != nil {
				return nil, err
			}
			if !truthy(summary.Get("expired")) {
				keys = append(keys, summary)
			}
		}
		unusedSince := now - unusedForMs
		var unused, ending []*core.Object
		for _, key := range keys {
			if jsNumber(coalesce(key.Get("lastUsedAt"), key.Get("createdAt"))) <= unusedSince {
				unused = append(unused, key)
			}
			if jsNumber(key.Get("expiresAt")) <= horizon {
				ending = append(ending, key)
			}
		}
		report.Set("credentials", core.NewObject(
			"total", len(keys),
			"unused", sortedObjects(unused, byEndThenID("createdAt")),
			"expiring", sortedObjects(ending, byEndThenID("expiresAt")),
		))
	} else {
		omitted = append(omitted, "credentials")
	}
	report.Set("omitted", omitted)
	return report, nil
}

// arrayLength is the length of an array member (0 when it is not an array).
func arrayLength(value any) int {
	list, _ := value.([]any)
	return len(list)
}

// ReportHasFindings (api/reports.ts reportHasFindings): Whether a report has anything worth telling someone about.
func ReportHasFindings(report *core.Object) (result bool, err error) {
	if arrayLength(member(report.Get("identities"), "expiring")) > 0 {
		return true, nil
	}
	if bindings := report.Get("bindings"); !isUndefined(bindings) {
		if arrayLength(member(bindings, "expiring")) > 0 ||
			arrayLength(member(bindings, "starting")) > 0 ||
			arrayLength(member(bindings, "expiringMemberships")) > 0 ||
			arrayLength(member(bindings, "activations")) > 0 ||
			jsNumber(member(bindings, "pendingRequests")) > 0 {
			return true, nil
		}
	}
	if credentials := report.Get("credentials"); !isUndefined(credentials) {
		if arrayLength(member(credentials, "unused")) > 0 || arrayLength(member(credentials, "expiring")) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// ReportWindows (api/reports.ts reportWindows): Validates the report windows: 0 to ten years, 30 days by default.
func ReportWindows(input *core.Object) (result *core.Object, err error) {
	within, err := Integer(coalesce(member(input, "withinMs"), 30*reportDay), "withinMs", 0, 10*365*reportDay)
	if err != nil {
		return nil, err
	}
	unused, err := Integer(coalesce(member(input, "unusedForMs"), 30*reportDay), "unusedForMs", 0, 10*365*reportDay)
	if err != nil {
		return nil, err
	}
	return core.NewObject("withinMs", within, "unusedForMs", unused), nil
}
