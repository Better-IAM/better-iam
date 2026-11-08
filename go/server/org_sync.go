package server

// Port of packages/server/src/org-sync.ts: configuration as code for teams and departments, the `teams` and
// `departments` kinds of a tenant configuration (sync.go). Teams are matched by slug and departments by name (ignoring
// case); people are named by email and roles by name, so one document applies to several environments. Temporary
// team memberships and join requests are runtime state and never synced.
//
// Document items (TenantConfigTeam, TenantConfigDepartment) are model objects whose members follow the TypeScript
// object literals, with core.Undefined where TypeScript leaves a member undefined.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/core"
)

// OrgPlanned is org-sync.ts OrgPlanned: one planned change next to the document item and the record it matches.
type OrgPlanned struct {
	// Change is the ConfigChange: { kind, name, action, fields?, before?, after? }.
	Change *core.Object
	// Desired is the document item (nil for deletions).
	Desired *core.Object
	// Record is the team or department record (nil for creations).
	Record *core.Object
}

// OrgPlan is org-sync.ts OrgPlan.
type OrgPlan struct {
	Teams       []*OrgPlanned
	Departments []*OrgPlanned
}

// OrgState is org-sync.ts OrgState: the tenant's teams and departments with the records the configuration compares
// against.
type OrgState struct {
	Teams []*core.Object
	// TeamMembers are the live direct team memberships.
	TeamMembers []*core.Object
	// TeamBindings are the standing bindings (not eligible, windowed, scheduled, temporary, or from a package) by
	// backing group ID.
	TeamBindings map[string][]*core.Object
	Departments  []*core.Object
	Placements   []*core.Object
}

// OrgDirectory is org-sync.ts Directory.
type OrgDirectory struct {
	// IdentityEmails maps identity IDs to lowercase emails, for people who are not deleted.
	IdentityEmails map[string]string
	// RoleNames maps role IDs to names.
	RoleNames map[string]string
	// GroupNames maps group IDs to names, for ordinary (not team-backed) groups.
	GroupNames map[string]string
}

// OrgPlanEnv is the environment of planOrg: the directory plus what exists after the apply.
type OrgPlanEnv struct {
	OrgDirectory
	IdentitiesByEmail map[string]*core.Object
	RoleNamesAfter    *orderedSet
	// GroupNamesAfter holds the names of the ordinary groups that exist after the apply.
	GroupNamesAfter *orderedSet
	Prune           bool
}

// SyncApplyEnv is the environment configuration apply hands to applyOrg and applyAi.
type SyncApplyEnv struct {
	// Allow authorizes one change like the equivalent API call (ACCESS_DENIED otherwise).
	Allow func(ctx context.Context, action, resourceID, what string) error
	// RoleIDs maps role names to IDs, including roles this apply created.
	RoleIDs map[string]string
	// GroupIDs maps ordinary group names to IDs, including groups this apply created.
	GroupIDs map[string]string
	// IdentitiesByEmail maps lowercase emails to the tenant's (not deleted) identities.
	IdentitiesByEmail map[string]*core.Object
}

// orgLower is org-sync.ts lower: value.trim().toLowerCase().
func orgLower(value string) string { return core.JSLower(core.JSTrim(value)) }

// syncSortedUnique is org-sync.ts sortedUnique: [...new Set(items)].sort().
func syncSortedUnique(items []string) []string {
	out := unique(items)
	sort.SliceStable(out, func(i, j int) bool { return compareUTF16(out[i], out[j]) < 0 })
	return out
}

// OrgRuleNames (org-sync.ts orgRuleNames): Birthright rules (access package `autoAssign`) name teams by slug and
// departments by name in a configuration document; the tenant stores IDs. `orgRuleNames` maps a stored rule's IDs to
// names (export and plan comparisons).
func OrgRuleNames(state *OrgState, rule any) (result any, err error) {
	slugs := map[string]string{}
	for _, team := range state.Teams {
		slugs[jsString(team.Get("id"))] = jsString(team.Get("slug"))
	}
	names := map[string]string{}
	for _, department := range state.Departments {
		names[jsString(department.Get("id"))] = jsString(department.Get("name"))
	}
	mapped, err := MapRuleValues(rule, "identity.teams", func(teamID string) string { return syncLookup(slugs, teamID) })
	if err != nil {
		return nil, err
	}
	return MapRuleValues(mapped, "identity.departments", func(departmentID string) string { return syncLookup(names, departmentID) })
}

// syncLookup is `map.get(key) ?? key`.
func syncLookup(values map[string]string, key string) string {
	if value, ok := values[key]; ok {
		return value
	}
	return key
}

// orgDepartmentNames is the `departments` set of a rule environment: department names, ignoring case.
type orgDepartmentNames map[string]string

// Has is `departments.has(lower(name))`.
func (names orgDepartmentNames) Has(name string) bool {
	_, ok := names[orgLower(name)]
	return ok
}

// OrgRuleEnvironmentAfterResult is org-sync.ts orgRuleEnvironmentAfter().
type OrgRuleEnvironmentAfterResult struct {
	// Env is the `org` member of a rule environment: { teams, departments }, each a set with Has (stored raw, so
	// package rules read them as sets).
	Env         *core.Object
	departments orgDepartmentNames
}

// Canonical (org-sync.ts orgRuleEnvironmentAfter().canonical): rewrites a rule's department names to their spelling
// in the document (or the tenant).
func (s *OrgRuleEnvironmentAfterResult) Canonical(rule any) (result any, err error) {
	return MapRuleValues(rule, "identity.departments", func(name string) string {
		if spelled, ok := s.departments[orgLower(name)]; ok {
			return spelled
		}
		return name
	})
}

// OrgRuleEnvironmentAfter (org-sync.ts orgRuleEnvironmentAfter): The teams and departments that exist after an
// apply, for validating package rules at plan time: team slugs, and department names ignoring case. `canonical`
// rewrites a rule's department names to their spelling in the document (or the tenant), so a case-only difference
// never shows as a change.
func OrgRuleEnvironmentAfter(desired *core.Object, state *OrgState, prune bool) (result *OrgRuleEnvironmentAfterResult, err error) {
	desiredTeams, hasTeams := syncConfigItems(desired, "teams")
	desiredDepartments, hasDepartments := syncConfigItems(desired, "departments")
	teams := newOrderedSet()
	for _, record := range state.Teams {
		slug := jsString(record.Get("slug"))
		if !hasTeams || !prune || syncSome(desiredTeams, func(item *core.Object) bool { return jsString(item.Get("slug")) == slug }) {
			teams.Add(slug)
		}
	}
	for _, team := range desiredTeams {
		teams.Add(jsString(team.Get("slug")))
	}
	departments := orgDepartmentNames{}
	for _, record := range state.Departments {
		name := jsString(record.Get("name"))
		if !hasDepartments || !prune || syncSome(desiredDepartments, func(item *core.Object) bool {
			return orgLower(jsString(item.Get("name"))) == orgLower(name)
		}) {
			departments[orgLower(name)] = name
		}
	}
	for _, department := range desiredDepartments {
		name := jsString(department.Get("name"))
		departments[orgLower(name)] = name
	}
	env := core.NewObject()
	env.SetRaw("teams", teams)
	env.SetRaw("departments", departments)
	return &OrgRuleEnvironmentAfterResult{Env: env, departments: departments}, nil
}

// syncSome is Array.prototype.some.
func syncSome(items []*core.Object, test func(*core.Object) bool) bool {
	for _, item := range items {
		if test(item) {
			return true
		}
	}
	return false
}

// OrgRuleIDs (org-sync.ts orgRuleIds): Maps a document rule's team slugs and department names to the tenant's IDs
// (after teams and departments exist).
func OrgRuleIDs(ctx context.Context, tx core.IamStore, tenantID string) (result func(any) (any, error), err error) {
	teamRecords, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	teams := map[string]string{}
	for _, team := range teamRecords {
		teams[jsString(team.Get("slug"))] = jsString(team.Get("id"))
	}
	departmentRecords, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	departments := map[string]string{}
	for _, department := range departmentRecords {
		departments[orgLower(jsString(department.Get("name")))] = jsString(department.Get("id"))
	}
	return func(rule any) (any, error) {
		mapped, err := MapRuleValues(rule, "identity.teams", func(slug string) string { return syncLookup(teams, slug) })
		if err != nil {
			return nil, err
		}
		return MapRuleValues(mapped, "identity.departments", func(name string) string {
			if id, ok := departments[orgLower(name)]; ok {
				return id
			}
			return name
		})
	}, nil
}

// orgOptionalText is org-sync.ts optionalText: undefined, or the trimmed text.
func orgOptionalText(item *core.Object, key string, max int) (any, error) {
	if isUndefined(item.Get(key)) {
		return core.Undefined, nil
	}
	value, err := Text(item.Get(key), key, max)
	if err != nil {
		return nil, err
	}
	return core.JSTrim(value), nil
}

// orgEmails is org-sync.ts emails: undefined, or the sorted unique lowercase emails.
func orgEmails(item *core.Object, key string) (any, error) {
	if isUndefined(item.Get(key)) {
		return core.Undefined, nil
	}
	list, err := Strings(item.Get(key), key)
	if err != nil {
		return nil, err
	}
	lowered := make([]string, len(list))
	for index, email := range list {
		lowered[index] = orgLower(email)
	}
	return stringsOf(syncSortedUnique(lowered)), nil
}

// ParseTeamsConfig (org-sync.ts parseTeamsConfig): Validates the `teams` list of a configuration document.
func ParseTeamsConfig(items []*core.Object) (result []*core.Object, err error) {
	teams := make([]*core.Object, 0, len(items))
	for _, item := range items {
		team, err := parseTeamConfig(item)
		if err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}
	seen := newOrderedSet()
	for _, team := range teams {
		slug := jsString(team.Get("slug"))
		if seen.Has(slug) {
			return nil, invalidInput("Duplicate team " + slug)
		}
		seen.Add(slug)
	}
	return teams, nil
}

func parseTeamConfig(item *core.Object) (*core.Object, error) {
	nameText, err := Text(item.Get("name"), "team name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(nameText)
	var slug string
	if isUndefined(item.Get("slug")) {
		if slug, err = SlugFromName(name); err != nil {
			return nil, err
		}
	} else if slug, err = TeamSlug(item.Get("slug")); err != nil {
		return nil, err
	}
	if slug == "" {
		return nil, invalidInput("Team " + name + ": choose a slug")
	}
	joinPolicy := item.Get("joinPolicy")
	if !isUndefined(joinPolicy) && joinPolicy != "closed" && joinPolicy != "request" {
		return nil, invalidInput("Team " + slug + ": joinPolicy must be closed or request")
	}
	management := item.Get("memberManagement")
	if !isUndefined(management) && management != "maintainers" && management != "admins" {
		return nil, invalidInput("Team " + slug + ": memberManagement must be maintainers or admins")
	}
	maintainers, err := orgEmails(item, "maintainers")
	if err != nil {
		return nil, err
	}
	members, err := orgEmails(item, "members")
	if err != nil {
		return nil, err
	}
	if maintainerList, ok := maintainers.([]any); ok {
		memberList, _ := members.([]any)
		for _, email := range maintainerList {
			if containsString(syncStringList(memberList), jsString(email)) {
				return nil, invalidInput("Team " + slug + ": " + jsString(email) + " is listed as both maintainer and member")
			}
		}
	}
	description, err := orgOptionalText(item, "description", 512)
	if err != nil {
		return nil, err
	}
	var parent any = core.Undefined
	if !isUndefined(item.Get("parent")) {
		if parent, err = TeamSlug(item.Get("parent")); err != nil {
			return nil, err
		}
	}
	department, err := orgOptionalText(item, "department", 100)
	if err != nil {
		return nil, err
	}
	var roles any = core.Undefined
	if !isUndefined(item.Get("roles")) {
		list, err := Strings(item.Get("roles"), "roles")
		if err != nil {
			return nil, err
		}
		roles = stringsOf(syncSortedUnique(list))
	}
	var syncGroups any = core.Undefined
	if !isUndefined(item.Get("syncGroups")) {
		list, err := Strings(item.Get("syncGroups"), "syncGroups")
		if err != nil {
			return nil, err
		}
		syncGroups = stringsOf(syncSortedUnique(list))
	}
	return core.NewObject(
		"name", name,
		"slug", slug,
		"description", description,
		"parent", parent,
		"department", department,
		"joinPolicy", joinPolicy,
		"memberManagement", management,
		"maintainers", maintainers,
		"members", members,
		"roles", roles,
		"syncGroups", syncGroups,
	), nil
}

// syncStringList is the strings of a model array (non-strings as String()).
func syncStringList(value any) []string {
	list, _ := value.([]any)
	out := make([]string, len(list))
	for index, item := range list {
		out[index] = jsString(item)
	}
	return out
}

// ParseDepartmentsConfig (org-sync.ts parseDepartmentsConfig): Validates the `departments` list of a configuration
// document.
func ParseDepartmentsConfig(items []*core.Object) (result []*core.Object, err error) {
	departments := make([]*core.Object, 0, len(items))
	for _, item := range items {
		nameText, err := Text(item.Get("name"), "department name", 100)
		if err != nil {
			return nil, err
		}
		var code any = core.Undefined
		if !isUndefined(item.Get("code")) {
			if code, err = DepartmentCode(item.Get("code")); err != nil {
				return nil, err
			}
		}
		description, err := orgOptionalText(item, "description", 512)
		if err != nil {
			return nil, err
		}
		parent, err := orgOptionalText(item, "parent", 100)
		if err != nil {
			return nil, err
		}
		var head any = core.Undefined
		if !isUndefined(item.Get("head")) {
			headText, err := Text(item.Get("head"), "head", 254)
			if err != nil {
				return nil, err
			}
			head = orgLower(headText)
		}
		costCenter, err := orgOptionalText(item, "costCenter", 64)
		if err != nil {
			return nil, err
		}
		members, err := orgEmails(item, "members")
		if err != nil {
			return nil, err
		}
		departments = append(departments, core.NewObject(
			"name", core.JSTrim(nameText),
			"code", code,
			"description", description,
			"parent", parent,
			"head", head,
			"costCenter", costCenter,
			"members", members,
		))
	}
	names := newOrderedSet()
	codes := newOrderedSet()
	for _, department := range departments {
		name := jsString(department.Get("name"))
		if names.Has(orgLower(name)) {
			return nil, invalidInput("Duplicate department " + name)
		}
		names.Add(orgLower(name))
		if code, ok := department.Get("code").(string); ok {
			if codes.Has(orgLower(code)) {
				return nil, invalidInput("Duplicate department code " + code)
			}
			codes.Add(orgLower(code))
		}
	}
	return departments, nil
}

// orgStandingBinding is the filter of the team bindings configuration manages: not eligible, windowed, scheduled,
// temporary, or from a package.
func orgStandingBinding(binding *core.Object) bool {
	return !truthy(binding.Get("eligible")) &&
		isUndefined(binding.Get("window")) &&
		isUndefined(binding.Get("startsAt")) &&
		isUndefined(binding.Get("expiresAt")) &&
		isUndefined(binding.Get("packageAssignmentId"))
}

// ReadOrgState (org-sync.ts readOrgState): Reads what the `teams` and `departments` kinds compare against.
func ReadOrgState(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result *OrgState, err error) {
	now := server.Now()
	teams, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(teams, func(i, j int) bool {
		return compareUTF16(jsString(teams[i].Get("slug")), jsString(teams[j].Get("slug"))) < 0
	})
	members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	teamMembers := []*core.Object{}
	for _, member := range members {
		if liveTeamMember(member, now) {
			teamMembers = append(teamMembers, member)
		}
	}
	teamBindings := map[string][]*core.Object{}
	for _, team := range teams {
		groupID := jsString(team.Get("groupId"))
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", team.Get("groupId")), nil)
		if err != nil {
			return nil, err
		}
		standing := []*core.Object{}
		for _, binding := range bindings {
			if orgStandingBinding(binding) {
				standing = append(standing, binding)
			}
		}
		teamBindings[groupID] = standing
	}
	departments, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(departments, func(i, j int) bool {
		return localeCompare(jsString(departments[i].Get("name")), jsString(departments[j].Get("name"))) < 0
	})
	placements, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	return &OrgState{Teams: teams, TeamMembers: teamMembers, TeamBindings: teamBindings, Departments: departments, Placements: placements}, nil
}

// syncByID is `new Map(records.map((item) => [item.id, item]))`.
func syncByID(records []*core.Object) map[string]*core.Object {
	byID := map[string]*core.Object{}
	for _, record := range records {
		byID[jsString(record.Get("id"))] = record
	}
	return byID
}

// orgExportedTeam is org-sync.ts exportedTeam: a team in document form, without its name and slug.
func orgExportedTeam(team *core.Object, state *OrgState, directory *OrgDirectory) *core.Object {
	byID := syncByID(state.Teams)
	departments := syncByID(state.Departments)
	teamID := jsString(team.Get("id"))
	// Temporary and synced memberships are runtime state.
	var permanent []*core.Object
	for _, member := range state.TeamMembers {
		if jsString(member.Get("teamId")) == teamID && isUndefined(member.Get("expiresAt")) && member.Get("source") != "sync" {
			permanent = append(permanent, member)
		}
	}
	emailsOf := func(role string) []any {
		var emails []string
		for _, member := range permanent {
			if member.Get("role") != role {
				continue
			}
			if email := directory.IdentityEmails[jsString(member.Get("identityId"))]; email != "" {
				emails = append(emails, email)
			}
		}
		return stringsOf(syncSortedUnique(emails))
	}
	var parent, department *core.Object
	if parentID := team.Get("parentId"); truthy(parentID) {
		parent = byID[jsString(parentID)]
	}
	if departmentID := team.Get("departmentId"); truthy(departmentID) {
		department = departments[jsString(departmentID)]
	}
	result := core.NewObject()
	if description := team.Get("description"); !isUndefined(description) {
		result.Set("description", description)
	}
	if parent != nil {
		result.Set("parent", parent.Get("slug"))
	}
	if department != nil {
		result.Set("department", department.Get("name"))
	}
	result.Set("joinPolicy", team.Get("joinPolicy"))
	result.Set("memberManagement", team.Get("memberManagement"))
	result.Set("maintainers", emailsOf("maintainer"))
	result.Set("members", emailsOf("member"))
	var roles []string
	for _, binding := range state.TeamBindings[jsString(team.Get("groupId"))] {
		if name, ok := directory.RoleNames[jsString(binding.Get("roleId"))]; ok {
			roles = append(roles, name)
		}
	}
	result.Set("roles", stringsOf(syncSortedUnique(roles)))
	if syncGroupIDs, ok := team.Get("syncGroupIds").([]any); ok && len(syncGroupIDs) > 0 {
		var names []string
		for _, groupID := range syncGroupIDs {
			if name, ok := directory.GroupNames[jsString(groupID)]; ok {
				names = append(names, name)
			}
		}
		result.Set("syncGroups", stringsOf(syncSortedUnique(names)))
	}
	return result
}

// orgExportedDepartment is org-sync.ts exportedDepartment: a department in document form, without its name.
func orgExportedDepartment(department *core.Object, state *OrgState, directory *OrgDirectory) *core.Object {
	byID := syncByID(state.Departments)
	var parent *core.Object
	if parentID := department.Get("parentId"); truthy(parentID) {
		parent = byID[jsString(parentID)]
	}
	head := ""
	if headID := department.Get("headId"); truthy(headID) {
		head = directory.IdentityEmails[jsString(headID)]
	}
	result := core.NewObject()
	if code := department.Get("code"); !isUndefined(code) {
		result.Set("code", code)
	}
	if description := department.Get("description"); !isUndefined(description) {
		result.Set("description", description)
	}
	if parent != nil {
		result.Set("parent", parent.Get("name"))
	}
	if head != "" {
		result.Set("head", head)
	}
	if costCenter := department.Get("costCenter"); !isUndefined(costCenter) {
		result.Set("costCenter", costCenter)
	}
	departmentID := jsString(department.Get("id"))
	var emails []string
	for _, placement := range state.Placements {
		if jsString(placement.Get("departmentId")) != departmentID {
			continue
		}
		if email := directory.IdentityEmails[jsString(placement.Get("identityId"))]; email != "" {
			emails = append(emails, email)
		}
	}
	result.Set("members", stringsOf(syncSortedUnique(emails)))
	return result
}

// ExportOrg (org-sync.ts exportOrg): The tenant's teams and departments in document form; each kind appears only
// when the tenant has some.
func ExportOrg(state *OrgState, directory *OrgDirectory) (result *core.Object, err error) {
	result = core.NewObject()
	if len(state.Departments) > 0 {
		departments := make([]any, len(state.Departments))
		for index, department := range state.Departments {
			departments[index] = core.NewObject("name", department.Get("name")).Assign(orgExportedDepartment(department, state, directory))
		}
		result.Set("departments", departments)
	}
	if len(state.Teams) > 0 {
		teams := make([]any, len(state.Teams))
		for index, team := range state.Teams {
			teams[index] = core.NewObject("name", team.Get("name"), "slug", team.Get("slug")).Assign(orgExportedTeam(team, state, directory))
		}
		result.Set("teams", teams)
	}
	return result, nil
}

// orgDesiredTeamForm is org-sync.ts desiredTeamForm: a desired team in its exported form (defaults filled, membership
// lists only when given).
func orgDesiredTeamForm(team *core.Object) *core.Object {
	managesMembers := !isUndefined(team.Get("maintainers")) || !isUndefined(team.Get("members"))
	form := core.NewObject()
	for _, key := range []string{"description", "parent", "department"} {
		if value := team.Get(key); !isUndefined(value) {
			form.Set(key, value)
		}
	}
	form.Set("joinPolicy", coalesce(team.Get("joinPolicy"), "closed"))
	form.Set("memberManagement", coalesce(team.Get("memberManagement"), "maintainers"))
	if managesMembers {
		form.Set("maintainers", coalesce(team.Get("maintainers"), []any{}))
		form.Set("members", coalesce(team.Get("members"), []any{}))
	}
	if roles := team.Get("roles"); !isUndefined(roles) {
		form.Set("roles", roles)
	}
	if syncGroups, ok := team.Get("syncGroups").([]any); ok && len(syncGroups) > 0 {
		form.Set("syncGroups", syncGroups)
	}
	return form
}

// orgDesiredDepartmentForm is org-sync.ts desiredDepartmentForm.
func orgDesiredDepartmentForm(department *core.Object) *core.Object {
	form := core.NewObject()
	for _, key := range []string{"code", "description", "parent", "head", "costCenter", "members"} {
		if value := department.Get(key); !isUndefined(value) {
			form.Set(key, value)
		}
	}
	return form
}

// PlanOrg (org-sync.ts planOrg): Plans the `teams` and `departments` kinds. References are checked against what will
// exist after the apply: people now (by email), roles (`roleNamesAfter`), parents and departments from the document
// or the tenant. Kinds absent from the document are left alone; with `prune`, listed kinds lose the items the
// document omits.
func PlanOrg(desired *core.Object, state *OrgState, env *OrgPlanEnv) (result *OrgPlan, err error) {
	plan := &OrgPlan{Teams: []*OrgPlanned{}, Departments: []*OrgPlanned{}}
	person := func(email, where string) (*core.Object, error) {
		identity := env.IdentitiesByEmail[email]
		if identity == nil || identity.Get("kind") != "user" {
			return nil, invalidInput(where + ": unknown person " + email)
		}
		return identity, nil
	}
	desiredDepartments, hasDepartments := syncConfigItems(desired, "departments")
	desiredTeams, hasTeams := syncConfigItems(desired, "teams")

	// Departments, by name regardless of case.
	departmentNamesAfter := newOrderedSet()
	for _, record := range state.Departments {
		name := orgLower(jsString(record.Get("name")))
		if !hasDepartments || !env.Prune || syncSome(desiredDepartments, func(item *core.Object) bool {
			return orgLower(jsString(item.Get("name"))) == name
		}) {
			departmentNamesAfter.Add(name)
		}
	}
	for _, department := range desiredDepartments {
		departmentNamesAfter.Add(orgLower(jsString(department.Get("name"))))
	}
	if hasDepartments {
		existing := map[string]*core.Object{}
		for _, record := range state.Departments {
			existing[orgLower(jsString(record.Get("name")))] = record
		}
		parents := map[string]string{}
		for _, record := range state.Departments {
			parent := ""
			if parentID := record.Get("parentId"); truthy(parentID) {
				for _, item := range state.Departments {
					if core.StrictEquals(item.Get("id"), parentID) {
						parent = core.JSLower(jsString(item.Get("name")))
						break
					}
				}
			}
			parents[orgLower(jsString(record.Get("name")))] = parent
		}
		for _, department := range desiredDepartments {
			name := jsString(department.Get("name"))
			where := "Department " + name
			if parent, ok := department.Get("parent").(string); ok && !departmentNamesAfter.Has(orgLower(parent)) {
				return nil, invalidInput(where + ": unknown parent " + parent)
			}
			if head, ok := department.Get("head").(string); ok {
				if _, err := person(head, where); err != nil {
					return nil, err
				}
			}
			for _, email := range syncStringList(department.Get("members")) {
				if _, err := person(email, where); err != nil {
					return nil, err
				}
			}
			parent := ""
			if value, ok := department.Get("parent").(string); ok {
				parent = orgLower(value)
			}
			parents[orgLower(name)] = parent
		}
		for _, name := range departmentNamesAfter.Values() {
			seen := newOrderedSet()
			for cursor := name; cursor != ""; cursor = parents[cursor] {
				if seen.Has(cursor) {
					return nil, invalidInput("Departments " + name + ": the parents form a cycle")
				}
				seen.Add(cursor)
			}
		}
		for _, department := range desiredDepartments {
			name := jsString(department.Get("name"))
			record := existing[orgLower(name)]
			after := orgDesiredDepartmentForm(department)
			if record == nil {
				plan.Departments = append(plan.Departments, &OrgPlanned{
					Change:  syncChange("department", name, "create", nil, nil, after),
					Desired: department,
				})
				continue
			}
			before := orgExportedDepartment(record, state, &env.OrgDirectory)
			if isUndefined(department.Get("members")) {
				before.Delete("members")
			}
			fields := syncDiffFields(before, after)
			if jsString(record.Get("name")) != name {
				fields = append(fields, "name")
			}
			plan.Departments = append(plan.Departments, &OrgPlanned{
				Change:  syncUpdateOrUnchanged("department", name, fields, before, after),
				Desired: department,
				Record:  record,
			})
		}
		if env.Prune {
			for _, record := range state.Departments {
				name := jsString(record.Get("name"))
				if !syncSome(desiredDepartments, func(item *core.Object) bool {
					return orgLower(jsString(item.Get("name"))) == orgLower(name)
				}) {
					plan.Departments = append(plan.Departments, &OrgPlanned{
						Change: syncChange("department", name, "delete", nil, nil, nil),
						Record: record,
					})
				}
			}
		}
	}

	// Teams, by slug.
	if hasTeams {
		existing := map[string]*core.Object{}
		for _, record := range state.Teams {
			existing[jsString(record.Get("slug"))] = record
		}
		slugsAfter := newOrderedSet()
		for _, record := range state.Teams {
			slug := jsString(record.Get("slug"))
			if !env.Prune || syncSome(desiredTeams, func(item *core.Object) bool { return jsString(item.Get("slug")) == slug }) {
				slugsAfter.Add(slug)
			}
		}
		for _, team := range desiredTeams {
			slugsAfter.Add(jsString(team.Get("slug")))
		}
		parents := map[string]string{}
		for _, record := range state.Teams {
			parent := ""
			if parentID := record.Get("parentId"); truthy(parentID) {
				for _, item := range state.Teams {
					if core.StrictEquals(item.Get("id"), parentID) {
						parent = jsString(item.Get("slug"))
						break
					}
				}
			}
			parents[jsString(record.Get("slug"))] = parent
		}
		for _, team := range desiredTeams {
			slug := jsString(team.Get("slug"))
			where := "Team " + slug
			if parent, ok := team.Get("parent").(string); ok && !slugsAfter.Has(parent) {
				return nil, invalidInput(where + ": unknown parent " + parent)
			}
			if department, ok := team.Get("department").(string); ok && !departmentNamesAfter.Has(orgLower(department)) {
				return nil, invalidInput(where + ": unknown department " + department)
			}
			for _, email := range append(syncStringList(team.Get("maintainers")), syncStringList(team.Get("members"))...) {
				if _, err := person(email, where); err != nil {
					return nil, err
				}
			}
			for _, role := range syncStringList(team.Get("roles")) {
				if !env.RoleNamesAfter.Has(role) {
					return nil, invalidInput(where + ": unknown role " + role)
				}
			}
			for _, group := range syncStringList(team.Get("syncGroups")) {
				if !env.GroupNamesAfter.Has(group) {
					return nil, invalidInput(where + ": unknown sync group " + group)
				}
			}
			parent, _ := team.Get("parent").(string)
			parents[slug] = parent
		}
		for _, slug := range slugsAfter.Values() {
			seen := newOrderedSet()
			for cursor := slug; cursor != ""; cursor = parents[cursor] {
				if seen.Has(cursor) {
					return nil, invalidInput("Team " + slug + ": the parents form a cycle")
				}
				seen.Add(cursor)
			}
		}
		for _, team := range desiredTeams {
			slug := jsString(team.Get("slug"))
			record := existing[slug]
			after := orgDesiredTeamForm(team)
			if record == nil {
				plan.Teams = append(plan.Teams, &OrgPlanned{
					Change:  syncChange("team", slug, "create", nil, nil, after),
					Desired: team,
				})
				continue
			}
			before := orgExportedTeam(record, state, &env.OrgDirectory)
			if !after.Has("maintainers") {
				before.Delete("maintainers")
				before.Delete("members")
			}
			if isUndefined(team.Get("roles")) {
				before.Delete("roles")
			}
			if isUndefined(team.Get("syncGroups")) {
				before.Delete("syncGroups")
			}
			fields := syncDiffFields(before, after)
			if !core.StrictEquals(record.Get("name"), team.Get("name")) {
				fields = append(fields, "name")
			}
			plan.Teams = append(plan.Teams, &OrgPlanned{
				Change:  syncUpdateOrUnchanged("team", slug, fields, before, after),
				Desired: team,
				Record:  record,
			})
		}
		if env.Prune {
			for _, record := range state.Teams {
				slug := jsString(record.Get("slug"))
				if !syncSome(desiredTeams, func(item *core.Object) bool { return jsString(item.Get("slug")) == slug }) {
					plan.Teams = append(plan.Teams, &OrgPlanned{
						Change: syncChange("team", slug, "delete", nil, nil, nil),
						Record: record,
					})
				}
			}
		}
	}
	return plan, nil
}

// syncDepth is org-sync.ts depthOf: the depth of an item in a name→parent map (0 for a top-level item).
func syncDepth(parents map[string]string, key string) int {
	depth := 0
	for cursor := parents[key]; cursor != "" && depth < 50; cursor = parents[cursor] {
		depth++
	}
	return depth
}

// ApplyOrg (org-sync.ts applyOrg): Applies a planned `teams`/`departments` change set inside the configuration apply
// transaction, after roles exist and before any role is deleted. Every change is authorized like the equivalent API
// call (`allow`). `upsert` creates and updates (before access packages, whose rules may name new teams and
// departments), `delete` removes (after packages stop naming them); both for "all" (or "").
func ApplyOrg(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, plan *OrgPlan, env *SyncApplyEnv, phase string) (err error) {
	if phase == "" {
		phase = "all"
	}
	tenantID := jsString(tenant.Get("id"))
	departments, err := DepartmentMutations(server)
	if err != nil {
		return err
	}
	teams, err := TeamMutations(server)
	if err != nil {
		return err
	}
	apply := &orgApply{server: server, tx: tx, principal: principal, tenant: tenant, tenantID: tenantID, plan: plan, env: env, departments: departments, teams: teams}
	if phase != "delete" {
		if err := apply.upsert(ctx); err != nil {
			return err
		}
	}
	if phase != "upsert" {
		if err := apply.remove(ctx); err != nil {
			return err
		}
	}
	return nil
}

type orgApply struct {
	server      *ServerContext
	tx          core.IamStore
	principal   *Principal
	tenant      *core.Object
	tenantID    string
	plan        *OrgPlan
	env         *SyncApplyEnv
	departments *DepartmentMutationsResult
	teams       *TeamMutationsResult
	// teamIDs maps slugs to team IDs, including the teams this apply created.
	teamIDs map[string]string
}

// personID is `env.identitiesByEmail.get(email)!.id`.
func (a *orgApply) personID(email string) (string, error) {
	identity := a.env.IdentitiesByEmail[email]
	if identity == nil {
		return "", core.NewIamError("INVALID_INPUT", "Unknown person "+email)
	}
	return jsString(identity.Get("id")), nil
}

// groupIDsOf maps group names to IDs.
func (a *orgApply) groupIDsOf(names []string) ([]any, error) {
	ids := make([]any, len(names))
	for index, name := range names {
		groupID, ok := a.env.GroupIDs[name]
		if !ok || groupID == "" {
			return nil, invalidInput("Unknown group " + name)
		}
		ids[index] = groupID
	}
	return ids, nil
}

// syncIDOrUndefined is `map.get(key)!`: the ID, or undefined when it is missing.
func syncIDOrUndefined(ids map[string]string, key string) any {
	if id, ok := ids[key]; ok {
		return id
	}
	return core.Undefined
}

func (a *orgApply) upsert(ctx context.Context) error {
	tx, tenantID, principal, tenant := a.tx, a.tenantID, a.principal, a.tenant
	// Departments: creates top-down, then updates, then people.
	records, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	departmentIDs := map[string]string{}
	for _, record := range records {
		departmentIDs[orgLower(jsString(record.Get("name")))] = jsString(record.Get("id"))
	}
	departmentParents := map[string]string{}
	for _, item := range a.plan.Departments {
		if item.Desired == nil {
			continue
		}
		parent := ""
		if value, ok := item.Desired.Get("parent").(string); ok {
			parent = core.JSLower(value)
		}
		departmentParents[orgLower(jsString(item.Desired.Get("name")))] = parent
	}
	var creates []*OrgPlanned
	for _, item := range a.plan.Departments {
		if syncChangeAction(item.Change) == "create" {
			creates = append(creates, item)
		}
	}
	sort.SliceStable(creates, func(i, j int) bool {
		return syncDepth(departmentParents, orgLower(jsString(creates[i].Desired.Get("name")))) <
			syncDepth(departmentParents, orgLower(jsString(creates[j].Desired.Get("name"))))
	})
	for _, item := range creates {
		desired := item.Desired
		if err := a.env.Allow(ctx, "iam:departments:manage", tenantID, "create department "+jsString(desired.Get("name"))); err != nil {
			return err
		}
		input := core.NewObject("tenantId", tenantID, "name", desired.Get("name"))
		if code := desired.Get("code"); !isUndefined(code) {
			input.Set("code", code)
		}
		if description := desired.Get("description"); !isUndefined(description) {
			input.Set("description", description)
		}
		if parent := desired.Get("parent"); !isUndefined(parent) {
			input.Set("parentId", syncIDOrUndefined(departmentIDs, orgLower(jsString(parent))))
		}
		if head := desired.Get("head"); !isUndefined(head) {
			headID, err := a.personID(jsString(head))
			if err != nil {
				return err
			}
			input.Set("headId", headID)
		}
		if costCenter := desired.Get("costCenter"); !isUndefined(costCenter) {
			input.Set("costCenter", costCenter)
		}
		created, err := a.departments.CreateDepartment(ctx, tx, principal, tenant, input)
		if err != nil {
			return err
		}
		departmentIDs[orgLower(jsString(created.Get("name")))] = jsString(created.Get("id"))
	}
	for _, item := range a.plan.Departments {
		if syncChangeAction(item.Change) != "update" {
			continue
		}
		settings := 0
		for _, field := range syncChangeFields(item.Change) {
			if field != "members" {
				settings++
			}
		}
		if settings == 0 {
			continue
		}
		desired, record := item.Desired, item.Record
		if err := a.env.Allow(ctx, "iam:departments:manage", jsString(record.Get("id")), "update department "+syncChangeName(item.Change)); err != nil {
			return err
		}
		var parentID any = nil
		if parent := desired.Get("parent"); !isUndefined(parent) {
			parentID = syncIDOrUndefined(departmentIDs, orgLower(jsString(parent)))
		}
		var headID any = nil
		if head := desired.Get("head"); !isUndefined(head) {
			id, err := a.personID(jsString(head))
			if err != nil {
				return err
			}
			headID = id
		}
		if _, err := a.departments.UpdateDepartment(ctx, tx, principal, tenant, core.NewObject(
			"tenantId", tenantID,
			"departmentId", record.Get("id"),
			"name", desired.Get("name"),
			"code", coalesce(desired.Get("code"), nil),
			"description", coalesce(desired.Get("description"), nil),
			"parentId", parentID,
			"headId", headID,
			"costCenter", coalesce(desired.Get("costCenter"), nil),
		)); err != nil {
			return err
		}
	}
	for _, item := range a.plan.Departments {
		action := syncChangeAction(item.Change)
		if action == "delete" || action == "unchanged" {
			continue
		}
		desired := item.Desired
		if isUndefined(desired.Get("members")) {
			continue
		}
		if action == "update" && !containsString(syncChangeFields(item.Change), "members") {
			continue
		}
		departmentID := departmentIDs[orgLower(jsString(desired.Get("name")))]
		department, err := tx.Get(ctx, DepartmentCollections.Departments, departmentID)
		if err != nil {
			return err
		}
		if err := a.env.Allow(ctx, "iam:departments:manage", departmentID, "place people in "+syncChangeName(item.Change)); err != nil {
			return err
		}
		wanted := newOrderedSet()
		for _, email := range syncStringList(desired.Get("members")) {
			identityID, err := a.personID(email)
			if err != nil {
				return err
			}
			wanted.Add(identityID)
		}
		placements, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID, "departmentId", departmentID), nil)
		if err != nil {
			return err
		}
		for _, placement := range placements {
			identityID := jsString(placement.Get("identityId"))
			if wanted.Has(identityID) {
				continue
			}
			if err := tx.Delete(ctx, DepartmentCollections.Members, jsString(placement.Get("id"))); err != nil {
				return err
			}
			if err := a.server.Events.Audit(ctx, tx, principal, "department:unassign", tenantID, departmentID, "allow", false,
				core.NewObject("identityId", placement.Get("identityId"))); err != nil {
				return err
			}
		}
		for _, identityID := range wanted.Values() {
			identity, err := a.departments.DepartmentPerson(ctx, tx, tenantID, identityID)
			if err != nil {
				return err
			}
			current, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID, "uniqueKey", "identity:"+identityID), nil)
			if err != nil {
				return err
			}
			if len(current) == 0 || !core.StrictEquals(current[0].Get("departmentId"), departmentID) {
				if _, err := a.departments.Place(ctx, tx, principal, department, identity, ""); err != nil {
					return err
				}
			}
		}
	}

	// Teams: creates top-down, then settings, then members and roles.
	teamRecords, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	teamIDs := map[string]string{}
	for _, record := range teamRecords {
		teamIDs[jsString(record.Get("slug"))] = jsString(record.Get("id"))
	}
	a.teamIDs = teamIDs
	teamParents := map[string]string{}
	for _, item := range a.plan.Teams {
		if item.Desired == nil {
			continue
		}
		parent, _ := item.Desired.Get("parent").(string)
		teamParents[jsString(item.Desired.Get("slug"))] = parent
	}
	var teamCreates []*OrgPlanned
	for _, item := range a.plan.Teams {
		if syncChangeAction(item.Change) == "create" {
			teamCreates = append(teamCreates, item)
		}
	}
	sort.SliceStable(teamCreates, func(i, j int) bool {
		return syncDepth(teamParents, jsString(teamCreates[i].Desired.Get("slug"))) <
			syncDepth(teamParents, jsString(teamCreates[j].Desired.Get("slug")))
	})
	for _, item := range teamCreates {
		desired := item.Desired
		slug := jsString(desired.Get("slug"))
		if err := a.env.Allow(ctx, "iam:teams:create", tenantID, "create team "+slug); err != nil {
			return err
		}
		input := core.NewObject("tenantId", tenantID, "name", desired.Get("name"), "slug", desired.Get("slug"))
		if description := desired.Get("description"); !isUndefined(description) {
			input.Set("description", description)
		}
		if parent := desired.Get("parent"); !isUndefined(parent) {
			input.Set("parentId", syncIDOrUndefined(teamIDs, jsString(parent)))
		}
		if department := desired.Get("department"); !isUndefined(department) {
			input.Set("departmentId", syncIDOrUndefined(departmentIDs, orgLower(jsString(department))))
		}
		if joinPolicy := desired.Get("joinPolicy"); !isUndefined(joinPolicy) {
			input.Set("joinPolicy", joinPolicy)
		}
		if management := desired.Get("memberManagement"); !isUndefined(management) {
			input.Set("memberManagement", management)
		}
		if syncGroups := syncStringList(desired.Get("syncGroups")); len(syncGroups) > 0 {
			ids, err := a.groupIDsOf(syncGroups)
			if err != nil {
				return err
			}
			input.Set("syncGroupIds", ids)
		}
		created, err := a.teams.CreateTeam(ctx, tx, principal, tenant, input)
		if err != nil {
			return err
		}
		teamIDs[jsString(created.Get("slug"))] = jsString(created.Get("id"))
	}
	for _, item := range a.plan.Teams {
		if syncChangeAction(item.Change) != "update" {
			continue
		}
		desired := item.Desired
		fields := syncChangeFields(item.Change)
		team, err := a.current(ctx, jsString(desired.Get("slug")))
		if err != nil {
			return err
		}
		update := core.NewObject("tenantId", tenantID, "teamId", team.Get("id"))
		if containsString(fields, "name") {
			update.Set("name", desired.Get("name"))
		}
		if containsString(fields, "description") {
			update.Set("description", coalesce(desired.Get("description"), nil))
		}
		if containsString(fields, "parent") {
			var parentID any = nil
			if parent := desired.Get("parent"); !isUndefined(parent) {
				parentID = syncIDOrUndefined(teamIDs, jsString(parent))
			}
			update.Set("parentId", parentID)
		}
		if containsString(fields, "department") {
			var departmentID any = nil
			if department := desired.Get("department"); !isUndefined(department) {
				departmentID = syncIDOrUndefined(departmentIDs, orgLower(jsString(department)))
			}
			update.Set("departmentId", departmentID)
		}
		if containsString(fields, "joinPolicy") {
			update.Set("joinPolicy", coalesce(desired.Get("joinPolicy"), "closed"))
		}
		if containsString(fields, "memberManagement") {
			update.Set("memberManagement", coalesce(desired.Get("memberManagement"), "maintainers"))
		}
		if containsString(fields, "syncGroups") {
			var syncGroupIDs any = nil
			if syncGroups := syncStringList(desired.Get("syncGroups")); len(syncGroups) > 0 {
				ids, err := a.groupIDsOf(syncGroups)
				if err != nil {
					return err
				}
				syncGroupIDs = ids
			}
			update.Set("syncGroupIds", syncGroupIDs)
		}
		if update.Len() == 2 {
			continue
		}
		if err := a.env.Allow(ctx, "iam:teams:update", jsString(team.Get("id")), "update team "+syncChangeName(item.Change)); err != nil {
			return err
		}
		if _, err := a.teams.UpdateTeam(ctx, tx, principal, team, update); err != nil {
			return err
		}
	}
	for _, item := range a.plan.Teams {
		action := syncChangeAction(item.Change)
		if action == "delete" || action == "unchanged" {
			continue
		}
		if err := a.teamMembersAndRoles(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

// teamMembersAndRoles makes a created or updated team's permanent direct members and standing roles match the
// document.
func (a *orgApply) teamMembersAndRoles(ctx context.Context, item *OrgPlanned) error {
	tx, tenantID, principal := a.tx, a.tenantID, a.principal
	desired := item.Desired
	action := syncChangeAction(item.Change)
	fields := syncChangeFields(item.Change)
	name := syncChangeName(item.Change)
	team, err := a.current(ctx, jsString(desired.Get("slug")))
	if err != nil {
		return err
	}
	teamID := jsString(team.Get("id"))
	membership := (!isUndefined(desired.Get("maintainers")) || !isUndefined(desired.Get("members"))) &&
		(action == "create" || containsString(fields, "maintainers") || containsString(fields, "members"))
	if membership {
		if err := a.env.Allow(ctx, "iam:teams:update", teamID, "set the members of team "+name); err != nil {
			return err
		}
		records, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return err
		}
		all := syncByID(records)
		if err := a.teams.AssertAuthorityOver(ctx, tx, principal, tenantID, teamChain(all, teamID)); err != nil {
			return err
		}
		wantedOrder := newOrderedSet()
		wanted := map[string]string{}
		for _, email := range syncStringList(desired.Get("members")) {
			identityID, err := a.personID(email)
			if err != nil {
				return err
			}
			wantedOrder.Add(identityID)
			wanted[identityID] = "member"
		}
		for _, email := range syncStringList(desired.Get("maintainers")) {
			identityID, err := a.personID(email)
			if err != nil {
				return err
			}
			wantedOrder.Add(identityID)
			wanted[identityID] = "maintainer"
		}
		now := a.server.Now()
		members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
		if err != nil {
			return err
		}
		mutation := core.NewObject()
		mutation.SetRaw("tx", tx)
		mutation.SetRaw("principal", principal)
		mutation.SetRaw("tenant", a.tenant)
		mutation.SetRaw("team", team)
		mutation.SetRaw("via", "permission")
		for _, member := range members {
			if !liveTeamMember(member, now) {
				continue
			}
			identityID := jsString(member.Get("identityId"))
			role, listed := wanted[identityID]
			if !listed {
				// Temporary and synced memberships are runtime state: only permanent manual ones are removed.
				if isUndefined(member.Get("expiresAt")) && member.Get("source") != "sync" {
					if err := a.teams.RemoveMember(ctx, tx, principal, team, member, "team:member:remove", ""); err != nil {
						return err
					}
				}
				continue
			}
			delete(wanted, identityID)
			wantedOrder.Delete(identityID)
			// The document lists manual memberships: a temporary or synced member it names becomes a permanent manual one.
			if member.Get("role") == role && isUndefined(member.Get("expiresAt")) && member.Get("source") != "sync" {
				continue
			}
			// Keeping someone for good, or appointing a maintainer, of a licensed team needs iam:licenses:assign.
			if !isUndefined(member.Get("expiresAt")) || member.Get("source") == "sync" || (role == "maintainer" && member.Get("role") != "maintainer") {
				if err := a.teams.AssertMayClaimTeamLicenses(ctx, tx, principal, tenantID, teamChain(all, teamID)); err != nil {
					return err
				}
			}
			rest := member.Spread()
			rest.Delete("expiresAt")
			rest.Delete("source")
			rest.Set("role", role)
			if _, err := tx.Put(ctx, TeamCollections.Members, rest); err != nil {
				return err
			}
			if _, err := SyncTeamGroups(ctx, tx, tenantID, []string{teamID}, now); err != nil {
				return err
			}
			if err := a.server.Events.Audit(ctx, tx, principal, "team:member:update", tenantID, teamID, "allow", false, core.NewObject(
				"team", team.Get("slug"),
				"identityId", member.Get("identityId"),
				"role", role,
				"source", "config",
			)); err != nil {
				return err
			}
		}
		for _, identityID := range wantedOrder.Values() {
			if _, err := a.teams.PutMember(ctx, mutation, core.NewObject("identityId", identityID, "role", wanted[identityID]), "config"); err != nil {
				return err
			}
		}
		// License seats of the team's chain follow its members in this transaction, as with groups (licenses.ts).
		chain := teamChain(all, teamID)
		groupIDs := make([]string, len(chain))
		for index, link := range chain {
			groupIDs[index] = jsString(link.Get("groupId"))
		}
		if _, err := ReconcileGroupLicenses(ctx, a.server, tx, tenantID, groupIDs, principal); err != nil {
			return err
		}
	}
	roles := !isUndefined(desired.Get("roles")) && (action == "create" || containsString(fields, "roles"))
	if !roles {
		return nil
	}
	wantedRoles := newOrderedSet()
	for _, roleName := range syncStringList(desired.Get("roles")) {
		roleID, ok := a.env.RoleIDs[roleName]
		if !ok || roleID == "" {
			return invalidInput("Team " + name + ": unknown role " + roleName)
		}
		wantedRoles.Add(roleID)
	}
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", team.Get("groupId")), nil)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if !orgStandingBinding(binding) {
			continue
		}
		roleID := jsString(binding.Get("roleId"))
		if wantedRoles.Has(roleID) {
			wantedRoles.Delete(roleID)
			continue
		}
		if err := a.env.Allow(ctx, "iam:bindings:delete", jsString(binding.Get("id")), "remove a role from team "+name); err != nil {
			return err
		}
		if err := DeleteBinding(ctx, a.server, tx, principal, binding); err != nil {
			return err
		}
	}
	for _, roleID := range wantedRoles.Values() {
		if err := a.env.Allow(ctx, "iam:bindings:create", roleID, "give team "+name+" a role"); err != nil {
			return err
		}
		if _, err := CreateBinding(ctx, a.server, tx, principal, core.NewObject(
			"tenantId", tenantID,
			"roleId", roleID,
			"subjectType", "group",
			"subjectId", team.Get("groupId"),
		), nil); err != nil {
			return err
		}
	}
	return nil
}

// current is `(await tx.get(teamCollections.teams, teamIds.get(slug)!))!`: a team's current record.
func (a *orgApply) current(ctx context.Context, slug string) (*core.Object, error) {
	team, err := a.tx.Get(ctx, TeamCollections.Teams, a.teamIDs[slug])
	if err != nil {
		return nil, err
	}
	if team == nil {
		return nil, core.NewIamError("NOT_FOUND", "Team not found", 404)
	}
	return team, nil
}

func (a *orgApply) remove(ctx context.Context) error {
	tx, tenantID, principal, tenant := a.tx, a.tenantID, a.principal, a.tenant
	// Deletions, lowest teams and departments first.
	teamRecords, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	allTeams := syncByID(teamRecords)
	var teamDeletes []*OrgPlanned
	for _, item := range a.plan.Teams {
		if syncChangeAction(item.Change) == "delete" {
			teamDeletes = append(teamDeletes, item)
		}
	}
	sort.SliceStable(teamDeletes, func(i, j int) bool {
		return len(teamChain(allTeams, jsString(teamDeletes[j].Record.Get("id")))) <
			len(teamChain(allTeams, jsString(teamDeletes[i].Record.Get("id"))))
	})
	for _, item := range teamDeletes {
		recordID := jsString(item.Record.Get("id"))
		if err := a.env.Allow(ctx, "iam:teams:delete", recordID, "delete team "+syncChangeName(item.Change)); err != nil {
			return err
		}
		team, err := tx.Get(ctx, TeamCollections.Teams, recordID)
		if err != nil {
			return err
		}
		if team != nil {
			if _, err := a.teams.DeleteTeam(ctx, tx, principal, team); err != nil {
				return err
			}
		}
	}
	departmentRecords, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	allDepartments := syncByID(departmentRecords)
	var departmentDeletes []*OrgPlanned
	for _, item := range a.plan.Departments {
		if syncChangeAction(item.Change) == "delete" {
			departmentDeletes = append(departmentDeletes, item)
		}
	}
	sort.SliceStable(departmentDeletes, func(i, j int) bool {
		return len(departmentChain(allDepartments, jsString(departmentDeletes[j].Record.Get("id")))) <
			len(departmentChain(allDepartments, jsString(departmentDeletes[i].Record.Get("id"))))
	})
	for _, item := range departmentDeletes {
		recordID := jsString(item.Record.Get("id"))
		if err := a.env.Allow(ctx, "iam:departments:manage", recordID, "delete department "+syncChangeName(item.Change)); err != nil {
			return err
		}
		if _, err := a.departments.DeleteDepartment(ctx, tx, principal, tenant, core.NewObject("tenantId", tenantID, "departmentId", recordID)); err != nil {
			return err
		}
	}
	return nil
}
