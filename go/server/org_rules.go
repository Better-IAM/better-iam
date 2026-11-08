package server

// Port of packages/server/src/org-rules.ts: the org structure as birthright rules (access package rules) see it:
// `identity.teams`, the teams a person belongs to with every team above them, and `identity.departments`, their
// department with every department above it (the same sets as the policy keys `principal.teams` and
// `principal.departments`). A synced team membership counts only while the person is in one of the team's source
// groups by a membership no access package created, so a rule never feeds on what a package granted (identity.groups
// follows the same rule).

import (
	"context"
	"slices"

	"github.com/Better-IAM/better-iam/go/core"
)

// TenantOrgFacts is org-rules.ts TenantOrgFacts: a tenant's teams and departments, read once, answering
// identity.teams / identity.departments per person.
type TenantOrgFacts struct {
	server        *ServerContext
	TeamIDs       []string
	DepartmentIDs []string
	// LicenseKeys The keys of the license products visible to the tenant: the valid identity.licenses values (licenses.ts).
	LicenseKeys []string

	teams       map[string]*core.Object
	members     map[string][]*core.Object
	departments map[string]*core.Object
	placements  map[string]string
	licenses    *TenantLicenseFacts
}

// Of (org-rules.ts TenantOrgFacts.of): What a rule sees for one person, given their live memberships no access
// package created: `{ teams, departments, licenses }` (RuleOrgFacts).
func (s *TenantOrgFacts) Of(identityID string, directGroupIDs []string) (*core.Object, error) {
	direct := newOrderedSet(directGroupIDs...)
	teamIDs := newOrderedSet()
	for _, record := range s.members[identityID] {
		team := s.teams[orgString(record, "teamId")]
		if team == nil {
			continue
		}
		if orgString(record, "source") == "sync" &&
			!slices.ContainsFunc(orgStrings(team, "syncGroupIds"), direct.Has) {
			continue
		}
		for _, link := range teamChain(s.teams, orgString(team, "id")) {
			teamIDs.Add(orgString(link, "id"))
		}
	}
	departmentID, placed := s.placements[identityID]
	// Seats held through groups count through the same memberships, a counted team's backing group included.
	licenseGroups := newOrderedSet(direct.Values()...)
	for _, teamID := range teamIDs.Values() {
		if groupID := orgString(s.teams[teamID], "groupId"); groupID != "" {
			licenseGroups.Add(groupID)
		}
	}
	teams := teamIDs.Values()
	slices.SortStableFunc(teams, compareUTF16)
	departments := []string{}
	if placed && departmentID != "" {
		for _, department := range departmentChain(s.departments, departmentID) {
			departments = append(departments, orgString(department, "id"))
		}
		slices.SortStableFunc(departments, compareUTF16)
	}
	licenses, err := s.licenses.Of(identityID, licenseGroups.Values())
	if err != nil {
		return nil, err
	}
	return core.NewObject(
		"teams", stringsOf(teams),
		"departments", stringsOf(departments),
		"licenses", stringsOf(licenses),
	), nil
}

// LoadOrgFacts (org-rules.ts loadOrgFacts): reads a tenant's teams, live team memberships, departments, department
// placements and license facts once.
func LoadOrgFacts(ctx context.Context, reader core.IamStore, tenantID string, now int64) (*TenantOrgFacts, error) {
	teamRecords, err := reader.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	teams, teamOrder := orgByID(teamRecords)
	memberRecords, err := reader.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	members := map[string][]*core.Object{}
	for _, record := range memberRecords {
		if liveTeamMember(record, now) {
			identityID := orgString(record, "identityId")
			members[identityID] = append(members[identityID], record)
		}
	}
	departmentRecords, err := reader.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	departments, departmentOrder := orgByID(departmentRecords)
	placementRecords, err := reader.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	placements := map[string]string{}
	for _, placement := range placementRecords {
		placements[orgString(placement, "identityId")] = orgString(placement, "departmentId")
	}
	licenses, err := LoadLicenseFacts(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	facts := &TenantOrgFacts{
		TeamIDs:       orgIDs(teamOrder),
		DepartmentIDs: orgIDs(departmentOrder),
		LicenseKeys:   licenses.Keys,
		teams:         teams,
		members:       members,
		departments:   departments,
		placements:    placements,
		licenses:      licenses,
	}
	return facts, nil
}

// orgIDs is the `id` of each record.
func orgIDs(records []*core.Object) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, orgString(record, "id"))
	}
	return ids
}

// OrgRuleEnvironment (org-rules.ts orgRuleEnvironment): The valid identity.teams and identity.departments values of
// a tenant: its team and department IDs; and the valid identity.licenses values, the keys of the license products it
// can use. The result is `{ teams, departments, licenses }`, each a list of distinct IDs (TypeScript Sets).
func OrgRuleEnvironment(ctx context.Context, reader core.IamStore, tenantID string) (*core.Object, error) {
	teams, err := reader.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	departments, err := reader.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	licenses, err := LicenseRuleKeys(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	return core.NewObject(
		"teams", stringsOf(unique(orgIDs(teams))),
		"departments", stringsOf(unique(orgIDs(departments))),
		"licenses", stringsOf(unique(licenses)),
	), nil
}

// PackagesNaming (org-rules.ts packagesNaming): The names of the tenant's access packages whose rule names one of
// `ids` under `key` (a team's backing group under identity.groups counts for the team). Teams and departments stay
// while a rule names them, like groups.
func PackagesNaming(ctx context.Context, reader core.IamStore, tenantID string, key string, ids []string, backingGroupIDs []string) ([]string, error) {
	wanted := newOrderedSet(ids...)
	groups := newOrderedSet(backingGroupIDs...)
	packages, err := reader.Find(ctx, "accessPackages", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, pkg := range packages {
		rule, _ := pkg.Get("autoAssign").(*core.Object)
		values, err := RuleValues(rule, key)
		if err != nil {
			return nil, err
		}
		named := slices.ContainsFunc(values, wanted.Has)
		if !named {
			groupValues, err := RuleValues(rule, "identity.groups")
			if err != nil {
				return nil, err
			}
			named = slices.ContainsFunc(groupValues, groups.Has)
		}
		if named {
			names = append(names, jsString(pkg.Get("name")))
		}
	}
	slices.SortStableFunc(names, localeCompare)
	return names, nil
}
