package server

// Port of packages/server/src/org-insights.ts: birthright suggestions. Access most people of a department (or team)
// already hold by hand, proposed as an automatic access package whose rule names that department (or team). The
// population of a unit is exactly who such a rule would match: active people whose `identity.departments` (or
// `identity.teams`) includes it, so a department counts the people of the departments below it. Only plain grants
// count: standing, permanent role bindings made directly to the person, and permanent memberships of ordinary groups,
// neither created by an access package. What most of a unit already receives from an automatic package, or is
// suggested for a unit above it, is never suggested again.

import (
	"context"
	"math"
	"slices"

	"github.com/Better-IAM/better-iam/go/core"
)

// birthrightRuleKey is org-insights.ts ruleKey.
var birthrightRuleKey = map[string]string{"department": "identity.departments", "team": "identity.teams"}

// BirthrightOptions (org-insights.ts birthrightOptions): Validates the API input of the `suggestBirthright` methods.
// The result is `{ minShare, minPeople }`.
func BirthrightOptions(input *core.Object) (*core.Object, error) {
	minShareValue := coalesce(member(input, "minShare"), 0.8)
	minShare, ok := minShareValue.(float64)
	if !ok || math.IsNaN(minShare) || math.IsInf(minShare, 0) || minShare < 0.5 || minShare > 1 {
		return nil, invalidInput("minShare must be between 0.5 and 1")
	}
	minPeople, err := Integer(coalesce(member(input, "minPeople"), 3.0), "minPeople", 2, 100_000)
	if err != nil {
		return nil, err
	}
	return core.NewObject("minShare", minShare, "minPeople", minPeople), nil
}

// birthrightHeld is a `Map<string, Set<string>>` (identity → item IDs).
type birthrightHeld map[string]*orderedSet

func (m birthrightHeld) add(identityID, itemID string) {
	set := m[identityID]
	if set == nil {
		set = newOrderedSet()
		m[identityID] = set
	}
	set.Add(itemID)
}

// birthrightCounts is a `Map<string, number>` in insertion order.
type birthrightCounts struct {
	keys   []string
	counts map[string]int
}

// orgSlice16 is `text.slice(0, max)` (UTF-16 code units).
func orgSlice16(text string, max int) string {
	units := core.ToUTF16(text)
	if len(units) <= max {
		return text
	}
	return core.FromUTF16(units[:max])
}

// SuggestBirthright (org-insights.ts suggestBirthright): suggestions for every unit of `kind` (`department` or
// `team`). Options: `{ unitId?, minShare, minPeople }` (BirthrightOptions).
func SuggestBirthright(ctx context.Context, server *ServerContext, reader core.IamStore, tenantID string, kind string, options *core.Object) ([]*core.Object, error) {
	now := server.Now()
	minShare := jsNumber(member(options, "minShare"))
	minPeople := jsNumber(member(options, "minPeople"))
	unitID, _ := member(options, "unitId").(string)
	tenantFilter := func() *core.Object { return core.NewObject("tenantId", tenantID) }
	// Sequential reads: a transaction holds one database connection.
	identities, err := reader.Find(ctx, "identities", tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	var people []*core.Object
	for _, identity := range identities {
		if orgString(identity, "kind") == "user" && orgString(identity, "status") == "active" && !server.IdentityExpired(identity) {
			people = append(people, identity)
		}
	}
	roleRecords, err := reader.Find(ctx, "roles", tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	roles, _ := orgByID(roleRecords)
	groupRecords, err := reader.Find(ctx, "groups", tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	groups, _ := orgByID(groupRecords)
	bindings, err := reader.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity"), nil)
	if err != nil {
		return nil, err
	}
	memberships, err := reader.Find(ctx, "groupMembers", tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	packages, err := reader.Find(ctx, "accessPackages", tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	// Assignments an automatic package made: what they grant is birthright access already.
	assignments, err := reader.Find(ctx, "packageAssignments", tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	automatic := map[string]bool{}
	for _, assignment := range assignments {
		if !isUndefined(assignment.Get("ruleRevision")) {
			automatic[orgString(assignment, "id")] = true
		}
	}
	org, err := LoadOrgFacts(ctx, reader, tenantID, now)
	if err != nil {
		return nil, err
	}
	collection := TeamCollections.Teams
	if kind == "department" {
		collection = DepartmentCollections.Departments
	}
	unitRecords, err := reader.Find(ctx, collection, tenantFilter(), nil)
	if err != nil {
		return nil, err
	}
	units, unitOrder := orgByID(unitRecords)
	chainOf := func(id string) []string {
		var chain []*core.Object
		if kind == "department" {
			chain = departmentChain(units, id)
		} else {
			chain = teamChain(units, id)
		}
		return orgIDs(chain)
	}

	// What each person holds by hand, and which units a rule would see them in.
	heldRoles, heldGroups := birthrightHeld{}, birthrightHeld{}
	autoRoles, autoGroups := birthrightHeld{}, birthrightHeld{}
	automaticAssignment := func(record *core.Object) bool {
		assignmentID, ok := record.Get("packageAssignmentId").(string)
		return ok && automatic[assignmentID]
	}
	for _, binding := range bindings {
		role := roles[orgString(binding, "roleId")]
		subjectID := orgString(binding, "subjectId")
		if role != nil && automaticAssignment(binding) && server.LiveBinding(binding) {
			autoRoles.add(subjectID, orgString(role, "id"))
		}
		if role == nil || truthy(role.Get("protected")) || !server.LiveBinding(binding) ||
			binding.Get("eligible") == true ||
			!isUndefined(binding.Get("window")) ||
			!isUndefined(binding.Get("startsAt")) ||
			!isUndefined(binding.Get("expiresAt")) ||
			!isUndefined(binding.Get("packageAssignmentId")) {
			continue
		}
		heldRoles.add(subjectID, orgString(role, "id"))
	}
	directGroups := map[string][]string{}
	for _, membership := range memberships {
		identityID := orgString(membership, "identityId")
		groupID := orgString(membership, "groupId")
		if automaticAssignment(membership) && server.LiveMembership(membership) {
			autoGroups.add(identityID, groupID)
		}
		if !isUndefined(membership.Get("packageAssignmentId")) || !server.LiveMembership(membership) {
			continue
		}
		directGroups[identityID] = append(directGroups[identityID], groupID)
		group := groups[groupID]
		if group == nil || !isUndefined(group.Get("teamId")) || !isUndefined(membership.Get("expiresAt")) {
			continue
		}
		heldGroups.add(identityID, orgString(group, "id"))
	}
	population := map[string][]*core.Object{}
	factsKey := "teams"
	if kind == "department" {
		factsKey = "departments"
	}
	for _, person := range people {
		personID := orgString(person, "id")
		facts, err := org.Of(personID, directGroups[personID])
		if err != nil {
			return nil, err
		}
		for _, id := range orgStrings(facts, factsKey) {
			population[id] = append(population[id], person)
		}
	}

	// Top-down, so a unit never repeats what is suggested for a unit above it.
	ordered := append([]*core.Object(nil), unitOrder...)
	slices.SortStableFunc(ordered, func(a, b *core.Object) int {
		if delta := len(chainOf(orgString(a, "id"))) - len(chainOf(orgString(b, "id"))); delta != 0 {
			return delta
		}
		return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
	})
	type unitSuggested struct{ roles, groups *orderedSet }
	suggested := map[string]unitSuggested{}
	result := []*core.Object{}
	ruleKey := birthrightRuleKey[kind]
	for _, unit := range ordered {
		id := orgString(unit, "id")
		name := jsString(unit.Get("name"))
		members := population[id]
		chain := chainOf(id)
		above := chain[1:]
		inheritedRoles, inheritedGroups := newOrderedSet(), newOrderedSet()
		for _, aboveID := range above {
			if entry, ok := suggested[aboveID]; ok {
				for _, roleID := range entry.roles.Values() {
					inheritedRoles.Add(roleID)
				}
			}
		}
		for _, aboveID := range above {
			if entry, ok := suggested[aboveID]; ok {
				for _, groupID := range entry.groups.Values() {
					inheritedGroups.Add(groupID)
				}
			}
		}
		var existing []*core.Object
		for _, pkg := range packages {
			rule, _ := pkg.Get("autoAssign").(*core.Object)
			values, err := RuleValues(rule, ruleKey)
			if err != nil {
				return nil, err
			}
			if slices.ContainsFunc(values, func(value string) bool { return slices.Contains(chain, value) }) {
				existing = append(existing, pkg)
			}
		}
		coveredRoles, coveredGroups := newOrderedSet(), newOrderedSet()
		for _, pkg := range existing {
			for _, roleID := range orgStrings(pkg, "roleIds") {
				coveredRoles.Add(roleID)
			}
		}
		for _, pkg := range existing {
			for _, groupID := range orgStrings(pkg, "groupIds") {
				coveredGroups.Add(groupID)
			}
		}
		if float64(len(members)) < minPeople {
			continue
		}
		tally := func(held birthrightHeld) *birthrightCounts {
			counts := &birthrightCounts{counts: map[string]int{}}
			for _, person := range members {
				for _, itemID := range held[orgString(person, "id")].Values() {
					if _, known := counts.counts[itemID]; !known {
						counts.keys = append(counts.keys, itemID)
					}
					counts.counts[itemID]++
				}
			}
			return counts
		}
		share := func(count int) bool { return float64(count)/float64(len(members)) >= minShare }
		// Items most of the unit already receives from some automatic package are birthright access already.
		already := func(counts *birthrightCounts) []string {
			var items []string
			for _, itemID := range counts.keys {
				if share(counts.counts[itemID]) {
					items = append(items, itemID)
				}
			}
			return items
		}
		type birthrightItem struct {
			id      string
			name    string
			holders int
			share   float64
		}
		pick := func(counts *birthrightCounts, skip *orderedSet, nameOf func(itemID string) string) []birthrightItem {
			var items []birthrightItem
			for _, itemID := range counts.keys {
				holders := counts.counts[itemID]
				if skip.Has(itemID) || !share(holders) {
					continue
				}
				items = append(items, birthrightItem{
					id:      itemID,
					name:    nameOf(itemID),
					holders: holders,
					share:   math.Floor(float64(holders)/float64(len(members))*100+0.5) / 100,
				})
			}
			slices.SortStableFunc(items, func(a, b birthrightItem) int {
				if delta := b.holders - a.holders; delta != 0 {
					return delta
				}
				return localeCompare(a.name, b.name)
			})
			return items
		}
		roleSkip := newOrderedSet(append(append(coveredRoles.Values(), inheritedRoles.Values()...), already(tally(autoRoles))...)...)
		roleItems := pick(tally(heldRoles), roleSkip, func(roleID string) string { return jsString(roles[roleID].Get("name")) })
		groupSkip := newOrderedSet(append(append(coveredGroups.Values(), inheritedGroups.Values()...), already(tally(autoGroups))...)...)
		groupItems := pick(tally(heldGroups), groupSkip, func(groupID string) string { return jsString(groups[groupID].Get("name")) })
		entry := unitSuggested{roles: newOrderedSet(), groups: newOrderedSet()}
		for _, item := range roleItems {
			entry.roles.Add(item.id)
		}
		for _, item := range groupItems {
			entry.groups.Add(item.id)
		}
		suggested[id] = entry
		if len(roleItems) == 0 && len(groupItems) == 0 {
			continue
		}
		wouldGrant := 0
		for _, person := range members {
			personID := orgString(person, "id")
			lacks := slices.ContainsFunc(roleItems, func(item birthrightItem) bool { return !heldRoles[personID].Has(item.id) }) ||
				slices.ContainsFunc(groupItems, func(item birthrightItem) bool { return !heldGroups[personID].Has(item.id) })
			if lacks {
				wouldGrant++
			}
		}
		itemList := func(items []birthrightItem) []any {
			out := make([]any, 0, len(items))
			for _, item := range items {
				out = append(out, core.NewObject("id", item.id, "name", item.name, "holders", item.holders, "share", item.share))
			}
			return out
		}
		itemIDs := func(items []birthrightItem) []any {
			out := make([]any, 0, len(items))
			for _, item := range items {
				out = append(out, item.id)
			}
			return out
		}
		existingNames := make([]string, 0, len(existing))
		for _, pkg := range existing {
			existingNames = append(existingNames, jsString(pkg.Get("name")))
		}
		slices.SortStableFunc(existingNames, localeCompare)
		label, below := "team", " and the teams below it"
		if kind == "department" {
			label, below = "department", " and the departments below it"
		}
		result = append(result, core.NewObject(
			"unit", core.NewObject("kind", kind, "id", id, "name", unit.Get("name")),
			"people", len(members),
			"roles", itemList(roleItems),
			"groups", itemList(groupItems),
			"wouldGrant", wouldGrant,
			"existingPackages", stringsOf(existingNames),
			"package", core.NewObject(
				"name", orgSlice16(name+" "+label+" basics", 100),
				"description", "Birthright access for everyone in the "+name+" "+kind+below+".",
				"roleIds", itemIDs(roleItems),
				"groupIds", itemIDs(groupItems),
				"autoAssign", core.NewObject("include", []any{
					core.NewObject(
						"StringEquals", core.NewObject("principal.kind", "user"),
						"ArrayContains", core.NewObject(ruleKey, []any{id}),
					),
				}),
			),
		))
	}
	if unitID != "" {
		result = slices.DeleteFunc(result, func(item *core.Object) bool {
			return orgString(item.Get("unit").(*core.Object), "id") != unitID
		})
	}
	slices.SortStableFunc(result, func(a, b *core.Object) int {
		if delta := jsNumber(b.Get("people")) - jsNumber(a.Get("people")); delta != 0 {
			if delta < 0 {
				return -1
			}
			return 1
		}
		return localeCompare(jsString(member(a.Get("unit"), "name")), jsString(member(b.Get("unit"), "name")))
	})
	return result, nil
}
