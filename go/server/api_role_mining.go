package server

// Port of packages/server/src/api/role-mining.ts: role mining. Reads who holds which roles and suggests simpler ways
// to grant the same access (role combinations to bundle into access packages, roles every member of a group holds
// directly, direct bindings a group already covers, and roles that duplicate each other) plus peer-group outliers:
// access a person holds that few people sharing their manager or an identity attribute hold. Read methods need
// `iam:analysis:read`; `apply` needs `iam:analysis:update` and the rights of the binding changes it makes.

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// RoleMiningAPI is the `roleMining` API group (packages/server/src/api/role-mining.ts createRoleMiningApi): every method runs through the
// operation envelope; the router maps POST {basePath}/roleMining/{method} onto it.
type RoleMiningAPI struct {
	server *ServerContext
}

// CreateRoleMiningAPI builds the `roleMining` API group.
func CreateRoleMiningAPI(server *ServerContext) *RoleMiningAPI {
	return &RoleMiningAPI{server: server}
}

// maxSeedSets is the distinct role sets considered as bundle seeds; pairwise intersections of these are the
// candidates.
const miningMaxSeedSets = 300

// maxBundles is the bundles reported at most: the ones saving the most grants (`bundlesTruncated` says when more
// qualified).
const miningMaxBundles = 2000

// miningRef is a named reference in a suggestion.
type miningRef struct {
	id   string
	name string
}

func (r miningRef) value() *core.Object { return core.NewObject("id", r.id, "name", r.name) }

func miningRefs(refs []miningRef) []any {
	out := make([]any, len(refs))
	for index, ref := range refs {
		out[index] = ref.value()
	}
	return out
}

// roleSuggestion is one way to simplify how a tenant grants access, derived from who holds what today. IDs are
// deterministic for the same condition, so `roleMining.apply` can act on a suggestion listed earlier as long as it
// still holds.
type miningSuggestion struct {
	id         string
	kind       string
	title      string
	detail     string
	roles      []miningRef
	identities []miningRef
	group      *miningRef
	bindingIDs []string
	savings    int
	applicable bool
}

func (s *miningSuggestion) value() *core.Object {
	record := core.NewObject("id", s.id, "kind", s.kind, "title", s.title, "detail", s.detail,
		"roles", miningRefs(s.roles), "identities", miningRefs(s.identities))
	if s.group != nil {
		record.Set("group", s.group.value())
	}
	if s.bindingIDs != nil {
		record.Set("bindingIds", stringsOf(s.bindingIDs))
	}
	record.Set("savings", s.savings)
	record.Set("applicable", s.applicable)
	return record
}

func miningSuggestionID(kind, key string) string { return Hash(kind + ":" + key)[:24] }

// sortedUTF16 is `[...ids].sort()`.
func miningSorted(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.SliceStable(out, func(i, j int) bool { return compareUTF16(out[i], out[j]) < 0 })
	return out
}

func miningSetKey(ids []string) string { return strings.Join(miningSorted(ids), ",") }

func miningLabel(identity *core.Object) string { return jsString(analysisLabel(identity)) }

// jsRound is Math.round (ties toward +∞).
func miningRound(value float64) float64 {
	floor := math.Floor(value)
	if value-floor >= 0.5 {
		return floor + 1
	}
	return floor
}

func miningShareRound(value float64) float64 { return miningRound(value*100) / 100 }

// miningSnapshot is what the mining reads of a tenant.
type miningSnapshot struct {
	roles        []*core.Object
	roleByID     map[string]*core.Object
	identities   []*core.Object
	identityByID map[string]*core.Object
	groups       []*core.Object
	bindings     []*core.Object
	members      []*core.Object
	packages     []*core.Object
	policies     []*core.Object
}

func miningData(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (*miningSnapshot, error) {
	byTenant := core.NewObject("tenantId", tenantID)
	data := &miningSnapshot{roleByID: map[string]*core.Object{}, identityByID: map[string]*core.Object{}}
	// Sequential reads: a transaction holds one database connection.
	var err error
	if data.roles, err = tx.Find(ctx, "roles", byTenant, nil); err != nil {
		return nil, err
	}
	identities, err := tx.Find(ctx, "identities", byTenant, nil)
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		if identity.Get("status") == "active" && !server.IdentityExpired(identity) {
			data.identities = append(data.identities, identity)
		}
	}
	if data.groups, err = tx.Find(ctx, "groups", byTenant, nil); err != nil {
		return nil, err
	}
	bindings, err := tx.Find(ctx, "bindings", byTenant, nil)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if server.LiveBinding(binding) {
			data.bindings = append(data.bindings, binding)
		}
	}
	members, err := tx.Find(ctx, "groupMembers", byTenant, nil)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if server.LiveMembership(member) {
			data.members = append(data.members, member)
		}
	}
	if data.packages, err = tx.Find(ctx, "accessPackages", byTenant, nil); err != nil {
		return nil, err
	}
	if data.policies, err = tx.Find(ctx, "policies", byTenant, nil); err != nil {
		return nil, err
	}
	for _, role := range data.roles {
		data.roleByID[jsString(role.Get("id"))] = role
	}
	for _, identity := range data.identities {
		data.identityByID[jsString(identity.Get("id"))] = identity
	}
	return data, nil
}

// unprotected is `data.roleById.get(roleId)?.protected === false`.
func (data *miningSnapshot) unprotected(roleID any) bool {
	role := data.roleByID[jsString(roleID)]
	return role != nil && role.Get("protected") == false
}

// standingBinding is an always-on grant: not just-in-time, not limited to a time window.
func miningStanding(binding *core.Object) bool {
	return binding.Get("eligible") != true && isUndefined(binding.Get("window"))
}

// plainDirect is a direct grant an administrator can safely fold into a group: standing, permanent, not owned by a
// package.
func miningPlainDirect(binding *core.Object) bool {
	return binding.Get("subjectType") == "identity" && miningStanding(binding) && isUndefined(binding.Get("expiresAt")) &&
		isUndefined(binding.Get("startsAt")) && isUndefined(binding.Get("packageAssignmentId"))
}

// heldRoles is the role IDs each active identity holds, directly or through groups (`eligible` includes just-in-time
// bindings), keyed by identity ID; order lists the identities in snapshot order.
func miningHeldRoles(data *miningSnapshot, eligible bool) (map[string]*orderedSet, []string) {
	// Members by group, so a group binding reaches its members without a pass over everyone.
	membersOf := map[string][]string{}
	for _, member := range data.members {
		groupID := jsString(member.Get("groupId"))
		membersOf[groupID] = append(membersOf[groupID], jsString(member.Get("identityId")))
	}
	held := map[string]*orderedSet{}
	var order []string
	for _, identity := range data.identities {
		id := jsString(identity.Get("id"))
		if _, ok := held[id]; !ok {
			order = append(order, id)
		}
		held[id] = newOrderedSet()
	}
	for _, binding := range data.bindings {
		if !eligible && !miningStanding(binding) {
			continue
		}
		if !data.unprotected(binding.Get("roleId")) {
			continue
		}
		roleID := jsString(binding.Get("roleId"))
		if binding.Get("subjectType") == "identity" {
			if set := held[jsString(binding.Get("subjectId"))]; set != nil {
				set.Add(roleID)
			}
		} else {
			for _, identityID := range membersOf[jsString(binding.Get("subjectId"))] {
				if set := held[identityID]; set != nil {
					set.Add(roleID)
				}
			}
		}
	}
	return held, order
}

func (data *miningSnapshot) policyByID() map[string]*core.Object {
	byID := map[string]*core.Object{}
	for _, policy := range data.policies {
		byID[jsString(policy.Get("id"))] = policy
	}
	return byID
}

// walkRoleDocuments visits the documents of a role and of the roles it inherits (each role once).
func (data *miningSnapshot) walkRoleDocuments(role *core.Object, visit func(document any)) {
	policyByID := data.policyByID()
	seen := map[string]bool{}
	var walk func(current *core.Object)
	walk = func(current *core.Object) {
		id := jsString(current.Get("id"))
		if seen[id] {
			return
		}
		seen[id] = true
		visit(current.Get("document"))
		for _, policyID := range stringList(current.Get("policyIds")) {
			if policy := policyByID[policyID]; policy != nil {
				visit(policy.Get("document"))
			} else {
				visit(core.Undefined)
			}
		}
		for _, parent := range stringList(current.Get("inherits")) {
			if inherited := data.roleByID[parent]; inherited != nil {
				walk(inherited)
			}
		}
	}
	walk(role)
}

// grantKey is the statements a role grants (inline, attached policies, inherited roles), as a canonical comparable
// key.
func miningGrantKey(data *miningSnapshot, role *core.Object) string {
	statements := newOrderedSet()
	data.walkRoleDocuments(role, func(document any) {
		for _, statement := range analysisStatements(document) {
			statements.Add(core.CanonicalJSON(miningNormalizeStatement(statement)))
		}
	})
	return strings.Join(miningSorted(statements.Values()), "\n")
}

// normalizeStatement drops statement fields that do not change what it grants; action and resource order is
// irrelevant.
func miningNormalizeStatement(statement *core.Object) *core.Object {
	rest := statement.Spread()
	rest.Delete("sid")
	rest.Set("actions", stringsOf(miningSorted(stringList(statement.Get("actions")))))
	rest.Set("resources", stringsOf(miningSorted(stringList(statement.Get("resources")))))
	return rest
}

// roleActions is the known actions a role can allow somewhere (its own, attached, and inherited allow statements).
// Resources and conditions are not considered: this is what the role could grant, compared with what its holders
// used.
func miningRoleActions(data *miningSnapshot, role *core.Object, known []string) []string {
	patterns := newOrderedSet()
	data.walkRoleDocuments(role, func(document any) {
		for _, statement := range analysisStatements(document) {
			if statement.Get("effect") == "allow" {
				for _, action := range stringList(statement.Get("actions")) {
					patterns.Add(action)
				}
			}
		}
	})
	list := patterns.Values()
	out := []string{}
	for _, action := range known {
		for _, pattern := range list {
			if core.MatchPattern(pattern, action, nil) {
				out = append(out, action)
				break
			}
		}
	}
	return out
}

type miningSettings struct {
	minIdentities int
	minRoles      int
}

// orderedStrings is a JavaScript Map from a string key to a role list: set keeps the first position.
type miningOrderedStrings struct {
	keys   []string
	values map[string][]string
}

func (m *miningOrderedStrings) set(key string, value []string) {
	if m.values == nil {
		m.values = map[string][]string{}
	}
	if _, ok := m.values[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
}

func miningMine(data *miningSnapshot, settings miningSettings) ([]*miningSuggestion, bool, error) {
	suggestions := []*miningSuggestion{}
	roleRef := func(roleID string) miningRef {
		if role := data.roleByID[roleID]; role != nil {
			return miningRef{id: roleID, name: jsString(coalesce(role.Get("name"), roleID))}
		}
		return miningRef{id: roleID, name: roleID}
	}
	identityRef := func(identityID string) miningRef {
		if identity := data.identityByID[identityID]; identity != nil {
			return miningRef{id: identityID, name: miningLabel(identity)}
		}
		return miningRef{id: identityID, name: identityID}
	}
	groupByID := map[string]*core.Object{}
	for _, group := range data.groups {
		groupByID[jsString(group.Get("id"))] = group
	}

	// Bundles: role combinations many people hold together, found as closed itemsets over the distinct role sets
	// and their pairwise intersections (every maximal shared combination is an intersection of two holders' sets).
	held, people := miningHeldRoles(data, false)
	// Each distinct role set with the people (positions in `people`, ascending) who hold exactly it.
	type distinctSet struct {
		key     string
		roles   []string
		count   int
		holders []int
	}
	distinct := map[string]*distinctSet{}
	var sets []*distinctSet
	for position, identityID := range people {
		roles := held[identityID]
		if roles.Len() < settings.minRoles {
			continue
		}
		key := miningSetKey(roles.Values())
		entry := distinct[key]
		if entry == nil {
			entry = &distinctSet{key: key, roles: miningSorted(roles.Values())}
			distinct[key] = entry
			sets = append(sets, entry)
		}
		entry.count++
		entry.holders = append(entry.holders, position)
	}
	seeds := append([]*distinctSet(nil), sets...)
	sort.SliceStable(seeds, func(i, j int) bool {
		if seeds[i].count != seeds[j].count {
			return seeds[i].count > seeds[j].count
		}
		return localeCompare(seeds[i].key, seeds[j].key) < 0
	})
	if len(seeds) > miningMaxSeedSets {
		seeds = seeds[:miningMaxSeedSets]
	}
	candidates := &miningOrderedStrings{}
	for i := range seeds {
		candidates.set(miningSetKey(seeds[i].roles), seeds[i].roles)
		first := newOrderedSet(seeds[i].roles...)
		for j := i + 1; j < len(seeds); j++ {
			common := []string{}
			for _, roleID := range seeds[j].roles {
				if first.Has(roleID) {
					common = append(common, roleID)
				}
			}
			if len(common) >= settings.minRoles {
				candidates.set(miningSetKey(common), common)
			}
		}
	}
	// Holders are counted over the distinct role sets, with one bitset per role (bit i: the i-th set includes it): the
	// sets holding a combination are the AND of its roles' bitsets.
	words := (len(sets) + 31) / 32
	roleBits := map[string][]uint32{}
	for index, entry := range sets {
		for _, roleID := range entry.roles {
			bitset := roleBits[roleID]
			if bitset == nil {
				bitset = make([]uint32, words)
				roleBits[roleID] = bitset
			}
			bitset[index>>5] |= 1 << (index & 31)
		}
	}
	// holding is the distinct role sets (indexes into `sets`) that include every role of a combination.
	holding := func(roles []string) []int {
		bitset := append([]uint32(nil), roleBits[roles[0]]...)
		for _, roleID := range roles[1:] {
			other := roleBits[roleID]
			for word := 0; word < words; word++ {
				bitset[word] &= other[word]
			}
		}
		indexes := []int{}
		for word := 0; word < words; word++ {
			for rest := bitset[word]; rest != 0; rest &= rest - 1 {
				indexes = append(indexes, word*32+bits.TrailingZeros32(rest))
			}
		}
		return indexes
	}
	packaged := newOrderedSet()
	for _, pkg := range data.packages {
		if len(stringList(pkg.Get("groupIds"))) == 0 {
			packaged.Add(miningSetKey(stringList(pkg.Get("roleIds"))))
		}
	}
	composite := newOrderedSet()
	for _, role := range data.roles {
		if inherits := stringList(role.Get("inherits")); len(inherits) > 0 {
			composite.Add(miningSetKey(inherits))
		}
	}
	type supportedSet struct {
		key     string
		roles   []string
		holders int
		order   int
	}
	var supported []supportedSet
	for _, key := range candidates.keys {
		roles := candidates.values[key]
		if packaged.Has(key) || composite.Has(key) {
			continue
		}
		holders := 0
		for _, index := range holding(roles) {
			holders += sets[index].count
		}
		if holders >= settings.minIdentities {
			supported = append(supported, supportedSet{key: key, roles: roles, holders: holders, order: len(supported)})
		}
	}
	// When more combinations qualify than are reported, the ones saving the most grants are kept.
	bundlesTruncated := len(supported) > miningMaxBundles
	reported := supported
	if bundlesTruncated {
		reported = append([]supportedSet(nil), supported...)
		sort.SliceStable(reported, func(i, j int) bool {
			a, b := reported[i], reported[j]
			if difference := b.holders*(len(b.roles)-1) - a.holders*(len(a.roles)-1); difference != 0 {
				return difference < 0
			}
			return a.order < b.order
		})
		reported = reported[:miningMaxBundles]
		sort.SliceStable(reported, func(i, j int) bool { return reported[i].order < reported[j].order })
	}
	// Closed sets only: of combinations with exactly the same holders, the largest stands for them.
	type closedSet struct {
		key     string
		roles   []string
		holders []string
	}
	closed := map[string]*closedSet{}
	var closedOrder []string
	for _, candidate := range reported {
		var positions []int
		for _, index := range holding(candidate.roles) {
			positions = append(positions, sets[index].holders...)
		}
		sort.Ints(positions)
		parts := make([]string, len(positions))
		for index, position := range positions {
			parts[index] = strconv.Itoa(position)
		}
		signature := strings.Join(parts, ",")
		current, ok := closed[signature]
		if !ok || len(candidate.roles) > len(current.roles) {
			holders := make([]string, len(positions))
			for index, position := range positions {
				holders[index] = people[position]
			}
			if !ok {
				closedOrder = append(closedOrder, signature)
			}
			closed[signature] = &closedSet{key: candidate.key, roles: candidate.roles, holders: holders}
		}
	}
	for _, signature := range closedOrder {
		candidate := closed[signature]
		roles := make([]miningRef, len(candidate.roles))
		names := make([]string, len(candidate.roles))
		for index, roleID := range candidate.roles {
			roles[index] = roleRef(roleID)
			names[index] = roles[index].name
		}
		identities := make([]miningRef, len(candidate.holders))
		for index, identityID := range candidate.holders {
			identities[index] = identityRef(identityID)
		}
		suggestions = append(suggestions, &miningSuggestion{
			id:         miningSuggestionID("bundle", candidate.key),
			kind:       "bundle",
			title:      strconv.Itoa(len(candidate.holders)) + " people hold " + strings.Join(names, " + ") + " together",
			detail:     "Grant the combination as one access package (optionally assigned automatically by attribute) or as a role that inherits these roles, instead of binding each role separately.",
			roles:      roles,
			identities: identities,
			savings:    len(candidate.holders) * (len(candidate.roles) - 1),
			applicable: false,
		})
	}

	// Group bindings: a role every permanent member of a group holds through their own direct binding. A team's
	// backing group is left out: the team's maintainers decide who belongs to it (teams.ts), so a role bound to it
	// would be theirs to hand out.
	membersOf := map[string][]*core.Object{}
	var groupOrder []string
	// Every live membership counts, including disabled or expired members: binding the role to the group would reach
	// them too (on re-activation), so a group qualifies only when all of them are active holders.
	for _, member := range data.members {
		groupID := jsString(member.Get("groupId"))
		if _, ok := membersOf[groupID]; !ok {
			groupOrder = append(groupOrder, groupID)
		}
		membersOf[groupID] = append(membersOf[groupID], member)
	}
	// The roles bound to each group, and each person's plain direct bindings of unprotected roles.
	groupRolesOf := map[string]*orderedSet{}
	directOf := map[string][]*core.Object{}
	for _, binding := range data.bindings {
		if binding.Get("subjectType") == "group" {
			subjectID := jsString(binding.Get("subjectId"))
			set := groupRolesOf[subjectID]
			if set == nil {
				set = newOrderedSet()
				groupRolesOf[subjectID] = set
			}
			set.Add(jsString(binding.Get("roleId")))
		} else if miningPlainDirect(binding) && data.unprotected(binding.Get("roleId")) {
			subjectID := jsString(binding.Get("subjectId"))
			directOf[subjectID] = append(directOf[subjectID], binding)
		}
	}
	for _, groupID := range groupOrder {
		members := membersOf[groupID]
		group := groupByID[groupID]
		if group == nil {
			continue
		}
		team, err := IsTeamGroup(group)
		if err != nil {
			return nil, false, err
		}
		if team || len(members) < settings.minIdentities {
			continue
		}
		skip := false
		for _, member := range members {
			if !isUndefined(member.Get("expiresAt")) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, member := range members {
			if _, ok := data.identityByID[jsString(member.Get("identityId"))]; !ok {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		groupRoles := groupRolesOf[groupID]
		direct := map[string][]*core.Object{}
		var directOrder []string
		memberIDs := newOrderedSet()
		for _, member := range members {
			memberIDs.Add(jsString(member.Get("identityId")))
		}
		for _, identityID := range memberIDs.Values() {
			for _, binding := range directOf[identityID] {
				roleID := jsString(binding.Get("roleId"))
				if groupRoles.Has(roleID) {
					continue
				}
				if _, ok := direct[roleID]; !ok {
					directOrder = append(directOrder, roleID)
				}
				direct[roleID] = append(direct[roleID], binding)
			}
		}
		for _, roleID := range directOrder {
			list := direct[roleID]
			holders := newOrderedSet()
			for _, binding := range list {
				holders.Add(jsString(binding.Get("subjectId")))
			}
			every := true
			for _, member := range members {
				if !holders.Has(jsString(member.Get("identityId"))) {
					every = false
					break
				}
			}
			if !every {
				continue
			}
			// One authority keeps the ceiling identical once the grant moves to the group.
			authorities := newOrderedSet()
			bindingIDs := make([]string, len(list))
			for index, binding := range list {
				authorities.Add(jsString(binding.Get("authorityId")))
				bindingIDs[index] = jsString(binding.Get("id"))
			}
			bindingIDs = miningSorted(bindingIDs)
			role := roleRef(roleID)
			mixed := ""
			if authorities.Len() > 1 {
				mixed = " The direct bindings come from different grant authorities, so apply is not offered."
			}
			holderIDs := miningSorted(holders.Values())
			identities := make([]miningRef, len(holderIDs))
			for index, identityID := range holderIDs {
				identities[index] = identityRef(identityID)
			}
			groupName := jsString(group.Get("name"))
			suggestions = append(suggestions, &miningSuggestion{
				id:         miningSuggestionID("group-binding", groupID+":"+roleID+":"+strings.Join(bindingIDs, ",")),
				kind:       "group-binding",
				title:      "Every member of " + groupName + " holds " + role.name + " directly",
				detail:     "Bind " + role.name + " to the group once and remove " + strconv.Itoa(len(list)) + " direct binding(s); new members then receive it automatically and leavers lose it." + mixed,
				roles:      []miningRef{role},
				identities: identities,
				group:      &miningRef{id: jsString(group.Get("id")), name: groupName},
				bindingIDs: bindingIDs,
				savings:    len(list) - 1,
				applicable: authorities.Len() == 1,
			})
		}
	}

	// Redundant direct bindings: the same role already reaches the person through a permanent group membership,
	// under the same authority (so the same ceiling) and at least as broadly. A team's backing group does not count:
	// relying on it would hand control of the access to the team's maintainers.
	groupBindingsOf := map[string][]*core.Object{}
	for _, other := range data.bindings {
		if other.Get("subjectType") != "group" {
			continue
		}
		team, err := IsTeamGroup(groupByID[jsString(other.Get("subjectId"))])
		if err != nil {
			return nil, false, err
		}
		if !team {
			roleID := jsString(other.Get("roleId"))
			groupBindingsOf[roleID] = append(groupBindingsOf[roleID], other)
		}
	}
	permanentGroups := map[string]*orderedSet{}
	// Package-owned memberships end with their assignment, so they cannot stand in for a direct binding.
	for _, member := range data.members {
		if isUndefined(member.Get("expiresAt")) && isUndefined(member.Get("packageAssignmentId")) {
			identityID := jsString(member.Get("identityId"))
			set := permanentGroups[identityID]
			if set == nil {
				set = newOrderedSet()
				permanentGroups[identityID] = set
			}
			set.Add(jsString(member.Get("groupId")))
		}
	}
	type redundantEntry struct {
		binding *core.Object
		group   *core.Object
	}
	redundant := map[string][]redundantEntry{}
	var redundantOrder []string
	for _, binding := range data.bindings {
		if binding.Get("subjectType") != "identity" || binding.Get("eligible") == true ||
			!isUndefined(binding.Get("packageAssignmentId")) {
			continue
		}
		if _, ok := data.identityByID[jsString(binding.Get("subjectId"))]; !ok || !data.unprotected(binding.Get("roleId")) {
			continue
		}
		groups := permanentGroups[jsString(binding.Get("subjectId"))]
		if groups == nil {
			continue
		}
		var cover *core.Object
		for _, other := range groupBindingsOf[jsString(binding.Get("roleId"))] {
			subjectID, ok := other.Get("subjectId").(string)
			if !ok || !groups.Has(subjectID) || other.Get("authorityId") != binding.Get("authorityId") ||
				!miningStanding(other) || !isUndefined(other.Get("startsAt")) {
				continue
			}
			if isUndefined(other.Get("expiresAt")) ||
				(!isUndefined(binding.Get("expiresAt")) && jsNumber(other.Get("expiresAt")) >= jsNumber(binding.Get("expiresAt"))) {
				cover = other
				break
			}
		}
		if cover == nil {
			continue
		}
		group := groupByID[jsString(cover.Get("subjectId"))]
		if group == nil {
			continue
		}
		key := jsString(group.Get("id")) + ":" + jsString(binding.Get("roleId"))
		if _, ok := redundant[key]; !ok {
			redundantOrder = append(redundantOrder, key)
		}
		redundant[key] = append(redundant[key], redundantEntry{binding: binding, group: group})
	}
	for _, key := range redundantOrder {
		list := redundant[key]
		group, binding := list[0].group, list[0].binding
		bindingIDs := make([]string, len(list))
		identities := make([]miningRef, len(list))
		for index, entry := range list {
			bindingIDs[index] = jsString(entry.binding.Get("id"))
			identities[index] = identityRef(jsString(entry.binding.Get("subjectId")))
		}
		bindingIDs = miningSorted(bindingIDs)
		role := roleRef(jsString(binding.Get("roleId")))
		groupName := jsString(group.Get("name"))
		suggestions = append(suggestions, &miningSuggestion{
			id:         miningSuggestionID("redundant-binding", key+":"+strings.Join(bindingIDs, ",")),
			kind:       "redundant-binding",
			title:      strconv.Itoa(len(list)) + " direct " + role.name + " binding(s) duplicate " + groupName + "'s",
			detail:     "These people already receive " + role.name + " through their permanent membership in " + groupName + ". Removing the direct bindings changes nothing today and keeps access tied to the group.",
			roles:      []miningRef{role},
			identities: identities,
			group:      &miningRef{id: jsString(group.Get("id")), name: groupName},
			bindingIDs: bindingIDs,
			savings:    len(list),
			applicable: true,
		})
	}

	// Duplicate roles: different roles that grant exactly the same statements.
	byGrant := map[string][]*core.Object{}
	var grantOrder []string
	for _, role := range data.roles {
		if truthy(role.Get("protected")) {
			continue
		}
		key := miningGrantKey(data, role)
		if key == "" {
			continue
		}
		if _, ok := byGrant[key]; !ok {
			grantOrder = append(grantOrder, key)
		}
		byGrant[key] = append(byGrant[key], role)
	}
	for _, key := range grantOrder {
		list := byGrant[key]
		if len(list) < 2 {
			continue
		}
		ids := make([]string, len(list))
		names := make([]string, len(list))
		for index, role := range list {
			ids[index] = jsString(role.Get("id"))
			names[index] = jsString(role.Get("name"))
		}
		ids = miningSorted(ids)
		roles := make([]miningRef, len(ids))
		for index, id := range ids {
			roles[index] = roleRef(id)
		}
		suggestions = append(suggestions, &miningSuggestion{
			id:         miningSuggestionID("duplicate-roles", strings.Join(ids, ",")),
			kind:       "duplicate-roles",
			title:      strings.Join(names, ", ") + " grant the same permissions",
			detail:     "The roles resolve to identical statements. Keep one, move its bindings over, and delete the rest so reviews have one thing to certify.",
			roles:      roles,
			identities: []miningRef{},
			savings:    len(list) - 1,
			applicable: false,
		})
	}
	return suggestions, bundlesTruncated, nil
}

var miningKindRank = map[string]int{"redundant-binding": 0, "group-binding": 1, "duplicate-roles": 2, "bundle": 3}

func miningSettingsOf(input interface{ Get(string) any }) (miningSettings, error) {
	minIdentities, err := Integer(coalesce(input.Get("minIdentities"), 3.0), "minIdentities", 2, 10_000)
	if err != nil {
		return miningSettings{}, err
	}
	minRoles, err := Integer(coalesce(input.Get("minRoles"), 2.0), "minRoles", 2, 50)
	if err != nil {
		return miningSettings{}, err
	}
	return miningSettings{minIdentities: int(minIdentities), minRoles: int(minRoles)}, nil
}

// knownActions is `[...new Set([...ctx.catalog.actions, ...tenant action names])]`.
func miningKnownActions(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID any) ([]string, error) {
	known := newOrderedSet(server.Catalog.Actions.Values()...)
	definitions, err := tx.Find(ctx, "actions", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, definition := range definitions {
		known.Add(jsString(definition.Get("name")))
	}
	return known.Values(), nil
}

// Suggest is POST {basePath}/roleMining/suggest. Lists suggestions, most actionable first. `minIdentities` (default
// 3) is how many people must share a pattern; `minRoles` (default 2) the smallest role combination reported as a
// bundle; `limit` caps the list.
func (api *RoleMiningAPI) Suggest(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningSuggestInput]) (Out[apitypes.RoleMiningSuggestOutput], error) {
	settings, err := miningSettingsOf(input)
	if err != nil {
		return Out[apitypes.RoleMiningSuggestOutput]{}, err
	}
	limit, err := Integer(coalesce(input.Get("limit"), 50.0), "limit", 1, 500)
	if err != nil {
		return Out[apitypes.RoleMiningSuggestOutput]{}, err
	}
	var kinds *orderedSet
	if raw := input.Get("kinds"); !isUndefined(raw) {
		kinds = newOrderedSet()
		switch value := raw.(type) {
		case nil:
		case []any:
			for _, item := range value {
				kinds.Add(jsString(item))
			}
		case string:
			for _, unit := range core.ToUTF16(value) {
				kinds.Add(core.FromUTF16([]uint16{unit}))
			}
		default:
			// `new Set(value)` throws a TypeError for anything that is not iterable.
			return Out[apitypes.RoleMiningSuggestOutput]{}, fmt.Errorf("%s is not iterable", jsString(raw))
		}
		for _, kind := range kinds.Values() {
			if _, ok := miningKindRank[kind]; !ok {
				return Out[apitypes.RoleMiningSuggestOutput]{}, invalidInput("Unknown suggestion kind")
			}
		}
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:analysis:read", "analysis/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		data, err := miningData(ctx, api.server, call.Tx, jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		mined, bundlesTruncated, err := miningMine(data, settings)
		if err != nil {
			return nil, err
		}
		var all []*miningSuggestion
		for _, suggestion := range mined {
			if kinds == nil || kinds.Has(suggestion.kind) {
				all = append(all, suggestion)
			}
		}
		summary := map[string]int{}
		for _, suggestion := range all {
			summary[suggestion.kind]++
		}
		sort.SliceStable(all, func(i, j int) bool {
			a, b := all[i], all[j]
			if rank := miningKindRank[a.kind] - miningKindRank[b.kind]; rank != 0 {
				return rank < 0
			}
			if a.savings != b.savings {
				return a.savings > b.savings
			}
			return localeCompare(a.id, b.id) < 0
		})
		shown := all
		if len(shown) > int(limit) {
			shown = shown[:int(limit)]
		}
		list := make([]any, len(shown))
		for index, suggestion := range shown {
			list[index] = suggestion.value()
		}
		answer := core.NewObject(
			"generatedAt", float64(api.server.Now()),
			"summary", core.NewObject("bundle", summary["bundle"], "group-binding", summary["group-binding"],
				"redundant-binding", summary["redundant-binding"], "duplicate-roles", summary["duplicate-roles"]),
			"suggestions", list,
		)
		if bundlesTruncated && (kinds == nil || kinds.Has("bundle")) {
			answer.Set("bundlesTruncated", true)
		}
		return answer, nil
	}, false)
	return Out[apitypes.RoleMiningSuggestOutput]{Value: result}, err
}

// Outliers is POST {basePath}/roleMining/outliers. Peer-group outliers. `peerBy` is `manager` (default: people with
// the same manager) or `attribute:{name}` for a declared identity attribute. A role is unusual when fewer than
// `threshold` (default 0.25) of the person's peers hold it, and missing when at least `commonShare` (default 0.8) of
// them hold it; groups smaller than `minPeers` (default 3, excluding the person) are skipped. Just-in-time (eligible)
// bindings count as held.
func (api *RoleMiningAPI) Outliers(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningOutliersInput]) (Out[apitypes.RoleMiningOutliersOutput], error) {
	server := api.server
	peerBy, err := Text(coalesce(input.Get("peerBy"), "manager"), "peerBy", 100)
	if err != nil {
		return Out[apitypes.RoleMiningOutliersOutput]{}, err
	}
	attribute, byAttribute := "", strings.HasPrefix(peerBy, "attribute:")
	if byAttribute {
		attribute = core.FromUTF16(core.ToUTF16(peerBy)[10:])
	}
	if peerBy != "manager" && !byAttribute {
		return Out[apitypes.RoleMiningOutliersOutput]{}, invalidInput("peerBy must be manager or attribute:{name}")
	}
	if byAttribute && (server.Catalog.IdentityAttributes == nil || !server.Catalog.IdentityAttributes.Has(attribute)) {
		return Out[apitypes.RoleMiningOutliersOutput]{}, invalidInput("Unknown identity attribute " + attribute)
	}
	share := func(value any, fallback float64, name string) (float64, error) {
		result, ok := coalesce(value, fallback).(float64)
		if !ok || !(result > 0 && result <= 1) {
			return 0, invalidInput(name + " must be a number above 0 and at most 1")
		}
		return result, nil
	}
	threshold, err := share(input.Get("threshold"), 0.25, "threshold")
	if err != nil {
		return Out[apitypes.RoleMiningOutliersOutput]{}, err
	}
	commonShare, err := share(input.Get("commonShare"), 0.8, "commonShare")
	if err != nil {
		return Out[apitypes.RoleMiningOutliersOutput]{}, err
	}
	minPeers, err := Integer(coalesce(input.Get("minPeers"), 3.0), "minPeers", 1, 10_000)
	if err != nil {
		return Out[apitypes.RoleMiningOutliersOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:analysis:read", "analysis/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		data, err := miningData(ctx, server, call.Tx, jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		held, _ := miningHeldRoles(data, true)
		// peerValue is the peer grouping (undefined: none), keyed so that values of different types stay apart.
		peerValue := func(identity *core.Object) (any, string, bool) {
			var value any
			if !byAttribute {
				value = identity.Get("managerId")
				if isUndefined(value) {
					return nil, "", false
				}
			} else {
				value = member(identity.Get("attributes"), attribute)
				if nullish(value) || typeOf(value) == "object" {
					return nil, "", false
				}
				value = jsString(value)
			}
			return value, typeOf(value) + ":" + jsString(value), true
		}
		type cohort struct {
			value   any
			members []*core.Object
		}
		cohorts := map[string]*cohort{}
		var cohortOrder []string
		for _, identity := range data.identities {
			value, key, ok := peerValue(identity)
			if !ok {
				continue
			}
			entry := cohorts[key]
			if entry == nil {
				entry = &cohort{value: value}
				cohorts[key] = entry
				cohortOrder = append(cohortOrder, key)
			}
			entry.members = append(entry.members, identity)
		}
		roleRef := func(roleID string) miningRef {
			if role := data.roleByID[roleID]; role != nil {
				return miningRef{id: roleID, name: jsString(coalesce(role.Get("name"), roleID))}
			}
			return miningRef{id: roleID, name: roleID}
		}
		type peerShare struct {
			role         miningRef
			peersHolding int
			share        float64
		}
		shareValues := func(list []peerShare) []any {
			out := make([]any, len(list))
			for index, entry := range list {
				out[index] = core.NewObject("role", entry.role.value(), "peersHolding", entry.peersHolding, "share", entry.share)
			}
			return out
		}
		type outlier struct {
			identity miningRef
			value    any
			peers    int
			unusual  []peerShare
			missing  []peerShare
		}
		var outliers []outlier
		compared := 0
		for _, key := range cohortOrder {
			group := cohorts[key]
			if float64(len(group.members)-1) < minPeers {
				continue
			}
			counts := map[string]int{}
			var countOrder []string
			for _, identity := range group.members {
				for _, roleID := range held[jsString(identity.Get("id"))].Values() {
					if _, ok := counts[roleID]; !ok {
						countOrder = append(countOrder, roleID)
					}
					counts[roleID]++
				}
			}
			for _, identity := range group.members {
				compared++
				own := held[jsString(identity.Get("id"))]
				peers := len(group.members) - 1
				var unusual, missing []peerShare
				for _, roleID := range countOrder {
					peersHolding := counts[roleID]
					if own.Has(roleID) {
						peersHolding--
					}
					fraction := float64(peersHolding) / float64(peers)
					entry := peerShare{role: roleRef(roleID), peersHolding: peersHolding, share: miningShareRound(fraction)}
					if own.Has(roleID) && fraction < threshold {
						unusual = append(unusual, entry)
					} else if !own.Has(roleID) && fraction >= commonShare {
						missing = append(missing, entry)
					}
				}
				if len(unusual) == 0 && len(missing) == 0 {
					continue
				}
				byShare := func(a, b peerShare) int {
					if difference := a.share - b.share; difference != 0 {
						if difference < 0 {
							return -1
						}
						return 1
					}
					return localeCompare(a.role.name, b.role.name)
				}
				sort.SliceStable(unusual, func(i, j int) bool { return byShare(unusual[i], unusual[j]) < 0 })
				sort.SliceStable(missing, func(i, j int) bool { return -byShare(missing[i], missing[j]) < 0 })
				outliers = append(outliers, outlier{
					identity: miningRef{id: jsString(identity.Get("id")), name: miningLabel(identity)},
					value:    group.value, peers: peers, unusual: unusual, missing: missing,
				})
			}
		}
		sort.SliceStable(outliers, func(i, j int) bool {
			a, b := outliers[i], outliers[j]
			if len(a.unusual) != len(b.unusual) {
				return len(a.unusual) > len(b.unusual)
			}
			if len(a.missing) != len(b.missing) {
				return len(a.missing) > len(b.missing)
			}
			return localeCompare(a.identity.name, b.identity.name) < 0
		})
		list := make([]any, len(outliers))
		for index, entry := range outliers {
			list[index] = core.NewObject(
				"identity", entry.identity.value(), "peerValue", entry.value, "peers", entry.peers,
				"unusualRoles", shareValues(entry.unusual), "missingRoles", shareValues(entry.missing),
			)
		}
		return core.NewObject("generatedAt", float64(server.Now()), "peerBy", peerBy, "identitiesCompared", compared, "outliers", list), nil
	}, false)
	return Out[apitypes.RoleMiningOutliersOutput]{Value: result}, err
}

// Apply is POST {basePath}/roleMining/apply. Carries out a `group-binding` or `redundant-binding` suggestion,
// recomputed inside the transaction so it applies only while the condition still holds (`NOT_FOUND` otherwise). A
// group binding is created under the authority the direct bindings share, so the caller must hold that authority (or
// be root) and `iam:bindings:create` on the role; every removed binding needs `iam:bindings:delete`. Requires
// iam:analysis:update. Bundles and duplicate roles are left to `packages.create` and role edits.
func (api *RoleMiningAPI) Apply(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningApplyInput]) (Out[apitypes.RoleMiningApplyOutput], error) {
	server := api.server
	settings, err := miningSettingsOf(input)
	if err != nil {
		return Out[apitypes.RoleMiningApplyOutput]{}, err
	}
	wanted, err := Text(input.Get("suggestionId"), "suggestionId", 64)
	if err != nil {
		return Out[apitypes.RoleMiningApplyOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:analysis:update", "analysis/"+wanted, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		data, err := miningData(ctx, server, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		mined, _, err := miningMine(data, settings)
		if err != nil {
			return nil, err
		}
		var suggestion *miningSuggestion
		for _, entry := range mined {
			if entry.id == wanted {
				suggestion = entry
				break
			}
		}
		if suggestion == nil {
			return nil, core.NewIamError("NOT_FOUND", "The suggestion no longer applies; list suggestions again", 404)
		}
		if !suggestion.applicable {
			if suggestion.kind == "bundle" {
				return nil, invalidInput("Create an access package from a bundle with packages.create")
			}
			return nil, invalidInput("This suggestion cannot be applied automatically")
		}
		bindingByID := map[string]*core.Object{}
		for _, binding := range data.bindings {
			bindingByID[jsString(binding.Get("id"))] = binding
		}
		removals := make([]*core.Object, len(suggestion.bindingIDs))
		for index, bindingID := range suggestion.bindingIDs {
			removals[index] = bindingByID[bindingID]
		}
		var created any = core.Undefined
		if suggestion.kind == "group-binding" {
			roleID := suggestion.roles[0].id
			// Never a team's backing group (mining leaves them out): its maintainers would hand the role out.
			var group *core.Object
			for _, candidate := range data.groups {
				if candidate.Get("id") == suggestion.group.id {
					group = candidate
					break
				}
			}
			if err := AssertNotTeamGroup(group); err != nil {
				return nil, err
			}
			if err := Allow(ctx, server, call.Tx, call.Principal, tenantID, "iam:bindings:create", roleID, "bind this role"); err != nil {
				return nil, err
			}
			binding, err := CreateBinding(ctx, server, call.Tx, call.Principal, core.NewObject(
				"tenantId", tenantID, "roleId", roleID, "subjectType", "group", "subjectId", suggestion.group.id,
				"authorityId", removals[0].Get("authorityId"),
			), nil)
			if err != nil {
				return nil, err
			}
			created = binding.Get("id")
		}
		removed := make([]any, len(removals))
		for index, binding := range removals {
			if err := Allow(ctx, server, call.Tx, call.Principal, tenantID, "iam:bindings:delete", jsString(binding.Get("id")), "remove this binding"); err != nil {
				return nil, err
			}
			if err := DeleteBinding(ctx, server, call.Tx, call.Principal, binding); err != nil {
				return nil, err
			}
			removed[index] = binding.Get("id")
		}
		return core.NewObject("applied", suggestion.kind, "createdBindingId", created, "removedBindingIds", removed), nil
	}, false)
	return Out[apitypes.RoleMiningApplyOutput]{Value: result}, err
}

// Usage is POST {basePath}/roleMining/usage. Recorded access usage (`accessUsage` option): per identity and action,
// when it was first and last allowed and how often, newest first. Buffered usage is written first. Requires
// iam:analysis:read.
func (api *RoleMiningAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningUsageInput]) (Out[apitypes.RoleMiningUsageOutput], error) {
	server := api.server
	limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
	if err != nil {
		return Out[apitypes.RoleMiningUsageOutput]{}, err
	}
	offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
	if err != nil {
		return Out[apitypes.RoleMiningUsageOutput]{}, err
	}
	identityID := ""
	if raw := input.Get("identityId"); !isUndefined(raw) {
		if identityID, err = Text(raw, "identityId"); err != nil {
			return Out[apitypes.RoleMiningUsageOutput]{}, err
		}
	}
	if server.Usage.Enabled() {
		if _, err := server.Usage.Flush(ctx); err != nil {
			return Out[apitypes.RoleMiningUsageOutput]{}, err
		}
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:analysis:read", "analysis/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := call.Tenant.Get("id")
		tracking, err := call.Tx.Get(ctx, "accessUsageTracking", jsString(tenantID))
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID)
		if identityID != "" {
			filter.Set("identityId", identityID)
		}
		records, err := call.Tx.Find(ctx, "accessUsage", filter, nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(records, func(i, j int) bool {
			a, b := records[i], records[j]
			if difference := jsNumber(b.Get("lastUsedAt")) - jsNumber(a.Get("lastUsedAt")); difference != 0 && !math.IsNaN(difference) {
				return difference < 0
			}
			if order := localeCompare(jsString(a.Get("identityId")), jsString(b.Get("identityId"))); order != 0 {
				return order < 0
			}
			return localeCompare(jsString(a.Get("action")), jsString(b.Get("action"))) < 0
		})
		start := int(offset)
		if start > len(records) {
			start = len(records)
		}
		end := start + int(limit)
		if end > len(records) {
			end = len(records)
		}
		list := make([]any, 0, end-start)
		for _, record := range records[start:end] {
			list = append(list, core.NewObject(
				"identityId", record.Get("identityId"), "action", record.Get("action"),
				"firstUsedAt", record.Get("firstUsedAt"), "lastUsedAt", record.Get("lastUsedAt"), "count", record.Get("count"),
			))
		}
		var since any = core.Undefined
		if tracking != nil {
			since = tracking.Get("startedAt")
		}
		return core.NewObject("tracking", server.Usage.Enabled(), "trackingSince", since, "total", len(records), "records", list), nil
	}, false)
	return Out[apitypes.RoleMiningUsageOutput]{Value: result}, err
}

// RightSize is POST {basePath}/roleMining/rightSize. Least-privilege right-sizing from recorded usage: every live
// binding whose holder used none (`unused`) or only some (`partial`) of the role's actions within `unusedDays`
// (default 90), plus per role the actions no holder used. `complete` is false until usage has been recorded for the
// whole window. Requires iam:analysis:read.
func (api *RoleMiningAPI) RightSize(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningRightSizeInput]) (Out[apitypes.RoleMiningRightSizeOutput], error) {
	server := api.server
	unusedDays, err := Integer(coalesce(input.Get("unusedDays"), 90.0), "unusedDays", 1, 3650)
	if err != nil {
		return Out[apitypes.RoleMiningRightSizeOutput]{}, err
	}
	if server.Usage.Enabled() {
		if _, err := server.Usage.Flush(ctx); err != nil {
			return Out[apitypes.RoleMiningRightSizeOutput]{}, err
		}
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:analysis:read", "analysis/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		data, err := miningData(ctx, server, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		since := now - unusedDays*analysisDayMs
		tracking, err := call.Tx.Get(ctx, "accessUsageTracking", tenantID)
		if err != nil {
			return nil, err
		}
		usage, err := call.Tx.Find(ctx, "accessUsage", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		used := map[string]map[string]float64{}
		for _, record := range usage {
			if jsNumber(record.Get("lastUsedAt")) < since {
				continue
			}
			identityID := jsString(record.Get("identityId"))
			actions := used[identityID]
			if actions == nil {
				actions = map[string]float64{}
				used[identityID] = actions
			}
			actions[jsString(record.Get("action"))] = jsNumber(record.Get("lastUsedAt"))
		}
		known, err := miningKnownActions(ctx, server, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		known = miningSorted(known)
		granted := map[string][]string{}
		actionsOf := func(role *core.Object) []string {
			id := jsString(role.Get("id"))
			list, ok := granted[id]
			if !ok {
				list = miningRoleActions(data, role, known)
				granted[id] = list
			}
			return list
		}
		groupByID := map[string]*core.Object{}
		for _, group := range data.groups {
			groupByID[jsString(group.Get("id"))] = group
		}
		type rightSizeEntry struct {
			value    *core.Object
			unused   bool
			identity string
			role     string
		}
		var entries []rightSizeEntry
		roleHolders := map[string]*orderedSet{}
		var holderOrder []string
		roleUsed := map[string]*orderedSet{}
		for _, binding := range data.bindings {
			role := data.roleByID[jsString(binding.Get("roleId"))]
			if role == nil || truthy(role.Get("protected")) {
				continue
			}
			actions := actionsOf(role)
			if len(actions) == 0 {
				continue
			}
			var group *core.Object
			if binding.Get("subjectType") == "group" {
				group = groupByID[jsString(binding.Get("subjectId"))]
			}
			var holders []string
			if binding.Get("subjectType") == "identity" {
				holders = []string{jsString(binding.Get("subjectId"))}
			} else {
				for _, member := range data.members {
					if member.Get("groupId") == binding.Get("subjectId") {
						holders = append(holders, jsString(member.Get("identityId")))
					}
				}
			}
			roleID := jsString(role.Get("id"))
			for _, identityID := range holders {
				identity := data.identityByID[identityID]
				if identity == nil {
					continue
				}
				holderUsage := used[identityID]
				usedActions := []string{}
				unused := []string{}
				for _, action := range actions {
					if _, ok := holderUsage[action]; ok {
						usedActions = append(usedActions, action)
					} else {
						unused = append(unused, action)
					}
				}
				holderSet := roleHolders[roleID]
				if holderSet == nil {
					holderSet = newOrderedSet()
					roleHolders[roleID] = holderSet
					holderOrder = append(holderOrder, roleID)
				}
				holderSet.Add(identityID)
				usedSet := roleUsed[roleID]
				if usedSet == nil {
					usedSet = newOrderedSet()
					roleUsed[roleID] = usedSet
				}
				for _, action := range usedActions {
					usedSet.Add(action)
				}
				if len(usedActions) == len(actions) {
					continue
				}
				last := 0.0
				for _, action := range usedActions {
					last = analysisMax(last, holderUsage[action])
				}
				via := core.NewObject("type", "identity")
				if group != nil {
					via = core.NewObject("type", "group", "id", group.Get("id"), "name", group.Get("name"))
				}
				status := "unused"
				if len(usedActions) > 0 {
					status = "partial"
				}
				shown := unused
				if len(shown) > 50 {
					shown = shown[:50]
				}
				label := miningLabel(identity)
				roleName := jsString(role.Get("name"))
				value := core.NewObject(
					"identity", core.NewObject("id", identity.Get("id"), "name", label),
					"role", core.NewObject("id", role.Get("id"), "name", role.Get("name")),
					"bindingId", binding.Get("id"), "via", via, "eligible", binding.Get("eligible") == true,
					"status", status, "grantedActions", len(actions), "usedActions", stringsOf(usedActions),
					"unusedActions", stringsOf(shown), "unusedCount", len(unused),
				)
				if truthy(last) {
					value.Set("lastUsedAt", last)
				}
				entries = append(entries, rightSizeEntry{value: value, unused: status == "unused", identity: label, role: roleName})
			}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			if a.unused != b.unused {
				return a.unused
			}
			if order := localeCompare(a.identity, b.identity); order != 0 {
				return order < 0
			}
			return localeCompare(a.role, b.role) < 0
		})
		type roleSummary struct {
			value          *core.Object
			neverUsedCount int
			name           string
		}
		var summaries []roleSummary
		for _, roleID := range holderOrder {
			role := data.roleByID[roleID]
			actions := actionsOf(role)
			usedSet := roleUsed[roleID]
			var neverUsed, usedActions []string
			for _, action := range actions {
				if usedSet.Has(action) {
					usedActions = append(usedActions, action)
				} else {
					neverUsed = append(neverUsed, action)
				}
			}
			shown := neverUsed
			if len(shown) > 100 {
				shown = shown[:100]
			}
			summaries = append(summaries, roleSummary{
				value: core.NewObject(
					"role", core.NewObject("id", role.Get("id"), "name", role.Get("name")),
					"holders", roleHolders[roleID].Len(), "grantedActions", len(actions),
					"usedActions", stringsOf(usedActions), "neverUsed", stringsOf(shown), "neverUsedCount", len(neverUsed),
				),
				neverUsedCount: len(neverUsed), name: jsString(role.Get("name")),
			})
		}
		sort.SliceStable(summaries, func(i, j int) bool {
			a, b := summaries[i], summaries[j]
			if a.neverUsedCount != b.neverUsedCount {
				return a.neverUsedCount > b.neverUsedCount
			}
			return localeCompare(a.name, b.name) < 0
		})
		entryList := make([]any, len(entries))
		for index, entry := range entries {
			entryList[index] = entry.value
		}
		roleList := make([]any, len(summaries))
		for index, summary := range summaries {
			roleList[index] = summary.value
		}
		answer := core.NewObject("generatedAt", now, "unusedDays", unusedDays, "tracking", server.Usage.Enabled())
		if tracking != nil {
			answer.Set("trackingSince", tracking.Get("startedAt"))
		}
		answer.Set("complete", tracking != nil && jsNumber(tracking.Get("startedAt")) <= since)
		answer.Set("entries", entryList)
		answer.Set("roles", roleList)
		return answer, nil
	}, false)
	return Out[apitypes.RoleMiningRightSizeOutput]{Value: result}, err
}

// ReviewRecommendations is POST {basePath}/roleMining/reviewRecommendations. Suggested decisions for an
// access-certification campaign's items: `revoke` when the person is no longer active or did not use the role within
// `unusedDays` (default 90; recorded usage when it covers the window, otherwise their last sign-in), `keep` when they
// did, and `none` for group items and when there is no evidence. Reviewers still decide. Requires iam:analysis:read.
func (api *RoleMiningAPI) ReviewRecommendations(ctx context.Context, credential core.CredentialInput, input In[apitypes.RoleMiningReviewRecommendationsInput]) (Out[apitypes.RoleMiningReviewRecommendationsOutput], error) {
	server := api.server
	unusedDays, err := Integer(coalesce(input.Get("unusedDays"), 90.0), "unusedDays", 1, 3650)
	if err != nil {
		return Out[apitypes.RoleMiningReviewRecommendationsOutput]{}, err
	}
	campaignID, err := Text(input.Get("campaignId"), "campaignId")
	if err != nil {
		return Out[apitypes.RoleMiningReviewRecommendationsOutput]{}, err
	}
	if server.Usage.Enabled() {
		if _, err := server.Usage.Flush(ctx); err != nil {
			return Out[apitypes.RoleMiningReviewRecommendationsOutput]{}, err
		}
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:analysis:read", "analysis/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		if _, err := server.Scoped(ctx, tx, "certificationCampaigns", campaignID, tenantID); err != nil {
			return nil, err
		}
		items, err := tx.Find(ctx, "certificationItems", core.NewObject("tenantId", tenantID, "campaignId", campaignID), nil)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		since := now - unusedDays*analysisDayMs
		tracking, err := tx.Get(ctx, "accessUsageTracking", tenantID)
		if err != nil {
			return nil, err
		}
		usageComplete := tracking != nil && jsNumber(tracking.Get("startedAt")) <= since
		data, err := miningData(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		known, err := miningKnownActions(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		plural := "s"
		if unusedDays == 1 {
			plural = ""
		}
		window := core.NumberString(unusedDays) + " day" + plural
		recommendations := []any{}
		sort.SliceStable(items, func(i, j int) bool {
			return localeCompare(jsString(items[i].Get("id")), jsString(items[j].Get("id"))) < 0
		})
		for _, item := range items {
			itemID := item.Get("id")
			if item.Get("subjectType") != "identity" {
				recommendations = append(recommendations, core.NewObject(
					"itemId", itemID, "recommendation", "none",
					"reason", "A group's binding; review who belongs to the group instead.",
				))
				continue
			}
			identity, err := tx.Get(ctx, "identities", jsString(item.Get("subjectId")))
			if err != nil {
				return nil, err
			}
			if identity == nil || identity.Get("status") != "active" || server.IdentityExpired(identity) {
				reason := "The account no longer exists."
				if identity != nil {
					status := jsString(identity.Get("status"))
					if identity.Get("status") == "active" {
						status = "expired"
					}
					reason = "The account is " + status + "."
				}
				recommendations = append(recommendations, core.NewObject(
					"itemId", itemID, "recommendation", "revoke", "basis", "status", "reason", reason,
				))
				continue
			}
			if usageComplete {
				actions := newOrderedSet()
				if role := data.roleByID[jsString(item.Get("roleId"))]; role != nil {
					actions = newOrderedSet(miningRoleActions(data, role, known)...)
				}
				records, err := tx.Find(ctx, "accessUsage", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				count := 0
				last := 0.0
				for _, record := range records {
					action, ok := record.Get("action").(string)
					if ok && actions.Has(action) && jsNumber(record.Get("lastUsedAt")) >= since {
						count++
						last = analysisMax(last, jsNumber(record.Get("lastUsedAt")))
					}
				}
				if count > 0 {
					recommendations = append(recommendations, core.NewObject(
						"itemId", itemID, "recommendation", "keep", "basis", "usage",
						"reason", "Used "+strconv.Itoa(count)+" of the role's actions in the last "+window+".",
						"lastUsedAt", last,
					))
				} else {
					recommendations = append(recommendations, core.NewObject(
						"itemId", itemID, "recommendation", "revoke", "basis", "usage",
						"reason", "None of the role's actions were used in the last "+window+".",
					))
				}
				continue
			}
			if identity.Get("kind") != "user" {
				recommendations = append(recommendations, core.NewObject(
					"itemId", itemID, "recommendation", "none",
					"reason", "Service accounts do not sign in; enable access usage tracking for evidence.",
				))
				continue
			}
			signIns, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "actorId", identity.Get("id"), "action", "auth:session:create"), nil)
			if err != nil {
				return nil, err
			}
			// An administrator's "view as" session is recorded on the member but is not the member signing in.
			last := 0.0
			for _, event := range signIns {
				if !truthy(event.Get("impersonatorId")) {
					last = analysisMax(last, jsNumber(event.Get("timestamp")))
				}
			}
			if last >= since {
				recommendations = append(recommendations, core.NewObject(
					"itemId", itemID, "recommendation", "keep", "basis", "sign-in",
					"reason", "Signed in within the last "+window+".", "lastUsedAt", last,
				))
			} else {
				reason := "Has never signed in."
				if truthy(last) {
					reason = "No sign-in in the last " + window + "."
				}
				recommendations = append(recommendations, core.NewObject(
					"itemId", itemID, "recommendation", "revoke", "basis", "sign-in", "reason", reason,
				))
			}
		}
		return core.NewObject("campaignId", campaignID, "unusedDays", unusedDays, "usageComplete", usageComplete, "recommendations", recommendations), nil
	}, false)
	return Out[apitypes.RoleMiningReviewRecommendationsOutput]{Value: result}, err
}
