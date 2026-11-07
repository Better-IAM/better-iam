package server

// Port of packages/server/src/teams.ts: teams inside an organization. Named groups of people with maintainers who
// manage the membership themselves, nested under parent teams, optionally in a department. Every team owns a backing
// group (`Team.groupId`, marked with `Group.teamId`) whose memberships this module writes: a team's backing group holds
// its own live members and those of every descendant team, so a child team's members receive whatever is bound to the
// parent team. Role bindings, relationships, separation of duties, reviews and analysis all read ordinary group
// memberships and need nothing else.

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/Better-IAM/better-iam/go/core"
)

var teamSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// orgString is a string member of a record ("" when absent or not a string).
func orgString(record *core.Object, key string) string {
	if record == nil {
		return ""
	}
	value, _ := record.String(key)
	return value
}

// orgIsString is `typeof value === 'string'`.
func orgIsString(value any) bool {
	_, ok := value.(string)
	return ok
}

// orgOwned is `record.tenantId === tenantId`.
func orgOwned(record *core.Object, tenantID string) bool {
	value, ok := record.Get("tenantId").(string)
	return ok && value == tenantID
}

// orgIncludes is `Array.isArray(list) && list.includes(item)` for a string item.
func orgIncludes(list any, item string) bool {
	items, ok := list.([]any)
	if !ok {
		return false
	}
	for _, value := range items {
		if text, ok := value.(string); ok && text == item {
			return true
		}
	}
	return false
}

// orgStrings is the items of an array member (`record.key ?? []`).
func orgStrings(record *core.Object, key string) []string {
	items, _ := member(record, key).([]any)
	out := make([]string, 0, len(items))
	for _, value := range items {
		out = append(out, jsString(value))
	}
	return out
}

// orgEnd is an optional end (`expiresAt`): permanent when undefined.
type orgEnd struct {
	at        float64
	permanent bool
}

// orgEndOf reads `record.expiresAt` (undefined means permanent).
func orgEndOf(record *core.Object) orgEnd {
	value := record.Get("expiresAt")
	if isUndefined(value) {
		return orgEnd{permanent: true}
	}
	return orgEnd{at: jsNumber(value)}
}

// orgDesired is a `Map<string, number | undefined>` of identity IDs to their end (insertion order).
type orgDesired struct {
	keys   []string
	values map[string]orgEnd
}

func newOrgDesired() *orgDesired { return &orgDesired{values: map[string]orgEnd{}} }

func (d *orgDesired) has(key string) bool {
	_, ok := d.values[key]
	return ok
}

func (d *orgDesired) set(key string, value orgEnd) {
	if _, ok := d.values[key]; !ok {
		d.keys = append(d.keys, key)
	}
	d.values[key] = value
}

func (d *orgDesired) delete(key string) {
	if _, ok := d.values[key]; !ok {
		return
	}
	delete(d.values, key)
	d.keys = slices.DeleteFunc(d.keys, func(item string) bool { return item == key })
}

// merge records one source's end: a permanent source wins over a temporary one; otherwise the latest end counts.
func (d *orgDesired) merge(key string, end orgEnd) {
	previous, known := d.values[key]
	if !known {
		d.set(key, end)
	} else if !previous.permanent {
		if end.permanent {
			d.set(key, orgEnd{permanent: true})
		} else {
			d.set(key, orgEnd{at: math.Max(previous.at, end.at)})
		}
	}
}

// orgSameEnd is `record.expiresAt === expiresAt`.
func orgSameEnd(record *core.Object, end orgEnd) bool {
	value := record.Get("expiresAt")
	if end.permanent {
		return isUndefined(value)
	}
	number, ok := value.(float64)
	return ok && number == end.at
}

// orgWithEnd sets `expiresAt` unless the end is permanent (`...(expiresAt !== undefined ? { expiresAt } : {})`).
func orgWithEnd(record *core.Object, end orgEnd) *core.Object {
	if !end.permanent {
		record.Set("expiresAt", end.at)
	}
	return record
}

// orgByAdded orders memberships by `addedAt`, then by a tie-break member (`a.addedAt - b.addedAt || (a.k < b.k ? -1 :
// 1)`).
func orgByAdded(tieBreak string) func(a, b *core.Object) int {
	return func(a, b *core.Object) int {
		if delta := jsNumber(a.Get("addedAt")) - jsNumber(b.Get("addedAt")); delta != 0 && !math.IsNaN(delta) {
			if delta < 0 {
				return -1
			}
			return 1
		}
		if compareUTF16(orgString(a, tieBreak), orgString(b, tieBreak)) < 0 {
			return -1
		}
		return 1
	}
}

// TeamSlug (teams.ts teamSlug): A team slug: 1-64 lowercase letters, digits or inner hyphens.
func TeamSlug(value any) (string, error) {
	text, ok := value.(string)
	if !ok || !teamSlugPattern.MatchString(text) {
		return "", invalidInput("slug must use 1-64 lowercase letters, digits, or inner hyphens")
	}
	return text, nil
}

var (
	teamSlugInvalidRun = regexp.MustCompile(`[^a-z0-9]+`)
	teamSlugEdges      = regexp.MustCompile(`^-+|-+$`)
	teamSlugTrailing   = regexp.MustCompile(`-+$`)
)

// SlugFromName (teams.ts slugFromName): A slug derived from a team name ("Platform Team" → `platform-team`), or
// undefined ("") when nothing usable is left.
func SlugFromName(name string) (string, error) {
	var stripped strings.Builder
	for _, r := range norm.NFKD.String(name) {
		if unicode.Is(unicode.M, r) {
			continue
		}
		stripped.WriteRune(r)
	}
	candidate := core.JSLower(stripped.String())
	candidate = teamSlugInvalidRun.ReplaceAllString(candidate, "-")
	candidate = teamSlugEdges.ReplaceAllString(candidate, "")
	// Only ASCII is left, so bytes are UTF-16 code units.
	if len(candidate) > 64 {
		candidate = candidate[:64]
	}
	candidate = teamSlugTrailing.ReplaceAllString(candidate, "")
	if candidate != "" && teamSlugPattern.MatchString(candidate) {
		return candidate, nil
	}
	return "", nil
}

// LiveTeamMember (teams.ts liveTeamMember): Whether a direct membership counts at `at` (no expiry, or one still
// ahead).
func LiveTeamMember(member *core.Object, at int64) (bool, error) {
	return liveTeamMember(member, at), nil
}

func liveTeamMember(member *core.Object, at int64) bool {
	expiresAt := member.Get("expiresAt")
	return isUndefined(expiresAt) || jsNumber(expiresAt) > float64(at)
}

// LoadTeam (teams.ts loadTeam): Loads a team of the tenant or fails with NOT_FOUND.
func LoadTeam(ctx context.Context, tx core.IamStore, tenantID string, teamID any) (*core.Object, error) {
	id, ok := teamID.(string)
	if !ok || id == "" {
		return nil, invalidInput("Invalid teamId")
	}
	team, err := tx.Get(ctx, TeamCollections.Teams, id)
	if err != nil {
		return nil, err
	}
	if team == nil || !orgOwned(team, tenantID) {
		return nil, core.NewIamError("NOT_FOUND", "Team not found", 404)
	}
	return team, nil
}

// TeamChain (teams.ts teamChain): The team followed by its ancestors, nearest first; tolerant of a missing parent
// (the chain stops there).
func TeamChain(teams map[string]*core.Object, teamID string) ([]*core.Object, error) {
	return teamChain(teams, teamID), nil
}

func teamChain(teams map[string]*core.Object, teamID string) []*core.Object {
	return orgChain(teams, teamID, MaxTeamDepth)
}

// orgChain follows `parentId` links from a node up (teams and departments share the shape).
func orgChain(nodes map[string]*core.Object, nodeID string, maxDepth int) []*core.Object {
	var chain []*core.Object
	seen := map[string]bool{}
	current := nodes[nodeID]
	for current != nil && !seen[orgString(current, "id")] && len(chain) <= maxDepth {
		chain = append(chain, current)
		seen[orgString(current, "id")] = true
		if parentID := orgString(current, "parentId"); parentID != "" {
			current = nodes[parentID]
		} else {
			current = nil
		}
	}
	return chain
}

// TeamDescendants (teams.ts teamDescendants): Every team below `teamId` (children, grandchildren, …), not including
// the team itself.
func TeamDescendants(teams []*core.Object, teamID string) ([]*core.Object, error) {
	return orgDescendants(teams, teamID), nil
}

// orgDescendants walks `parentId` links breadth first (teams and departments share the shape).
func orgDescendants(nodes []*core.Object, rootID string) []*core.Object {
	children := map[string][]*core.Object{}
	for _, node := range nodes {
		if parentID := orgString(node, "parentId"); parentID != "" {
			children[parentID] = append(children[parentID], node)
		}
	}
	result := []*core.Object{}
	seen := map[string]bool{rootID: true}
	queue := append([]*core.Object(nil), children[rootID]...)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		nextID := orgString(next, "id")
		if seen[nextID] {
			continue
		}
		seen[nextID] = true
		result = append(result, next)
		queue = append(queue, children[nextID]...)
	}
	return result
}

// orgByID is `new Map(records.map((record) => [record.id, record]))`, with the map's values in its order.
func orgByID(records []*core.Object) (map[string]*core.Object, []*core.Object) {
	byID := make(map[string]*core.Object, len(records))
	var order []*core.Object
	position := map[string]int{}
	for _, record := range records {
		id := orgString(record, "id")
		if index, known := position[id]; known {
			order[index] = record
		} else {
			position[id] = len(order)
			order = append(order, record)
		}
		byID[id] = record
	}
	return byID, order
}

// teamsByID is teams.ts tenantTeams: the tenant's teams by ID, with the map's values in its order.
func teamsByID(ctx context.Context, tx core.IamStore, tenantID string) (map[string]*core.Object, []*core.Object, error) {
	records, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, nil, err
	}
	byID, order := orgByID(records)
	return byID, order, nil
}

// orgOptionAt is `options.at ?? Date.now()`.
func orgOptionAt(options *core.Object) int64 {
	if options != nil {
		if at := options.Get("at"); !nullish(at) {
			return int64(jsNumber(at))
		}
	}
	return core.NowMillis()
}

// TeamsOf (teams.ts teamsOf): The teams a person belongs to at `at` (default now): their live direct memberships
// (oldest first) and, with `includeAncestors`, the parent teams those memberships make them part of. Team IDs, never
// backing group IDs. There is no membership history, so callers that attribute something to teams should call this
// when it happens. Options: `{ at?, includeAncestors? }`.
func TeamsOf(ctx context.Context, tx core.IamStore, tenantID string, identityID string, options *core.Object) ([]string, error) {
	at := orgOptionAt(options)
	records, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	var direct []*core.Object
	for _, record := range records {
		if liveTeamMember(record, at) {
			direct = append(direct, record)
		}
	}
	slices.SortStableFunc(direct, orgByAdded("teamId"))
	if len(direct) == 0 {
		return []string{}, nil
	}
	teams, _, err := teamsByID(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, record := range direct {
		if teamID := orgString(record, "teamId"); teams[teamID] != nil {
			ids = append(ids, teamID)
		}
	}
	if options == nil || !truthy(options.Get("includeAncestors")) {
		return ids, nil
	}
	result := newOrderedSet(ids...)
	for _, teamID := range ids {
		for _, team := range teamChain(teams, teamID) {
			result.Add(orgString(team, "id"))
		}
	}
	return result.Values(), nil
}

// PrimaryTeamOf (teams.ts primaryTeamOf): The person's oldest live direct team membership, for callers that
// attribute to one team only ("" when none). `at` nil means now.
func PrimaryTeamOf(ctx context.Context, tx core.IamStore, tenantID string, identityID string, at *int64) (string, error) {
	options := core.NewObject()
	if at != nil {
		options.Set("at", *at)
	}
	teams, err := TeamsOf(ctx, tx, tenantID, identityID, options)
	if err != nil || len(teams) == 0 {
		return "", err
	}
	return teams[0], nil
}

// TeamMaintainers (teams.ts teamMaintainers): The live direct maintainers of a team (identity IDs, oldest first).
func TeamMaintainers(ctx context.Context, tx core.IamStore, tenantID string, teamID string, at int64) ([]string, error) {
	records, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
	if err != nil {
		return nil, err
	}
	var maintainers []*core.Object
	for _, record := range records {
		if orgString(record, "role") == "maintainer" && liveTeamMember(record, at) {
			maintainers = append(maintainers, record)
		}
	}
	slices.SortStableFunc(maintainers, orgByAdded("identityId"))
	result := make([]string, 0, len(maintainers))
	for _, record := range maintainers {
		result = append(result, orgString(record, "identityId"))
	}
	return result, nil
}

// IsTeamMaintainer (teams.ts isTeamMaintainer): Whether a person maintains a team: a live maintainer membership of
// the team itself or, with `includeAncestors`, of any team above it (a parent team's maintainers manage its child
// teams too). Options: `{ at?, includeAncestors? }`.
func IsTeamMaintainer(ctx context.Context, tx core.IamStore, tenantID string, teamID string, identityID string, options *core.Object) (bool, error) {
	at := orgOptionAt(options)
	records, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return false, err
	}
	var memberships []*core.Object
	for _, record := range records {
		if orgString(record, "role") == "maintainer" && liveTeamMember(record, at) {
			memberships = append(memberships, record)
		}
	}
	if len(memberships) == 0 {
		return false, nil
	}
	scope := []string{teamID}
	if options != nil && truthy(options.Get("includeAncestors")) {
		teams, _, err := teamsByID(ctx, tx, tenantID)
		if err != nil {
			return false, err
		}
		scope = []string{}
		for _, team := range teamChain(teams, teamID) {
			scope = append(scope, orgString(team, "id"))
		}
	}
	for _, membership := range memberships {
		if slices.Contains(scope, orgString(membership, "teamId")) {
			return true, nil
		}
	}
	return false, nil
}

// AssertNotTeamGroup (teams.ts assertNotTeamGroup): Refuses direct membership changes to a team's backing group: its
// members come from the team (TEAM_MANAGED).
func AssertNotTeamGroup(group *core.Object) error {
	if isTeamGroup(group) {
		return core.NewIamError("TEAM_MANAGED", "This group belongs to a team; manage its members with the teams API", 409)
	}
	return nil
}

// IsTeamGroup (teams.ts isTeamGroup): Whether a group is a team's backing group.
func IsTeamGroup(group *core.Object) (bool, error) {
	return isTeamGroup(group), nil
}

func isTeamGroup(group *core.Object) bool {
	return group != nil && orgIsString(group.Get("teamId"))
}

// AssertNoTeamGroups (teams.ts assertNoTeamGroups): Refuses when any of `groupIds` is a team's backing group
// (packages, invitations, onboarding grant real groups).
func AssertNoTeamGroups(ctx context.Context, tx core.IamStore, groupIDs []string) error {
	for _, groupID := range groupIDs {
		group, err := tx.Get(ctx, "groups", groupID)
		if err != nil {
			return err
		}
		if err := AssertNotTeamGroup(group); err != nil {
			return err
		}
	}
	return nil
}

// SyncTeamGroups (teams.ts syncTeamGroups): Brings the backing groups of `teamIds` and of every team above them in
// line with team membership: a team's group holds the live direct members of the team and of all its descendant
// teams (a permanent source wins over a temporary one; otherwise the latest end counts). Deleted identities are left
// out. Removing a membership also ends the person's activations of the group's eligible bindings, as
// `groups.removeMember` does. Idempotent. The result is `{ added, removed, updated }`.
func SyncTeamGroups(ctx context.Context, tx core.IamStore, tenantID string, teamIDs []string, now int64) (*core.Object, error) {
	added, removed, updated := 0, 0, 0
	result := func() *core.Object {
		return core.NewObject("added", added, "removed", removed, "updated", updated)
	}
	teams, order, err := teamsByID(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	var affected []*core.Object
	affectedIndex := map[string]int{}
	for _, teamID := range teamIDs {
		for _, team := range teamChain(teams, teamID) {
			id := orgString(team, "id")
			if index, known := affectedIndex[id]; known {
				affected[index] = team
				continue
			}
			affectedIndex[id] = len(affected)
			affected = append(affected, team)
		}
	}
	if len(affected) == 0 {
		return result(), nil
	}
	records, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	byTeam := map[string][]*core.Object{}
	for _, record := range records {
		if liveTeamMember(record, now) {
			teamID := orgString(record, "teamId")
			byTeam[teamID] = append(byTeam[teamID], record)
		}
	}
	usable := map[string]bool{}
	identityUsable := func(identityID string) (bool, error) {
		if known, ok := usable[identityID]; ok {
			return known, nil
		}
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return false, err
		}
		usable[identityID] = identity != nil && orgOwned(identity, tenantID) && orgString(identity, "status") != "deleted"
		return usable[identityID], nil
	}
	for _, team := range affected {
		teamID := orgString(team, "id")
		// Undefined means permanent.
		desired := newOrgDesired()
		sources := append([]*core.Object{team}, orgDescendants(order, teamID)...)
		for _, source := range sources {
			for _, record := range byTeam[orgString(source, "id")] {
				identityID := orgString(record, "identityId")
				ok, err := identityUsable(identityID)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				desired.merge(identityID, orgEndOf(record))
			}
		}
		group, err := tx.Get(ctx, "groups", orgString(team, "groupId"))
		if err != nil {
			return nil, err
		}
		if group == nil || !orgOwned(group, tenantID) {
			continue
		}
		groupID := orgString(group, "id")
		current, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", groupID), nil)
		if err != nil {
			return nil, err
		}
		var bindings []*core.Object
		bindingsLoaded := false
		for _, membership := range current {
			identityID := orgString(membership, "identityId")
			if !desired.has(identityID) {
				if err := tx.Delete(ctx, "groupMembers", orgString(membership, "id")); err != nil {
					return nil, err
				}
				if !bindingsLoaded {
					bindings, err = tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
					if err != nil {
						return nil, err
					}
					bindingsLoaded = true
				}
				activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
				if err != nil {
					return nil, err
				}
				for _, activation := range activations {
					bindingID := orgString(activation, "bindingId")
					if slices.ContainsFunc(bindings, func(binding *core.Object) bool { return orgString(binding, "id") == bindingID }) {
						if err := tx.Delete(ctx, "bindingActivations", orgString(activation, "id")); err != nil {
							return nil, err
						}
					}
				}
				removed++
				continue
			}
			end := desired.values[identityID]
			desired.delete(identityID)
			if orgSameEnd(membership, end) && orgOwnedBy(membership, "teamId", teamID) {
				continue
			}
			rest := membership.Clone()
			rest.Delete("expiresAt")
			rest.Delete("packageAssignmentId")
			rest.Set("teamId", teamID)
			if _, err := tx.Put(ctx, "groupMembers", orgWithEnd(rest, end)); err != nil {
				return nil, err
			}
			updated++
		}
		for _, identityID := range append([]string(nil), desired.keys...) {
			record := core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"uniqueKey", groupID+":"+identityID,
				"groupId", groupID,
				"identityId", identityID,
				"teamId", teamID,
			)
			if _, err := tx.Insert(ctx, "groupMembers", orgWithEnd(record, desired.values[identityID])); err != nil {
				return nil, err
			}
			added++
		}
	}
	return result(), nil
}

// orgOwnedBy is `record[key] === value` for a string value.
func orgOwnedBy(record *core.Object, key, value string) bool {
	text, ok := record.Get(key).(string)
	return ok && text == value
}

// RemoveFromAllTeams (teams.ts removeFromAllTeams): Removes a person from every team of the tenant (offboarding,
// deletion) and from the teams' backing groups, and cancels their pending join requests. Returns the number of team
// memberships removed.
func RemoveFromAllTeams(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (float64, error) {
	memberships, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return 0, err
	}
	for _, record := range memberships {
		if err := tx.Delete(ctx, TeamCollections.Members, orgString(record, "id")); err != nil {
			return 0, err
		}
	}
	requests, err := tx.Find(ctx, TeamCollections.Requests, core.NewObject("tenantId", tenantID, "identityId", identityID, "status", "pending"), nil)
	if err != nil {
		return 0, err
	}
	for _, request := range requests {
		cancelled := request.Clone()
		cancelled.Set("status", "cancelled")
		cancelled.Set("decidedAt", now)
		if _, err := tx.Put(ctx, TeamCollections.Requests, cancelled); err != nil {
			return 0, err
		}
	}
	if len(memberships) > 0 {
		teamIDs := make([]string, 0, len(memberships))
		for _, record := range memberships {
			teamIDs = append(teamIDs, orgString(record, "teamId"))
		}
		if _, err := SyncTeamGroups(ctx, tx, tenantID, teamIDs, now); err != nil {
			return 0, err
		}
	}
	// Whatever still ties the person to a backing group (records written before a repair) goes as well.
	groupMemberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return 0, err
	}
	for _, membership := range groupMemberships {
		if orgIsString(membership.Get("teamId")) {
			if err := tx.Delete(ctx, "groupMembers", orgString(membership, "id")); err != nil {
				return 0, err
			}
		}
	}
	return float64(len(memberships)), nil
}

// OrgKeys are the organization-structure keys documents name.
type OrgKeys struct {
	Teams       bool
	Departments bool
}

// MentionedOrgKeys (teams.ts mentionedOrgKeys): which organization-structure keys the documents name anywhere
// (condition keys, condition values such as `${principal.departmentId}`, resource patterns), so decisions read team
// and department records only when needed.
func MentionedOrgKeys(documents []any) OrgKeys {
	var found OrgKeys
	for _, document := range documents {
		serialized, _, _ := core.Stringify(member(document, "statements"))
		if strings.Contains(serialized, "principal.teams") {
			found.Teams = true
		}
		if strings.Contains(serialized, "principal.department") {
			found.Departments = true
		}
		if found.Teams && found.Departments {
			break
		}
	}
	return found
}

// TeamContext (teams.ts teamContext): Policy context for a person in their own tenant: `principal.teams` lists the
// teams they belong to directly and the teams above those (the same teams whose backing groups hold them). Nothing
// for other principals.
func TeamContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (*core.Object, error) {
	teams, err := TeamsOf(ctx, tx, tenantID, identityID, core.NewObject("at", now, "includeAncestors", true))
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(teams, compareUTF16)
	return core.NewObject("principal.teams", stringsOf(teams)), nil
}

// MaxSyncGroups is teams.ts maxSyncGroups: at most this many source groups per team.
const MaxSyncGroups = 10

// SyncTeamsFromGroups (teams.ts syncTeamsFromGroups): Team sync: brings the synced members of teams with
// `syncGroupIds` in line with their source groups. Every active person with a live membership of a source group is a
// member (added as `member` with `source: 'sync'`, expiring when their last source membership does); synced members
// who left every source group are removed. Manual memberships are never changed. `groupId` limits the run to teams
// syncing from that group, `teamIds` to those teams. Changes are audited as `team:member:add` / `team:member:remove`
// with `source: 'sync'` under `actorId`. The seats of license products assigned to `groupId`, and to the backing
// groups the run changed (the synced teams' and those of the teams above them), are reconciled afterwards
// (licenses.ts), under the same actor. Options: `{ groupId?, teamIds?, actorId }`; the result is
// `{ added, removed, updated, teams }`.
func SyncTeamsFromGroups(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, options *core.Object) (*core.Object, error) {
	added, removed, updated := 0, 0, 0
	changedTeams := []string{}
	result := func() *core.Object {
		return core.NewObject("added", added, "removed", removed, "updated", updated, "teams", stringsOf(changedTeams))
	}
	if options == nil {
		options = core.NewObject()
	}
	groupValue := options.Get("groupId")
	hasGroup := !isUndefined(groupValue)
	groupID := jsString(groupValue)
	actorID := orgString(options, "actorId")
	teamIDs := options.Get("teamIds")
	hasTeamIDs := !isUndefined(teamIDs)
	// Every writer of a group's membership comes through here: seats of licenses assigned to the group follow as well.
	var sources []string
	if hasGroup {
		sources = []string{groupID}
	}
	teams, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	// Named teams are included even without sources, so turning sync off removes their synced members.
	var synced []*core.Object
	for _, team := range teams {
		var named bool
		if hasTeamIDs {
			named = orgIncludes(teamIDs, orgString(team, "id"))
		} else {
			list, _ := team.Get("syncGroupIds").([]any)
			named = len(list) > 0
		}
		if named && (!hasGroup || orgIncludes(team.Get("syncGroupIds"), groupID)) {
			synced = append(synced, team)
		}
	}
	if len(synced) == 0 {
		if len(sources) > 0 {
			if _, err := ReconcileGroupLicenses(ctx, server, tx, tenantID, sources, actorID); err != nil {
				return nil, err
			}
		}
		return result(), nil
	}
	now := server.Now()
	people := map[string]bool{}
	active := func(identityID string) (bool, error) {
		if known, ok := people[identityID]; ok {
			return known, nil
		}
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return false, err
		}
		people[identityID] = identity != nil && orgOwned(identity, tenantID) && orgString(identity, "kind") == "user" &&
			orgString(identity, "status") == "active" && !server.IdentityExpired(identity)
		return people[identityID], nil
	}
	audit := func(action string, team *core.Object, metadata *core.Object) error {
		return server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", actorID,
			"action", action,
			"resourceId", team.Get("id"),
			"timestamp", now,
			"outcome", "allow",
			"metadata", core.NewObject("team", team.Get("slug"), "source", "sync").Assign(metadata),
		))
	}
	for _, team := range synced {
		teamID := orgString(team, "id")
		// Undefined means permanent: the latest end among the person's source memberships.
		desired := newOrgDesired()
		for _, sourceGroupID := range orgStrings(team, "syncGroupIds") {
			memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", sourceGroupID), nil)
			if err != nil {
				return nil, err
			}
			for _, membership := range memberships {
				if !server.LiveMembership(membership) {
					continue
				}
				identityID := orgString(membership, "identityId")
				ok, err := active(identityID)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				desired.merge(identityID, orgEndOf(membership))
			}
		}
		changed := false
		records, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			live := liveTeamMember(record, now)
			identityID := orgString(record, "identityId")
			if !desired.has(identityID) {
				if orgString(record, "source") == "sync" && live {
					if err := tx.Delete(ctx, TeamCollections.Members, orgString(record, "id")); err != nil {
						return nil, err
					}
					if err := audit("team:member:remove", team, core.NewObject("identityId", record.Get("identityId"))); err != nil {
						return nil, err
					}
					removed++
					changed = true
				}
				continue
			}
			if !live {
				continue
			}
			end := desired.values[identityID]
			desired.delete(identityID)
			// A synced member's end follows the source memberships; manual members keep their own.
			if orgString(record, "source") == "sync" && !orgSameEnd(record, end) {
				rest := record.Clone()
				rest.Delete("expiresAt")
				if _, err := tx.Put(ctx, TeamCollections.Members, orgWithEnd(rest, end)); err != nil {
					return nil, err
				}
				updated++
				changed = true
			}
		}
		for _, identityID := range append([]string(nil), desired.keys...) {
			end := desired.values[identityID]
			uniqueKey := teamID + ":" + identityID
			var lapsed *core.Object
			for _, record := range records {
				if orgString(record, "uniqueKey") == uniqueKey {
					lapsed = record
					break
				}
			}
			recordID := ID()
			if lapsed != nil {
				recordID = orgString(lapsed, "id")
			}
			record := orgWithEnd(core.NewObject(
				"id", recordID,
				"tenantId", tenantID,
				"uniqueKey", uniqueKey,
				"teamId", teamID,
				"identityId", identityID,
				"role", "member",
				"addedAt", now,
				"addedBy", actorID,
				"source", "sync",
			), end)
			if lapsed != nil {
				_, err = tx.Put(ctx, TeamCollections.Members, record)
			} else {
				_, err = tx.Insert(ctx, TeamCollections.Members, record)
			}
			if err != nil {
				return nil, err
			}
			if err := audit("team:member:add", team, orgWithEnd(core.NewObject("identityId", identityID, "role", "member"), end)); err != nil {
				return nil, err
			}
			added++
			changed = true
		}
		if changed {
			if _, err := SyncTeamGroups(ctx, tx, tenantID, []string{teamID}, now); err != nil {
				return nil, err
			}
			changedTeams = append(changedTeams, teamID)
		}
	}
	// syncTeamGroups filled or emptied the backing groups of the changed teams and of every team above them.
	byID, _ := orgByID(teams)
	var filled []string
	for _, teamID := range changedTeams {
		for _, team := range teamChain(byID, teamID) {
			filled = append(filled, orgString(team, "groupId"))
		}
	}
	if len(sources) > 0 || len(filled) > 0 {
		if _, err := ReconcileGroupLicenses(ctx, server, tx, tenantID, append(append([]string{}, sources...), filled...), actorID); err != nil {
			return nil, err
		}
	}
	return result(), nil
}

// TeamSyncGroups (teams.ts teamSyncGroups): Validates a team's source groups: ordinary groups (not teams' backing
// groups) of the tenant, at most ten.
func TeamSyncGroups(ctx context.Context, tx core.IamStore, tenantID string, value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) > MaxSyncGroups {
		return nil, invalidInput("syncGroupIds must list at most " + core.NumberString(MaxSyncGroups) + " groups")
	}
	values := make([]string, 0, len(list))
	for _, item := range list {
		values = append(values, jsString(item))
	}
	ids := unique(values)
	for _, groupID := range ids {
		group, err := tx.Get(ctx, "groups", groupID)
		if err != nil {
			return nil, err
		}
		if group == nil || !orgOwned(group, tenantID) {
			return nil, core.NewIamError("NOT_FOUND", "Group "+groupID+" not found", 404)
		}
		if isTeamGroup(group) {
			return nil, invalidInput("A team cannot sync from another team’s backing group")
		}
	}
	return ids, nil
}

// TeamsSyncingFrom (teams.ts teamsSyncingFrom): Teams that sync their members from a group (a group they depend on).
func TeamsSyncingFrom(ctx context.Context, tx core.IamStore, tenantID string, groupID string) ([]*core.Object, error) {
	teams, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	result := []*core.Object{}
	for _, team := range teams {
		if orgIncludes(team.Get("syncGroupIds"), groupID) {
			result = append(result, team)
		}
	}
	return result, nil
}

// TeamChainBindings (teams.ts teamChainBindings): The bindings on the backing groups of `teamIds` and of every team
// above them: what membership of those teams hands out. Changing who is in them needs the grant authority behind
// each binding, as `groups.addMember` does for a group.
func TeamChainBindings(ctx context.Context, tx core.IamStore, tenantID string, teamIDs []string) ([]*core.Object, error) {
	teams, _, err := teamsByID(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	groupIDs := newOrderedSet()
	for _, teamID := range teamIDs {
		for _, team := range teamChain(teams, teamID) {
			groupIDs.Add(orgString(team, "groupId"))
		}
	}
	bindings := []*core.Object{}
	for _, groupID := range groupIDs.Values() {
		found, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, found...)
	}
	return bindings, nil
}

// RoleHoldsDeny (teams.ts roleHoldsDeny): Whether a role, or a role it inherits, holds a deny statement (in its own
// document or an attached policy). Leaving a group bound to such a role lifts a restriction, which needs the same
// authority as removing the person would.
func RoleHoldsDeny(ctx context.Context, tx core.IamStore, roleID string) (bool, error) {
	seen := map[string]bool{}
	queue := []string{roleID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		role, err := tx.Get(ctx, "roles", current)
		if err != nil {
			return false, err
		}
		if role == nil {
			continue
		}
		var documents []any
		if document := role.Get("document"); truthy(document) {
			documents = append(documents, document)
		}
		for _, policyID := range orgStrings(role, "policyIds") {
			policy, err := tx.Get(ctx, "policies", policyID)
			if err != nil {
				return false, err
			}
			if policy != nil {
				documents = append(documents, policy.Get("document"))
			}
		}
		for _, document := range documents {
			statements, _ := member(document, "statements").([]any)
			for _, statement := range statements {
				if effect, _ := member(statement, "effect").(string); effect == "deny" {
					return true, nil
				}
			}
		}
		queue = append(queue, orgStrings(role, "inherits")...)
	}
	return false, nil
}

// MaxTeamDepth is teams.ts maxTeamDepth.
const MaxTeamDepth = 10

// MaxTeams is teams.ts maxTeams.
const MaxTeams = 1000

// TeamCollections is teams.ts teamCollections.
var TeamCollections = struct {
	Teams    string
	Members  string
	Requests string
}{"teams", "teamMembers", "teamJoinRequests"}
