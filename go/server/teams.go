package server

// Skeleton of packages/server/src/teams.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssertNotTeamGroup (teams.ts assertNotTeamGroup): Refuses direct membership changes to a team's backing group: its
// members come from the team (TEAM_MANAGED).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertNotTeamGroup(group *core.Object) (err error) {
	err = notImplemented("teams.ts assertNotTeamGroup")
	return
}

// IsTeamGroup (teams.ts isTeamGroup): Whether a group is a team's backing group.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IsTeamGroup(group *core.Object) (result bool, err error) {
	err = notImplemented("teams.ts isTeamGroup")
	return
}

// IsTeamMaintainer (teams.ts isTeamMaintainer): Whether a person maintains a team: a live maintainer membership of
// the team itself or, with `includeAncestors`, of any team above it (a parent team's maintainers manage its child
// teams too).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IsTeamMaintainer(ctx context.Context, tx core.IamStore, tenantID string, teamID string, identityID string, options *core.Object) (result bool, err error) {
	err = notImplemented("teams.ts isTeamMaintainer")
	return
}

// LiveTeamMember (teams.ts liveTeamMember): Whether a direct membership counts at `at` (no expiry, or one still
// ahead).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveTeamMember(member *core.Object, at int64) (result bool, err error) {
	err = notImplemented("teams.ts liveTeamMember")
	return
}

// LoadTeam (teams.ts loadTeam): Loads a team of the tenant or fails with NOT_FOUND.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoadTeam(ctx context.Context, tx core.IamStore, tenantID string, teamID any) (result *core.Object, err error) {
	err = notImplemented("teams.ts loadTeam")
	return
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

// RemoveFromAllTeams (teams.ts removeFromAllTeams): Removes a person from every team of the tenant (offboarding,
// deletion) and from the teams' backing groups, and cancels their pending join requests. Returns the number of team
// memberships removed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RemoveFromAllTeams(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (result float64, err error) {
	err = notImplemented("teams.ts removeFromAllTeams")
	return
}

// RoleHoldsDeny (teams.ts roleHoldsDeny): Whether a role, or a role it inherits, holds a deny statement (in its own
// document or an attached policy). Leaving a group bound to such a role lifts a restriction, which needs the same
// authority as removing the person would.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RoleHoldsDeny(ctx context.Context, tx core.IamStore, roleID string) (result bool, err error) {
	err = notImplemented("teams.ts roleHoldsDeny")
	return
}

// SlugFromName (teams.ts slugFromName): A slug derived from a team name ("Platform Team" → `platform-team`), or
// undefined when nothing usable is left.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SlugFromName(name string) (result string, err error) {
	err = notImplemented("teams.ts slugFromName")
	return
}

// SyncTeamGroups (teams.ts syncTeamGroups): Brings the backing groups of `teamIds` and of every team above them in
// line with team membership: a team's group holds the live direct members of the team and of all its descendant
// teams (a permanent source wins over a temporary one; otherwise the latest end counts). Deleted identities are left
// out. Removing a membership also ends the person's activations of the group's eligible bindings, as
// `groups.removeMember` does. Idempotent.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SyncTeamGroups(ctx context.Context, tx core.IamStore, tenantID string, teamIDs []string, now int64) (result *core.Object, err error) {
	err = notImplemented("teams.ts syncTeamGroups")
	return
}

// SyncTeamsFromGroups (teams.ts syncTeamsFromGroups): Team sync: brings the synced members of teams with
// `syncGroupIds` in line with their source groups. Every active person with a live membership of a source group is a
// member (added as `member` with `source: 'sync'`, expiring when their last source membership does); synced members
// who left every source group are removed. Manual memberships are never changed. `groupId` limits the run to teams
// syncing from that group, `teamIds` to those teams. Changes are audited as `team:member:add` / `team:member:remove`
// with `source: 'sync'` under `actorId`. The seats of license products assigned to `groupId`, and to the backing
// groups the run changed (the synced teams' and those of the teams above them), are reconciled afterwards
// (licenses.ts), under the same actor.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SyncTeamsFromGroups(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("teams.ts syncTeamsFromGroups")
	return
}

// TeamChain (teams.ts teamChain): The team followed by its ancestors, nearest first; tolerant of a missing parent
// (the chain stops there).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamChain(teams map[string]*core.Object, teamID string) (result []*core.Object, err error) {
	err = notImplemented("teams.ts teamChain")
	return
}

// TeamChainBindings (teams.ts teamChainBindings): The bindings on the backing groups of `teamIds` and of every team
// above them: what membership of those teams hands out. Changing who is in them needs the grant authority behind
// each binding, as `groups.addMember` does for a group.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamChainBindings(ctx context.Context, tx core.IamStore, tenantID string, teamIDs []string) (result []*core.Object, err error) {
	err = notImplemented("teams.ts teamChainBindings")
	return
}

// TeamContext (teams.ts teamContext): Policy context for a person in their own tenant: `principal.teams` lists the
// teams they belong to directly and the teams above those (the same teams whose backing groups hold them). Nothing
// for other principals.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (result *core.Object, err error) {
	err = notImplemented("teams.ts teamContext")
	return
}

// TeamDescendants (teams.ts teamDescendants): Every team below `teamId` (children, grandchildren, …), not including
// the team itself.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamDescendants(teams []*core.Object, teamID string) (result []*core.Object, err error) {
	err = notImplemented("teams.ts teamDescendants")
	return
}

// TeamMaintainers (teams.ts teamMaintainers): The live direct maintainers of a team (identity IDs, oldest first).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamMaintainers(ctx context.Context, tx core.IamStore, tenantID string, teamID string, at int64) (result []string, err error) {
	err = notImplemented("teams.ts teamMaintainers")
	return
}

// TeamSlug (teams.ts teamSlug): A team slug: 1-64 lowercase letters, digits or inner hyphens.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamSlug(value any) (result string, err error) {
	err = notImplemented("teams.ts teamSlug")
	return
}

// TeamSyncGroups (teams.ts teamSyncGroups): Validates a team's source groups: ordinary groups (not teams' backing
// groups) of the tenant, at most ten.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamSyncGroups(ctx context.Context, tx core.IamStore, tenantID string, value any) (result []string, err error) {
	err = notImplemented("teams.ts teamSyncGroups")
	return
}

// TeamsOf (teams.ts teamsOf): The teams a person belongs to at `at` (default now): their live direct memberships
// (oldest first) and, with `includeAncestors`, the parent teams those memberships make them part of. Team IDs, never
// backing group IDs. There is no membership history, so callers that attribute something to teams should call this
// when it happens.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamsOf(ctx context.Context, tx core.IamStore, tenantID string, identityID string, options *core.Object) (result []string, err error) {
	err = notImplemented("teams.ts teamsOf")
	return
}

// TeamsSyncingFrom (teams.ts teamsSyncingFrom): Teams that sync their members from a group (a group they depend on).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamsSyncingFrom(ctx context.Context, tx core.IamStore, tenantID string, groupID string) (result []*core.Object, err error) {
	err = notImplemented("teams.ts teamsSyncingFrom")
	return
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
