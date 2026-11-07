package server

// Port of packages/server/src/api/teams.ts: teams inside an organization. Administrators holding `iam:teams:*`
// manage every team; a team's maintainers (and those of the teams above it) manage its membership and join requests
// themselves unless the team's `memberManagement` is `admins`; members see their own team. Give a team access by
// binding roles to its backing group (`team.groupId`) with `bindings.create`; everyone in the team and in the teams
// below it then holds them.

import (
	"context"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// TeamsAPI is the `teams` API group (packages/server/src/api/teams.ts createTeamsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/teams/{method} onto it.
type TeamsAPI struct {
	server *ServerContext
	module *teamModule
}

// CreateTeamsAPI builds the `teams` API group.
func CreateTeamsAPI(server *ServerContext) *TeamsAPI {
	return &TeamsAPI{server: server, module: newTeamModule(server)}
}

// How long a join request waits for a maintainer (fourteen days).
const joinRequestLifetimeMs = 14 * 86_400_000
const maxMaintainersOnCreate = 20

var (
	teamJoinPolicies     = []string{"closed", "request"}
	teamManagementModes  = []string{"maintainers", "admins"}
	teamRoles            = []string{"maintainer", "member"}
	teamReviewDecisions  = []string{"keep", "remove"}
	teamRequestStatuses  = []string{"pending", "approved", "denied", "cancelled", "expired"}
	teamReviewStatusList = []string{"open", "completed", "cancelled"}
)

// teamMutation is `MutationContext & { team, via }`: via is permission, maintainer, or member.
type teamMutation struct {
	MutationContext
	team *core.Object
	via  string
}

// teamIndex is allTeams' Map: the tenant's teams by ID, in the order the store returned them.
type teamIndex struct {
	byID map[string]*core.Object
	list []*core.Object
}

func (index *teamIndex) get(teamID string) *core.Object { return index.byID[teamID] }
func (index *teamIndex) has(teamID string) bool         { _, ok := index.byID[teamID]; return ok }
func (index *teamIndex) values() []*core.Object         { return index.list }
func (index *teamIndex) keys() []string {
	keys := make([]string, len(index.list))
	for position, team := range index.list {
		keys[position] = jsString(team.Get("id"))
	}
	return keys
}

// teamModule is api/teams.ts teamModule(ctx): the API and the transaction-level helpers configuration sync uses.
type teamModule struct {
	server *ServerContext
	// clearedLicenses is the per-transaction memo of assertMayClaimTeamLicenses (a WeakMap keyed by the transaction
	// in TypeScript). It only spares repeated checks inside one transaction, so it keeps the most recent
	// transactions and forgets older ones (a forgotten entry is simply checked again).
	mu           sync.Mutex
	cleared      map[core.IamStore]map[string]bool
	clearedOrder []core.IamStore
}

const clearedLicenseTransactions = 64

func newTeamModule(server *ServerContext) *teamModule {
	return &teamModule{server: server, cleared: map[core.IamStore]map[string]bool{}}
}

func teamChoice(value any, allowed []string, name string) (string, error) {
	text, ok := value.(string)
	if !ok || !containsString(allowed, text) {
		return "", invalidInput(name + " must be one of " + strings.Join(allowed, ", "))
	}
	return text, nil
}

func teamRef(team *core.Object) *core.Object {
	return core.NewObject("id", team.Get("id"), "name", team.Get("name"), "slug", team.Get("slug"))
}

func teamPersonOf(identity *core.Object) *core.Object {
	view := core.NewObject("id", identity.Get("id"), "name", identity.Get("name"))
	if truthy(identity.Get("email")) {
		view.Set("email", identity.Get("email"))
	}
	return view.Set("status", identity.Get("status"))
}

func teamUnknownPerson(identityID string) *core.Object {
	return core.NewObject("id", identityID, "name", identityID, "status", "deleted")
}

// teamPersonLabel is `person.email ?? person.name`.
func teamPersonLabel(person *core.Object) string {
	if email := person.Get("email"); !nullish(email) {
		return jsString(email)
	}
	return jsString(person.Get("name"))
}

// teamRefs is `teams.map(ref)`.
func teamRefs(teams []*core.Object) []any {
	list := make([]any, len(teams))
	for index, team := range teams {
		list[index] = teamRef(team)
	}
	return list
}

// teamIDs is `teams.map((team) => team.id)`.
func teamIDs(teams []*core.Object) []string {
	ids := make([]string, len(teams))
	for index, team := range teams {
		ids[index] = jsString(team.Get("id"))
	}
	return ids
}

// reversedTail is `chain.slice(1).reverse()`.
func reversedTail(chain []*core.Object) []*core.Object {
	if len(chain) <= 1 {
		return []*core.Object{}
	}
	tail := make([]*core.Object, 0, len(chain)-1)
	for index := len(chain) - 1; index >= 1; index-- {
		tail = append(tail, chain[index])
	}
	return tail
}

// ownUserSession is a person acting for themselves in their own tenant (the self-service calls and the maintainer
// path).
func ownUserSession(principal *Principal, tenantID any) bool {
	session, identity := principal.Session, principal.Identity
	return session.Get("kind") == "user" &&
		ActsInOwnRight(session) &&
		!truthy(session.Get("impersonatorId")) &&
		core.StrictEquals(session.Get("tenantId"), tenantID) &&
		core.StrictEquals(identity.Get("tenantId"), tenantID) &&
		identity.Get("kind") == "user"
}

func requireOwnSession(principal *Principal, tenantID string) error {
	if truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "Teams cannot be joined or left while impersonating", 403)
	}
	if !ownUserSession(principal, tenantID) {
		return core.NewIamError("ACCESS_DENIED", "Teams are joined and left from a person’s own session in their organization", 403)
	}
	return nil
}

// liveTeamMembers is `members.filter((member) => liveTeamMember(member, now))`.
func liveTeamMembers(members []*core.Object, now int64) ([]*core.Object, error) {
	live := []*core.Object{}
	for _, member := range members {
		ok, err := LiveTeamMember(member, now)
		if err != nil {
			return nil, err
		}
		if ok {
			live = append(live, member)
		}
	}
	return live, nil
}

// teamReconciled is `.then((result) => afterIdentityChange(ctx, tenantId, [...touched], result))` of reconciling.
func (m *teamModule) reconciling(ctx context.Context, tenantID any, run func(touch func(identityIDs ...string)) (any, error)) (any, error) {
	touched := newOrderedSet()
	result, err := run(func(identityIDs ...string) {
		for _, identityID := range identityIDs {
			touched.Add(identityID)
		}
	})
	if err != nil {
		return nil, err
	}
	return AfterIdentityChange(ctx, m.server, jsString(tenantID), touched.Values(), result)
}

// membersBelow is the direct members (any expiry or source) of a team and of every team below it.
func (m *teamModule) membersBelow(ctx context.Context, tx core.IamStore, team *core.Object) ([]string, error) {
	tenantID := jsString(team.Get("tenantId"))
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	descendants, err := TeamDescendants(teams.values(), jsString(team.Get("id")))
	if err != nil {
		return nil, err
	}
	scope := newOrderedSet(jsString(team.Get("id")))
	for _, item := range descendants {
		scope.Add(jsString(item.Get("id")))
	}
	members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, member := range members {
		if scope.Has(jsString(member.Get("teamId"))) {
			ids = append(ids, jsString(member.Get("identityId")))
		}
	}
	return ids, nil
}

func (m *teamModule) people(ctx context.Context, tx core.IamStore, ids []string) (map[string]*core.Object, error) {
	result := map[string]*core.Object{}
	for _, identityID := range unique(ids) {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			result[identityID] = teamPersonOf(identity)
		} else {
			result[identityID] = teamUnknownPerson(identityID)
		}
	}
	return result, nil
}

// standingMemberships is the person's live maintainer memberships that give standing over `team`: of the team
// itself or of a team above it, as long as no team from that one down to `team` takes membership changes from
// administrators only. Otherwise a parent's maintainer would reach through an admins-only team and hand out what it
// holds to whoever they put below.
func (m *teamModule) standingMemberships(ctx context.Context, tx core.IamStore, identityID string, team *core.Object, now int64) ([]*core.Object, error) {
	tenantID := jsString(team.Get("tenantId"))
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	chain, err := TeamChain(teams.byID, jsString(team.Get("id")))
	if err != nil {
		return nil, err
	}
	scope := newOrderedSet()
	for _, holder := range chain {
		if holder.Get("memberManagement") == "admins" {
			break
		}
		scope.Add(jsString(holder.Get("id")))
	}
	if scope.Len() == 0 {
		return []*core.Object{}, nil
	}
	members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	standing := []*core.Object{}
	for _, member := range members {
		if member.Get("role") != "maintainer" {
			continue
		}
		live, err := LiveTeamMember(member, now)
		if err != nil {
			return nil, err
		}
		if live && scope.Has(jsString(member.Get("teamId"))) {
			standing = append(standing, member)
		}
	}
	return standing, nil
}

// teamStanding is whether the principal may act on the team at `level` through membership rather than a
// permission.
func (m *teamModule) teamStanding(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, level string) (bool, error) {
	if !ownUserSession(principal, team.Get("tenantId")) {
		return false, nil
	}
	now := m.server.Now()
	standing, err := m.standingMemberships(ctx, tx, jsString(principal.Identity.Get("id")), team, now)
	if err != nil {
		return false, err
	}
	maintains := len(standing) > 0
	if maintains || level == "maintainer" {
		return maintains, nil
	}
	// Members see their team: a direct membership of it or of any team below it.
	teams, err := TeamsOf(ctx, tx, jsString(team.Get("tenantId")), jsString(principal.Identity.Get("id")), core.NewObject("at", float64(now), "includeAncestors", true))
	if err != nil {
		return false, err
	}
	return containsString(teams, jsString(team.Get("id"))), nil
}

// teamOperation is the team-scoped envelope. A caller holding `action` on `iam/{teamId}` goes through the ordinary
// operation; a maintainer (or, for reads, a member) without it acts through the same transactional steps
// (separation of duties, invariants, plugin hooks) and is audited with `via: team-maintainer` / `team-member`.
// level "" is undefined (administrators only).
func (m *teamModule) teamOperation(ctx context.Context, credential core.CredentialInput, tenantID any, teamIDInput any, action string, level string, fn func(ctx context.Context, mutation *teamMutation) (any, error)) (any, error) {
	server := m.server
	teamID, err := Text(teamIDInput, "teamId", 128)
	if err != nil {
		return nil, err
	}
	if level != "" {
		authenticated, err := server.Principals.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		byStanding, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return false, err
			}
			team, err := tx.Get(ctx, TeamCollections.Teams, teamID)
			if err != nil {
				return false, err
			}
			if team == nil || !core.StrictEquals(team.Get("tenantId"), tenantID) {
				return false, nil
			}
			standing, err := m.teamStanding(ctx, tx, principal, team, level)
			if err != nil || !standing {
				return false, err
			}
			decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: jsString(tenantID), Action: action, Resource: ResourceTarget{Type: "iam", ID: jsString(team.Get("id"))},
			}, true)
			if err != nil {
				return false, nil
			}
			// Standing stands in for a missing grant only: an explicit deny, a boundary, or a refused tenant or
			// credential still refuses a maintainer, through the ordinary operation below.
			return decision.Reason == "NO_APPLICABLE_GRANT", nil
		})
		if err != nil {
			return nil, err
		}
		if byStanding {
			return m.standingOperation(ctx, authenticated, jsString(tenantID), teamID, action, level, fn)
		}
	}
	return server.Operations.Operation(ctx, credential, tenantID, action, teamID, func(ctx context.Context, call MutationContext) (any, error) {
		team, err := LoadTeam(ctx, call.Tx, jsString(tenantID), teamID)
		if err != nil {
			return nil, err
		}
		return fn(ctx, &teamMutation{MutationContext: call, team: team, via: "permission"})
	}, false)
}

type standingOutcome struct {
	denied bool
	value  any
}

func (m *teamModule) standingOperation(ctx context.Context, authenticated *Principal, tenantID, teamID, action, level string, fn func(ctx context.Context, mutation *teamMutation) (any, error)) (any, error) {
	server := m.server
	return Span(server.Observe, "operation", action, tenantID, func() (any, error) {
		outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (standingOutcome, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return standingOutcome{}, err
			}
			tenant, err := server.Tenant(ctx, tx, tenantID)
			if err != nil {
				return standingOutcome{}, err
			}
			chain, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return standingOutcome{}, err
			}
			team, err := tx.Get(ctx, TeamCollections.Teams, teamID)
			if err != nil {
				return standingOutcome{}, err
			}
			standing := true
			for _, realm := range chain {
				if realm.Get("status") != "active" {
					standing = false
					break
				}
			}
			standing = standing && team != nil && team.Get("tenantId") == tenantID
			if standing {
				if standing, err = m.teamStanding(ctx, tx, principal, team, level); err != nil {
					return standingOutcome{}, err
				}
			}
			if !standing || team == nil {
				if err := server.Events.Audit(ctx, tx, principal, action, tenantID, teamID, "deny", false, nil); err != nil {
					return standingOutcome{}, err
				}
				return standingOutcome{denied: true}, nil
			}
			via := "member"
			if level == "maintainer" {
				via = "maintainer"
			}
			hook := core.OperationHookInput{Store: tx, Principal: corePrincipal(principal), TenantID: tenantID, Action: action, ResourceID: teamID}
			for _, plugin := range server.Plugins {
				if plugin.Hooks != nil && plugin.Hooks.BeforeOperation != nil {
					if err := plugin.Hooks.BeforeOperation(ctx, hook); err != nil {
						return standingOutcome{}, err
					}
				}
			}
			separation, err := SodSnapshot(ctx, server, tx, tenantID, action)
			if err != nil {
				return standingOutcome{}, err
			}
			guardrails, err := InvariantSnapshot(ctx, server, tx, tenantID, action)
			if err != nil {
				return standingOutcome{}, err
			}
			value, err := fn(ctx, &teamMutation{MutationContext: MutationContext{Tx: tx, Principal: principal, Tenant: tenant}, team: team, via: via})
			if err != nil {
				return standingOutcome{}, err
			}
			if err := SodVerify(ctx, server, tx, tenantID, separation, nil); err != nil {
				return standingOutcome{}, err
			}
			if err := InvariantVerify(ctx, server, tx, tenantID, guardrails); err != nil {
				return standingOutcome{}, err
			}
			for _, plugin := range server.Plugins {
				if plugin.Hooks != nil && plugin.Hooks.AfterOperation != nil {
					after := hook
					after.Result = value
					if err := plugin.Hooks.AfterOperation(ctx, after); err != nil {
						return standingOutcome{}, err
					}
				}
			}
			if err := server.Events.Audit(ctx, tx, principal, action, tenantID, teamID, "allow", false, core.NewObject("via", "team-"+via)); err != nil {
				return standingOutcome{}, err
			}
			return standingOutcome{value: value}, nil
		})
		if err != nil {
			return nil, err
		}
		if outcome.denied {
			return nil, accessDenied()
		}
		return outcome.value, nil
	}, nil, nil)
}

// selfService runs a self-service call: an ordinary session of a person in their own organization.
func (m *teamModule) selfService(ctx context.Context, credential core.CredentialInput, tenantIDInput any, fn func(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (any, error)) (any, error) {
	server := m.server
	tenantID, err := Text(tenantIDInput, "tenantId")
	if err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := requireOwnSession(principal, tenantID); err != nil {
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
		for _, realm := range chain {
			if realm.Get("status") != "active" {
				return nil, core.NewIamError("TENANT_INACTIVE", "The organization is not active", 403)
			}
		}
		return fn(ctx, tx, principal, tenantID)
	})
}

func (m *teamModule) audit(ctx context.Context, tx core.IamStore, principal *Principal, action string, team *core.Object, metadata *core.Object) error {
	return m.server.Events.Audit(ctx, tx, principal, action, jsString(team.Get("tenantId")), jsString(team.Get("id")), "allow", false,
		core.NewObject("team", team.Get("slug")).Spread(metadata))
}

func (m *teamModule) email(ctx context.Context, tx core.IamStore, tenantID string, identityIDs []string, template string, payload *core.Object) error {
	options := m.server.Options
	if options == nil || options.Authentication == nil || options.Authentication.SendEmail == nil {
		return nil
	}
	for _, identityID := range unique(identityIDs) {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return err
		}
		if identity == nil || !truthy(identity.Get("email")) || identity.Get("status") != "active" || identity.Get("tenantId") != tenantID {
			continue
		}
		if _, err := m.server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID, Kind: "email", To: jsString(identity.Get("email")), Template: template, Payload: payload,
		}); err != nil {
			return err
		}
	}
	return nil
}

// groupBindings is the bindings whose subject is the group.
func groupBindings(ctx context.Context, tx core.IamStore, tenantID, groupID string) ([]*core.Object, error) {
	return tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
}

// assertAuthorityOver: administrators who grant through a team need authority over what the team's backing groups
// (and those of the teams above it) are bound to, exactly as adding someone to those groups would. Maintainers act
// under the delegation the team's administrators gave them and skip this.
func (m *teamModule) assertAuthorityOver(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, teams []*core.Object) error {
	for _, team := range teams {
		bindings, err := groupBindings(ctx, tx, tenantID, jsString(team.Get("groupId")))
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			if _, err := m.server.GrantingAuthority(ctx, tx, principal, tenantID, optionalString(binding, "authorityId")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *teamModule) clearedHas(tx core.IamStore, key string) bool {
	if tx == nil || !reflect.TypeOf(tx).Comparable() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleared[tx][key]
}

func (m *teamModule) clearedAdd(tx core.IamStore, key string) {
	if tx == nil || !reflect.TypeOf(tx).Comparable() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.cleared[tx]
	if !ok {
		set = map[string]bool{}
		m.cleared[tx] = set
		m.clearedOrder = append(m.clearedOrder, tx)
		if len(m.clearedOrder) > clearedLicenseTransactions {
			delete(m.cleared, m.clearedOrder[0])
			m.clearedOrder = m.clearedOrder[1:]
		}
	}
	set[key] = true
}

// assertMayClaimTeamLicenses: administrators who put people into a team, keep them there longer, or appoint its
// maintainers claim license seats for them when a product is assigned to the backing group of the team or of a team
// above it (`teams`: that chain): that needs iam:licenses:assign, as adding them to those groups directly does
// (api/groups.ts), refused with OperationDenied. Maintainers acting as maintainers skip this by design. Checked once
// per caller and chain in a transaction, so batches ask once.
func (m *teamModule) assertMayClaimTeamLicenses(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, teams []*core.Object) error {
	key := jsString(principal.Identity.Get("id")) + ":" + strings.Join(teamIDs(teams), ",")
	if m.clearedHas(tx, key) {
		return nil
	}
	groupIDs := make([]any, len(teams))
	for index, team := range teams {
		groupIDs[index] = team.Get("groupId")
	}
	if err := AssertMayClaimLicenses(ctx, m.server, tx, principal, tenantID, groupIDs,
		"This team, or a team above it, carries license seats; adding people to it, changing how long they stay, or appointing its maintainers needs iam:licenses:assign"); err != nil {
		return err
	}
	m.clearedAdd(tx, key)
	return nil
}

// heldChainGroups is the backing groups of `team` and of the teams above it that hold the person right now.
func (m *teamModule) heldChainGroups(ctx context.Context, tx core.IamStore, team *core.Object, identityID string) (*orderedSet, error) {
	tenantID := jsString(team.Get("tenantId"))
	held := newOrderedSet()
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	chain, err := TeamChain(teams.byID, jsString(team.Get("id")))
	if err != nil {
		return nil, err
	}
	for _, holder := range chain {
		groupID := jsString(holder.Get("groupId"))
		found, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "uniqueKey", groupID+":"+identityID), nil)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 && m.server.LiveMembership(found[0]) {
			held.Add(groupID)
		}
	}
	return held, nil
}

// droppedGroups is `[...held].filter((groupId) => !kept.has(groupId))`.
func droppedGroups(held, kept *orderedSet) []string {
	dropped := []string{}
	for _, groupID := range held.Values() {
		if !kept.Has(groupID) {
			dropped = append(dropped, groupID)
		}
	}
	return dropped
}

// assertMayDropDenies: people ending their own membership (leaving, or a maintainer removing or shortening
// themselves) drop out of backing groups, and a deny bound to one of those groups stops applying to them.
// `groups.removeMember` needs the grant authority behind a group's bindings for exactly that reason, so the same holds
// here for bindings whose role holds a deny statement: without that authority, an administrator removes the person.
func (m *teamModule) assertMayDropDenies(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, groupIDs []string) error {
	for _, groupID := range unique(groupIDs) {
		bindings, err := groupBindings(ctx, tx, tenantID, groupID)
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			if m.server.ExpiredBinding(binding) {
				continue
			}
			deny, err := RoleHoldsDeny(ctx, tx, jsString(binding.Get("roleId")))
			if err != nil {
				return err
			}
			if !deny {
				continue
			}
			if _, err := m.server.GrantingAuthority(ctx, tx, principal, tenantID, optionalString(binding, "authorityId")); err != nil {
				return core.NewIamError("ACCESS_DENIED", "This team carries a restriction (a deny) you cannot lift yourself; ask an administrator to remove you", 403)
			}
		}
	}
	return nil
}

func (m *teamModule) allTeams(ctx context.Context, tx core.IamStore, tenantID string) (*teamIndex, error) {
	found, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	index := &teamIndex{byID: map[string]*core.Object{}}
	positions := map[string]int{}
	for _, team := range found {
		id := jsString(team.Get("id"))
		if position, seen := positions[id]; seen {
			index.list[position] = team
		} else {
			positions[id] = len(index.list)
			index.list = append(index.list, team)
		}
		index.byID[id] = team
	}
	return index, nil
}

func (m *teamModule) summaries(ctx context.Context, tx core.IamStore, teams []*core.Object, all []*core.Object) ([]*core.Object, error) {
	now := m.server.Now()
	tenantIDs := newOrderedSet()
	for _, team := range teams {
		tenantIDs.Add(jsString(team.Get("tenantId")))
	}
	members := map[string][]*core.Object{}
	for _, tenantID := range tenantIDs.Values() {
		found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, member := range found {
			live, err := LiveTeamMember(member, now)
			if err != nil {
				return nil, err
			}
			if live {
				teamID := jsString(member.Get("teamId"))
				members[teamID] = append(members[teamID], member)
			}
		}
	}
	result := make([]*core.Object, len(teams))
	for index, team := range teams {
		result[index] = teamSummary(team, members[jsString(team.Get("id"))], all)
	}
	return result, nil
}

func teamSummary(team *core.Object, members []*core.Object, all []*core.Object) *core.Object {
	rest := team.Clone()
	rest.Delete("uniqueKey")
	rest.Delete("createdBy")
	maintainers := 0
	for _, member := range members {
		if member.Get("role") == "maintainer" {
			maintainers++
		}
	}
	children := 0
	for _, other := range all {
		if core.StrictEquals(other.Get("parentId"), team.Get("id")) {
			children++
		}
	}
	return rest.Spread(core.NewObject(
		"memberCount", float64(len(members)),
		"maintainerCount", float64(maintainers),
		"childCount", float64(children),
	))
}

// sortTeamsByName is `.sort((a, b) => a.name.localeCompare(b.name))`.
func sortTeamsByName(teams []*core.Object) {
	sort.SliceStable(teams, func(i, j int) bool {
		return localeCompare(jsString(teams[i].Get("name")), jsString(teams[j].Get("name"))) < 0
	})
}

func (m *teamModule) detail(ctx context.Context, tx core.IamStore, team *core.Object) (*core.Object, error) {
	server := m.server
	now := server.Now()
	tenantID := jsString(team.Get("tenantId"))
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	chain, err := TeamChain(teams.byID, jsString(team.Get("id")))
	if err != nil {
		return nil, err
	}
	bases, err := m.summaries(ctx, tx, []*core.Object{team}, teams.values())
	if err != nil {
		return nil, err
	}
	children := []*core.Object{}
	for _, other := range teams.values() {
		if core.StrictEquals(other.Get("parentId"), team.Get("id")) {
			children = append(children, other)
		}
	}
	sortTeamsByName(children)
	childCounts, err := m.summaries(ctx, tx, children, teams.values())
	if err != nil {
		return nil, err
	}
	maintainerIDs, err := TeamMaintainers(ctx, tx, tenantID, jsString(team.Get("id")), now)
	if err != nil {
		return nil, err
	}
	maintainers, err := m.people(ctx, tx, maintainerIDs)
	if err != nil {
		return nil, err
	}
	var department *core.Object
	if departmentID := team.Get("departmentId"); truthy(departmentID) {
		found, err := tx.Get(ctx, "departments", jsString(departmentID))
		if err != nil {
			return nil, err
		}
		if found != nil && core.StrictEquals(found.Get("tenantId"), team.Get("tenantId")) {
			department = core.NewObject("id", found.Get("id"), "name", found.Get("name"))
			if truthy(found.Get("code")) {
				department.Set("code", found.Get("code"))
			}
		}
	}
	groupMembers, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", team.Get("groupId")), nil)
	if err != nil {
		return nil, err
	}
	total := 0
	for _, member := range groupMembers {
		if server.LiveMembership(member) {
			total++
		}
	}
	roles := []any{}
	for _, holder := range chain {
		bindings, err := groupBindings(ctx, tx, tenantID, jsString(holder.Get("groupId")))
		if err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if server.ExpiredBinding(binding) {
				continue
			}
			role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
			if err != nil {
				return nil, err
			}
			roleName := binding.Get("roleId")
			if role != nil && !nullish(role.Get("name")) {
				roleName = role.Get("name")
			}
			grant := core.NewObject(
				"bindingId", binding.Get("id"),
				"roleId", binding.Get("roleId"),
				"roleName", roleName,
				"team", teamRef(holder),
				"inherited", !core.StrictEquals(holder.Get("id"), team.Get("id")),
			)
			if truthy(binding.Get("eligible")) {
				grant.Set("eligible", true)
			}
			if startsAt := binding.Get("startsAt"); !isUndefined(startsAt) {
				grant.Set("startsAt", startsAt)
			}
			if expiresAt := binding.Get("expiresAt"); !isUndefined(expiresAt) {
				grant.Set("expiresAt", expiresAt)
			}
			roles = append(roles, grant)
		}
	}
	childViews := make([]any, len(children))
	for index, child := range children {
		childViews[index] = teamRef(child).Set("memberCount", childCounts[index].Get("memberCount"))
	}
	maintainerViews := make([]any, len(maintainerIDs))
	for index, identityID := range maintainerIDs {
		maintainerViews[index] = maintainers[identityID]
	}
	syncGroups := []any{}
	if list, ok := team.Get("syncGroupIds").([]any); ok {
		for _, groupID := range list {
			group, err := tx.Get(ctx, "groups", jsString(groupID))
			if err != nil {
				return nil, err
			}
			name := groupID
			if group != nil && !nullish(group.Get("name")) {
				name = group.Get("name")
			}
			syncGroups = append(syncGroups, core.NewObject("id", groupID, "name", name))
		}
	}
	view := bases[0].Spread(core.NewObject(
		"path", teamRefs(reversedTail(chain)),
		"children", childViews,
	))
	if department != nil {
		view.Set("department", department)
	}
	return view.Spread(core.NewObject(
		"maintainers", maintainerViews,
		"totalMemberCount", float64(total),
		"roles", roles,
		"syncGroups", syncGroups,
	)), nil
}

func (m *teamModule) requestView(ctx context.Context, tx core.IamStore, request *core.Object) (*core.Object, error) {
	team, err := tx.Get(ctx, TeamCollections.Teams, jsString(request.Get("teamId")))
	if err != nil {
		return nil, err
	}
	requester, err := tx.Get(ctx, "identities", jsString(request.Get("identityId")))
	if err != nil {
		return nil, err
	}
	rest := request.Clone()
	for _, key := range []string{"uniqueKey", "tenantId", "teamId", "identityId"} {
		rest.Delete(key)
	}
	var teamView, requesterView *core.Object
	if team != nil {
		teamView = teamRef(team)
	} else {
		teamView = core.NewObject("id", request.Get("teamId"), "name", request.Get("teamId"), "slug", "")
	}
	if requester != nil {
		requesterView = teamPersonOf(requester)
	} else {
		requesterView = teamUnknownPerson(jsString(request.Get("identityId")))
	}
	return rest.Spread(core.NewObject("id", request.Get("id"), "team", teamView, "requester", requesterView)), nil
}

// freeSlug is a slug that no other team of the tenant uses.
func (m *teamModule) freeSlug(ctx context.Context, tx core.IamStore, tenantID, slug, exceptID string) (string, error) {
	found, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID, "uniqueKey", "slug:"+slug), nil)
	if err != nil {
		return "", err
	}
	for _, team := range found {
		if exceptID == "" || team.Get("id") != exceptID {
			return "", core.NewIamError("CONFLICT", "A team with the slug "+slug+" exists", 409)
		}
	}
	return slug, nil
}

// teamPerson is a person who can belong to a team: an active person (not a service account or agent) of the tenant.
func (m *teamModule) teamPerson(ctx context.Context, tx core.IamStore, tenantID string, identityID any) (*core.Object, error) {
	id, err := Text(identityID, "identityId", 128)
	if err != nil {
		return nil, err
	}
	identity, err := m.server.ActiveIdentity(ctx, tx, id, tenantID)
	if err != nil {
		return nil, err
	}
	if identity.Get("kind") != "user" {
		return nil, invalidInput("Teams hold people; service accounts and agents cannot join")
	}
	if identity.Get("status") != "active" {
		return nil, invalidInput("Only active people can join a team")
	}
	return identity, nil
}

// putMember adds or re-adds a direct member, then refreshes the backing groups. Shared by add, approve, create and
// configuration sync. An administrator (`via: 'permission'`) needs iam:licenses:assign when the team's chain carries
// license seats. input holds identityId and optionally role and expiresAt.
func (m *teamModule) putMember(ctx context.Context, mutation *teamMutation, input *core.Object, source string) (*core.Object, error) {
	server := m.server
	tx, principal, team := mutation.Tx, mutation.Principal, mutation.team
	tenantID, teamID := jsString(team.Get("tenantId")), jsString(team.Get("id"))
	identity, err := m.teamPerson(ctx, tx, tenantID, input.Get("identityId"))
	if err != nil {
		return nil, err
	}
	role := "member"
	if raw := input.Get("role"); !isUndefined(raw) {
		if role, err = teamChoice(raw, teamRoles, "role"); err != nil {
			return nil, err
		}
	}
	var expiresAt any = core.Undefined
	if raw := input.Get("expiresAt"); !nullish(raw) {
		value, err := server.BindingExpiry(raw)
		if err != nil {
			return nil, err
		}
		expiresAt = value
	}
	if mutation.via == "permission" {
		teams, err := m.allTeams(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		chain, err := TeamChain(teams.byID, teamID)
		if err != nil {
			return nil, err
		}
		if err := m.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, chain); err != nil {
			return nil, err
		}
	}
	identityID := jsString(identity.Get("id"))
	uniqueKey := teamID + ":" + identityID
	found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil {
		return nil, err
	}
	var existing *core.Object
	if len(found) > 0 {
		existing = found[0]
	}
	now := server.Now()
	if existing != nil {
		live, err := LiveTeamMember(existing, now)
		if err != nil {
			return nil, err
		}
		if live {
			return nil, core.NewIamError("CONFLICT", jsString(identity.Get("name"))+" is already in this team", 409)
		}
	}
	// A maintainer adding themselves (to a team below the one they maintain) may not outlast their own standing.
	if mutation.via == "maintainer" && identityID == jsString(principal.Identity.Get("id")) {
		standing, err := m.standingMemberships(ctx, tx, identityID, team, now)
		if err != nil {
			return nil, err
		}
		var ends any = core.Undefined
		permanent := false
		latest := math.Inf(-1)
		for _, member := range standing {
			if isUndefined(member.Get("expiresAt")) {
				permanent = true
			}
			latest = math.Max(latest, jsNumber(member.Get("expiresAt")))
		}
		if !permanent {
			ends = latest
		}
		if !isUndefined(ends) && (isUndefined(expiresAt) || jsNumber(expiresAt) > jsNumber(ends)) {
			return nil, core.NewIamError("ACCESS_DENIED", "Maintainers cannot add themselves for longer than they maintain the team; ask an administrator", 403)
		}
	}
	recordID := ID()
	if existing != nil {
		recordID = jsString(existing.Get("id"))
	}
	record := core.NewObject(
		"id", recordID,
		"tenantId", tenantID,
		"uniqueKey", uniqueKey,
		"teamId", teamID,
		"identityId", identityID,
		"role", role,
		"addedAt", float64(now),
		"addedBy", principal.Identity.Get("id"),
	)
	if !isUndefined(expiresAt) {
		record.Set("expiresAt", expiresAt)
	}
	if existing != nil {
		_, err = tx.Put(ctx, TeamCollections.Members, record)
	} else {
		_, err = tx.Insert(ctx, TeamCollections.Members, record)
	}
	if err != nil {
		return nil, err
	}
	if _, err := SyncTeamGroups(ctx, tx, tenantID, []string{teamID}, now); err != nil {
		return nil, err
	}
	// A pending request of theirs is settled by the membership.
	requests, err := tx.Find(ctx, TeamCollections.Requests, core.NewObject("tenantId", tenantID, "teamId", teamID, "identityId", identityID, "status", "pending"), nil)
	if err != nil {
		return nil, err
	}
	for _, request := range requests {
		if source != "approve" {
			if _, err := tx.Put(ctx, TeamCollections.Requests, request.Spread(core.NewObject(
				"status", "approved",
				"decidedBy", principal.Identity.Get("id"),
				"decidedAt", float64(now),
			))); err != nil {
				return nil, err
			}
		}
	}
	metadata := core.NewObject("identityId", identityID, "role", role, "source", source)
	if !isUndefined(expiresAt) {
		metadata.Set("expiresAt", expiresAt)
	}
	if mutation.via != "permission" {
		metadata.Set("via", mutation.via)
	}
	if err := m.audit(ctx, tx, principal, "team:member:add", team, metadata); err != nil {
		return nil, err
	}
	return record, nil
}

func (m *teamModule) memberRecord(ctx context.Context, tx core.IamStore, team *core.Object, identityID any) (*core.Object, error) {
	id, err := Text(identityID, "identityId", 128)
	if err != nil {
		return nil, err
	}
	found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", team.Get("tenantId"), "uniqueKey", jsString(team.Get("id"))+":"+id), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Not a member of this team", 404)
	}
	live, err := LiveTeamMember(found[0], m.server.Now())
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, core.NewIamError("NOT_FOUND", "Not a member of this team", 404)
	}
	return found[0], nil
}

// removeMember deletes a direct membership; via "" is undefined.
func (m *teamModule) removeMember(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, member *core.Object, action, via string) error {
	if err := tx.Delete(ctx, TeamCollections.Members, jsString(member.Get("id"))); err != nil {
		return err
	}
	if _, err := SyncTeamGroups(ctx, tx, jsString(team.Get("tenantId")), []string{jsString(team.Get("id"))}, m.server.Now()); err != nil {
		return err
	}
	metadata := core.NewObject("identityId", member.Get("identityId"), "role", member.Get("role"))
	if via != "" && via != "permission" {
		metadata.Set("via", via)
	}
	return m.audit(ctx, tx, principal, action, team, metadata)
}

// parentChain is the chain a parent brings: its own chain, checked for depth against the subtree that moves under
// it.
func parentChain(teams *teamIndex, parent *core.Object, subtreeHeight int) ([]*core.Object, error) {
	chain, err := TeamChain(teams.byID, jsString(parent.Get("id")))
	if err != nil {
		return nil, err
	}
	if len(chain)+subtreeHeight > MaxTeamDepth {
		return nil, invalidInput("Teams nest at most " + jsString(float64(MaxTeamDepth)) + " levels deep")
	}
	return chain, nil
}

func subtreeHeight(teams *teamIndex, team *core.Object) (int, error) {
	height := 1
	descendants, err := TeamDescendants(teams.values(), jsString(team.Get("id")))
	if err != nil {
		return 0, err
	}
	for _, descendant := range descendants {
		chain, err := TeamChain(teams.byID, jsString(descendant.Get("id")))
		if err != nil {
			return 0, err
		}
		depth := 0
		for index, item := range chain {
			if core.StrictEquals(item.Get("id"), team.Get("id")) {
				depth = index + 1
				break
			}
		}
		if depth > height {
			height = depth
		}
	}
	return height, nil
}

// assertCanNestUnder: moving a team (or creating one) under a parent needs the caller to be able to manage the
// parent and grant its access.
func (m *teamModule) assertCanNestUnder(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, chain []*core.Object) error {
	parent := chain[0]
	decision, err := m.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: "iam:teams:update", Resource: ResourceTarget{Type: "iam", ID: jsString(parent.Get("id"))},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return core.NewIamError("ACCESS_DENIED", "Placing a team under "+jsString(parent.Get("name"))+" needs iam:teams:update on it", 403)
	}
	// Members of the nested team join the parent's groups, so its bindings must be within the caller's authority.
	return m.assertAuthorityOver(ctx, tx, principal, tenantID, chain)
}

// createTeam creates a team with its backing group (and maintainers); the caller has authorized `iam:teams:create`.
func (m *teamModule) createTeam(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (*core.Object, error) {
	server := m.server
	tenantID := jsString(tenant.Get("id"))
	rawName, err := Text(input.Get("name"), "name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(rawName)
	existing, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(existing.list) >= MaxTeams {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+jsString(float64(MaxTeams))+" teams", 409)
	}
	var derived string
	if raw := input.Get("slug"); isUndefined(raw) {
		derived, err = SlugFromName(name)
	} else {
		derived, err = TeamSlug(raw)
	}
	if err != nil {
		return nil, err
	}
	if derived == "" {
		return nil, invalidInput("Choose a slug: the name has no letters or digits")
	}
	slug, err := m.freeSlug(ctx, tx, tenantID, derived, "")
	if err != nil {
		return nil, err
	}
	chain := []*core.Object{}
	if raw := input.Get("parentId"); !isUndefined(raw) {
		parent, err := LoadTeam(ctx, tx, tenantID, raw)
		if err != nil {
			return nil, err
		}
		if chain, err = parentChain(existing, parent, 1); err != nil {
			return nil, err
		}
		if err := m.assertCanNestUnder(ctx, tx, principal, tenantID, chain); err != nil {
			return nil, err
		}
	}
	if raw := input.Get("departmentId"); !isUndefined(raw) {
		if _, err := LoadDepartment(ctx, tx, tenantID, raw); err != nil {
			return nil, err
		}
	}
	maintainerIDs := []string{}
	if raw := input.Get("maintainerIds"); !isUndefined(raw) {
		list, err := Strings(raw, "maintainerIds")
		if err != nil {
			return nil, err
		}
		maintainerIDs = unique(list)
	}
	if len(maintainerIDs) > maxMaintainersOnCreate {
		return nil, invalidInput("Name at most " + jsString(float64(maxMaintainersOnCreate)) + " maintainers when creating a team")
	}
	syncGroupIDs := []string{}
	if raw := input.Get("syncGroupIds"); !isUndefined(raw) {
		if syncGroupIDs, err = TeamSyncGroups(ctx, tx, tenantID, raw); err != nil {
			return nil, err
		}
	}
	now := float64(server.Now())
	group, err := CreateGroup(ctx, server, tx, tenant, core.NewObject(
		"tenantId", tenantID,
		"name", "team:"+slug,
		"description", "Members of team "+name+" (managed by the team)",
	))
	if err != nil {
		return nil, err
	}
	team := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", "slug:"+slug,
		"name", name,
		"slug", slug,
	)
	if raw := input.Get("description"); !isUndefined(raw) && raw != "" {
		description, err := Text(raw, "description", 512)
		if err != nil {
			return nil, err
		}
		team.Set("description", description)
	}
	if !isUndefined(input.Get("parentId")) {
		team.Set("parentId", chain[0].Get("id"))
	}
	if raw := input.Get("departmentId"); !isUndefined(raw) {
		team.Set("departmentId", raw)
	}
	team.Set("groupId", group.Get("id"))
	joinPolicy := "closed"
	if raw := input.Get("joinPolicy"); !isUndefined(raw) {
		if joinPolicy, err = teamChoice(raw, teamJoinPolicies, "joinPolicy"); err != nil {
			return nil, err
		}
	}
	team.Set("joinPolicy", joinPolicy)
	memberManagement := "maintainers"
	if raw := input.Get("memberManagement"); !isUndefined(raw) {
		if memberManagement, err = teamChoice(raw, teamManagementModes, "memberManagement"); err != nil {
			return nil, err
		}
	}
	team.Set("memberManagement", memberManagement)
	if len(syncGroupIDs) > 0 {
		team.Set("syncGroupIds", stringsOf(syncGroupIDs))
	}
	team.Set("createdAt", now)
	team.Set("createdBy", principal.Identity.Get("id"))
	team.Set("updatedAt", now)
	if _, err := tx.Put(ctx, "groups", group.Spread(core.NewObject("teamId", team.Get("id")))); err != nil {
		return nil, err
	}
	if _, err := tx.Insert(ctx, TeamCollections.Teams, team); err != nil {
		return nil, err
	}
	for _, identityID := range maintainerIDs {
		if _, err := m.putMember(ctx, &teamMutation{
			MutationContext: MutationContext{Tx: tx, Principal: principal, Tenant: tenant}, team: team, via: "permission",
		}, core.NewObject("identityId", identityID, "role", "maintainer"), "create"); err != nil {
			return nil, err
		}
	}
	if len(syncGroupIDs) > 0 {
		// Syncing brings the source groups' members into the teams above it too.
		if err := m.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, append([]*core.Object{team}, chain...)); err != nil {
			return nil, err
		}
		if _, err := SyncTeamsFromGroups(ctx, server, tx, tenantID, core.NewObject(
			"teamIds", []any{team.Get("id")},
			"actorId", principal.Identity.Get("id"),
		)); err != nil {
			return nil, err
		}
	}
	metadata := core.NewObject("name", name)
	if truthy(team.Get("parentId")) {
		metadata.Set("parentId", team.Get("parentId"))
	}
	if err := m.audit(ctx, tx, principal, "team:create", team, metadata); err != nil {
		return nil, err
	}
	return team, nil
}

var teamUpdateKeys = []string{"name", "slug", "description", "parentId", "departmentId", "joinPolicy", "memberManagement", "syncGroupIds"}

// syncGroupsInclude is `team.syncGroupIds?.includes(groupId)`.
func syncGroupsInclude(team *core.Object, groupID string) bool {
	list, ok := team.Get("syncGroupIds").([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if item == groupID {
			return true
		}
	}
	return false
}

// updateTeam changes a team's settings or place; the caller has authorized `iam:teams:update` on it.
func (m *teamModule) updateTeam(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, input *core.Object) (*core.Object, error) {
	server := m.server
	tenantID, teamID := jsString(team.Get("tenantId")), jsString(team.Get("id"))
	nothing := true
	for _, key := range teamUpdateKeys {
		if !isUndefined(input.Get(key)) {
			nothing = false
		}
	}
	if nothing {
		return nil, invalidInput("Nothing to update")
	}
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	next := team.Spread(core.NewObject("updatedAt", float64(server.Now())))
	if raw := input.Get("name"); !isUndefined(raw) {
		name, err := Text(raw, "name", 100)
		if err != nil {
			return nil, err
		}
		next.Set("name", core.JSTrim(name))
	}
	if raw := input.Get("slug"); !isUndefined(raw) && !core.StrictEquals(raw, team.Get("slug")) {
		candidate, err := TeamSlug(raw)
		if err != nil {
			return nil, err
		}
		slug, err := m.freeSlug(ctx, tx, tenantID, candidate, teamID)
		if err != nil {
			return nil, err
		}
		next.Set("slug", slug)
		next.Set("uniqueKey", "slug:"+slug)
	}
	if raw := input.Get("description"); !isUndefined(raw) {
		next.Delete("description")
		if raw != nil && raw != "" {
			description, err := Text(raw, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", description)
		}
	}
	if raw := input.Get("departmentId"); !isUndefined(raw) {
		next.Delete("departmentId")
		if raw != nil {
			if _, err := LoadDepartment(ctx, tx, tenantID, raw); err != nil {
				return nil, err
			}
			next.Set("departmentId", raw)
		}
	}
	if raw := input.Get("joinPolicy"); !isUndefined(raw) {
		joinPolicy, err := teamChoice(raw, teamJoinPolicies, "joinPolicy")
		if err != nil {
			return nil, err
		}
		next.Set("joinPolicy", joinPolicy)
	}
	if raw := input.Get("memberManagement"); !isUndefined(raw) {
		memberManagement, err := teamChoice(raw, teamManagementModes, "memberManagement")
		if err != nil {
			return nil, err
		}
		next.Set("memberManagement", memberManagement)
	}
	if raw := input.Get("syncGroupIds"); !isUndefined(raw) {
		next.Delete("syncGroupIds")
		sources := []string{}
		if raw != nil {
			if sources, err = TeamSyncGroups(ctx, tx, tenantID, raw); err != nil {
				return nil, err
			}
		}
		if len(sources) > 0 {
			next.Set("syncGroupIds", stringsOf(sources))
		}
		// Syncing brings people in, and with them what the team and the teams above it hold.
		added := false
		for _, groupID := range sources {
			if !syncGroupsInclude(team, groupID) {
				added = true
				break
			}
		}
		if added {
			chain, err := TeamChain(teams.byID, teamID)
			if err != nil {
				return nil, err
			}
			if err := m.assertAuthorityOver(ctx, tx, principal, tenantID, chain); err != nil {
				return nil, err
			}
			if chain, err = TeamChain(teams.byID, teamID); err != nil {
				return nil, err
			}
			if err := m.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, chain); err != nil {
				return nil, err
			}
		}
	}
	previousParent := team.Get("parentId")
	if raw := input.Get("parentId"); !isUndefined(raw) && !core.StrictEquals(coalesce(raw, core.Undefined), previousParent) {
		next.Delete("parentId")
		if raw != nil {
			parent, err := LoadTeam(ctx, tx, tenantID, raw)
			if err != nil {
				return nil, err
			}
			descendants, err := TeamDescendants(teams.values(), teamID)
			if err != nil {
				return nil, err
			}
			circular := core.StrictEquals(parent.Get("id"), team.Get("id"))
			for _, item := range descendants {
				if core.StrictEquals(item.Get("id"), parent.Get("id")) {
					circular = true
				}
			}
			if circular {
				return nil, invalidInput("A team cannot move under itself or its own team")
			}
			height, err := subtreeHeight(teams, team)
			if err != nil {
				return nil, err
			}
			chain, err := parentChain(teams, parent, height)
			if err != nil {
				return nil, err
			}
			if err := m.assertCanNestUnder(ctx, tx, principal, tenantID, chain); err != nil {
				return nil, err
			}
			// The new parent's maintainers gain standing over the moved team and every team below it, so moving
			// them hands out what those teams hold: it needs the same authority as adding someone to them.
			if descendants, err = TeamDescendants(teams.values(), teamID); err != nil {
				return nil, err
			}
			if err := m.assertAuthorityOver(ctx, tx, principal, tenantID, append([]*core.Object{team}, descendants...)); err != nil {
				return nil, err
			}
			// Its members claim the seats of the new chain, and the new parent's maintainers hand out the moved
			// teams'.
			if descendants, err = TeamDescendants(teams.values(), teamID); err != nil {
				return nil, err
			}
			claimed := append(append(append([]*core.Object{}, chain...), team), descendants...)
			if err := m.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, claimed); err != nil {
				return nil, err
			}
			next.Set("parentId", parent.Get("id"))
		}
	}
	// Opening an admins-only team to its maintainers lets them grant what it and the teams above it hold.
	if team.Get("memberManagement") == "admins" && next.Get("memberManagement") != "admins" {
		opened := []*core.Object{team}
		if parentID := next.Get("parentId"); truthy(parentID) {
			chain, err := TeamChain(teams.byID, jsString(parentID))
			if err != nil {
				return nil, err
			}
			opened = append(opened, chain...)
		}
		if err := m.assertAuthorityOver(ctx, tx, principal, tenantID, opened); err != nil {
			return nil, err
		}
		if err := m.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, opened); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Put(ctx, TeamCollections.Teams, next); err != nil {
		return nil, err
	}
	if !core.StrictEquals(next.Get("slug"), team.Get("slug")) || !core.StrictEquals(next.Get("name"), team.Get("name")) {
		group, err := tx.Get(ctx, "groups", jsString(team.Get("groupId")))
		if err != nil {
			return nil, err
		}
		if group != nil {
			if _, err := tx.Put(ctx, "groups", group.Spread(core.NewObject(
				"name", "team:"+jsString(next.Get("slug")),
				"description", "Members of team "+jsString(next.Get("name"))+" (managed by the team)",
			))); err != nil {
				return nil, err
			}
		}
	}
	moved := !core.StrictEquals(next.Get("parentId"), previousParent)
	if moved {
		ids := []string{teamID}
		if truthy(previousParent) {
			ids = append(ids, jsString(previousParent))
		}
		if _, err := SyncTeamGroups(ctx, tx, tenantID, ids, server.Now()); err != nil {
			return nil, err
		}
	}
	if !isUndefined(input.Get("syncGroupIds")) {
		if _, err := SyncTeamsFromGroups(ctx, server, tx, tenantID, core.NewObject(
			"teamIds", []any{team.Get("id")},
			"actorId", principal.Identity.Get("id"),
		)); err != nil {
			return nil, err
		}
	}
	fields := []any{}
	for _, key := range teamUpdateKeys {
		if !isUndefined(input.Get(key)) {
			fields = append(fields, key)
		}
	}
	metadata := core.NewObject("fields", fields)
	if moved {
		metadata.Set("parentId", coalesce(next.Get("parentId"), nil))
		metadata.Set("previousParentId", coalesce(previousParent, nil))
	}
	if err := m.audit(ctx, tx, principal, "team:update", next, metadata); err != nil {
		return nil, err
	}
	return next, nil
}

// deleteTeam deletes a team with its memberships, requests, and backing group; it returns how many members it had.
func (m *teamModule) deleteTeam(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object) (float64, error) {
	server := m.server
	tenantID, teamID := jsString(team.Get("tenantId")), jsString(team.Get("id"))
	all, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return 0, err
	}
	children := []string{}
	for _, other := range all {
		if core.StrictEquals(other.Get("parentId"), team.Get("id")) {
			children = append(children, jsString(other.Get("name")))
		}
	}
	if len(children) > 0 {
		return 0, core.NewIamError("RESOURCE_IN_USE", "Move or delete the teams below it first: "+strings.Join(children, ", "), 409)
	}
	// A team a birthright rule names stays until the package stops naming it (like groups).
	naming, err := PackagesNaming(ctx, tx, tenantID, "identity.teams", []string{teamID}, []string{jsString(team.Get("groupId"))})
	if err != nil {
		return 0, err
	}
	if len(naming) > 0 {
		return 0, core.NewIamError("RESOURCE_IN_USE", "Access packages name it in a rule: "+strings.Join(naming, ", "), 409)
	}
	members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
	if err != nil {
		return 0, err
	}
	for _, member := range members {
		if err := tx.Delete(ctx, TeamCollections.Members, jsString(member.Get("id"))); err != nil {
			return 0, err
		}
	}
	requests, err := tx.Find(ctx, TeamCollections.Requests, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
	if err != nil {
		return 0, err
	}
	for _, request := range requests {
		if err := tx.Delete(ctx, TeamCollections.Requests, jsString(request.Get("id"))); err != nil {
			return 0, err
		}
	}
	// Membership reviews go with the team (their outcome stays in the audit trail).
	for _, collection := range []string{TeamReviewCollections.Items, TeamReviewCollections.Reviews} {
		records, err := tx.Find(ctx, collection, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
		if err != nil {
			return 0, err
		}
		for _, record := range records {
			if err := tx.Delete(ctx, collection, jsString(record.Get("id"))); err != nil {
				return 0, err
			}
		}
	}
	group, err := tx.Get(ctx, "groups", jsString(team.Get("groupId")))
	if err != nil {
		return 0, err
	}
	if group != nil {
		if err := DeleteGroup(ctx, server, tx, principal, group); err != nil {
			return 0, err
		}
	}
	if err := tx.Delete(ctx, TeamCollections.Teams, teamID); err != nil {
		return 0, err
	}
	if parentID := team.Get("parentId"); truthy(parentID) {
		if _, err := SyncTeamGroups(ctx, tx, tenantID, []string{jsString(parentID)}, server.Now()); err != nil {
			return 0, err
		}
	}
	if err := m.audit(ctx, tx, principal, "team:delete", team, core.NewObject("name", team.Get("name"), "members", float64(len(members)))); err != nil {
		return 0, err
	}
	return float64(len(members)), nil
}

// teamChainOf is `teamChain(await allTeams(tx, team.tenantId), team.id)`.
func (m *teamModule) teamChainOf(ctx context.Context, tx core.IamStore, team *core.Object) ([]*core.Object, error) {
	teams, err := m.allTeams(ctx, tx, jsString(team.Get("tenantId")))
	if err != nil {
		return nil, err
	}
	return TeamChain(teams.byID, jsString(team.Get("id")))
}

// assertAuthorityOverChain is `assertAuthorityOver(tx, principal, team.tenantId, teamChain(...))`.
func (m *teamModule) assertAuthorityOverChain(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object) error {
	chain, err := m.teamChainOf(ctx, tx, team)
	if err != nil {
		return err
	}
	return m.assertAuthorityOver(ctx, tx, principal, jsString(team.Get("tenantId")), chain)
}

// reviewTeamID is routing only: the team a review belongs to (the operation re-reads and checks the review under
// authorization).
func (m *teamModule) reviewTeamID(ctx context.Context, tenantIDInput, reviewIDInput any) (string, error) {
	tenantID, err := Text(tenantIDInput, "tenantId")
	if err != nil {
		return "", err
	}
	reviewID, err := Text(reviewIDInput, "reviewId", 128)
	if err != nil {
		return "", err
	}
	return core.Transact(ctx, m.server.Store, func(ctx context.Context, tx core.IamStore) (string, error) {
		review, err := tx.Get(ctx, TeamReviewCollections.Reviews, reviewID)
		if err != nil {
			return "", err
		}
		if review != nil && review.Get("tenantId") == tenantID {
			return jsString(review.Get("teamId")), nil
		}
		return reviewID, nil
	})
}

func (m *teamModule) loadReview(ctx context.Context, tx core.IamStore, team *core.Object, reviewID any) (*core.Object, error) {
	id, err := Text(reviewID, "reviewId", 128)
	if err != nil {
		return nil, err
	}
	review, err := tx.Get(ctx, TeamReviewCollections.Reviews, id)
	if err != nil {
		return nil, err
	}
	if review == nil || !core.StrictEquals(review.Get("tenantId"), team.Get("tenantId")) || !core.StrictEquals(review.Get("teamId"), team.Get("id")) {
		return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
	}
	return review, nil
}

// teamRoleRank is `Number(role === 'maintainer')`.
func teamRoleRank(role any) int {
	if role == "maintainer" {
		return 1
	}
	return 0
}

func (m *teamModule) reviewView(ctx context.Context, tx core.IamStore, review *core.Object, team *core.Object, withItems bool) (*core.Object, error) {
	items, err := tx.Find(ctx, TeamReviewCollections.Items, core.NewObject("tenantId", review.Get("tenantId"), "reviewId", review.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return compareUTF16(jsString(items[i].Get("identityId")), jsString(items[j].Get("identityId"))) < 0
	})
	ids := []string{jsString(review.Get("startedBy"))}
	for _, item := range items {
		ids = append(ids, jsString(item.Get("identityId")))
		if truthy(item.Get("decidedBy")) {
			ids = append(ids, jsString(item.Get("decidedBy")))
		}
	}
	directory, err := m.people(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	// counts[item.decision ?? 'undecided']++ (decisions are keep or remove; anything else would read as NaN).
	keep, remove, undecided := 0, 0, 0
	var others []string
	for _, item := range items {
		decision := item.Get("decision")
		switch {
		case nullish(decision):
			undecided++
		case decision == "keep":
			keep++
		case decision == "remove":
			remove++
		default:
			if !containsString(others, jsString(decision)) {
				others = append(others, jsString(decision))
			}
		}
	}
	view := core.NewObject(
		"id", review.Get("id"),
		"team", teamRef(team),
		"status", review.Get("status"),
		"onUndecided", review.Get("onUndecided"),
		"startedAt", review.Get("startedAt"),
		"startedBy", directory[jsString(review.Get("startedBy"))],
		"dueAt", review.Get("dueAt"),
	)
	if truthy(review.Get("note")) {
		view.Set("note", review.Get("note"))
	}
	if completedAt := review.Get("completedAt"); !isUndefined(completedAt) {
		view.Set("completedAt", completedAt)
	}
	if truthy(review.Get("completedBy")) {
		view.Set("completedBy", review.Get("completedBy"))
	}
	if truthy(review.Get("outcome")) {
		view.Set("outcome", review.Get("outcome"))
	}
	counts := core.NewObject("total", float64(len(items)), "keep", float64(keep), "remove", float64(remove), "undecided", float64(undecided))
	for _, other := range others {
		counts.Set(other, math.NaN())
	}
	view.Set("counts", counts)
	if withItems {
		views := make([]*core.Object, len(items))
		for index, item := range items {
			entry := core.NewObject("person", directory[jsString(item.Get("identityId"))], "role", item.Get("role"))
			if truthy(item.Get("decision")) {
				entry.Set("decision", item.Get("decision"))
			}
			if truthy(item.Get("decidedBy")) {
				entry.Set("decidedBy", directory[jsString(item.Get("decidedBy"))])
			}
			if decidedAt := item.Get("decidedAt"); !isUndefined(decidedAt) {
				entry.Set("decidedAt", decidedAt)
			}
			if truthy(item.Get("note")) {
				entry.Set("note", item.Get("note"))
			}
			views[index] = entry
		}
		sort.SliceStable(views, func(i, j int) bool {
			a, b := views[i], views[j]
			if rank := teamRoleRank(b.Get("role")) - teamRoleRank(a.Get("role")); rank != 0 {
				return rank < 0
			}
			return localeCompare(teamPersonLabel(a.Get("person").(*core.Object)), teamPersonLabel(b.Get("person").(*core.Object))) < 0
		})
		view.Set("items", certRecordList(views))
	}
	return view, nil
}

// lapse reads a pending request past its lapse time as expired.
func (m *teamModule) lapse(request *core.Object) *core.Object {
	if request.Get("status") == "pending" && jsNumber(request.Get("expiresAt")) <= float64(m.server.Now()) {
		return request.Spread(core.NewObject("status", "expired"))
	}
	return request
}

func (m *teamModule) membershipsOf(ctx context.Context, tx core.IamStore, tenantID, identityID string) ([]*core.Object, error) {
	now := m.server.Now()
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	result := []*core.Object{}
	for _, member := range members {
		live, err := LiveTeamMember(member, now)
		if err != nil {
			return nil, err
		}
		if !live || !teams.has(jsString(member.Get("teamId"))) {
			continue
		}
		team := teams.get(jsString(member.Get("teamId")))
		view := teamRef(team)
		if truthy(team.Get("description")) {
			view.Set("description", team.Get("description"))
		}
		view.Set("role", member.Get("role"))
		if expiresAt := member.Get("expiresAt"); !isUndefined(expiresAt) {
			view.Set("expiresAt", expiresAt)
		}
		chain, err := TeamChain(teams.byID, jsString(team.Get("id")))
		if err != nil {
			return nil, err
		}
		view.Set("parents", teamRefs(reversedTail(chain)))
		result = append(result, view)
	}
	sortTeamsByName(result)
	return result, nil
}

// nearestMaintainers is the maintainers of the team or, when it has none, of the nearest team above it.
func (m *teamModule) nearestMaintainers(ctx context.Context, tx core.IamStore, tenantID string, team *core.Object, now int64) ([]string, error) {
	teams, err := m.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	chain, err := TeamChain(teams.byID, jsString(team.Get("id")))
	if err != nil {
		return nil, err
	}
	recipients := []string{}
	for _, holder := range chain {
		if recipients, err = TeamMaintainers(ctx, tx, tenantID, jsString(holder.Get("id")), now); err != nil {
			return nil, err
		}
		if len(recipients) > 0 {
			break
		}
	}
	return recipients, nil
}

// optionalNote is an optional text of at most 1000 units: "" when the value is undefined or empty.
func optionalNote(value any, name string) (string, error) {
	if isUndefined(value) || value == "" {
		return "", nil
	}
	return Text(value, name, 1000)
}

func (m *teamModule) decide(ctx context.Context, credential core.CredentialInput, input *core.Object, outcome string) (any, error) {
	server := m.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	requestID, err := Text(input.Get("requestId"), "requestId", 128)
	if err != nil {
		return nil, err
	}
	// Routing only: the operation below re-reads and checks the request under authorization.
	teamID, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (string, error) {
		request, err := tx.Get(ctx, TeamCollections.Requests, requestID)
		if err != nil {
			return "", err
		}
		if request != nil && request.Get("tenantId") == tenantID {
			return jsString(request.Get("teamId")), nil
		}
		return requestID, nil
	})
	if err != nil {
		return nil, err
	}
	note, err := optionalNote(input.Get("note"), "note")
	if err != nil {
		return nil, err
	}
	return m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, tenantID, teamID, "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			tx, principal, team := mutation.Tx, mutation.Principal, mutation.team
			request, err := server.Scoped(ctx, tx, TeamCollections.Requests, requestID, tenantID)
			if err != nil {
				return nil, err
			}
			if !core.StrictEquals(request.Get("teamId"), team.Get("id")) {
				return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
			}
			if m.lapse(request).Get("status") != "pending" {
				return nil, core.NewIamError("INVALID_TRANSITION", "The request is no longer pending", 409)
			}
			if core.StrictEquals(request.Get("identityId"), principal.Identity.Get("id")) {
				return nil, core.NewIamError("ACCESS_DENIED", "Nobody decides their own join request", 403)
			}
			if outcome == "approved" {
				if mutation.via == "permission" {
					if err := m.assertAuthorityOverChain(ctx, tx, principal, team); err != nil {
						return nil, err
					}
				}
				memberInput := core.NewObject("identityId", request.Get("identityId"))
				if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
					memberInput.Set("expiresAt", expiresAt)
				}
				if _, err := m.putMember(ctx, mutation, memberInput, "approve"); err != nil {
					return nil, err
				}
				touch(jsString(request.Get("identityId")))
			}
			decision := core.NewObject(
				"status", outcome,
				"decidedBy", principal.Identity.Get("id"),
				"decidedAt", float64(server.Now()),
			)
			if note != "" {
				decision.Set("note", note)
			}
			decided, err := tx.Put(ctx, TeamCollections.Requests, request.Spread(decision))
			if err != nil {
				return nil, err
			}
			payload := core.NewObject("teamId", team.Get("id"), "teamName", team.Get("name"), "decision", outcome)
			if note != "" {
				payload.Set("note", note)
			}
			if err := m.email(ctx, tx, tenantID, []string{jsString(request.Get("identityId"))}, "team-join-decided", payload); err != nil {
				return nil, err
			}
			action := "team:join:deny"
			if outcome == "approved" {
				action = "team:join:approve"
			}
			metadata := core.NewObject("requestId", request.Get("id"), "identityId", request.Get("identityId"))
			if mutation.via != "permission" {
				metadata.Set("via", mutation.via)
			}
			if err := m.audit(ctx, tx, principal, action, team, metadata); err != nil {
				return nil, err
			}
			return m.requestView(ctx, tx, decided)
		})
	})
}

// teamTouch is `touch(await membersBelow(tx, team))`.
func (m *teamModule) teamTouch(ctx context.Context, tx core.IamStore, team *core.Object, touch func(identityIDs ...string)) error {
	ids, err := m.membersBelow(ctx, tx, team)
	if err != nil {
		return err
	}
	touch(ids...)
	return nil
}

// Create is POST {basePath}/teams/create. Creates a team with its backing group. `parentId` nests it (its members
// then also receive the parent's access; needs iam:teams:update on the parent and authority over what the parent
// holds); `maintainerIds` names up to 20 people who manage its membership.
func (api *TeamsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCreateInput]) (Out[apitypes.TeamsCreateOutput], error) {
	m := api.module
	body := input.Body
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return api.server.Operations.Operation(ctx, credential, input.Get("tenantId"), "iam:teams:create", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
			team, err := m.createTeam(ctx, call.Tx, call.Principal, call.Tenant, body)
			if err != nil {
				return nil, err
			}
			if err := m.teamTouch(ctx, call.Tx, team, touch); err != nil {
				return nil, err
			}
			return m.detail(ctx, call.Tx, team)
		}, false)
	})
	return Out[apitypes.TeamsCreateOutput]{Value: result}, err
}

// Update is POST {basePath}/teams/update. Renames, re-slugs, re-describes, moves (`parentId`, null for top level), or
// re-files (`departmentId`) a team, or changes its join policy or who manages members. Moving re-computes the backing
// groups of the old and new parents; the new parent needs the same rights as creating under it.
func (api *TeamsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsUpdateInput]) (Out[apitypes.TeamsUpdateOutput], error) {
	m := api.module
	body := input.Body
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "", func(ctx context.Context, mutation *teamMutation) (any, error) {
			// A move or a sync change alters identity.teams at or below the team.
			moving := !isUndefined(input.Get("parentId")) || !isUndefined(input.Get("syncGroupIds"))
			if moving {
				if err := m.teamTouch(ctx, mutation.Tx, mutation.team, touch); err != nil {
					return nil, err
				}
			}
			updated, err := m.updateTeam(ctx, mutation.Tx, mutation.Principal, mutation.team, body)
			if err != nil {
				return nil, err
			}
			if moving {
				if err := m.teamTouch(ctx, mutation.Tx, updated, touch); err != nil {
					return nil, err
				}
			}
			return m.detail(ctx, mutation.Tx, updated)
		})
	})
	return Out[apitypes.TeamsUpdateOutput]{Value: result}, err
}

// Delete is POST {basePath}/teams/delete. Deletes a team, its memberships and join requests, and its backing group
// with the bindings and relationships on it (which needs authority over those bindings, as `groups.delete` does).
// Teams below it must be moved or deleted first (RESOURCE_IN_USE).
func (api *TeamsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsDeleteInput]) (Out[apitypes.TeamsDeleteOutput], error) {
	m := api.module
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:delete", "", func(ctx context.Context, mutation *teamMutation) (any, error) {
			if err := m.teamTouch(ctx, mutation.Tx, mutation.team, touch); err != nil {
				return nil, err
			}
			members, err := m.deleteTeam(ctx, mutation.Tx, mutation.Principal, mutation.team)
			if err != nil {
				return nil, err
			}
			return core.NewObject("deleted", true, "members", members), nil
		})
	})
	return Out[apitypes.TeamsDeleteOutput]{Value: result}, err
}

// List is POST {basePath}/teams/list. Every team of the organization with member counts, name order. Filters:
// `parentId` (null for top-level teams), `departmentId`, and `query` (name or slug, case-insensitive).
func (api *TeamsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListInput]) (Out[apitypes.TeamsListOutput], error) {
	m := api.module
	result, err := api.server.Operations.Operation(ctx, credential, input.Get("tenantId"), "iam:teams:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		teams, err := m.allTeams(ctx, call.Tx, jsString(input.Get("tenantId")))
		if err != nil {
			return nil, err
		}
		all := teams.values()
		query, hasQuery := "", false
		if raw := input.Get("query"); !isUndefined(raw) {
			text, err := Text(raw, "query", 100)
			if err != nil {
				return nil, err
			}
			query, hasQuery = core.JSLower(text), true
		}
		parentID, departmentID := input.Get("parentId"), input.Get("departmentId")
		selected := []*core.Object{}
		for _, team := range all {
			if !isUndefined(parentID) && !core.StrictEquals(coalesce(team.Get("parentId"), nil), parentID) {
				continue
			}
			if !isUndefined(departmentID) && !core.StrictEquals(team.Get("departmentId"), departmentID) {
				continue
			}
			if hasQuery && !strings.Contains(core.JSLower(jsString(team.Get("name"))), query) && !strings.Contains(jsString(team.Get("slug")), query) {
				continue
			}
			selected = append(selected, team)
		}
		sort.SliceStable(selected, func(i, j int) bool {
			a, b := selected[i], selected[j]
			if order := localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))); order != 0 {
				return order < 0
			}
			return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		summaries, err := m.summaries(ctx, call.Tx, selected, all)
		if err != nil {
			return nil, err
		}
		return certRecordList(summaries), nil
	}, false)
	return Out[apitypes.TeamsListOutput]{Value: result}, err
}

// Get is POST {basePath}/teams/get. One team with its place in the tree, maintainers, department, and the roles its
// members hold through it. Members may read their own team.
func (api *TeamsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsGetInput]) (Out[apitypes.TeamsGetOutput], error) {
	m := api.module
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:read", "member", func(ctx context.Context, mutation *teamMutation) (any, error) {
		return m.detail(ctx, mutation.Tx, mutation.team)
	})
	return Out[apitypes.TeamsGetOutput]{Value: result}, err
}

// ListMembers is POST {basePath}/teams/listMembers. The team's live direct members with their role;
// `includeChildTeams` adds the members of every team below it (each with the team they belong to). Members may read
// their own team.
func (api *TeamsAPI) ListMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListMembersInput]) (Out[apitypes.TeamsListMembersOutput], error) {
	m := api.module
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:read", "member", func(ctx context.Context, mutation *teamMutation) (any, error) {
		tx, team := mutation.Tx, mutation.team
		tenantID := jsString(team.Get("tenantId"))
		teams, err := m.allTeams(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		scope := []*core.Object{team}
		if truthy(input.Get("includeChildTeams")) {
			descendants, err := TeamDescendants(teams.values(), jsString(team.Get("id")))
			if err != nil {
				return nil, err
			}
			scope = append(scope, descendants...)
		}
		now := api.server.Now()
		members := []*core.Object{}
		for _, item := range scope {
			found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "teamId", item.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			live, err := liveTeamMembers(found, now)
			if err != nil {
				return nil, err
			}
			members = append(members, live...)
		}
		ids := make([]string, len(members))
		for index, member := range members {
			ids[index] = jsString(member.Get("identityId"))
		}
		directory, err := m.people(ctx, tx, ids)
		if err != nil {
			return nil, err
		}
		views := []*core.Object{}
		for _, member := range members {
			holder := teams.get(jsString(member.Get("teamId")))
			if holder == nil {
				holder = team
			}
			view := directory[jsString(member.Get("identityId"))].Spread(core.NewObject(
				"role", member.Get("role"),
				"team", teamRef(holder),
				"addedAt", member.Get("addedAt"),
				"addedBy", member.Get("addedBy"),
			))
			if expiresAt := member.Get("expiresAt"); !isUndefined(expiresAt) {
				view.Set("expiresAt", expiresAt)
			}
			if truthy(member.Get("source")) {
				view.Set("source", member.Get("source"))
			}
			if view.Get("status") != "deleted" {
				views = append(views, view)
			}
		}
		sort.SliceStable(views, func(i, j int) bool {
			a, b := views[i], views[j]
			if rank := teamRoleRank(b.Get("role")) - teamRoleRank(a.Get("role")); rank != 0 {
				return rank < 0
			}
			return localeCompare(teamPersonLabel(a), teamPersonLabel(b)) < 0
		})
		return certRecordList(views), nil
	})
	return Out[apitypes.TeamsListMembersOutput]{Value: result}, err
}

// AddMember is POST {basePath}/teams/addMember. Adds a person (`role` member by default, or maintainer; `expiresAt`
// for a temporary membership). Maintainers of the team or a team above it may do this without iam:teams:update unless
// the team's memberManagement is `admins`.
func (api *TeamsAPI) AddMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsAddMemberInput]) (Out[apitypes.TeamsAddMemberOutput], error) {
	m := api.module
	body := input.Body
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			if mutation.via == "permission" {
				if err := m.assertAuthorityOverChain(ctx, mutation.Tx, mutation.Principal, mutation.team); err != nil {
					return nil, err
				}
			}
			member, err := m.putMember(ctx, mutation, body, "add")
			if err != nil {
				return nil, err
			}
			touch(jsString(member.Get("identityId")))
			return member, nil
		})
	})
	return Out[apitypes.TeamsAddMemberOutput]{Value: result}, err
}

// AddMembers is POST {basePath}/teams/addMembers. Adds up to 100 people in one transaction with the same role and
// expiry; one failure rejects the batch.
func (api *TeamsAPI) AddMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsAddMembersInput]) (Out[apitypes.TeamsAddMembersOutput], error) {
	m := api.module
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			list, err := Strings(input.Get("identityIds"), "identityIds")
			if err != nil {
				return nil, err
			}
			identityIDs := unique(list)
			if len(identityIDs) == 0 {
				return nil, invalidInput("Provide 1-100 identityIds")
			}
			if mutation.via == "permission" {
				if err := m.assertAuthorityOverChain(ctx, mutation.Tx, mutation.Principal, mutation.team); err != nil {
					return nil, err
				}
			}
			members := []any{}
			for _, identityID := range identityIDs {
				memberInput := core.NewObject("identityId", identityID)
				if role := input.Get("role"); !isUndefined(role) {
					memberInput.Set("role", role)
				}
				if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
					memberInput.Set("expiresAt", expiresAt)
				}
				member, err := m.putMember(ctx, mutation, memberInput, "add")
				if err != nil {
					return nil, err
				}
				members = append(members, member)
			}
			touch(identityIDs...)
			return core.NewObject("members", members), nil
		})
	})
	return Out[apitypes.TeamsAddMembersOutput]{Value: result}, err
}

// UpdateMember is POST {basePath}/teams/updateMember. Changes a member's role or expiry (`expiresAt: null` makes the
// membership permanent).
func (api *TeamsAPI) UpdateMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsUpdateMemberInput]) (Out[apitypes.TeamsUpdateMemberOutput], error) {
	m := api.module
	server := api.server
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			tx, principal, team, via := mutation.Tx, mutation.Principal, mutation.team, mutation.via
			tenantID := jsString(team.Get("tenantId"))
			rawRole, rawExpiresAt := input.Get("role"), input.Get("expiresAt")
			if isUndefined(rawRole) && isUndefined(rawExpiresAt) {
				return nil, invalidInput("Nothing to update")
			}
			if via == "permission" {
				if err := m.assertAuthorityOverChain(ctx, tx, principal, team); err != nil {
					return nil, err
				}
			}
			member, err := m.memberRecord(ctx, tx, team, input.Get("identityId"))
			if err != nil {
				return nil, err
			}
			if member.Get("source") == "sync" && !isUndefined(rawExpiresAt) {
				return nil, core.NewIamError("INVALID_TRANSITION", "A synced membership ends with the source group membership; change it there", 409)
			}
			next := member.Clone()
			if !isUndefined(rawRole) {
				role, err := teamChoice(rawRole, teamRoles, "role")
				if err != nil {
					return nil, err
				}
				next.Set("role", role)
			}
			if !isUndefined(rawExpiresAt) {
				next.Delete("expiresAt")
				if rawExpiresAt != nil {
					expiresAt, err := server.BindingExpiry(rawExpiresAt)
					if err != nil {
						return nil, err
					}
					next.Set("expiresAt", expiresAt)
				}
			}
			previous, updated := member.Get("expiresAt"), next.Get("expiresAt")
			// longerThan is `next.expiresAt === undefined || next.expiresAt > member.expiresAt` (with member.expiresAt
			// set).
			longer := !isUndefined(previous) && (isUndefined(updated) || jsNumber(updated) > jsNumber(previous))
			// Maintainers act under the administrators' delegation: they never extend their own membership (a
			// temporary maintainer would make themselves permanent), and ending it early is leaving the team.
			if via != "permission" && core.StrictEquals(member.Get("identityId"), principal.Identity.Get("id")) && !isUndefined(rawExpiresAt) {
				if longer {
					return nil, core.NewIamError("ACCESS_DENIED", "Maintainers cannot extend their own membership; ask an administrator", 403)
				}
				if !core.StrictEquals(updated, previous) {
					held, err := m.heldChainGroups(ctx, tx, team, jsString(member.Get("identityId")))
					if err != nil {
						return nil, err
					}
					if err := m.assertMayDropDenies(ctx, tx, principal, tenantID, held.Values()); err != nil {
						return nil, err
					}
				}
			}
			// An administrator keeping someone longer, or appointing a maintainer (who then adds people), claims
			// license seats of a licensed team; shortening or demoting does not.
			if via == "permission" && (longer || (next.Get("role") == "maintainer" && member.Get("role") != "maintainer")) {
				chain, err := m.teamChainOf(ctx, tx, team)
				if err != nil {
					return nil, err
				}
				if err := m.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, chain); err != nil {
					return nil, err
				}
			}
			if _, err := tx.Put(ctx, TeamCollections.Members, next); err != nil {
				return nil, err
			}
			if _, err := SyncTeamGroups(ctx, tx, tenantID, []string{jsString(team.Get("id"))}, server.Now()); err != nil {
				return nil, err
			}
			metadata := core.NewObject("identityId", member.Get("identityId"), "role", next.Get("role"))
			if !isUndefined(updated) {
				metadata.Set("expiresAt", updated)
			}
			if via != "permission" {
				metadata.Set("via", via)
			}
			if err := m.audit(ctx, tx, principal, "team:member:update", team, metadata); err != nil {
				return nil, err
			}
			touch(jsString(member.Get("identityId")))
			return next, nil
		})
	})
	return Out[apitypes.TeamsUpdateMemberOutput]{Value: result}, err
}

// RemoveMember is POST {basePath}/teams/removeMember. Removes a direct member; the backing groups (and their
// eligible-binding activations) follow.
func (api *TeamsAPI) RemoveMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsRemoveMemberInput]) (Out[apitypes.TeamsRemoveMemberOutput], error) {
	m := api.module
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			tx, principal, team, via := mutation.Tx, mutation.Principal, mutation.team, mutation.via
			if via == "permission" {
				if err := m.assertAuthorityOverChain(ctx, tx, principal, team); err != nil {
					return nil, err
				}
			}
			member, err := m.memberRecord(ctx, tx, team, input.Get("identityId"))
			if err != nil {
				return nil, err
			}
			// Team sync would add them straight back.
			if member.Get("source") == "sync" {
				return nil, core.NewIamError("INVALID_TRANSITION", "This person is a member through team sync; remove them from the source group", 409)
			}
			// A maintainer removing themselves is leaving the team (see leave).
			identityID := jsString(member.Get("identityId"))
			self := via != "permission" && core.StrictEquals(member.Get("identityId"), principal.Identity.Get("id"))
			var held *orderedSet
			if self {
				if held, err = m.heldChainGroups(ctx, tx, team, identityID); err != nil {
					return nil, err
				}
			}
			if err := m.removeMember(ctx, tx, principal, team, member, "team:member:remove", via); err != nil {
				return nil, err
			}
			if held != nil {
				kept, err := m.heldChainGroups(ctx, tx, team, identityID)
				if err != nil {
					return nil, err
				}
				if err := m.assertMayDropDenies(ctx, tx, principal, jsString(team.Get("tenantId")), droppedGroups(held, kept)); err != nil {
					return nil, err
				}
			}
			touch(identityID)
			return core.NewObject("deleted", true), nil
		})
	})
	return Out[apitypes.TeamsRemoveMemberOutput]{Value: result}, err
}

// Candidates is POST {basePath}/teams/candidates. People who could be added to the team: active people of the
// organization who are not direct members, matched on name or email by `query` (at most `limit`, default 50).
// Maintainers may use it to pick people without iam:identities:read.
func (api *TeamsAPI) Candidates(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCandidatesInput]) (Out[apitypes.TeamsCandidatesOutput], error) {
	m := api.module
	server := api.server
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
		tx, team := mutation.Tx, mutation.team
		query, hasQuery := "", false
		if raw := input.Get("query"); !isUndefined(raw) && raw != "" {
			text, err := Text(raw, "query", 100)
			if err != nil {
				return nil, err
			}
			query, hasQuery = core.JSLower(text), true
		}
		limit := 50
		if raw := input.Get("limit"); !isUndefined(raw) {
			value, err := Integer(raw, "limit", 1, 200)
			if err != nil {
				return nil, err
			}
			limit = int(value)
		}
		now := server.Now()
		found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", team.Get("tenantId"), "teamId", team.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		live, err := liveTeamMembers(found, now)
		if err != nil {
			return nil, err
		}
		members := newOrderedSet()
		for _, member := range live {
			members.Add(jsString(member.Get("identityId")))
		}
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", team.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		selected := []*core.Object{}
		for _, identity := range identities {
			if identity.Get("kind") != "user" || identity.Get("status") != "active" || server.IdentityExpired(identity) || members.Has(jsString(identity.Get("id"))) {
				continue
			}
			if hasQuery && !strings.Contains(core.JSLower(jsString(identity.Get("name"))), query) &&
				!strings.Contains(core.JSLower(jsString(coalesce(identity.Get("email"), ""))), query) {
				continue
			}
			selected = append(selected, identity)
		}
		sort.SliceStable(selected, func(i, j int) bool {
			return localeCompare(teamPersonLabel(selected[i]), teamPersonLabel(selected[j])) < 0
		})
		if len(selected) > limit {
			selected = selected[:limit]
		}
		people := make([]any, len(selected))
		for index, identity := range selected {
			people[index] = teamPersonOf(identity)
		}
		return people, nil
	})
	return Out[apitypes.TeamsCandidatesOutput]{Value: result}, err
}

// ListForIdentity is POST {basePath}/teams/listForIdentity. The teams a person belongs to directly, with their role
// and the teams above each one.
func (api *TeamsAPI) ListForIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListForIdentityInput]) (Out[apitypes.TeamsListForIdentityOutput], error) {
	m := api.module
	result, err := api.server.Operations.Operation(ctx, credential, input.Get("tenantId"), "iam:teams:read", jsString(input.Get("identityId")), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(input.Get("tenantId"))
		if _, err := api.server.Scoped(ctx, call.Tx, "identities", input.Get("identityId"), tenantID); err != nil {
			return nil, err
		}
		teams, err := m.membershipsOf(ctx, call.Tx, tenantID, jsString(input.Get("identityId")))
		if err != nil {
			return nil, err
		}
		return certRecordList(teams), nil
	}, false)
	return Out[apitypes.TeamsListForIdentityOutput]{Value: result}, err
}

// ListMine is POST {basePath}/teams/listMine. The caller's teams, their join requests, the teams they may ask to
// join, and the open membership reviews of teams they maintain.
func (api *TeamsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListMineInput]) (Out[apitypes.TeamsListMineOutput], error) {
	m := api.module
	result, err := m.selfService(ctx, credential, input.Get("tenantId"), func(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (any, error) {
		identityID := jsString(principal.Identity.Get("id"))
		teams, err := m.membershipsOf(ctx, tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, TeamCollections.Requests, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		requests := make([]*core.Object, len(found))
		for index, request := range found {
			requests[index] = m.lapse(request)
		}
		sort.SliceStable(requests, func(i, j int) bool {
			return jsNumber(requests[j].Get("requestedAt"))-jsNumber(requests[i].Get("requestedAt")) < 0
		})
		if len(requests) > 50 {
			requests = requests[:50]
		}
		all, err := m.allTeams(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		mine := newOrderedSet()
		for _, team := range teams {
			mine.Add(jsString(team.Get("id")))
		}
		joinable := []*core.Object{}
		for _, team := range all.values() {
			if team.Get("joinPolicy") == "request" && !mine.Has(jsString(team.Get("id"))) {
				joinable = append(joinable, team)
			}
		}
		sortTeamsByName(joinable)
		counts, err := m.summaries(ctx, tx, joinable, all.values())
		if err != nil {
			return nil, err
		}
		// Reviews waiting on the caller as a maintainer (their own membership is someone else's to decide).
		reviews := []*core.Object{}
		open, err := tx.Find(ctx, TeamReviewCollections.Reviews, core.NewObject("tenantId", tenantID, "status", "open"), nil)
		if err != nil {
			return nil, err
		}
		for _, review := range open {
			team := all.get(jsString(review.Get("teamId")))
			if team == nil {
				continue
			}
			maintains, err := IsTeamMaintainer(ctx, tx, tenantID, jsString(team.Get("id")), identityID, core.NewObject("includeAncestors", true))
			if err != nil {
				return nil, err
			}
			if !maintains {
				continue
			}
			items, err := tx.Find(ctx, TeamReviewCollections.Items, core.NewObject("tenantId", tenantID, "reviewId", review.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			undecided := 0
			for _, item := range items {
				if isUndefined(item.Get("decision")) && item.Get("identityId") != identityID {
					undecided++
				}
			}
			reviews = append(reviews, core.NewObject(
				"id", review.Get("id"),
				"team", teamRef(team),
				"dueAt", review.Get("dueAt"),
				"undecided", float64(undecided),
			))
		}
		sort.SliceStable(reviews, func(i, j int) bool {
			return jsNumber(reviews[i].Get("dueAt"))-jsNumber(reviews[j].Get("dueAt")) < 0
		})
		requestViews := make([]any, len(requests))
		for index, request := range requests {
			view, err := m.requestView(ctx, tx, request)
			if err != nil {
				return nil, err
			}
			requestViews[index] = view
		}
		joinableViews := make([]any, len(joinable))
		for index, team := range joinable {
			view := teamRef(team)
			if truthy(team.Get("description")) {
				view.Set("description", team.Get("description"))
			}
			joinableViews[index] = view.Set("memberCount", counts[index].Get("memberCount"))
		}
		return core.NewObject(
			"reviews", certRecordList(reviews),
			"teams", certRecordList(teams),
			"requests", requestViews,
			"joinable", joinableViews,
		), nil
	})
	return Out[apitypes.TeamsListMineOutput]{Value: result}, err
}

// RequestToJoin is POST {basePath}/teams/requestToJoin. Asks to join a team whose join policy is `request`. Its
// maintainers (or, when it has none, those of the teams above it) are emailed; the request lapses after fourteen
// days. Audited as `team:join:request`.
func (api *TeamsAPI) RequestToJoin(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsRequestToJoinInput]) (Out[apitypes.TeamsRequestToJoinOutput], error) {
	m := api.module
	server := api.server
	result, err := m.selfService(ctx, credential, input.Get("tenantId"), func(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (any, error) {
		team, err := LoadTeam(ctx, tx, tenantID, input.Get("teamId"))
		if err != nil {
			return nil, err
		}
		if team.Get("joinPolicy") != "request" {
			return nil, core.NewIamError("INVALID_TRANSITION", "This team does not take join requests; ask a maintainer to add you", 409)
		}
		now := server.Now()
		identityID := jsString(principal.Identity.Get("id"))
		teamID := jsString(team.Get("id"))
		found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "uniqueKey", teamID+":"+identityID), nil)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			live, err := LiveTeamMember(found[0], now)
			if err != nil {
				return nil, err
			}
			if live {
				return nil, core.NewIamError("CONFLICT", "You are already in this team", 409)
			}
		}
		pending, err := tx.Find(ctx, TeamCollections.Requests, core.NewObject("tenantId", tenantID, "teamId", teamID, "identityId", identityID, "status", "pending"), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range pending {
			if jsNumber(request.Get("expiresAt")) > float64(now) {
				return nil, core.NewIamError("CONFLICT", "You already asked to join this team", 409)
			}
		}
		justification, err := optionalNote(input.Get("justification"), "justification")
		if err != nil {
			return nil, err
		}
		request := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"teamId", teamID,
			"identityId", identityID,
			"status", "pending",
			"requestedAt", float64(now),
			"expiresAt", float64(now+joinRequestLifetimeMs),
		)
		if justification != "" {
			request.Set("justification", justification)
		}
		if _, err := tx.Insert(ctx, TeamCollections.Requests, request); err != nil {
			return nil, err
		}
		recipients, err := m.nearestMaintainers(ctx, tx, tenantID, team, now)
		if err != nil {
			return nil, err
		}
		others := []string{}
		for _, recipient := range recipients {
			if recipient != identityID {
				others = append(others, recipient)
			}
		}
		payload := core.NewObject(
			"teamId", teamID,
			"teamName", team.Get("name"),
			"requestId", request.Get("id"),
			"requesterName", principal.Identity.Get("name"),
		)
		if truthy(principal.Identity.Get("email")) {
			payload.Set("requesterEmail", principal.Identity.Get("email"))
		}
		if justification != "" {
			payload.Set("justification", justification)
		}
		if err := m.email(ctx, tx, tenantID, others, "team-join-request", payload); err != nil {
			return nil, err
		}
		metadata := core.NewObject("requestId", request.Get("id"))
		if justification != "" {
			metadata.Set("justification", justification)
		}
		if err := m.audit(ctx, tx, principal, "team:join:request", team, metadata); err != nil {
			return nil, err
		}
		return m.requestView(ctx, tx, request)
	})
	return Out[apitypes.TeamsRequestToJoinOutput]{Value: result}, err
}

// CancelRequest is POST {basePath}/teams/cancelRequest. Withdraws the caller's own pending request.
func (api *TeamsAPI) CancelRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCancelRequestInput]) (Out[apitypes.TeamsCancelRequestOutput], error) {
	m := api.module
	server := api.server
	result, err := m.selfService(ctx, credential, input.Get("tenantId"), func(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (any, error) {
		requestID, err := Text(input.Get("requestId"), "requestId", 128)
		if err != nil {
			return nil, err
		}
		request, err := server.Scoped(ctx, tx, TeamCollections.Requests, requestID, tenantID)
		if err != nil {
			return nil, err
		}
		if !core.StrictEquals(request.Get("identityId"), principal.Identity.Get("id")) {
			return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
		}
		if m.lapse(request).Get("status") != "pending" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The request is no longer pending", 409)
		}
		cancelled, err := tx.Put(ctx, TeamCollections.Requests, request.Spread(core.NewObject(
			"status", "cancelled",
			"decidedAt", float64(server.Now()),
		)))
		if err != nil {
			return nil, err
		}
		team, err := tx.Get(ctx, TeamCollections.Teams, jsString(request.Get("teamId")))
		if err != nil {
			return nil, err
		}
		if team != nil {
			if err := m.audit(ctx, tx, principal, "team:join:cancel", team, core.NewObject("requestId", request.Get("id"))); err != nil {
				return nil, err
			}
		}
		return m.requestView(ctx, tx, cancelled)
	})
	return Out[apitypes.TeamsCancelRequestOutput]{Value: result}, err
}

// ListRequests is POST {basePath}/teams/listRequests. Join requests for a team (pending by default; `status` picks
// another state). Maintainers may list their team's.
func (api *TeamsAPI) ListRequests(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListRequestsInput]) (Out[apitypes.TeamsListRequestsOutput], error) {
	m := api.module
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:read", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
		tx, team := mutation.Tx, mutation.team
		status := "pending"
		if raw := input.Get("status"); !isUndefined(raw) {
			var err error
			if status, err = teamChoice(raw, teamRequestStatuses, "status"); err != nil {
				return nil, err
			}
		}
		found, err := tx.Find(ctx, TeamCollections.Requests, core.NewObject("tenantId", team.Get("tenantId"), "teamId", team.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		requests := []*core.Object{}
		for _, request := range found {
			if lapsed := m.lapse(request); lapsed.Get("status") == status {
				requests = append(requests, lapsed)
			}
		}
		sort.SliceStable(requests, func(i, j int) bool {
			return jsNumber(requests[j].Get("requestedAt"))-jsNumber(requests[i].Get("requestedAt")) < 0
		})
		if len(requests) > 200 {
			requests = requests[:200]
		}
		views := make([]any, len(requests))
		for index, request := range requests {
			view, err := m.requestView(ctx, tx, request)
			if err != nil {
				return nil, err
			}
			views[index] = view
		}
		return views, nil
	})
	return Out[apitypes.TeamsListRequestsOutput]{Value: result}, err
}

// ApproveRequest is POST {basePath}/teams/approveRequest. Grants a pending join request: the requester joins as a
// member (optionally until `expiresAt`) and is emailed. Nobody decides their own request. Maintainers may decide
// their team's requests.
func (api *TeamsAPI) ApproveRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsApproveRequestInput]) (Out[apitypes.TeamsApproveRequestOutput], error) {
	result, err := api.module.decide(ctx, credential, input.Body, "approved")
	return Out[apitypes.TeamsApproveRequestOutput]{Value: result}, err
}

// DenyRequest is POST {basePath}/teams/denyRequest. Refuses a pending join request; the requester is emailed with
// the note.
func (api *TeamsAPI) DenyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsDenyRequestInput]) (Out[apitypes.TeamsDenyRequestOutput], error) {
	result, err := api.module.decide(ctx, credential, input.Body, "denied")
	return Out[apitypes.TeamsDenyRequestOutput]{Value: result}, err
}

// Leave is POST {basePath}/teams/leave. Leaves a team the caller belongs to directly. Audited as `team:leave`.
// Refused (ACCESS_DENIED) when leaving would take the caller out of a backing group bound to a role with a deny
// statement whose grant authority they lack.
func (api *TeamsAPI) Leave(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsLeaveInput]) (Out[apitypes.TeamsLeaveOutput], error) {
	m := api.module
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.selfService(ctx, credential, input.Get("tenantId"), func(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (any, error) {
			team, err := LoadTeam(ctx, tx, tenantID, input.Get("teamId"))
			if err != nil {
				return nil, err
			}
			member, err := m.memberRecord(ctx, tx, team, principal.Identity.Get("id"))
			if err != nil {
				return nil, err
			}
			identityID := jsString(member.Get("identityId"))
			held, err := m.heldChainGroups(ctx, tx, team, identityID)
			if err != nil {
				return nil, err
			}
			if err := m.removeMember(ctx, tx, principal, team, member, "team:leave", ""); err != nil {
				return nil, err
			}
			kept, err := m.heldChainGroups(ctx, tx, team, identityID)
			if err != nil {
				return nil, err
			}
			if err := m.assertMayDropDenies(ctx, tx, principal, tenantID, droppedGroups(held, kept)); err != nil {
				return nil, err
			}
			touch(identityID)
			return core.NewObject("left", true), nil
		})
	})
	return Out[apitypes.TeamsLeaveOutput]{Value: result}, err
}

// Reconcile is POST {basePath}/teams/reconcile. Runs team sync for every synced team (`synced`: team memberships
// added, removed, and updated from their source groups), then re-computes every team's backing group from team
// membership (after a restore, an import, or a manual repair): how many group memberships were added, removed, and
// updated.
func (api *TeamsAPI) Reconcile(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsReconcileInput]) (Out[apitypes.TeamsReconcileOutput], error) {
	m := api.module
	server := api.server
	result, err := server.Operations.Operation(ctx, credential, input.Get("tenantId"), "iam:teams:update", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(input.Get("tenantId"))
		synced, err := SyncTeamsFromGroups(ctx, server, call.Tx, tenantID, core.NewObject("actorId", call.Principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		teams, err := m.allTeams(ctx, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		groups, err := SyncTeamGroups(ctx, call.Tx, tenantID, teams.keys(), server.Now())
		if err != nil {
			return nil, err
		}
		if groups == nil {
			groups = core.NewObject()
		}
		return groups.Spread(core.NewObject("synced", synced)), nil
	}, false)
	return Out[apitypes.TeamsReconcileOutput]{Value: result}, err
}

// SuggestBirthright is POST {basePath}/teams/suggestBirthright. Birthright suggestions: roles and groups that at
// least `minShare` (default 0.8) of a team's members (with those of the teams below it) hold by hand, for teams of at
// least `minPeople` (default 3), as a ready-made automatic access package whose rule names the team. `teamId` limits
// the answer to one team. Read-only; requires iam:analysis:read.
func (api *TeamsAPI) SuggestBirthright(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsSuggestBirthrightInput]) (Out[apitypes.TeamsSuggestBirthrightOutput], error) {
	server := api.server
	body := input.Body
	result, err := server.Operations.Operation(ctx, credential, input.Get("tenantId"), "iam:analysis:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		options, err := BirthrightOptions(body)
		if err != nil {
			return nil, err
		}
		teamID := input.Get("teamId")
		if !isUndefined(teamID) {
			if _, err := LoadTeam(ctx, call.Tx, tenantID, teamID); err != nil {
				return nil, err
			}
		}
		merged := core.NewObject()
		if options != nil {
			merged = options.Spread()
		}
		if !isUndefined(teamID) {
			merged.Set("unitId", teamID)
		}
		suggestions, err := SuggestBirthright(ctx, server, call.Tx, tenantID, "team", merged)
		if err != nil {
			return nil, err
		}
		return certRecordList(suggestions), nil
	}, false)
	return Out[apitypes.TeamsSuggestBirthrightOutput]{Value: result}, err
}

// StartReview is POST {basePath}/teams/startReview. Opens a membership review of the team: every live manual member
// (team sync members are reviewed through their source group) becomes an item its maintainers decide `keep` or
// `remove` by `dueAt` (default in 14 days, one to 90 days ahead). `onUndecided` (`keep` by default) settles the
// people nobody decided on. The maintainers (or, without any, those of the nearest team above) are emailed. One open
// review per team. Administrators only.
func (api *TeamsAPI) StartReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsStartReviewInput]) (Out[apitypes.TeamsStartReviewOutput], error) {
	m := api.module
	server := api.server
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), input.Get("teamId"), "iam:teams:update", "", func(ctx context.Context, mutation *teamMutation) (any, error) {
		tx, principal, team := mutation.Tx, mutation.Principal, mutation.team
		tenantID, teamID := jsString(team.Get("tenantId")), jsString(team.Get("id"))
		now := server.Now()
		dueAt := float64(now + DefaultReviewMs)
		if raw := input.Get("dueAt"); !isUndefined(raw) {
			var err error
			if dueAt, err = Integer(raw, "dueAt", float64(now+MinReviewMs), float64(now+MaxReviewMs)); err != nil {
				return nil, err
			}
		}
		onUndecided := "keep"
		if raw := input.Get("onUndecided"); !isUndefined(raw) {
			var err error
			if onUndecided, err = teamChoice(raw, teamReviewDecisions, "onUndecided"); err != nil {
				return nil, err
			}
		}
		note, err := optionalNote(input.Get("note"), "note")
		if err != nil {
			return nil, err
		}
		open, err := tx.Find(ctx, TeamReviewCollections.Reviews, core.NewObject("tenantId", tenantID, "uniqueKey", "open:"+teamID), nil)
		if err != nil {
			return nil, err
		}
		if len(open) > 0 {
			return nil, core.NewIamError("CONFLICT", "This team already has an open membership review", 409)
		}
		found, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "teamId", teamID), nil)
		if err != nil {
			return nil, err
		}
		members := []*core.Object{}
		for _, member := range found {
			live, err := LiveTeamMember(member, now)
			if err != nil {
				return nil, err
			}
			if live && member.Get("source") != "sync" {
				members = append(members, member)
			}
		}
		if len(members) == 0 {
			return nil, core.NewIamError("INVALID_TRANSITION", "The team has no members to review (members team sync manages are reviewed through their source groups)", 409)
		}
		record := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", "open:"+teamID,
			"teamId", teamID,
			"status", "open",
			"onUndecided", onUndecided,
			"startedAt", float64(now),
			"startedBy", principal.Identity.Get("id"),
			"dueAt", dueAt,
		)
		if note != "" {
			record.Set("note", note)
		}
		review, err := tx.Insert(ctx, TeamReviewCollections.Reviews, record)
		if err != nil {
			return nil, err
		}
		reviewID := jsString(review.Get("id"))
		for _, member := range members {
			if _, err := tx.Insert(ctx, TeamReviewCollections.Items, core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"uniqueKey", reviewID+":"+jsString(member.Get("identityId")),
				"reviewId", review.Get("id"),
				"teamId", teamID,
				"identityId", member.Get("identityId"),
				"role", member.Get("role"),
			)); err != nil {
				return nil, err
			}
		}
		recipients, err := m.nearestMaintainers(ctx, tx, tenantID, team, now)
		if err != nil {
			return nil, err
		}
		payload := core.NewObject(
			"teamId", teamID,
			"teamName", team.Get("name"),
			"reviewId", review.Get("id"),
			"memberCount", jsString(float64(len(members))),
			"dueAt", isoString(dueAt),
			"onUndecided", onUndecided,
		)
		if note != "" {
			payload.Set("note", note)
		}
		if err := m.email(ctx, tx, tenantID, recipients, "team-review-requested", payload); err != nil {
			return nil, err
		}
		if err := m.audit(ctx, tx, principal, "team:review:start", team, core.NewObject(
			"reviewId", review.Get("id"),
			"members", float64(len(members)),
			"dueAt", dueAt,
			"onUndecided", onUndecided,
		)); err != nil {
			return nil, err
		}
		return m.reviewView(ctx, tx, review, team, true)
	})
	return Out[apitypes.TeamsStartReviewOutput]{Value: result}, err
}

// GetReview is POST {basePath}/teams/getReview. One review with every person under it. Maintainers of the team (or a
// team above) may read it.
func (api *TeamsAPI) GetReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsGetReviewInput]) (Out[apitypes.TeamsGetReviewOutput], error) {
	m := api.module
	teamID, err := m.reviewTeamID(ctx, input.Get("tenantId"), input.Get("reviewId"))
	if err != nil {
		return Out[apitypes.TeamsGetReviewOutput]{}, err
	}
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), teamID, "iam:teams:read", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
		review, err := m.loadReview(ctx, mutation.Tx, mutation.team, input.Get("reviewId"))
		if err != nil {
			return nil, err
		}
		return m.reviewView(ctx, mutation.Tx, review, mutation.team, true)
	})
	return Out[apitypes.TeamsGetReviewOutput]{Value: result}, err
}

// ListReviews is POST {basePath}/teams/listReviews. Membership reviews, newest first (at most 100): of one team
// (`teamId`; its maintainers may list them) or, for administrators holding iam:teams:read, of every team. `status`
// filters.
func (api *TeamsAPI) ListReviews(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListReviewsInput]) (Out[apitypes.TeamsListReviewsOutput], error) {
	m := api.module
	status := ""
	if raw := input.Get("status"); !isUndefined(raw) {
		var err error
		if status, err = teamChoice(raw, teamReviewStatusList, "status"); err != nil {
			return Out[apitypes.TeamsListReviewsOutput]{}, err
		}
	}
	list := func(ctx context.Context, tx core.IamStore, teams []*core.Object) (any, error) {
		views := []*core.Object{}
		for _, team := range teams {
			filter := core.NewObject("tenantId", team.Get("tenantId"), "teamId", team.Get("id"))
			if status != "" {
				filter.Set("status", status)
			}
			reviews, err := tx.Find(ctx, TeamReviewCollections.Reviews, filter, nil)
			if err != nil {
				return nil, err
			}
			for _, review := range reviews {
				view, err := m.reviewView(ctx, tx, review, team, false)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
		}
		sort.SliceStable(views, func(i, j int) bool {
			return jsNumber(views[j].Get("startedAt"))-jsNumber(views[i].Get("startedAt")) < 0
		})
		if len(views) > 100 {
			views = views[:100]
		}
		return certRecordList(views), nil
	}
	if teamID := input.Get("teamId"); !isUndefined(teamID) {
		result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), teamID, "iam:teams:read", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			return list(ctx, mutation.Tx, []*core.Object{mutation.team})
		})
		return Out[apitypes.TeamsListReviewsOutput]{Value: result}, err
	}
	result, err := api.server.Operations.Operation(ctx, credential, input.Get("tenantId"), "iam:teams:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		teams, err := m.allTeams(ctx, call.Tx, jsString(input.Get("tenantId")))
		if err != nil {
			return nil, err
		}
		return list(ctx, call.Tx, teams.values())
	}, false)
	return Out[apitypes.TeamsListReviewsOutput]{Value: result}, err
}

// DecideReview is POST {basePath}/teams/decideReview. Records `keep` or `remove` for up to 200 people under an open
// review (a later decision replaces an earlier one). Maintainers of the team or a team above, or administrators;
// nobody decides on their own membership. Removals take effect when the review completes.
func (api *TeamsAPI) DecideReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsDecideReviewInput]) (Out[apitypes.TeamsDecideReviewOutput], error) {
	m := api.module
	server := api.server
	teamID, err := m.reviewTeamID(ctx, input.Get("tenantId"), input.Get("reviewId"))
	if err != nil {
		return Out[apitypes.TeamsDecideReviewOutput]{}, err
	}
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), teamID, "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
		tx, principal, team, via := mutation.Tx, mutation.Principal, mutation.team, mutation.via
		review, err := m.loadReview(ctx, tx, team, input.Get("reviewId"))
		if err != nil {
			return nil, err
		}
		if review.Get("status") != "open" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The review is no longer open", 409)
		}
		decisions, ok := input.Get("decisions").([]any)
		if !ok || len(decisions) < 1 || len(decisions) > 200 {
			return nil, invalidInput("Provide 1-200 decisions")
		}
		now := float64(server.Now())
		keep, remove := 0, 0
		for _, entry := range decisions {
			if entry == nil || !(isPlainObject(entry) || isArray(entry)) {
				return nil, invalidInput("Each decision needs identityId and decision")
			}
			identityID, err := Text(member(entry, "identityId"), "identityId", 128)
			if err != nil {
				return nil, err
			}
			decision, err := teamChoice(member(entry, "decision"), teamReviewDecisions, "decision")
			if err != nil {
				return nil, err
			}
			note, err := optionalNote(member(entry, "note"), "note")
			if err != nil {
				return nil, err
			}
			if identityID == jsString(principal.Identity.Get("id")) {
				return nil, core.NewIamError("ACCESS_DENIED", "Nobody reviews their own membership", 403)
			}
			found, err := tx.Find(ctx, TeamReviewCollections.Items, core.NewObject("tenantId", team.Get("tenantId"), "uniqueKey", jsString(review.Get("id"))+":"+identityID), nil)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				return nil, core.NewIamError("NOT_FOUND", "This person is not under review", 404)
			}
			rest := found[0].Clone()
			rest.Delete("note")
			rest = rest.Spread(core.NewObject(
				"decision", decision,
				"decidedBy", principal.Identity.Get("id"),
				"decidedAt", now,
			))
			if note != "" {
				rest.Set("note", note)
			}
			if _, err := tx.Put(ctx, TeamReviewCollections.Items, rest); err != nil {
				return nil, err
			}
			if decision == "keep" {
				keep++
			} else {
				remove++
			}
		}
		metadata := core.NewObject("reviewId", review.Get("id"), "keep", float64(keep), "remove", float64(remove))
		if via != "permission" {
			metadata.Set("via", via)
		}
		if err := m.audit(ctx, tx, principal, "team:review:decide", team, metadata); err != nil {
			return nil, err
		}
		return m.reviewView(ctx, tx, review, team, true)
	})
	return Out[apitypes.TeamsDecideReviewOutput]{Value: result}, err
}

// CompleteReview is POST {basePath}/teams/completeReview. Completes an open review: people decided `remove` leave the
// team (and lose what it gave them), and the people nobody decided on follow `onUndecided`. Maintainers may complete
// it once every person is decided; administrators at any time. Audited as `team:review:complete` with the counts,
// and `team:member:remove` (`source: review`) per removal.
func (api *TeamsAPI) CompleteReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCompleteReviewInput]) (Out[apitypes.TeamsCompleteReviewOutput], error) {
	m := api.module
	server := api.server
	teamID, err := m.reviewTeamID(ctx, input.Get("tenantId"), input.Get("reviewId"))
	if err != nil {
		return Out[apitypes.TeamsCompleteReviewOutput]{}, err
	}
	result, err := m.reconciling(ctx, input.Get("tenantId"), func(touch func(identityIDs ...string)) (any, error) {
		return m.teamOperation(ctx, credential, input.Get("tenantId"), teamID, "iam:teams:update", "maintainer", func(ctx context.Context, mutation *teamMutation) (any, error) {
			tx, principal, team, via := mutation.Tx, mutation.Principal, mutation.team, mutation.via
			review, err := m.loadReview(ctx, tx, team, input.Get("reviewId"))
			if err != nil {
				return nil, err
			}
			if review.Get("status") != "open" {
				return nil, core.NewIamError("INVALID_TRANSITION", "The review is no longer open", 409)
			}
			if via != "permission" {
				items, err := tx.Find(ctx, TeamReviewCollections.Items, core.NewObject("tenantId", team.Get("tenantId"), "reviewId", review.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				undecided := 0
				for _, item := range items {
					if isUndefined(item.Get("decision")) {
						undecided++
					}
				}
				if undecided > 0 {
					return nil, core.NewIamError("INVALID_TRANSITION", "Decide every person first ("+jsString(float64(undecided))+" left); an administrator can complete it early", 409)
				}
			}
			done, err := CompleteTeamReview(ctx, server, tx, review, principal)
			if err != nil {
				return nil, err
			}
			switch removed := done.Get("removed").(type) {
			case []any:
				for _, identityID := range removed {
					touch(jsString(identityID))
				}
			case []string:
				touch(removed...)
			}
			completed, _ := done.Get("review").(*core.Object)
			return m.reviewView(ctx, tx, completed, team, true)
		})
	})
	return Out[apitypes.TeamsCompleteReviewOutput]{Value: result}, err
}

// CancelReview is POST {basePath}/teams/cancelReview. Cancels an open review without changing the team.
// Administrators only.
func (api *TeamsAPI) CancelReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCancelReviewInput]) (Out[apitypes.TeamsCancelReviewOutput], error) {
	m := api.module
	server := api.server
	teamID, err := m.reviewTeamID(ctx, input.Get("tenantId"), input.Get("reviewId"))
	if err != nil {
		return Out[apitypes.TeamsCancelReviewOutput]{}, err
	}
	result, err := m.teamOperation(ctx, credential, input.Get("tenantId"), teamID, "iam:teams:update", "", func(ctx context.Context, mutation *teamMutation) (any, error) {
		tx, principal, team := mutation.Tx, mutation.Principal, mutation.team
		review, err := m.loadReview(ctx, tx, team, input.Get("reviewId"))
		if err != nil {
			return nil, err
		}
		if review.Get("status") != "open" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The review is no longer open", 409)
		}
		rest := review.Clone()
		rest.Delete("uniqueKey")
		cancelled, err := tx.Put(ctx, TeamReviewCollections.Reviews, rest.Spread(core.NewObject(
			"status", "cancelled",
			"completedAt", float64(server.Now()),
			"completedBy", principal.Identity.Get("id"),
		)))
		if err != nil {
			return nil, err
		}
		if err := m.audit(ctx, tx, principal, "team:review:cancel", team, core.NewObject("reviewId", review.Get("id"))); err != nil {
			return nil, err
		}
		return m.reviewView(ctx, tx, cancelled, team, false)
	})
	return Out[apitypes.TeamsCancelReviewOutput]{Value: result}, err
}

// TeamMutationsResult is api/teams.ts teamMutations().
type TeamMutationsResult struct {
	server *ServerContext
	module *teamModule
}

// CreateTeam (api/teams.ts teamMutations().createTeam) creates a team with its backing group (and maintainers); the
// caller has authorized `iam:teams:create`.
func (s *TeamMutationsResult) CreateTeam(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	return s.module.createTeam(ctx, tx, principal, tenant, input)
}

// UpdateTeam (api/teams.ts teamMutations().updateTeam) changes a team's settings or place; the caller has authorized
// `iam:teams:update` on it.
func (s *TeamMutationsResult) UpdateTeam(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, input *core.Object) (result *core.Object, err error) {
	return s.module.updateTeam(ctx, tx, principal, team, input)
}

// DeleteTeam (api/teams.ts teamMutations().deleteTeam) deletes a team with its memberships, requests, and backing
// group; it returns how many members it had.
func (s *TeamMutationsResult) DeleteTeam(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object) (result float64, err error) {
	return s.module.deleteTeam(ctx, tx, principal, team)
}

// PutMember (api/teams.ts teamMutations().putMember) adds or re-adds a direct member. mutation is the TypeScript
// TeamMutation as an object: tx (core.IamStore), principal (*Principal), tenant, team, and via (permission,
// maintainer, or member; permission when absent).
func (s *TeamMutationsResult) PutMember(ctx context.Context, mutation *core.Object, input *core.Object, source string) (result *core.Object, err error) {
	decoded := &teamMutation{via: "permission"}
	decoded.Tx, _ = mutation.Get("tx").(core.IamStore)
	decoded.Principal, _ = mutation.Get("principal").(*Principal)
	decoded.Tenant, _ = mutation.Get("tenant").(*core.Object)
	decoded.team, _ = mutation.Get("team").(*core.Object)
	if via, ok := mutation.Get("via").(string); ok {
		decoded.via = via
	}
	if decoded.Tx == nil || decoded.Principal == nil || decoded.team == nil {
		return nil, invalidInput("putMember needs tx, principal, and team")
	}
	return s.module.putMember(ctx, decoded, input, source)
}

// RemoveMember (api/teams.ts teamMutations().removeMember) deletes a direct membership and refreshes the backing
// groups; via "" is undefined.
func (s *TeamMutationsResult) RemoveMember(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, member *core.Object, action string, via string) (err error) {
	return s.module.removeMember(ctx, tx, principal, team, member, action, via)
}

// MemberRecord (api/teams.ts teamMutations().memberRecord) is a live direct membership (NOT_FOUND otherwise).
func (s *TeamMutationsResult) MemberRecord(ctx context.Context, tx core.IamStore, team *core.Object, identityID any) (result *core.Object, err error) {
	return s.module.memberRecord(ctx, tx, team, identityID)
}

// AssertAuthorityOver (api/teams.ts teamMutations().assertAuthorityOver) needs the grant authority behind what the
// teams' backing groups are bound to.
func (s *TeamMutationsResult) AssertAuthorityOver(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, teams []*core.Object) (err error) {
	return s.module.assertAuthorityOver(ctx, tx, principal, tenantID, teams)
}

// AssertMayClaimTeamLicenses (api/teams.ts teamMutations().assertMayClaimTeamLicenses) needs iam:licenses:assign
// when the chain carries license seats (once per caller and chain in a transaction).
func (s *TeamMutationsResult) AssertMayClaimTeamLicenses(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, teams []*core.Object) (err error) {
	return s.module.assertMayClaimTeamLicenses(ctx, tx, principal, tenantID, teams)
}

// AllTeams (api/teams.ts teamMutations().allTeams) is the tenant's teams by ID.
func (s *TeamMutationsResult) AllTeams(ctx context.Context, tx core.IamStore, tenantID string) (result map[string]*core.Object, err error) {
	teams, err := s.module.allTeams(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	return teams.byID, nil
}

// TeamMutations (api/teams.ts teamMutations): Transaction-level team changes for configuration sync (org-sync.ts):
// the same validation, backing-group upkeep, and audit events as the API. Callers authorize each change first.
func TeamMutations(server *ServerContext) (result *TeamMutationsResult, err error) {
	return &TeamMutationsResult{server: server, module: newTeamModule(server)}, nil
}
