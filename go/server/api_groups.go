package server

// Port of packages/server/src/api/groups.ts: the `groups` API group and the group helpers configuration sync, teams,
// access packages, workflows and other modules share (createGroup, addGroupMember, updateGroupMember,
// removeGroupMember, deleteGroup, assertMayClaimLicenses).

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// GroupsAPI is the `groups` API group (packages/server/src/api/groups.ts createGroupsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/groups/{method} onto it.
type GroupsAPI struct {
	server *ServerContext
}

// CreateGroupsAPI builds the `groups` API group.
func CreateGroupsAPI(server *ServerContext) *GroupsAPI {
	return &GroupsAPI{server: server}
}

// AddMember is POST {basePath}/groups/addMember. `expiresAt` (epoch milliseconds) makes the membership temporary; it
// ends by itself and the purge worker removes it.
func (api *GroupsAPI) AddMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsAddMemberInput]) (Out[apitypes.GroupsAddMemberOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:update", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return AddGroupMember(ctx, api.server, call.Tx, call.Principal, input.Body)
	}, false)
	return Out[apitypes.GroupsAddMemberOutput]{Value: result}, err
}

// AddMembers is POST {basePath}/groups/addMembers. Adds up to 100 members in one transaction, optionally all with the
// same expiry.
func (api *GroupsAPI) AddMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsAddMembersInput]) (Out[apitypes.GroupsAddMembersOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:update", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		members, err := addGroupMembers(ctx, api.server, call.Tx, call.Principal, input.Body)
		if err != nil {
			return nil, err
		}
		return core.NewObject("members", recordValues(members)), nil
	}, false)
	return Out[apitypes.GroupsAddMembersOutput]{Value: result}, err
}

// Create is POST {basePath}/groups/create. Creates a group in the tenant.
func (api *GroupsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsCreateInput]) (Out[apitypes.GroupsCreateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return CreateGroup(ctx, api.server, call.Tx, call.Tenant, input.Body)
	}, false)
	return Out[apitypes.GroupsCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/groups/delete. Deletes a group together with its memberships, its role bindings, their
// activations, and its relationship tuples.
func (api *GroupsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsDeleteInput]) (Out[apitypes.GroupsDeleteOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:delete", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		group, err := api.server.Scoped(ctx, call.Tx, "groups", input.Get("groupId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		// A team's backing group goes with its team (`teams.delete`).
		if err := AssertNotTeamGroup(group); err != nil {
			return nil, err
		}
		if err := DeleteGroup(ctx, api.server, call.Tx, call.Principal, group); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.GroupsDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/groups/get. Returns one group by id.
func (api *GroupsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsGetInput]) (Out[apitypes.GroupsGetOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:read", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return api.server.Scoped(ctx, call.Tx, "groups", input.Get("groupId"), jsString(tenantID))
	}, false)
	return Out[apitypes.GroupsGetOutput]{Value: result}, err
}

// List is POST {basePath}/groups/list. Lists every group in the tenant.
func (api *GroupsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsListInput]) (Out[apitypes.GroupsListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		groups, err := call.Tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		return recordValues(groups), nil
	}, false)
	return Out[apitypes.GroupsListOutput]{Value: result}, err
}

// ListMembers is POST {basePath}/groups/listMembers. Current members (expired memberships are omitted), each with
// `membershipExpiresAt` when temporary.
func (api *GroupsAPI) ListMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsListMembersInput]) (Out[apitypes.GroupsListMembersOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	groupID := input.Get("groupId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:groups:read", jsString(groupID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		if _, err := server.Scoped(ctx, tx, "groups", groupID, jsString(tenantID)); err != nil {
			return nil, err
		}
		memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", groupID), nil)
		if err != nil {
			return nil, err
		}
		members := []any{}
		for _, membership := range memberships {
			if !server.LiveMembership(membership) {
				continue
			}
			identity, err := tx.Get(ctx, "identities", jsString(membership.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if identity != nil && core.StrictEquals(identity.Get("tenantId"), tenantID) {
				entry := PublicIdentity(identity)
				if expiresAt := membership.Get("expiresAt"); !isUndefined(expiresAt) {
					entry.SetRaw("membershipExpiresAt", expiresAt)
				}
				members = append(members, entry)
			}
		}
		return members, nil
	}, false)
	return Out[apitypes.GroupsListMembersOutput]{Value: result}, err
}

// RemoveMember is POST {basePath}/groups/removeMember. Removes a person from a group, ending the access the group's
// roles gave them.
func (api *GroupsAPI) RemoveMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsRemoveMemberInput]) (Out[apitypes.GroupsRemoveMemberOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:update", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if err := RemoveGroupMember(ctx, api.server, call.Tx, call.Principal, input.Body); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.GroupsRemoveMemberOutput]{Value: result}, err
}

// Update is POST {basePath}/groups/update. Renames a group or changes its description.
func (api *GroupsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsUpdateInput]) (Out[apitypes.GroupsUpdateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:update", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		group, err := api.server.Scoped(ctx, call.Tx, "groups", input.Get("groupId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		name, description := input.Get("name"), input.Get("description")
		if isUndefined(name) && isUndefined(description) {
			return nil, invalidInput("Nothing to update")
		}
		next := group.Spread()
		if !isUndefined(name) {
			text, err := Text(name, "name")
			if err != nil {
				return nil, err
			}
			next.Set("name", text)
		}
		if !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", text)
		}
		return call.Tx.Put(ctx, "groups", next)
	}, false)
	return Out[apitypes.GroupsUpdateOutput]{Value: result}, err
}

// UpdateMember is POST {basePath}/groups/updateMember. Extends, shortens, or clears (null) a temporary membership.
func (api *GroupsAPI) UpdateMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsUpdateMemberInput]) (Out[apitypes.GroupsUpdateMemberOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:groups:update", jsString(input.Get("groupId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return UpdateGroupMember(ctx, api.server, call.Tx, call.Principal, input.Body)
	}, false)
	return Out[apitypes.GroupsUpdateMemberOutput]{Value: result}, err
}

// groupIDList is `typeof groupId === 'string' ? [groupId] : groupId` as strings.
func groupIDList(groupID any) []string {
	switch value := groupID.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			result = append(result, jsString(item))
		}
		return result
	}
	return nil
}

// AssertMayClaimLicenses (api/groups.ts assertMayClaimLicenses): A license product assigned to a group gives each
// member a claim on a seat, as assigning the product to them would: adding someone to such a group, or changing how
// long they stay, needs iam:licenses:assign in the tenant as well. The same holds for the backing groups the write
// fills through team sync (of the teams that sync from the group and of the teams above them). Team maintainers
// manage their own team under its administrators' delegation instead, and directory sync (SCIM) sets members as the
// directory says. Every other writer that puts people into groups (`identities.createMany` and `invite`, guest
// invitations, access packages, onboarding completion groups, the teams API for administrators) asks the same,
// through this check: it refuses with `OperationDenied`, which an operation records as a denial of itself. Pass the
// groups the write fills (`groupId`: a string, []string or model array) and, optionally, the refusal's message (""
// for the default).
func AssertMayClaimLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, groupID any, message string) (err error) {
	if message == "" {
		message = "Members of this group hold license seats through it; changing them needs iam:licenses:assign"
	}
	direct := unique(groupIDList(groupID))
	if len(direct) == 0 {
		return nil
	}
	groupIDs := append([]string(nil), direct...)
	var teams map[string]*core.Object
	for _, each := range direct {
		syncing, err := TeamsSyncingFrom(ctx, tx, tenantID, each)
		if err != nil {
			return err
		}
		if len(syncing) == 0 {
			continue
		}
		if teams == nil {
			records, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return err
			}
			teams = map[string]*core.Object{}
			for _, team := range records {
				teams[jsString(team.Get("id"))] = team
			}
		}
		for _, team := range syncing {
			chain, err := TeamChain(teams, jsString(team.Get("id")))
			if err != nil {
				return err
			}
			for _, link := range chain {
				groupIDs = append(groupIDs, jsString(link.Get("groupId")))
			}
		}
	}
	holds, err := GroupsHoldLicenses(ctx, tx, tenantID, groupIDs)
	if err != nil || !holds {
		return err
	}
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: "iam:licenses:assign", Resource: ResourceTarget{Type: "iam", ID: "licenses/assignments"},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return NewOperationDenied(message)
	}
	return nil
}

// followSyncedTeams brings the teams that sync their members from the group in step (teams.ts). A synced person joins
// or leaves those teams' backing groups and those of every team above them, so a membership change that moves a team
// needs the grant authority behind what those groups hold, exactly as changing the team's members directly does.
func followSyncedTeams(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, groupID string) error {
	synced, err := SyncTeamsFromGroups(ctx, server, tx, tenantID, core.NewObject("groupId", groupID, "actorId", principal.Identity.Get("id")))
	if err != nil {
		return err
	}
	var teamIDs []string
	if synced != nil {
		if teams, ok := synced.Get("teams").([]any); ok {
			for _, team := range teams {
				teamIDs = append(teamIDs, jsString(team))
			}
		}
	}
	bindings, err := TeamChainBindings(ctx, tx, tenantID, teamIDs)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, optionalID(binding.Get("authorityId"))); err != nil {
			return err
		}
	}
	return nil
}

// requireGroupBindingAuthorities requires the grant authority behind each binding of the group: membership confers
// them all.
func requireGroupBindingAuthorities(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, groupID any) ([]*core.Object, error) {
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, optionalID(binding.Get("authorityId"))); err != nil {
			return nil, err
		}
	}
	return bindings, nil
}

// CreateGroup (api/groups.ts createGroup): Creates a group within the tenant's plan limit; shared by `groups.create`
// and configuration sync.
func CreateGroup(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	tenantID := input.Get("tenantId")
	if err := server.EnforceLimit(ctx, tx, tenant, "groups", func(ctx context.Context) (int, error) {
		groups, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
		return len(groups), err
	}); err != nil {
		return nil, err
	}
	name, err := Text(input.Get("name"), "name")
	if err != nil {
		return nil, err
	}
	group := core.NewObject("id", ID(), "tenantId", tenantID, "name", name)
	if value := input.Get("description"); !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		group.Set("description", description)
	}
	return tx.Insert(ctx, "groups", group)
}

// withoutMembershipTerms is `const { expiresAt, packageAssignmentId, ...rest } = member`.
func withoutMembershipTerms(member *core.Object) *core.Object {
	rest := member.Spread()
	rest.Delete("expiresAt")
	rest.Delete("packageAssignmentId")
	return rest
}

// AddGroupMember (api/groups.ts addGroupMember): Adds an identity to a group; membership confers every group
// binding, so each binding's authority is required (and, for teams that sync from the group, that of their backing
// groups' bindings), and iam:licenses:assign when license products are assigned to those groups. `expiresAt` makes
// the membership temporary. Re-adding an expired member renews the membership.
func AddGroupMember(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	tenantID := jsString(input.Get("tenantId"))
	groupID, identityID := input.Get("groupId"), input.Get("identityId")
	// A team's backing group takes its members from the team (teams.ts).
	group, err := server.Scoped(ctx, tx, "groups", groupID, tenantID)
	if err != nil {
		return nil, err
	}
	if err := AssertNotTeamGroup(group); err != nil {
		return nil, err
	}
	if _, err := server.ActiveIdentity(ctx, tx, identityID, tenantID); err != nil {
		return nil, err
	}
	if _, err := requireGroupBindingAuthorities(ctx, server, tx, principal, tenantID, groupID); err != nil {
		return nil, err
	}
	if err := AssertMayClaimLicenses(ctx, server, tx, principal, tenantID, jsString(groupID), ""); err != nil {
		return nil, err
	}
	var expiresAt any = core.Undefined
	if value := input.Get("expiresAt"); !isUndefined(value) {
		expiry, err := server.BindingExpiry(value)
		if err != nil {
			return nil, err
		}
		expiresAt = expiry
	}
	uniqueKey := jsString(groupID) + ":" + jsString(identityID)
	found, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil {
		return nil, err
	}
	var member *core.Object
	if len(found) > 0 {
		existing := found[0]
		if server.LiveMembership(existing) {
			return nil, core.NewIamError("CONFLICT", "Already a member of this group", 409)
		}
		// A renewed membership starts fresh: it no longer belongs to the package assignment that once created it.
		rest := withoutMembershipTerms(existing)
		if !isUndefined(expiresAt) {
			rest.Set("expiresAt", expiresAt)
		}
		if member, err = tx.Put(ctx, "groupMembers", rest); err != nil {
			return nil, err
		}
	} else {
		record := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", uniqueKey, "groupId", groupID, "identityId", identityID)
		if !isUndefined(expiresAt) {
			record.Set("expiresAt", expiresAt)
		}
		if member, err = tx.Insert(ctx, "groupMembers", record); err != nil {
			return nil, err
		}
	}
	// Teams that sync their members from this group follow (teams.ts).
	if err := followSyncedTeams(ctx, server, tx, principal, tenantID, jsString(groupID)); err != nil {
		return nil, err
	}
	return member, nil
}

// UpdateGroupMember (api/groups.ts updateGroupMember): Extends, shortens, or clears (null) a membership's expiry
// under the same authority rules as adding a member.
func UpdateGroupMember(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	tenantID := jsString(input.Get("tenantId"))
	groupID, identityID := input.Get("groupId"), input.Get("identityId")
	group, err := server.Scoped(ctx, tx, "groups", groupID, tenantID)
	if err != nil {
		return nil, err
	}
	if err := AssertNotTeamGroup(group); err != nil {
		return nil, err
	}
	if _, err := requireGroupBindingAuthorities(ctx, server, tx, principal, tenantID, groupID); err != nil {
		return nil, err
	}
	if err := AssertMayClaimLicenses(ctx, server, tx, principal, tenantID, jsString(groupID), ""); err != nil {
		return nil, err
	}
	found, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "uniqueKey", jsString(groupID)+":"+jsString(identityID)), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 || !server.LiveMembership(found[0]) {
		return nil, core.NewIamError("NOT_FOUND", "Not a member of this group", 404)
	}
	// Editing a package's membership by hand takes it over: revoking the package no longer removes it.
	rest := withoutMembershipTerms(found[0])
	if value := input.Get("expiresAt"); value != nil {
		expiresAt, err := server.BindingExpiry(value)
		if err != nil {
			return nil, err
		}
		rest.Set("expiresAt", expiresAt)
	}
	updated, err := tx.Put(ctx, "groupMembers", rest)
	if err != nil {
		return nil, err
	}
	// Synced team memberships end when their source membership does (teams.ts).
	if err := followSyncedTeams(ctx, server, tx, principal, tenantID, jsString(groupID)); err != nil {
		return nil, err
	}
	return updated, nil
}

// addGroupMembers adds up to 100 identities atomically (cohort onboarding); one failure rejects the batch. License
// seats of the group's products are reconciled once, after the batch (licenses.ts `batchGroupLicenses`).
func addGroupMembers(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) ([]*core.Object, error) {
	listed, err := Strings(input.Get("identityIds"), "identityIds")
	if err != nil {
		return nil, err
	}
	identityIDs := unique(listed)
	if len(identityIDs) == 0 {
		return nil, invalidInput("Provide 1-100 identityIds")
	}
	var members []*core.Object
	_, err = BatchGroupLicenses(ctx, server, tx, func(ctx context.Context) (any, error) {
		for _, identityID := range identityIDs {
			each := core.NewObject("tenantId", input.Get("tenantId"), "groupId", input.Get("groupId"), "identityId", identityID)
			if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
				each.SetRaw("expiresAt", expiresAt)
			}
			member, err := AddGroupMember(ctx, server, tx, principal, each)
			if err != nil {
				return nil, err
			}
			members = append(members, member)
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return members, nil
}

// RemoveGroupMember (api/groups.ts removeGroupMember): Removes an identity from a group, ending its activations of
// the group's eligible bindings.
func RemoveGroupMember(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (err error) {
	tenantID := jsString(input.Get("tenantId"))
	groupID, identityID := input.Get("groupId"), input.Get("identityId")
	group, err := server.Scoped(ctx, tx, "groups", groupID, tenantID)
	if err != nil {
		return err
	}
	if err := AssertNotTeamGroup(group); err != nil {
		return err
	}
	bindings, err := requireGroupBindingAuthorities(ctx, server, tx, principal, tenantID, groupID)
	if err != nil {
		return err
	}
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, member := range members {
		if err := tx.Delete(ctx, "groupMembers", jsString(member.Get("id"))); err != nil {
			return err
		}
	}
	activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, activation := range activations {
		for _, binding := range bindings {
			if core.StrictEquals(binding.Get("id"), activation.Get("bindingId")) {
				if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
					return err
				}
				break
			}
		}
	}
	// Teams that sync their members from this group follow (teams.ts); leaving one may lift a deny bound to it.
	return followSyncedTeams(ctx, server, tx, principal, tenantID, jsString(groupID))
}

// DeleteGroup (api/groups.ts deleteGroup): Deletes a group with its memberships, bindings, activations, and
// relationships.
func DeleteGroup(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, group *core.Object) (err error) {
	tenantID, groupID := group.Get("tenantId"), group.Get("id")
	packages, err := tx.Find(ctx, "accessPackages", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	// A group a package grants, or one its birthright rule tests, stays until the package stops using it.
	var packaged []*core.Object
	for _, pkg := range packages {
		groupIDs, _ := pkg.Get("groupIds").([]any)
		if includesValue(groupIDs, groupID) {
			packaged = append(packaged, pkg)
			continue
		}
		rule, _ := pkg.Get("autoAssign").(*core.Object)
		ruleGroups, err := RuleGroupIDs(rule)
		if err != nil {
			return err
		}
		if containsString(ruleGroups, jsString(groupID)) {
			packaged = append(packaged, pkg)
		}
	}
	if len(packaged) > 0 {
		return core.NewIamError("RESOURCE_IN_USE", "Access packages still include it or name it in a rule: "+joinNames(packaged), 409)
	}
	// Teams that sync their members from it would silently lose them.
	syncing, err := TeamsSyncingFrom(ctx, tx, jsString(tenantID), jsString(groupID))
	if err != nil {
		return err
	}
	if len(syncing) > 0 {
		return core.NewIamError("RESOURCE_IN_USE", "Teams sync their members from it: "+joinNames(syncing)+"; stop syncing first", 409)
	}
	// An approver group that disappeared would silently leave its requests to whoever else may decide.
	var approving []string
	for _, pkg := range packages {
		if core.StrictEquals(pkg.Get("approverGroupId"), groupID) {
			approving = append(approving, "package "+jsString(pkg.Get("name")))
		}
	}
	approverBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "approverGroupId", groupID), nil)
	if err != nil {
		return err
	}
	approvingBindings := 0
	for _, binding := range approverBindings {
		// The group's own bindings go with it.
		if !server.ExpiredBinding(binding) && !(binding.Get("subjectType") == "group" && core.StrictEquals(binding.Get("subjectId"), groupID)) {
			approvingBindings++
		}
	}
	if len(approving) > 0 || approvingBindings > 0 {
		if approvingBindings > 0 {
			approving = append(approving, core.NumberString(float64(approvingBindings))+" eligible binding(s)")
		}
		return core.NewIamError("RESOURCE_IN_USE", "It approves requests for "+strings.Join(approving, ", ")+"; name another approver group first", 409)
	}
	bindings, err := requireGroupBindingAuthorities(ctx, server, tx, principal, jsString(tenantID), groupID)
	if err != nil {
		return err
	}
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", groupID), nil)
	if err != nil {
		return err
	}
	for _, member := range members {
		if err := tx.Delete(ctx, "groupMembers", jsString(member.Get("id"))); err != nil {
			return err
		}
	}
	for _, binding := range bindings {
		activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "bindingId", binding.Get("id")), nil)
		if err != nil {
			return err
		}
		for _, activation := range activations {
			if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
				return err
			}
		}
		if err := tx.Delete(ctx, "bindings", jsString(binding.Get("id"))); err != nil {
			return err
		}
	}
	tuples, err := tx.Find(ctx, "relationships", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
	if err != nil {
		return err
	}
	for _, tuple := range tuples {
		if err := tx.Delete(ctx, "relationships", jsString(tuple.Get("id"))); err != nil {
			return err
		}
	}
	// App assignments to the group go with it (applications.ts).
	if err := ReleaseGroupApps(ctx, tx, jsString(tenantID), jsString(groupID)); err != nil {
		return err
	}
	// So do license assignments to it, releasing the seats they carried (licenses.ts).
	if _, err := ReleaseGroupLicenses(ctx, server, tx, jsString(tenantID), jsString(groupID), principal); err != nil {
		return err
	}
	return tx.Delete(ctx, "groups", jsString(groupID))
}
