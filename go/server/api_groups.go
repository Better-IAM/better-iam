package server

// Skeleton of packages/server/src/api/groups.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

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

// AddMember is POST {basePath}/groups/addMember. Adds a person to a group so they receive every role bound to the group, optionally until a given time.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) AddMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsAddMemberInput]) (Out[apitypes.GroupsAddMemberOutput], error) {
	return Out[apitypes.GroupsAddMemberOutput]{}, notImplemented("groups.addMember")
}

// AddMembers is POST {basePath}/groups/addMembers. Adds up to 100 people to a group in one transaction, all with the same optional expiry.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) AddMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsAddMembersInput]) (Out[apitypes.GroupsAddMembersOutput], error) {
	return Out[apitypes.GroupsAddMembersOutput]{}, notImplemented("groups.addMembers")
}

// Create is POST {basePath}/groups/create. Creates a group in the tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsCreateInput]) (Out[apitypes.GroupsCreateOutput], error) {
	return Out[apitypes.GroupsCreateOutput]{}, notImplemented("groups.create")
}

// Delete is POST {basePath}/groups/delete. Deletes a group together with its memberships, its role bindings, their activations, and its relationship tuples.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsDeleteInput]) (Out[apitypes.GroupsDeleteOutput], error) {
	return Out[apitypes.GroupsDeleteOutput]{}, notImplemented("groups.delete")
}

// Get is POST {basePath}/groups/get. Returns one group by id.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsGetInput]) (Out[apitypes.GroupsGetOutput], error) {
	return Out[apitypes.GroupsGetOutput]{}, notImplemented("groups.get")
}

// List is POST {basePath}/groups/list. Lists every group in the tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsListInput]) (Out[apitypes.GroupsListOutput], error) {
	return Out[apitypes.GroupsListOutput]{}, notImplemented("groups.list")
}

// ListMembers is POST {basePath}/groups/listMembers. Lists the current members of a group, with membershipExpiresAt on temporary memberships.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) ListMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsListMembersInput]) (Out[apitypes.GroupsListMembersOutput], error) {
	return Out[apitypes.GroupsListMembersOutput]{}, notImplemented("groups.listMembers")
}

// RemoveMember is POST {basePath}/groups/removeMember. Removes a person from a group, ending the access the group's roles gave them.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) RemoveMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsRemoveMemberInput]) (Out[apitypes.GroupsRemoveMemberOutput], error) {
	return Out[apitypes.GroupsRemoveMemberOutput]{}, notImplemented("groups.removeMember")
}

// Update is POST {basePath}/groups/update. Renames a group or changes its description.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsUpdateInput]) (Out[apitypes.GroupsUpdateOutput], error) {
	return Out[apitypes.GroupsUpdateOutput]{}, notImplemented("groups.update")
}

// UpdateMember is POST {basePath}/groups/updateMember. Extends, shortens, or clears the expiry of an existing membership.
//
// STUB: returns NOT_IMPLEMENTED until api/groups.ts is ported.
func (api *GroupsAPI) UpdateMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GroupsUpdateMemberInput]) (Out[apitypes.GroupsUpdateMemberOutput], error) {
	return Out[apitypes.GroupsUpdateMemberOutput]{}, notImplemented("groups.updateMember")
}

// AddGroupMember (api/groups.ts addGroupMember): Adds an identity to a group; membership confers every group
// binding, so each binding's authority is required (and, for teams that sync from the group, that of their backing
// groups' bindings), and iam:licenses:assign when license products are assigned to those groups. `expiresAt` makes
// the membership temporary. Re-adding an expired member renews the membership.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AddGroupMember(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/groups.ts addGroupMember")
	return
}

// AssertMayClaimLicenses (api/groups.ts assertMayClaimLicenses): A license product assigned to a group gives each
// member a claim on a seat, as assigning the product to them would: adding someone to such a group, or changing how
// long they stay, needs iam:licenses:assign in the tenant as well. The same holds for the backing groups the write
// fills through team sync (of the teams that sync from the group and of the teams above them). Team maintainers
// manage their own team under its administrators' delegation instead, and directory sync (SCIM) sets members as the
// directory says. Every other writer that puts people into groups (`identities.createMany` and `invite`, guest
// invitations, access packages, onboarding completion groups, the teams API for administrators) asks the same,
// through this check: it refuses with `OperationDenied`, which an operation records as a denial of itself. Pass the
// groups the write fills (`groupIds`) and, optionally, the refusal's message.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertMayClaimLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, groupID any, message string) (err error) {
	err = notImplemented("api/groups.ts assertMayClaimLicenses")
	return
}

// CreateGroup (api/groups.ts createGroup): Creates a group within the tenant's plan limit; shared by `groups.create`
// and configuration sync.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateGroup(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/groups.ts createGroup")
	return
}

// DeleteGroup (api/groups.ts deleteGroup): Deletes a group with its memberships, bindings, activations, and
// relationships.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteGroup(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, group *core.Object) (err error) {
	err = notImplemented("api/groups.ts deleteGroup")
	return
}

// RemoveGroupMember (api/groups.ts removeGroupMember): Removes an identity from a group, ending its activations of
// the group's eligible bindings.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RemoveGroupMember(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (err error) {
	err = notImplemented("api/groups.ts removeGroupMember")
	return
}

// UpdateGroupMember (api/groups.ts updateGroupMember): Extends, shortens, or clears (null) a membership's expiry
// under the same authority rules as adding a member.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UpdateGroupMember(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/groups.ts updateGroupMember")
	return
}
