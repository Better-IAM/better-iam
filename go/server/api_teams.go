package server

// Skeleton of packages/server/src/api/teams.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// TeamsAPI is the `teams` API group (packages/server/src/api/teams.ts createTeamsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/teams/{method} onto it.
type TeamsAPI struct {
	server *ServerContext
}

// CreateTeamsAPI builds the `teams` API group.
func CreateTeamsAPI(server *ServerContext) *TeamsAPI {
	return &TeamsAPI{server: server}
}

// AddMember is POST {basePath}/teams/addMember. Adds a person to a team as a member (default) or maintainer, optionally until expiresAt.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) AddMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsAddMemberInput]) (Out[apitypes.TeamsAddMemberOutput], error) {
	return Out[apitypes.TeamsAddMemberOutput]{}, notImplemented("teams.addMember")
}

// AddMembers is POST {basePath}/teams/addMembers. Adds up to 100 people with the same role and expiry in one transaction; one failure rejects the batch.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) AddMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsAddMembersInput]) (Out[apitypes.TeamsAddMembersOutput], error) {
	return Out[apitypes.TeamsAddMembersOutput]{}, notImplemented("teams.addMembers")
}

// ApproveRequest is POST {basePath}/teams/approveRequest. Grants a pending join request: the requester joins as a member (optionally until expiresAt) and is emailed (team-join-decided). Nobody decides their own request.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) ApproveRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsApproveRequestInput]) (Out[apitypes.TeamsApproveRequestOutput], error) {
	return Out[apitypes.TeamsApproveRequestOutput]{}, notImplemented("teams.approveRequest")
}

// CancelRequest is POST {basePath}/teams/cancelRequest. Withdraws your own pending join request.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) CancelRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCancelRequestInput]) (Out[apitypes.TeamsCancelRequestOutput], error) {
	return Out[apitypes.TeamsCancelRequestOutput]{}, notImplemented("teams.cancelRequest")
}

// CancelReview is POST {basePath}/teams/cancelReview. Cancels an open membership review without changing the team.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) CancelReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCancelReviewInput]) (Out[apitypes.TeamsCancelReviewOutput], error) {
	return Out[apitypes.TeamsCancelReviewOutput]{}, notImplemented("teams.cancelReview")
}

// Candidates is POST {basePath}/teams/candidates. People who could be added: active people of the organization who are not direct members, matched on name or email by query, at most limit (default 50, up to 200).
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Candidates(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCandidatesInput]) (Out[apitypes.TeamsCandidatesOutput], error) {
	return Out[apitypes.TeamsCandidatesOutput]{}, notImplemented("teams.candidates")
}

// CompleteReview is POST {basePath}/teams/completeReview. Completes an open review: people decided remove leave the team, and people nobody decided on follow the review's onUndecided.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) CompleteReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCompleteReviewInput]) (Out[apitypes.TeamsCompleteReviewOutput], error) {
	return Out[apitypes.TeamsCompleteReviewOutput]{}, notImplemented("teams.completeReview")
}

// Create is POST {basePath}/teams/create. Creates a team with its backing group.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsCreateInput]) (Out[apitypes.TeamsCreateOutput], error) {
	return Out[apitypes.TeamsCreateOutput]{}, notImplemented("teams.create")
}

// DecideReview is POST {basePath}/teams/decideReview. Records keep or remove for up to 200 people under an open review, each with an optional note. A later decision replaces an earlier one; nothing changes in the team until the review completes.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) DecideReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsDecideReviewInput]) (Out[apitypes.TeamsDecideReviewOutput], error) {
	return Out[apitypes.TeamsDecideReviewOutput]{}, notImplemented("teams.decideReview")
}

// Delete is POST {basePath}/teams/delete. Deletes a team, its memberships and join requests, and its backing group with the bindings and relationships on it.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsDeleteInput]) (Out[apitypes.TeamsDeleteOutput], error) {
	return Out[apitypes.TeamsDeleteOutput]{}, notImplemented("teams.delete")
}

// DenyRequest is POST {basePath}/teams/denyRequest. Refuses a pending join request; the requester is emailed with the note.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) DenyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsDenyRequestInput]) (Out[apitypes.TeamsDenyRequestOutput], error) {
	return Out[apitypes.TeamsDenyRequestOutput]{}, notImplemented("teams.denyRequest")
}

// Get is POST {basePath}/teams/get. One team with its path (the teams above it), its children, department, maintainers, total member count (with the teams below), and the roles its members hold through it or a team above (inherited).
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsGetInput]) (Out[apitypes.TeamsGetOutput], error) {
	return Out[apitypes.TeamsGetOutput]{}, notImplemented("teams.get")
}

// GetReview is POST {basePath}/teams/getReview. One membership review with every person under it: their role, the decision, who made it and when, and the note.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) GetReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsGetReviewInput]) (Out[apitypes.TeamsGetReviewOutput], error) {
	return Out[apitypes.TeamsGetReviewOutput]{}, notImplemented("teams.getReview")
}

// Leave is POST {basePath}/teams/leave. Leaves a team you belong to directly.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Leave(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsLeaveInput]) (Out[apitypes.TeamsLeaveOutput], error) {
	return Out[apitypes.TeamsLeaveOutput]{}, notImplemented("teams.leave")
}

// List is POST {basePath}/teams/list. Every team with member, maintainer, and child counts, in name order. Filters: parentId (null for top-level teams), departmentId, and query (name or slug).
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListInput]) (Out[apitypes.TeamsListOutput], error) {
	return Out[apitypes.TeamsListOutput]{}, notImplemented("teams.list")
}

// ListForIdentity is POST {basePath}/teams/listForIdentity. The teams one person belongs to directly, with their role, expiry, and the teams above each one.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) ListForIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListForIdentityInput]) (Out[apitypes.TeamsListForIdentityOutput], error) {
	return Out[apitypes.TeamsListForIdentityOutput]{}, notImplemented("teams.listForIdentity")
}

// ListMembers is POST {basePath}/teams/listMembers. The team's live direct members with their role, expiry, and who added them; includeChildTeams adds the members of every team below, each with the team they belong to.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) ListMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListMembersInput]) (Out[apitypes.TeamsListMembersOutput], error) {
	return Out[apitypes.TeamsListMembersOutput]{}, notImplemented("teams.listMembers")
}

// ListMine is POST {basePath}/teams/listMine. Your teams (with role, expiry, and parents), your join requests (newest first), the teams that take join requests that you are not in, and the open membership reviews of teams you maintain (reviews,…
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListMineInput]) (Out[apitypes.TeamsListMineOutput], error) {
	return Out[apitypes.TeamsListMineOutput]{}, notImplemented("teams.listMine")
}

// ListRequests is POST {basePath}/teams/listRequests. A team's join requests, pending by default (status picks another state; lapsed requests read as expired).
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) ListRequests(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListRequestsInput]) (Out[apitypes.TeamsListRequestsOutput], error) {
	return Out[apitypes.TeamsListRequestsOutput]{}, notImplemented("teams.listRequests")
}

// ListReviews is POST {basePath}/teams/listReviews. Membership reviews, newest first (at most 100), without their items: of one team with teamId, or of every team. status (open, completed, cancelled) filters.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) ListReviews(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsListReviewsInput]) (Out[apitypes.TeamsListReviewsOutput], error) {
	return Out[apitypes.TeamsListReviewsOutput]{}, notImplemented("teams.listReviews")
}

// Reconcile is POST {basePath}/teams/reconcile. Runs team sync for every synced team (synced: team memberships added, removed, and updated), then recomputes every backing group from team membership, after a restore, an import, or a manual repair:…
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Reconcile(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsReconcileInput]) (Out[apitypes.TeamsReconcileOutput], error) {
	return Out[apitypes.TeamsReconcileOutput]{}, notImplemented("teams.reconcile")
}

// RemoveMember is POST {basePath}/teams/removeMember. Removes a direct member; the backing groups and the person's activations of their eligible bindings follow.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) RemoveMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsRemoveMemberInput]) (Out[apitypes.TeamsRemoveMemberOutput], error) {
	return Out[apitypes.TeamsRemoveMemberOutput]{}, notImplemented("teams.removeMember")
}

// RequestToJoin is POST {basePath}/teams/requestToJoin. Asks to join a team whose joinPolicy is request, with an optional justification.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) RequestToJoin(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsRequestToJoinInput]) (Out[apitypes.TeamsRequestToJoinOutput], error) {
	return Out[apitypes.TeamsRequestToJoinOutput]{}, notImplemented("teams.requestToJoin")
}

// StartReview is POST {basePath}/teams/startReview. Opens a membership review of the team, due at dueAt (one to 90 days ahead; in 14 days by default), with an optional note for the maintainers.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) StartReview(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsStartReviewInput]) (Out[apitypes.TeamsStartReviewOutput], error) {
	return Out[apitypes.TeamsStartReviewOutput]{}, notImplemented("teams.startReview")
}

// SuggestBirthright is POST {basePath}/teams/suggestBirthright. Roles and groups that most of a team's members already hold by hand, proposed as a ready-made automatic access package whose rule names the team.
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) SuggestBirthright(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsSuggestBirthrightInput]) (Out[apitypes.TeamsSuggestBirthrightOutput], error) {
	return Out[apitypes.TeamsSuggestBirthrightOutput]{}, notImplemented("teams.suggestBirthright")
}

// Update is POST {basePath}/teams/update. Renames, re-slugs, re-describes, moves (parentId, null for top level), or re-files (departmentId, null to clear) a team, or changes joinPolicy, memberManagement, or syncGroupIds (team sync; null stop…
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsUpdateInput]) (Out[apitypes.TeamsUpdateOutput], error) {
	return Out[apitypes.TeamsUpdateOutput]{}, notImplemented("teams.update")
}

// UpdateMember is POST {basePath}/teams/updateMember. Changes a member's role or expiry (expiresAt: null makes the membership permanent).
//
// STUB: returns NOT_IMPLEMENTED until api/teams.ts is ported.
func (api *TeamsAPI) UpdateMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.TeamsUpdateMemberInput]) (Out[apitypes.TeamsUpdateMemberOutput], error) {
	return Out[apitypes.TeamsUpdateMemberOutput]{}, notImplemented("teams.updateMember")
}

// TeamMutationsResult is api/teams.ts teamMutations().
type TeamMutationsResult struct {
	server *ServerContext
}

// CreateTeam (api/teams.ts teamMutations().createTeam): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) CreateTeam(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/teams.ts teamMutations().createTeam")
	return
}

// UpdateTeam (api/teams.ts teamMutations().updateTeam): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) UpdateTeam(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/teams.ts teamMutations().updateTeam")
	return
}

// DeleteTeam (api/teams.ts teamMutations().deleteTeam): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) DeleteTeam(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object) (result float64, err error) {
	err = notImplemented("api/teams.ts teamMutations().deleteTeam")
	return
}

// PutMember (api/teams.ts teamMutations().putMember): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) PutMember(ctx context.Context, mutation *core.Object, input *core.Object, source string) (result *core.Object, err error) {
	err = notImplemented("api/teams.ts teamMutations().putMember")
	return
}

// RemoveMember (api/teams.ts teamMutations().removeMember): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) RemoveMember(ctx context.Context, tx core.IamStore, principal *Principal, team *core.Object, member *core.Object, action string, via string) (err error) {
	err = notImplemented("api/teams.ts teamMutations().removeMember")
	return
}

// MemberRecord (api/teams.ts teamMutations().memberRecord): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) MemberRecord(ctx context.Context, tx core.IamStore, team *core.Object, identityID any) (result *core.Object, err error) {
	err = notImplemented("api/teams.ts teamMutations().memberRecord")
	return
}

// AssertAuthorityOver (api/teams.ts teamMutations().assertAuthorityOver): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) AssertAuthorityOver(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, teams []*core.Object) (err error) {
	err = notImplemented("api/teams.ts teamMutations().assertAuthorityOver")
	return
}

// AssertMayClaimTeamLicenses (api/teams.ts teamMutations().assertMayClaimTeamLicenses): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) AssertMayClaimTeamLicenses(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, teams []*core.Object) (err error) {
	err = notImplemented("api/teams.ts teamMutations().assertMayClaimTeamLicenses")
	return
}

// AllTeams (api/teams.ts teamMutations().allTeams): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamMutationsResult) AllTeams(ctx context.Context, tx core.IamStore, tenantID string) (result map[string]*core.Object, err error) {
	err = notImplemented("api/teams.ts teamMutations().allTeams")
	return
}

// TeamMutations (api/teams.ts teamMutations): Transaction-level team changes for configuration sync (org-sync.ts):
// the same validation, backing-group upkeep, and audit events as the API. Callers authorize each change first.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamMutations(server *ServerContext) (result *TeamMutationsResult, err error) {
	err = notImplemented("api/teams.ts teamMutations")
	return
}
