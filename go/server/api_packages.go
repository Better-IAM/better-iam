package server

// Skeleton of packages/server/src/api/packages.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// PackagesAPI is the `packages` API group (packages/server/src/api/packages.ts createPackagesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/packages/{method} onto it.
type PackagesAPI struct {
	server *ServerContext
}

// CreatePackagesAPI builds the `packages` API group.
func CreatePackagesAPI(server *ServerContext) *PackagesAPI {
	return &PackagesAPI{server: server}
}

// ApproveRequest is POST {basePath}/packages/approveRequest. Grants a pending package request by assigning the package to the requester under your own authority.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) ApproveRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesApproveRequestInput]) (Out[apitypes.PackagesApproveRequestOutput], error) {
	return Out[apitypes.PackagesApproveRequestOutput]{}, notImplemented("packages.approveRequest")
}

// Assign is POST {basePath}/packages/assign. Grants a package to a person: one binding per role and one membership per group, all ending together.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesAssignInput]) (Out[apitypes.PackagesAssignOutput], error) {
	return Out[apitypes.PackagesAssignOutput]{}, notImplemented("packages.assign")
}

// CancelRequest is POST {basePath}/packages/cancelRequest. Withdraws one of your own pending package requests.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) CancelRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesCancelRequestInput]) (Out[apitypes.PackagesCancelRequestOutput], error) {
	return Out[apitypes.PackagesCancelRequestOutput]{}, notImplemented("packages.cancelRequest")
}

// Create is POST {basePath}/packages/create. Defines a package of roles and groups, optionally requestable or assigned automatically by a rule.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesCreateInput]) (Out[apitypes.PackagesCreateOutput], error) {
	return Out[apitypes.PackagesCreateOutput]{}, notImplemented("packages.create")
}

// Delete is POST {basePath}/packages/delete. Deletes a package nobody holds, together with its request history.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesDeleteInput]) (Out[apitypes.PackagesDeleteOutput], error) {
	return Out[apitypes.PackagesDeleteOutput]{}, notImplemented("packages.delete")
}

// DenyRequest is POST {basePath}/packages/denyRequest. Refuses a pending package request, with an optional note to the requester.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) DenyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesDenyRequestInput]) (Out[apitypes.PackagesDenyRequestOutput], error) {
	return Out[apitypes.PackagesDenyRequestOutput]{}, notImplemented("packages.denyRequest")
}

// Extend is POST {basePath}/packages/extend. Moves the end of a person's manual assignment, for the assignment and every record it created at once.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Extend(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesExtendInput]) (Out[apitypes.PackagesExtendOutput], error) {
	return Out[apitypes.PackagesExtendOutput]{}, notImplemented("packages.extend")
}

// Get is POST {basePath}/packages/get. Returns one package with its live holder counts and, for a rule package, the rule's state.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesGetInput]) (Out[apitypes.PackagesGetOutput], error) {
	return Out[apitypes.PackagesGetOutput]{}, notImplemented("packages.get")
}

// List is POST {basePath}/packages/list. Lists the tenant's packages by name, each with its live holder counts.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListInput]) (Out[apitypes.PackagesListOutput], error) {
	return Out[apitypes.PackagesListOutput]{}, notImplemented("packages.list")
}

// ListApprovals is POST {basePath}/packages/listApprovals. Lists the pending package requests you may decide on.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) ListApprovals(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListApprovalsInput]) (Out[apitypes.PackagesListApprovalsOutput], error) {
	return Out[apitypes.PackagesListApprovalsOutput]{}, notImplemented("packages.listApprovals")
}

// ListAssignments is POST {basePath}/packages/listAssignments. Lists the holders of a package, or the packages of a person, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListAssignmentsInput]) (Out[apitypes.PackagesListAssignmentsOutput], error) {
	return Out[apitypes.PackagesListAssignmentsOutput]{}, notImplemented("packages.listAssignments")
}

// ListMine is POST {basePath}/packages/listMine. Returns your self-service view: the requestable packages with your status on each, your assignments, and your recent requests.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListMineInput]) (Out[apitypes.PackagesListMineOutput], error) {
	return Out[apitypes.PackagesListMineOutput]{}, notImplemented("packages.listMine")
}

// ListRequests is POST {basePath}/packages/listRequests. Lists package requests for a package or a person, newest first, optionally by status.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) ListRequests(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListRequestsInput]) (Out[apitypes.PackagesListRequestsOutput], error) {
	return Out[apitypes.PackagesListRequestsOutput]{}, notImplemented("packages.listRequests")
}

// PreviewAutoAssign is POST {basePath}/packages/previewAutoAssign. Shows what a package rule matches and, for a package, what a reconcile would change, without writing anything.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) PreviewAutoAssign(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesPreviewAutoAssignInput]) (Out[apitypes.PackagesPreviewAutoAssignOutput], error) {
	return Out[apitypes.PackagesPreviewAutoAssignOutput]{}, notImplemented("packages.previewAutoAssign")
}

// Reconcile is POST {basePath}/packages/reconcile. Runs the package-rule reconciler now for the tenant or one package, optionally confirming held-back changes.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Reconcile(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesReconcileInput]) (Out[apitypes.PackagesReconcileOutput], error) {
	return Out[apitypes.PackagesReconcileOutput]{}, notImplemented("packages.reconcile")
}

// Request is POST {basePath}/packages/request. Asks for a requestable package for yourself; approvers are notified and one of them decides.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Request(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesRequestInput]) (Out[apitypes.PackagesRequestOutput], error) {
	return Out[apitypes.PackagesRequestOutput]{}, notImplemented("packages.request")
}

// Revoke is POST {basePath}/packages/revoke. Removes a package from a person, taking away exactly the bindings and memberships the assignment still owns.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesRevokeInput]) (Out[apitypes.PackagesRevokeOutput], error) {
	return Out[apitypes.PackagesRevokeOutput]{}, notImplemented("packages.revoke")
}

// Update is POST {basePath}/packages/update. Changes a package's name, description, contents, request settings, or rule.
//
// STUB: returns NOT_IMPLEMENTED until api/packages.ts is ported.
func (api *PackagesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesUpdateInput]) (Out[apitypes.PackagesUpdateOutput], error) {
	return Out[apitypes.PackagesUpdateOutput]{}, notImplemented("packages.update")
}

// Allow (api/packages.ts allow): Every part of an assignment is authorized like the direct call, so a package never
// widens what its assigner may grant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Allow(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, action string, resourceID string, what string) (err error) {
	err = notImplemented("api/packages.ts allow")
	return
}

// AssignPackage (api/packages.ts assignPackage): Grants a package to an identity: every role becomes an identity
// binding of the assignment's own and every group a membership, all ending at `expiresAt`, created under the
// caller's grant authority and tagged with the assignment (see materialize). A live automatic assignment is taken
// over (revoked and replaced by this manual one); a broken one is replaced. The identity's pending request for the
// package is marked approved (cancelled, for an automatic assignment). With `automatic`, the rule engine assigns
// under the rule owner's authority.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssignPackage(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, input *core.Object, automatic *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts assignPackage")
	return
}

// AuthorizePackage (api/packages.ts authorizePackage): The rights assigning a package by hand needs:
// iam:bindings:create on each role and iam:groups:update on each group, and (with `groupAuthorities`) the use of
// every grant authority behind the groups' own bindings, which membership confers. A packaged group that carries
// license seats (a product is assigned to it, or to a team it syncs into) needs iam:licenses:assign too, refused
// with `OperationDenied` (api/groups.ts): so assigning or approving the package, lengthening an assignment,
// confirming a rule's held-back changes, and saving or running a rule (its owner; `ruleHealth` suspends the rule's
// additions in advance) all need it. Returns the caller's grant authority when the package has roles (or
// `requireAuthority`). Callers outside a transaction must pass `authorityId`: the root path of grantingAuthority
// writes a record.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AuthorizePackage(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts authorizePackage")
	return
}

// CreatePackage (api/packages.ts createPackage): Creates a package; shared by `packages.create` and configuration
// sync.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreatePackage(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object, principal *Principal) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts createPackage")
	return
}

// DeletePackage (api/packages.ts deletePackage): Deletes a package nobody holds, with its request history; shared by
// `packages.delete` and configuration sync.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeletePackage(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object) (err error) {
	err = notImplemented("api/packages.ts deletePackage")
	return
}

// EndOf (api/packages.ts endOf): Ends compare with "no end" last.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EndOf(expiresAt *float64) (result float64, err error) {
	err = notImplemented("api/packages.ts endOf")
	return
}

// LiveAssignment (api/packages.ts liveAssignment): Whether an assignment still applies; an ended one grants nothing
// and waits for the purge worker.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveAssignment(server *ServerContext, assignment *core.Object) (result bool, err error) {
	err = notImplemented("api/packages.ts liveAssignment")
	return
}

// RefreshAssignment (api/packages.ts refreshAssignment): Brings an automatic assignment up to its package and rule:
// bindings of roles no longer packaged, or issued under another authority than the rule's, are removed; memberships
// of groups no longer packaged are removed (or handed over); what is missing is materialized. Memberships that stay
// are untouched, so live activations survive.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RefreshAssignment(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, assignment *core.Object, authority *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts refreshAssignment")
	return
}

// RetimeAssignment (api/packages.ts retimeAssignment): Moves the end of an assignment and of exactly its records
// (undefined: no end). Shortening a shared membership hands it to the package that still needs it longer;
// lengthening extends a shorter membership of the package's groups (held by hand or through another package) and
// makes it the assignment's. Authorization is the caller's, for the package's current contents: lengthening
// therefore reaches only records of roles and groups the package still bundles, and those it no longer bundles
// (removed by packages.update since) keep their end. A caller nobody authorized for the current contents (a guest's
// renewal, api/guests.ts) passes `lengthenOnly`: lengthening then reaches only those memberships of the assignment,
// takes no other membership over, and leaves the rest as they are.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RetimeAssignment(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object, assignment *core.Object, expiresAt *float64, lengthenOnly []string) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts retimeAssignment")
	return
}

// RevokeAssignment (api/packages.ts revokeAssignment): Removes exactly the bindings and memberships an assignment
// created, then the assignment. The assignment owns those records whichever authority issued them, so revoking needs
// only the right to manage the package.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RevokeAssignment(ctx context.Context, server *ServerContext, tx core.IamStore, assignment *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts revokeAssignment")
	return
}

// RuleEnvironment (api/packages.ts ruleEnvironment): What a rule of this package may name: the deployment's declared
// attributes and the tenant's groups, teams, and departments.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleEnvironment(ctx context.Context, server *ServerContext, reader core.IamStore, pkg *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts ruleEnvironment")
	return
}

// UpdatePackage (api/packages.ts updatePackage): Changes a package's contents and rules; existing manual assignments
// keep what they were given. Changing the contents of a package without a rule needs no rights over what is added or
// removed because it grants nothing: extending an assignment lengthens only what the package still bundles (and the
// extender is authorized for), and handing a shared membership over never lengthens it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UpdatePackage(ctx context.Context, server *ServerContext, tx core.IamStore, existing *core.Object, input *core.Object, principal *Principal) (result *core.Object, err error) {
	err = notImplemented("api/packages.ts updatePackage")
	return
}
