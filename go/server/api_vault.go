package server

// Skeleton of packages/server/src/api/vault.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// VaultAPI is the `vault` API group (packages/server/src/api/vault.ts createVaultApi): every method runs through the
// operation envelope; the router maps POST {basePath}/vault/{method} onto it.
type VaultAPI struct {
	server *ServerContext
}

// CreateVaultAPI builds the `vault` API group.
func CreateVaultAPI(server *ServerContext) *VaultAPI {
	return &VaultAPI{server: server}
}

// AccessLog is POST {basePath}/vault/accessLog. Who used a secret, newest first: reveals, check-outs and returns, leases, renewals, revocations, new versions and rotations, with the person's name, session kind and agent.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) AccessLog(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultAccessLogInput]) (Out[apitypes.VaultAccessLogOutput], error) {
	return Out[apitypes.VaultAccessLogOutput]{}, notImplemented("vault.accessLog")
}

// Checkin is POST {basePath}/vault/checkin. Returns a check-out.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Checkin(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultCheckinInput]) (Out[apitypes.VaultCheckinOutput], error) {
	return Out[apitypes.VaultCheckinOutput]{}, notImplemented("vault.checkin")
}

// Checkout is POST {basePath}/vault/checkout. Hands out a static secret's current value with a lease of durationMs (default and at most the policy's maxDurationMs), with a reason when the policy asks for one.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Checkout(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultCheckoutInput]) (Out[apitypes.VaultCheckoutOutput], error) {
	return Out[apitypes.VaultCheckoutOutput]{}, notImplemented("vault.checkout")
}

// Create is POST {basePath}/vault/create. Creates a secret. A static secret may start with value (or fields for a json secret), with generate (true or a generator), or without a value.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultCreateInput]) (Out[apitypes.VaultCreateOutput], error) {
	return Out[apitypes.VaultCreateOutput]{}, notImplemented("vault.create")
}

// Delete is POST {basePath}/vault/delete. Schedules the secret for deletion after recoveryDays (7-30, default 30), during which it can be restored but not read, changed or leased; its check-outs end.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultDeleteInput]) (Out[apitypes.VaultDeleteOutput], error) {
	return Out[apitypes.VaultDeleteOutput]{}, notImplemented("vault.delete")
}

// DestroyVersion is POST {basePath}/vault/destroyVersion. Erases a version's value for good; its record stays as history and labels on it are removed. The current version cannot be destroyed.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) DestroyVersion(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultDestroyVersionInput]) (Out[apitypes.VaultDestroyVersionOutput], error) {
	return Out[apitypes.VaultDestroyVersionOutput]{}, notImplemented("vault.destroyVersion")
}

// Generate is POST {basePath}/vault/generate. A value from a generator without storing it: length 8-256 (default 32), charset (alphanumeric, ascii, hex, base64url, numeric), exclude, and eachClass. Needs only a credential.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Generate(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultGenerateInput]) (Out[apitypes.VaultGenerateOutput], error) {
	return Out[apitypes.VaultGenerateOutput]{}, notImplemented("vault.generate")
}

// Get is POST {basePath}/vault/get. A secret's metadata: kind, format, tags, status, stage labels, rotation schedule (with due and the last failure), check-out policy, engine settings, key, live check-outs (who holds the value until wh…
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultGetInput]) (Out[apitypes.VaultGetOutput], error) {
	return Out[apitypes.VaultGetOutput]{}, notImplemented("vault.get")
}

// Lease is POST {basePath}/vault/lease. Asks a dynamic secret's engine for a credential minted for the caller, valid for ttlMs (default and at most from the secret's lease settings). The credential is returned once and never stored.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Lease(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultLeaseInput]) (Out[apitypes.VaultLeaseOutput], error) {
	return Out[apitypes.VaultLeaseOutput]{}, notImplemented("vault.lease")
}

// List is POST {basePath}/vault/list. The secrets the caller may read, sorted by name, optionally under prefix, with all of tags, and by status (active by default, pending-deletion or all), at most limit (1-500, default 100) from offset,…
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListInput]) (Out[apitypes.VaultListOutput], error) {
	return Out[apitypes.VaultListOutput]{}, notImplemented("vault.list")
}

// ListLeases is POST {basePath}/vault/listLeases. A secret's live check-outs and leases, or all kept history with includeEnded, newest first, with the holder's name and reason.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) ListLeases(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListLeasesInput]) (Out[apitypes.VaultListLeasesOutput], error) {
	return Out[apitypes.VaultListLeasesOutput]{}, notImplemented("vault.listLeases")
}

// ListMine is POST {basePath}/vault/listMine. The caller's own live check-outs and leases in the tenant. Needs only a session of the tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListMineInput]) (Out[apitypes.VaultListMineOutput], error) {
	return Out[apitypes.VaultListMineOutput]{}, notImplemented("vault.listMine")
}

// ListVersions is POST {basePath}/vault/listVersions. Every kept version, newest first, with its state (enabled, disabled, destroyed), stage labels, source (put, generated, rotation) and author. Never a value.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) ListVersions(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListVersionsInput]) (Out[apitypes.VaultListVersionsOutput], error) {
	return Out[apitypes.VaultListVersionsOutput]{}, notImplemented("vault.listVersions")
}

// Promote is POST {basePath}/vault/promote. Makes an enabled version current; the old current version becomes previous. Rolls back as well as forward; rolling back does not restart the rotation clock.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Promote(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultPromoteInput]) (Out[apitypes.VaultPromoteOutput], error) {
	return Out[apitypes.VaultPromoteOutput]{}, notImplemented("vault.promote")
}

// Put is POST {basePath}/vault/put. Stores a new version from value, fields or generate. It becomes current (the old one previous) unless stage names pending or a custom label. Versions past maxVersions that no label names are deleted.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Put(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultPutInput]) (Out[apitypes.VaultPutOutput], error) {
	return Out[apitypes.VaultPutOutput]{}, notImplemented("vault.put")
}

// RenewLease is POST {basePath}/vault/renewLease. Extends the caller's live check-out or dynamic lease by ttlMs from now (default: the length it was issued for), never past maxExpiresAt; tells the engine when it has renew.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) RenewLease(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRenewLeaseInput]) (Out[apitypes.VaultRenewLeaseOutput], error) {
	return Out[apitypes.VaultRenewLeaseOutput]{}, notImplemented("vault.renewLease")
}

// Restore is POST {basePath}/vault/restore. Cancels a scheduled deletion.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Restore(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRestoreInput]) (Out[apitypes.VaultRestoreOutput], error) {
	return Out[apitypes.VaultRestoreOutput]{}, notImplemented("vault.restore")
}

// Reveal is POST {basePath}/vault/reveal. The value of the current version, or of version or stage: value, and fields for json secrets.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Reveal(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRevealInput]) (Out[apitypes.VaultRevealOutput], error) {
	return Out[apitypes.VaultRevealOutput]{}, notImplemented("vault.reveal")
}

// RevokeLease is POST {basePath}/vault/revokeLease. Ends a lease now: a check-out ends like a check-in (a secret with rotateOnCheckin rotates once its last holder is gone, reported as rotated), a dynamic lease is revoked at its engine.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) RevokeLease(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRevokeLeaseInput]) (Out[apitypes.VaultRevokeLeaseOutput], error) {
	return Out[apitypes.VaultRevokeLeaseOutput]{}, notImplemented("vault.revokeLease")
}

// Rotate is POST {basePath}/vault/rotate. Rotates a static secret now: stages a new version as pending (generated, or value / fields when given), calls the secret's rotator with it outside any transaction, then makes it current.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Rotate(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRotateInput]) (Out[apitypes.VaultRotateOutput], error) {
	return Out[apitypes.VaultRotateOutput]{}, notImplemented("vault.rotate")
}

// SetStage is POST {basePath}/vault/setStage. Points a custom stage label, or pending, at a version, or removes it with version: null. current and previous move only through put, promote and rotate.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) SetStage(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultSetStageInput]) (Out[apitypes.VaultSetStageOutput], error) {
	return Out[apitypes.VaultSetStageOutput]{}, notImplemented("vault.setStage")
}

// SetVersionState is POST {basePath}/vault/setVersionState. Disables a version (kept, but not revealed) or enables it again. The current version cannot be disabled.
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) SetVersionState(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultSetVersionStateInput]) (Out[apitypes.VaultSetVersionStateOutput], error) {
	return Out[apitypes.VaultSetVersionStateOutput]{}, notImplemented("vault.setVersionState")
}

// Update is POST {basePath}/vault/update. Changes settings: description (null clears), tags (replaced), maxVersions, rotation and checkout (null removes), a dynamic secret's engineConfig and lease, and kmsKey (a new key re-encrypts every kep…
//
// STUB: returns NOT_IMPLEMENTED until api/vault.ts is ported.
func (api *VaultAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultUpdateInput]) (Out[apitypes.VaultUpdateOutput], error) {
	return Out[apitypes.VaultUpdateOutput]{}, notImplemented("vault.update")
}

// IamVault is api/vault.ts IamVault.
type IamVault struct {
	server *ServerContext
}

// Get (api/vault.ts IamVault.get): A static secret's value for server code: the `current` version, or `version` /
// `stage`. No credential and no audit event (the access log records nothing either); check-out rules do not apply.
// NOT_FOUND for secrets pending deletion.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamVault) Get(ctx context.Context, tenantID string, name string, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/vault.ts IamVault.get")
	return
}

// Resolve (api/vault.ts IamVault.resolve): Replaces every string of the form `vault://{name}` (the value) or
// `vault://{name}#{field}` (one field of a json secret) inside a JSON value, for configuration objects. Each secret
// is read once per call.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamVault) Resolve(ctx context.Context, tenantID string, value any) (result any, err error) {
	err = notImplemented("api/vault.ts IamVault.resolve")
	return
}

// RotateDue (api/vault.ts IamVault.rotateDue): Rotates every static secret whose scheduled rotation (or a retry of a
// failed one) is due (hourly job): generated values and rotators run as `deployment-operator`; secrets with neither
// are recorded once per due date as `vault:rotation-due`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamVault) RotateDue(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/vault.ts IamVault.rotateDue")
	return
}

// ExpireLeases (api/vault.ts IamVault.expireLeases): Ends expired check-outs (rotating `rotateOnCheckin` secrets),
// revokes expired dynamic leases and those of people who are no longer active at their engine, retries failed
// revocations with backoff for seven days, and deletes lease history past `accessRetentionDays` (every few minutes).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamVault) ExpireLeases(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/vault.ts IamVault.expireLeases")
	return
}

// PurgeDeleted (api/vault.ts IamVault.purgeDeleted): Deletes secrets whose recovery window has ended, once their
// dynamic leases are revoked (daily).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamVault) PurgeDeleted(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/vault.ts IamVault.purgeDeleted")
	return
}

// CreateVaultRuntime builds the IamVault (api/vault.ts createVaultRuntime). Its methods are stubs until the module is ported.
func CreateVaultRuntime(server *ServerContext) *IamVault {
	return &IamVault{server: server}
}
