package server

// Skeleton of packages/server/src/api/keys.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// KeysAPI is the `keys` API group (packages/server/src/api/keys.ts createKeysApi): every method runs through the
// operation envelope; the router maps POST {basePath}/keys/{method} onto it.
type KeysAPI struct {
	server *ServerContext
}

// CreateKeysAPI builds the `keys` API group.
func CreateKeysAPI(server *ServerContext) *KeysAPI {
	return &KeysAPI{server: server}
}

// CancelDeletion is POST {basePath}/keys/cancelDeletion. Cancels a scheduled deletion. The key comes back disabled.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) CancelDeletion(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCancelDeletionInput]) (Out[apitypes.KeysCancelDeletionOutput], error) {
	return Out[apitypes.KeysCancelDeletionOutput]{}, notImplemented("keys.cancelDeletion")
}

// Create is POST {basePath}/keys/create. Creates a key, optionally with an alias, tags, a description and automatic rotation.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCreateInput]) (Out[apitypes.KeysCreateOutput], error) {
	return Out[apitypes.KeysCreateOutput]{}, notImplemented("keys.create")
}

// CreateAlias is POST {basePath}/keys/createAlias. Names a key alias/{name}. Names use letters, digits, slashes, underscores and hyphens and are unique within the tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) CreateAlias(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCreateAliasInput]) (Out[apitypes.KeysCreateAliasOutput], error) {
	return Out[apitypes.KeysCreateAliasOutput]{}, notImplemented("keys.createAlias")
}

// CreateGrant is POST {basePath}/keys/createGrant. Allows an identity to perform named operations on one key, optionally until expiresAt and, for encryption operations, only with a matching encryption context (constraints.encryptionContextEquals or e…
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) CreateGrant(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCreateGrantInput]) (Out[apitypes.KeysCreateGrantOutput], error) {
	return Out[apitypes.KeysCreateGrantOutput]{}, notImplemented("keys.createGrant")
}

// Decrypt is POST {basePath}/keys/decrypt. Decrypts a ciphertext from encrypt, generateDataKey or reEncrypt, given the same encryption context. Text comes back as plaintext, bytes as plaintextBase64.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Decrypt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysDecryptInput]) (Out[apitypes.KeysDecryptOutput], error) {
	return Out[apitypes.KeysDecryptOutput]{}, notImplemented("keys.decrypt")
}

// DeleteAlias is POST {basePath}/keys/deleteAlias. Removes an alias. The key stays.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) DeleteAlias(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysDeleteAliasInput]) (Out[apitypes.KeysDeleteAliasOutput], error) {
	return Out[apitypes.KeysDeleteAliasOutput]{}, notImplemented("keys.deleteAlias")
}

// Disable is POST {basePath}/keys/disable. Disables a key. Every cryptographic call with it is refused with KEYSTATEINVALID until it is enabled again, so data encrypted under it cannot be read in the meantime.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Disable(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysDisableInput]) (Out[apitypes.KeysDisableOutput], error) {
	return Out[apitypes.KeysDisableOutput]{}, notImplemented("keys.disable")
}

// Enable is POST {basePath}/keys/enable. Enables a disabled key.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Enable(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysEnableInput]) (Out[apitypes.KeysEnableOutput], error) {
	return Out[apitypes.KeysEnableOutput]{}, notImplemented("keys.enable")
}

// Encrypt is POST {basePath}/keys/encrypt. Encrypts up to 4 KiB (plaintext as UTF-8 text, or plaintextBase64) with the key's current version, bound to the optional encryption context.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Encrypt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysEncryptInput]) (Out[apitypes.KeysEncryptOutput], error) {
	return Out[apitypes.KeysEncryptOutput]{}, notImplemented("keys.encrypt")
}

// GenerateDataKey is POST {basePath}/keys/generateDataKey. Returns a fresh random data key of 16, 24, 32 (default) or 64 bytes for encrypting large data locally: the plaintext key to use and discard, and its ciphertext under the KMS key to store beside the d…
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) GenerateDataKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysGenerateDataKeyInput]) (Out[apitypes.KeysGenerateDataKeyOutput], error) {
	return Out[apitypes.KeysGenerateDataKeyOutput]{}, notImplemented("keys.generateDataKey")
}

// GenerateMac is POST {basePath}/keys/generateMac. Computes an HMAC of a message with the key's current version and returns it as base64url.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) GenerateMac(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysGenerateMacInput]) (Out[apitypes.KeysGenerateMacOutput], error) {
	return Out[apitypes.KeysGenerateMacOutput]{}, notImplemented("keys.generateMac")
}

// Get is POST {basePath}/keys/get. One key by id or alias: its spec, usage, state, current version, tags, aliases, algorithms and rotation schedule. Never its material.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysGetInput]) (Out[apitypes.KeysGetOutput], error) {
	return Out[apitypes.KeysGetOutput]{}, notImplemented("keys.get")
}

// Jwks is POST {basePath}/keys/jwks. Every version's public key of an asymmetric key, as a JWK Set for verifying tokens signed with signJwt.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Jwks(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysJwksInput]) (Out[apitypes.KeysJwksOutput], error) {
	return Out[apitypes.KeysJwksOutput]{}, notImplemented("keys.jwks")
}

// List is POST {basePath}/keys/list. The tenant's keys that the caller may read, newest first, optionally filtered by state or keyUsage.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListInput]) (Out[apitypes.KeysListOutput], error) {
	return Out[apitypes.KeysListOutput]{}, notImplemented("keys.list")
}

// ListAliases is POST {basePath}/keys/listAliases. Every alias in the tenant, or the aliases of one key (keyId), sorted by name.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) ListAliases(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListAliasesInput]) (Out[apitypes.KeysListAliasesOutput], error) {
	return Out[apitypes.KeysListAliasesOutput]{}, notImplemented("keys.listAliases")
}

// ListGrants is POST {basePath}/keys/listGrants. The key's grants, newest first, each with active (not lapsed).
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) ListGrants(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListGrantsInput]) (Out[apitypes.KeysListGrantsOutput], error) {
	return Out[apitypes.KeysListGrantsOutput]{}, notImplemented("keys.listGrants")
}

// ListVersions is POST {basePath}/keys/listVersions. The key's versions, newest first, with their origin (create, rotate or automatic) and, for asymmetric keys, a fingerprint of the public key.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) ListVersions(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListVersionsInput]) (Out[apitypes.KeysListVersionsOutput], error) {
	return Out[apitypes.KeysListVersionsOutput]{}, notImplemented("keys.listVersions")
}

// PublicKey is POST {basePath}/keys/publicKey. The public key of an asymmetric key version (the current one by default), as SPKI PEM and as a JWK whose kid is {keyId}.{version}. Anyone holding it can verify signatures without calling IAM.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) PublicKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysPublicKeyInput]) (Out[apitypes.KeysPublicKeyOutput], error) {
	return Out[apitypes.KeysPublicKeyOutput]{}, notImplemented("keys.publicKey")
}

// ReEncrypt is POST {basePath}/keys/reEncrypt. Decrypts a ciphertext and encrypts it again under another key or context, without the plaintext leaving the server.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) ReEncrypt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysReEncryptInput]) (Out[apitypes.KeysReEncryptOutput], error) {
	return Out[apitypes.KeysReEncryptOutput]{}, notImplemented("keys.reEncrypt")
}

// RetireGrant is POST {basePath}/keys/retireGrant. Gives up a grant made to the caller's own identity. It needs no permission, so a workload can drop access it no longer uses.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) RetireGrant(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysRetireGrantInput]) (Out[apitypes.KeysRetireGrantOutput], error) {
	return Out[apitypes.KeysRetireGrantOutput]{}, notImplemented("keys.retireGrant")
}

// RevokeGrant is POST {basePath}/keys/revokeGrant. Revokes a grant.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) RevokeGrant(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysRevokeGrantInput]) (Out[apitypes.KeysRevokeGrantOutput], error) {
	return Out[apitypes.KeysRevokeGrantOutput]{}, notImplemented("keys.revokeGrant")
}

// Rotate is POST {basePath}/keys/rotate. Creates a new version on demand. The new version encrypts, signs and computes MACs from now on, and older versions keep decrypting and verifying.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Rotate(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysRotateInput]) (Out[apitypes.KeysRotateOutput], error) {
	return Out[apitypes.KeysRotateOutput]{}, notImplemented("keys.rotate")
}

// ScheduleDeletion is POST {basePath}/keys/scheduleDeletion. Schedules the key's destruction after a waiting period of 7 to 30 days (30 by default). The key is unusable while it waits.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) ScheduleDeletion(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysScheduleDeletionInput]) (Out[apitypes.KeysScheduleDeletionOutput], error) {
	return Out[apitypes.KeysScheduleDeletionOutput]{}, notImplemented("keys.scheduleDeletion")
}

// Sign is POST {basePath}/keys/sign. Signs a message (message or messageBase64, up to 64 KiB) with the key's current version. algorithm defaults to the key's first (ES256, ES384, EdDSA, or PS256 for RSA).
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Sign(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysSignInput]) (Out[apitypes.KeysSignOutput], error) {
	return Out[apitypes.KeysSignOutput]{}, notImplemented("keys.sign")
}

// SignJwt is POST {basePath}/keys/signJwt. Signs a JWT with a signing key or a MAC key. The header is { alg, kid, typ } with kid = {keyId}.{version} (the same kid as in jwks).
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) SignJwt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysSignJwtInput]) (Out[apitypes.KeysSignJwtOutput], error) {
	return Out[apitypes.KeysSignJwtOutput]{}, notImplemented("keys.signJwt")
}

// Update is POST {basePath}/keys/update. Changes the description, replaces the tags, or sets or clears (null) the automatic rotation period.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysUpdateInput]) (Out[apitypes.KeysUpdateOutput], error) {
	return Out[apitypes.KeysUpdateOutput]{}, notImplemented("keys.update")
}

// UpdateAlias is POST {basePath}/keys/updateAlias. Points an alias at another key of the same kind and usage, so applications that name the alias switch keys without a deploy.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) UpdateAlias(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysUpdateAliasInput]) (Out[apitypes.KeysUpdateAliasOutput], error) {
	return Out[apitypes.KeysUpdateAliasOutput]{}, notImplemented("keys.updateAlias")
}

// Verify is POST {basePath}/keys/verify. Checks a signature from sign with the given keyVersion (the current one by default). Returns { valid }: a mismatch is not an error.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysVerifyInput]) (Out[apitypes.KeysVerifyOutput], error) {
	return Out[apitypes.KeysVerifyOutput]{}, notImplemented("keys.verify")
}

// VerifyJwt is POST {basePath}/keys/verifyJwt. Verifies a JWT made with a key.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) VerifyJwt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysVerifyJwtInput]) (Out[apitypes.KeysVerifyJwtOutput], error) {
	return Out[apitypes.KeysVerifyJwtOutput]{}, notImplemented("keys.verifyJwt")
}

// VerifyMac is POST {basePath}/keys/verifyMac. Checks a MAC in constant time with the given keyVersion (the current one by default). Returns { valid }.
//
// STUB: returns NOT_IMPLEMENTED until api/keys.ts is ported.
func (api *KeysAPI) VerifyMac(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysVerifyMacInput]) (Out[apitypes.KeysVerifyMacOutput], error) {
	return Out[apitypes.KeysVerifyMacOutput]{}, notImplemented("keys.verifyMac")
}

// KmsRuntime is api/keys.ts createKmsRuntime().
type KmsRuntime struct {
	server *ServerContext
}

// Maintain (api/keys.ts createKmsRuntime().maintain): Automatic rotation, destruction after the deletion waiting
// period, and grant cleanup (run hourly).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *KmsRuntime) Maintain(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/keys.ts createKmsRuntime().maintain")
	return
}

// CreateKmsRuntime builds the KmsRuntime (api/keys.ts createKmsRuntime). Its methods are stubs until the module is ported.
func CreateKmsRuntime(server *ServerContext) *KmsRuntime {
	return &KmsRuntime{server: server}
}
