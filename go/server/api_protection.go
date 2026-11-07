package server

// Skeleton of packages/server/src/api/protection.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ProtectionAPI is the `protection` API group (packages/server/src/api/protection.ts createProtectionApi): every method runs through the
// operation envelope; the router maps POST {basePath}/protection/{method} onto it.
type ProtectionAPI struct {
	server *ServerContext
}

// CreateProtectionAPI builds the `protection` API group.
func CreateProtectionAPI(server *ServerContext) *ProtectionAPI {
	return &ProtectionAPI{server: server}
}

// CreateProfile is POST {basePath}/protection/createProfile. Creates a tokenization profile, with an existing tenant AES key the caller may use (keyId) or a new one.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) CreateProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionCreateProfileInput]) (Out[apitypes.ProtectionCreateProfileOutput], error) {
	return Out[apitypes.ProtectionCreateProfileOutput]{}, notImplemented("protection.createProfile")
}

// DeleteProfile is POST {basePath}/protection/deleteProfile. Deletes a profile that holds no tokens. A key the profile created is scheduled for deletion after 7 days.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) DeleteProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionDeleteProfileInput]) (Out[apitypes.ProtectionDeleteProfileOutput], error) {
	return Out[apitypes.ProtectionDeleteProfileOutput]{}, notImplemented("protection.deleteProfile")
}

// DeleteTokens is POST {basePath}/protection/deleteTokens. Deletes tokens and their values for good, named by tokens or by values. Erasing by value finds every token issued for it, even in profiles that are not deterministic.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) DeleteTokens(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionDeleteTokensInput]) (Out[apitypes.ProtectionDeleteTokensOutput], error) {
	return Out[apitypes.ProtectionDeleteTokensOutput]{}, notImplemented("protection.deleteTokens")
}

// Detokenize is POST {basePath}/protection/detokenize. Turns up to 100 tokens of the profile back into their values, in order, with null for tokens the profile does not hold. purpose is required: a short lowercase name such as payment-processing.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) Detokenize(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionDetokenizeInput]) (Out[apitypes.ProtectionDetokenizeOutput], error) {
	return Out[apitypes.ProtectionDetokenizeOutput]{}, notImplemented("protection.detokenize")
}

// GetProfile is POST {basePath}/protection/getProfile. One profile, with the number of tokens it holds.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) GetProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionGetProfileInput]) (Out[apitypes.ProtectionGetProfileOutput], error) {
	return Out[apitypes.ProtectionGetProfileOutput]{}, notImplemented("protection.getProfile")
}

// ListProfiles is POST {basePath}/protection/listProfiles. The tenant's profiles the caller may read, by name.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) ListProfiles(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionListProfilesInput]) (Out[apitypes.ProtectionListProfilesOutput], error) {
	return Out[apitypes.ProtectionListProfilesOutput]{}, notImplemented("protection.listProfiles")
}

// Mask is POST {basePath}/protection/mask. The masked form of up to 100 tokens' values (4242, j@example.com), with the profile's mask or a style its data type allows (last4, first6last4 for cards, email for email addresses, full).
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) Mask(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionMaskInput]) (Out[apitypes.ProtectionMaskOutput], error) {
	return Out[apitypes.ProtectionMaskOutput]{}, notImplemented("protection.mask")
}

// Tokenize is POST {basePath}/protection/tokenize. Replaces up to 100 values by tokens, in order. Values are validated and normalized for the data type (text to Unicode NFC; a card number must pass the Luhn check).
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) Tokenize(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionTokenizeInput]) (Out[apitypes.ProtectionTokenizeOutput], error) {
	return Out[apitypes.ProtectionTokenizeOutput]{}, notImplemented("protection.tokenize")
}

// UpdateProfile is POST {basePath}/protection/updateProfile. Changes the description, the mask, or the retention (retentionDays: null keeps tokens until they are deleted). The data type, format and key never change.
//
// STUB: returns NOT_IMPLEMENTED until api/protection.ts is ported.
func (api *ProtectionAPI) UpdateProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionUpdateProfileInput]) (Out[apitypes.ProtectionUpdateProfileOutput], error) {
	return Out[apitypes.ProtectionUpdateProfileOutput]{}, notImplemented("protection.updateProfile")
}

// ProtectionRuntime is api/protection.ts createProtectionRuntime().
type ProtectionRuntime struct {
	server *ServerContext
}

// Sweep (api/protection.ts createProtectionRuntime().sweep): Deletes tokens older than their profile's
// `retentionDays` (run daily).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *ProtectionRuntime) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/protection.ts createProtectionRuntime().sweep")
	return
}

// CreateProtectionRuntime builds the ProtectionRuntime (api/protection.ts createProtectionRuntime). Its methods are stubs until the module is ported.
func CreateProtectionRuntime(server *ServerContext) *ProtectionRuntime {
	return &ProtectionRuntime{server: server}
}
