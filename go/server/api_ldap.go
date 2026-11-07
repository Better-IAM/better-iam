package server

// Skeleton of packages/server/src/api/ldap.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// LdapAPI is the `ldap` API group (packages/server/src/api/ldap.ts createLdapApi): every method runs through the
// operation envelope; the router maps POST {basePath}/ldap/{method} onto it.
type LdapAPI struct {
	server *ServerContext
}

// CreateLdapAPI builds the `ldap` API group.
func CreateLdapAPI(server *ServerContext) *LdapAPI {
	return &LdapAPI{server: server}
}

// Directory is POST {basePath}/ldap/directory. The directory as the caller may read it: active people, published groups with their members and, when listed, service accounts and agents.
//
// STUB: returns NOT_IMPLEMENTED until api/ldap.ts is ported.
func (api *LdapAPI) Directory(ctx context.Context, credential core.CredentialInput, input In[apitypes.LdapDirectoryInput]) (Out[apitypes.LdapDirectoryOutput], error) {
	return Out[apitypes.LdapDirectoryOutput]{}, notImplemented("ldap.directory")
}

// GetSettings is POST {basePath}/ldap/getSettings. The organization's gateway settings: whether it is on, its base DN, how uid is formed (email, localPart or id), who may bind (peopleBind, serviceBind), requireTls, mfaSuffix, whether service accounts…
//
// STUB: returns NOT_IMPLEMENTED until api/ldap.ts is ported.
func (api *LdapAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.LdapGetSettingsInput]) (Out[apitypes.LdapGetSettingsOutput], error) {
	return Out[apitypes.LdapGetSettingsOutput]{}, notImplemented("ldap.getSettings")
}

// UpdateSettings is POST {basePath}/ldap/updateSettings. Changes the gateway settings; fields left out keep their values. A base DN is attr=value components (letters, digits, spaces, ., or -), at most 10, compared without regard to case.
//
// STUB: returns NOT_IMPLEMENTED until api/ldap.ts is ported.
func (api *LdapAPI) UpdateSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.LdapUpdateSettingsInput]) (Out[apitypes.LdapUpdateSettingsOutput], error) {
	return Out[apitypes.LdapUpdateSettingsOutput]{}, notImplemented("ldap.updateSettings")
}
