package server

// Port of packages/server/src/api/ldap.ts: the `ldap` API group, each tenant's LDAP directory gateway.
// Administrators turn it on under a base DN and choose what it publishes (`iam:ldap:manage`, `iam:ldap:read`); the
// gateway (`@better-iam/ldap`) reads the directory as the account that bound, which sees everyone with
// `iam:ldap:read` and otherwise only itself.

import (
	"context"
	"regexp"

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

// ldapAttributeName is a declared identity attribute LDAP can publish.
var ldapAttributeName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)

// ldapBooleanSettings are the boolean settings updateSettings takes, in the TypeScript order.
var ldapBooleanSettings = []string{"enabled", "peopleBind", "serviceBind", "requireTls", "includeServiceAccounts"}

// ldapSettingsView is the settings as the API answers them (api/ldap.ts view).
func ldapSettingsView(settings *core.Object) *core.Object {
	view := core.NewObject(
		"tenantId", settings.Get("tenantId"), "enabled", settings.Get("enabled"), "baseDn", settings.Get("baseDn"),
		"uid", settings.Get("uid"), "peopleBind", settings.Get("peopleBind"), "serviceBind", settings.Get("serviceBind"),
		"requireTls", settings.Get("requireTls"), "mfaSuffix", settings.Get("mfaSuffix"),
		"includeServiceAccounts", settings.Get("includeServiceAccounts"), "attributes", settings.Get("attributes"),
		"groups", settings.Get("groups"), "groupIds", settings.Get("groupIds"),
	)
	if truthy(settings.Get("updatedAt")) {
		view.Set("updatedAt", settings.Get("updatedAt"))
		view.Set("updatedBy", settings.Get("updatedBy"))
	}
	return view
}

// Directory is POST {basePath}/ldap/directory. The directory as the caller may read it: active people, published
// groups with their members and, when listed, service accounts and agents. With iam:ldap:read on
// `iam/ldap/directory` the whole published directory (audited as `ldap:directory:read`), otherwise only the caller's
// own entry and groups.
func (api *LdapAPI) Directory(ctx context.Context, credential core.CredentialInput, input In[apitypes.LdapDirectoryInput]) (Out[apitypes.LdapDirectoryOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.LdapDirectoryOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.LdapDirectoryOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		settings, err := LoadLdapSettings(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if !truthy(settings.Get("enabled")) {
			return nil, core.NewIamError("FEATURE_DISABLED", "The LDAP gateway is off for this organization", 403)
		}
		if principal.Session.Get("tenantId") != tenant.Get("id") || truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("ACCESS_DENIED", "Access denied", 403)
		}
		decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
			TenantID: tenantID, Action: "iam:ldap:read", Resource: ResourceTarget{Type: "iam", ID: "ldap/directory"},
		}, true)
		if err != nil {
			return nil, err
		}
		// The platform root override does not read an organization's directory over LDAP.
		full := decision.Allowed && decision.Reason != "ROOT_OVERRIDE"
		self := principal
		if full {
			self = nil
		}
		directory, err := BuildLdapDirectory(ctx, server, tx, tenant, settings, self)
		if err != nil {
			return nil, err
		}
		if full {
			people, _ := directory.Get("people").([]any)
			groups, _ := directory.Get("groups").([]any)
			if err := server.Events.Audit(ctx, tx, principal, "ldap:directory:read", tenantID, "ldap/directory", "allow", false,
				core.NewObject("people", len(people), "groups", len(groups))); err != nil {
				return nil, err
			}
		}
		return directory, nil
	})
	return Out[apitypes.LdapDirectoryOutput]{Value: result}, err
}

// GetSettings is POST {basePath}/ldap/getSettings. The organization's gateway settings. Requires iam:ldap:read.
func (api *LdapAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.LdapGetSettingsInput]) (Out[apitypes.LdapGetSettingsOutput], error) {
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.LdapGetSettingsOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:ldap:read", "ldap/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		settings, err := LoadLdapSettings(ctx, call.Tx, call.Tenant)
		if err != nil {
			return nil, err
		}
		return ldapSettingsView(settings), nil
	}, false)
	return Out[apitypes.LdapGetSettingsOutput]{Value: result}, err
}

// UpdateSettings is POST {basePath}/ldap/updateSettings. Changes the gateway settings; fields left out keep their
// values. A base DN belongs to one organization (`LDAP_BASE_TAKEN`). Requires iam:ldap:manage.
func (api *LdapAPI) UpdateSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.LdapUpdateSettingsInput]) (Out[apitypes.LdapUpdateSettingsOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.LdapUpdateSettingsOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:ldap:manage", "ldap/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		current, err := LoadLdapSettings(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		next := current.Spread(core.NewObject("updatedAt", server.Now(), "updatedBy", call.Principal.Identity.Get("id")))
		if raw := input.Get("baseDn"); !isUndefined(raw) {
			normalized, err := NormalizeBaseDn(raw)
			if err != nil {
				return nil, err
			}
			next.Set("baseDn", normalized.Get("baseDn"))
			next.Set("normalizedBaseDn", normalized.Get("normalized"))
		}
		for _, key := range ldapBooleanSettings {
			value := input.Get(key)
			if isUndefined(value) {
				continue
			}
			if _, ok := value.(bool); !ok {
				return nil, invalidInput(key + " must be a boolean")
			}
			next.Set(key, value)
		}
		if raw := input.Get("uid"); !isUndefined(raw) {
			if raw != "email" && raw != "localPart" && raw != "id" {
				return nil, invalidInput("uid must be 'email', 'localPart' or 'id'")
			}
			next.Set("uid", raw)
		}
		if raw := input.Get("mfaSuffix"); !isUndefined(raw) {
			if raw != "auto" && raw != "never" {
				return nil, invalidInput("mfaSuffix must be 'auto' or 'never'")
			}
			next.Set("mfaSuffix", raw)
		}
		if raw := input.Get("attributes"); !isUndefined(raw) {
			list, ok := raw.([]any)
			if !ok || len(list) > 64 {
				return nil, invalidInput("attributes must list at most 64 identity attributes")
			}
			texts := make([]string, len(list))
			for index, item := range list {
				name, err := Text(item, "attribute", 64)
				if err != nil {
					return nil, err
				}
				texts[index] = name
			}
			names := unique(texts)
			for _, name := range names {
				if !server.Catalog.IdentityAttributes.Has(name) || !ldapAttributeName.MatchString(name) {
					return nil, invalidInput(name + " is not a declared identity attribute LDAP can publish")
				}
			}
			next.Set("attributes", stringsOf(names))
		}
		if raw := input.Get("groups"); !isUndefined(raw) {
			if raw != "all" && raw != "selected" {
				return nil, invalidInput("groups must be 'all' or 'selected'")
			}
			next.Set("groups", raw)
		}
		if raw := input.Get("groupIds"); !isUndefined(raw) {
			list, ok := raw.([]any)
			if !ok || len(list) > 500 {
				return nil, invalidInput("groupIds must list at most 500 groups")
			}
			texts := make([]string, len(list))
			for index, item := range list {
				groupID, err := Text(item, "groupId")
				if err != nil {
					return nil, err
				}
				texts[index] = groupID
			}
			ids := unique(texts)
			for _, groupID := range ids {
				if _, err := server.Scoped(ctx, tx, "groups", groupID, jsString(tenant.Get("id"))); err != nil {
					return nil, err
				}
			}
			next.Set("groupIds", stringsOf(ids))
		}
		saved, err := SaveLdapSettings(ctx, tx, next, current)
		if err != nil {
			return nil, err
		}
		return ldapSettingsView(saved), nil
	}, false)
	return Out[apitypes.LdapUpdateSettingsOutput]{Value: result}, err
}
