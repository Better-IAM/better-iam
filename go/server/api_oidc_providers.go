package server

// Port of packages/server/src/api/oidc-providers.ts: the `oidcProviders` group, tenant-managed OIDC identity
// providers whose tokens web-identity trusts admit. Every provider records its creator's grant authority, which bounds
// each web-identity session through it; it is edited only under that authority (or by root). Creating and changing
// providers needs `sts.webIdentity.enabled`, except an update that only disables one; reading, deleting and revoking
// sessions keep working when the feature is off.

import (
	"context"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// oidcFeatureDisabled is api/oidc-providers.ts featureDisabled.
func oidcFeatureDisabled() *core.IamError {
	return core.NewIamError("FEATURE_DISABLED", "Web identity federation is not enabled", 403)
}

// oidcUpdatableFields is api/oidc-providers.ts updatableFields.
var oidcUpdatableFields = []string{"name", "audiences", "jwksUri", "jwks", "algorithms", "maxTokenLifetimeSeconds",
	"clockToleranceSeconds", "replayProtection", "enabled"}

// oidcVerificationFields is api/oidc-providers.ts verificationFields: the settings a token's acceptance depends on
// (keys, algorithms, audiences, lifetime and skew). An update that changes any of them ends the sessions issued under
// the old ones, as `trust.update` does when a trust tightens.
var oidcVerificationFields = []string{"audiences", "jwksUri", "jwks", "algorithms", "maxTokenLifetimeSeconds", "clockToleranceSeconds"}

// oidcIssuerKey is api/oidc-providers.ts issuerKey: the provider's natural key within its tenant, `issuer:{issuer}`.
// Stored keys are limited to 512 bytes, so an issuer too long for that is keyed by its SHA-256 instead; both forms are
// deterministic, so duplicates still collide.
func oidcIssuerKey(issuer string) string {
	key := "issuer:" + issuer
	if len(utf8Bytes(key)) <= 512 {
		return key
	}
	return "issuer#sha256:" + Hash(issuer)
}

// ToPublicOidcProvider (api/oidc-providers.ts publicOidcProvider): an OIDC provider as the API returns it, an explicit
// allowlist projection (static keys are public members only, as validated when they were stored).
func ToPublicOidcProvider(provider *core.Object) *core.Object {
	replayProtection := "single-use"
	if provider.Get("replayProtection") == "off" {
		replayProtection = "off"
	}
	result := core.NewObject(
		"id", provider.Get("id"),
		"tenantId", provider.Get("tenantId"),
		"name", provider.Get("name"),
		"issuer", provider.Get("issuer"),
		"audiences", core.CloneValue(provider.Get("audiences")),
		"algorithms", core.CloneValue(provider.Get("algorithms")),
		"maxTokenLifetimeSeconds", provider.Get("maxTokenLifetimeSeconds"),
		"clockToleranceSeconds", provider.Get("clockToleranceSeconds"),
		"replayProtection", replayProtection,
		"enabled", provider.Get("enabled") == true,
		"authorityId", provider.Get("authorityId"),
		"createdAt", provider.Get("createdAt"),
		"createdBy", provider.Get("createdBy"),
		"updatedAt", provider.Get("updatedAt"),
	)
	if value := provider.Get("jwksUri"); !isUndefined(value) {
		result.Set("jwksUri", value)
	}
	if value := provider.Get("jwks"); !isUndefined(value) {
		result.Set("jwks", core.CloneValue(value))
	}
	if value := provider.Get("sessionsRevokedBefore"); !isUndefined(value) {
		result.Set("sessionsRevokedBefore", value)
	}
	return result
}

// oidcReplayProtectionValue is api/oidc-providers.ts replayProtectionValue.
func oidcReplayProtectionValue(value any) (string, error) {
	if value != "single-use" && value != "off" {
		return "", invalidInput("replayProtection must be 'single-use' or 'off'")
	}
	return value.(string), nil
}

// oidcEnabledValue is api/oidc-providers.ts enabledValue.
func oidcEnabledValue(value any) (bool, error) {
	enabled, ok := value.(bool)
	if !ok {
		return false, invalidInput("enabled must be a boolean")
	}
	return enabled, nil
}

// deleteProviderSessions is api/oidc-providers.ts deleteProviderSessions: deletes the provider's web-identity
// sessions created before createdBefore, across every trust that uses it.
func deleteProviderSessions(ctx context.Context, tx core.IamStore, provider *core.Object, createdBefore float64) (float64, error) {
	revoked := 0.0
	trusts, err := tx.Find(ctx, "trusts", core.NewObject("tenantId", provider.Get("tenantId"), "providerId", provider.Get("id")), nil)
	if err != nil {
		return 0, err
	}
	for _, trust := range trusts {
		roleID, ok := trust.Get("roleId").(string)
		if !strictEquals(trust.Get("providerId"), provider.Get("id")) || !ok {
			continue
		}
		count, err := DeleteTemporarySessions(ctx, tx, core.NewObject(
			"tenantId", provider.Get("tenantId"), "roleId", roleID, "trustId", trust.Get("id"),
			"providerId", provider.Get("id"), "createdBefore", createdBefore,
		))
		if err != nil {
			return 0, err
		}
		revoked += count
	}
	return revoked, nil
}

// OidcProvidersAPI is the `oidcProviders` API group (packages/server/src/api/oidc-providers.ts createOidcProvidersApi): every method runs through the
// operation envelope; the router maps POST {basePath}/oidcProviders/{method} onto it.
type OidcProvidersAPI struct {
	server *ServerContext
}

// CreateOidcProvidersAPI builds the `oidcProviders` API group.
func CreateOidcProvidersAPI(server *ServerContext) *OidcProvidersAPI {
	return &OidcProvidersAPI{server: server}
}

// issuerValue is the issuer rules: https (loopback http in development), not IAM's own issuer, and on the
// deployment's pin list.
func (api *OidcProvidersAPI) issuerValue(value any) (string, error) {
	settings := api.server.Config.Sts.WebIdentity
	defaultIssuer := api.server.Config.BaseOrigin() + api.server.Config.BasePath
	selfIssuer := defaultIssuer
	if api.server.SessionTokens != nil {
		selfIssuer = api.server.SessionTokens.Issuer
	}
	for _, issuer := range unique([]string{selfIssuer, defaultIssuer}) {
		self := issuer
		if _, err := WebIdentityIssuer(value, WebIdentityIssuerOptions{
			AllowInsecureLocalhost: settings.AllowInsecureLocalhost, SelfIssuer: &self, AllowedIssuers: settings.AllowedIssuers,
		}); err != nil {
			return "", err
		}
	}
	issuer, _ := value.(string)
	return issuer, nil
}

func (api *OidcProvidersAPI) jwksURIValue(value any) (string, error) {
	settings := api.server.Config.Sts.WebIdentity
	return WebIdentityJwksURI(value, core.NewObject(
		"allowInsecureLocalhost", settings.AllowInsecureLocalhost, "allowPrivateNetworks", settings.AllowPrivateNetworks,
	))
}

func oidcLifetimeValue(value any) (float64, error) {
	return Integer(value, "maxTokenLifetimeSeconds", 60, 86400)
}

func oidcToleranceValue(value any) (float64, error) {
	return Integer(value, "clockToleranceSeconds", 0, 120)
}

// forget drops cached keys once a change is committed, so the next token is checked against the new settings.
func (api *OidcProvidersAPI) forget(providerID string) error {
	if api.server.WebIdentity == nil {
		return nil
	}
	return api.server.WebIdentity.Forget(providerID)
}

// Create is POST {basePath}/oidcProviders/create. Registers an OIDC provider (iam:oidc-providers:create on the
// tenant, recent authentication, web identity enabled). The issuer must be https, not IAM's own, and on
// `sts.webIdentity.allowedIssuers` when that is set; static keys must be public signature keys. One provider per
// issuer and tenant (CONFLICT otherwise). Nothing is fetched now: keys are fetched (or discovered) when a token first
// needs them.
func (api *OidcProvidersAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersCreateInput]) (Out[apitypes.OidcProvidersCreateOutput], error) {
	fail := func(err error) (Out[apitypes.OidcProvidersCreateOutput], error) {
		return Out[apitypes.OidcProvidersCreateOutput]{}, err
	}
	server := api.server
	if !server.Config.Sts.WebIdentity.Enabled {
		return fail(oidcFeatureDisabled())
	}
	name, err := Text(input.Get("name"), "name", 128)
	if err != nil {
		return fail(err)
	}
	issuer, err := api.issuerValue(input.Get("issuer"))
	if err != nil {
		return fail(err)
	}
	audiences, err := WebIdentityAudiences(input.Get("audiences"))
	if err != nil {
		return fail(err)
	}
	var jwksURI any = core.Undefined
	if given := input.Get("jwksUri"); !isUndefined(given) {
		value, err := api.jwksURIValue(given)
		if err != nil {
			return fail(err)
		}
		jwksURI = value
	}
	var jwks any = core.Undefined
	if given := input.Get("jwks"); !isUndefined(given) {
		value, err := WebIdentityKeys(given)
		if err != nil {
			return fail(err)
		}
		jwks = value
	}
	if !isUndefined(jwksURI) && !isUndefined(jwks) {
		return fail(invalidInput("Give jwks or jwksUri, not both"))
	}
	algorithms, err := WebIdentityWebIdentityAlgorithms(input.Get("algorithms"))
	if err != nil {
		return fail(err)
	}
	maxTokenLifetimeSeconds := 3600.0
	if given := input.Get("maxTokenLifetimeSeconds"); !isUndefined(given) {
		if maxTokenLifetimeSeconds, err = oidcLifetimeValue(given); err != nil {
			return fail(err)
		}
	}
	clockToleranceSeconds := 30.0
	if given := input.Get("clockToleranceSeconds"); !isUndefined(given) {
		if clockToleranceSeconds, err = oidcToleranceValue(given); err != nil {
			return fail(err)
		}
	}
	replayProtection := "single-use"
	if given := input.Get("replayProtection"); !isUndefined(given) {
		if replayProtection, err = oidcReplayProtectionValue(given); err != nil {
			return fail(err)
		}
	}
	enabled := true
	if given := input.Get("enabled"); !isUndefined(given) {
		if enabled, err = oidcEnabledValue(given); err != nil {
			return fail(err)
		}
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:oidc-providers:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		uniqueKey := oidcIssuerKey(issuer)
		existing, err := tx.Find(ctx, "oidcProviders", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return nil, core.NewIamError("CONFLICT", "A provider for this issuer already exists", 409)
		}
		authority, err := server.GrantingAuthority(ctx, tx, call.Principal, jsString(tenantID), "")
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		provider := core.NewObject(
			"id", ID(), "tenantId", tenantID, "uniqueKey", uniqueKey, "name", name, "issuer", issuer,
			"audiences", stringsOf(audiences), "algorithms", stringsOf(algorithms),
			"maxTokenLifetimeSeconds", maxTokenLifetimeSeconds, "clockToleranceSeconds", clockToleranceSeconds,
			"replayProtection", replayProtection, "enabled", enabled, "authorityId", authority.Get("id"),
			"createdAt", now, "createdBy", call.Principal.Identity.Get("id"), "updatedAt", now,
		)
		if !isUndefined(jwksURI) {
			provider.Set("jwksUri", jwksURI)
		}
		if !isUndefined(jwks) {
			provider.Set("jwks", jwks)
		}
		stored, err := tx.Insert(ctx, "oidcProviders", provider)
		if err != nil {
			return nil, err
		}
		return ToPublicOidcProvider(stored), nil
	}, false)
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.OidcProvidersCreateOutput]{Value: result}, nil
}

// Delete is POST {basePath}/oidcProviders/delete. Deletes a provider (iam:oidc-providers:delete, recent
// authentication, the creator's authority or root). Refused with CONFLICT while unrevoked trusts reference it;
// revoking those trusts has already ended their sessions.
func (api *OidcProvidersAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersDeleteInput]) (Out[apitypes.OidcProvidersDeleteOutput], error) {
	server := api.server
	providerID, err := Text(input.Get("providerId"), "providerId")
	if err != nil {
		return Out[apitypes.OidcProvidersDeleteOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:oidc-providers:delete", providerID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		provider, err := server.Scoped(ctx, tx, "oidcProviders", providerID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := server.CanEditGrantResource(ctx, tx, call.Principal, provider); err != nil {
			return nil, err
		}
		trusts, err := tx.Find(ctx, "trusts", core.NewObject("tenantId", tenantID, "providerId", providerID), nil)
		if err != nil {
			return nil, err
		}
		for _, trust := range trusts {
			if strictEquals(trust.Get("providerId"), provider.Get("id")) && trust.Get("revoked") != true {
				return nil, core.NewIamError("CONFLICT", "Revoke the trusts that use this provider first", 409)
			}
		}
		if err := tx.Delete(ctx, "oidcProviders", jsString(provider.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	if err != nil {
		return Out[apitypes.OidcProvidersDeleteOutput]{}, err
	}
	if err := api.forget(providerID); err != nil {
		return Out[apitypes.OidcProvidersDeleteOutput]{}, err
	}
	return Out[apitypes.OidcProvidersDeleteOutput]{Value: result}, nil
}

// Get is POST {basePath}/oidcProviders/get. Returns one provider (iam:oidc-providers:read on the provider).
func (api *OidcProvidersAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersGetInput]) (Out[apitypes.OidcProvidersGetOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:oidc-providers:read", jsString(input.Get("providerId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		provider, err := server.Scoped(ctx, call.Tx, "oidcProviders", input.Get("providerId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return ToPublicOidcProvider(provider), nil
	}, false)
	return Out[apitypes.OidcProvidersGetOutput]{Value: result}, err
}

// List is POST {basePath}/oidcProviders/list. Lists the tenant's OIDC providers, oldest first
// (iam:oidc-providers:read on the tenant).
func (api *OidcProvidersAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersListInput]) (Out[apitypes.OidcProvidersListOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:oidc-providers:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		providers, err := call.Tx.Find(ctx, "oidcProviders", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(providers, func(i, j int) bool {
			a, b := providers[i], providers[j]
			if difference := jsNumber(a.Get("createdAt")) - jsNumber(b.Get("createdAt")); difference != 0 && !math.IsNaN(difference) {
				return difference < 0
			}
			return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		result := make([]any, len(providers))
		for index, provider := range providers {
			result[index] = ToPublicOidcProvider(provider)
		}
		return result, nil
	}, false)
	return Out[apitypes.OidcProvidersListOutput]{Value: result}, err
}

// RevokeSessions is POST {basePath}/oidcProviders/revokeSessions. Revokes the web-identity sessions issued through
// this provider before `before` (default: every session so far): moves the provider's `sessionsRevokedBefore`
// watermark forward and deletes the matching rows of every trust that uses it. Requires iam:roles:revoke-sessions on
// the provider and recent authentication; it only removes access, so it is delegable and works while the feature is
// off. Audited as `role:sessions-revoked`.
func (api *OidcProvidersAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersRevokeSessionsInput]) (Out[apitypes.OidcProvidersRevokeSessionsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:roles:revoke-sessions", jsString(input.Get("providerId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		provider, err := server.Scoped(ctx, tx, "oidcProviders", input.Get("providerId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		sessionsRevokedBefore, err := NextWatermark(provider.Get("sessionsRevokedBefore"), input.Get("before"), float64(server.Now()))
		if err != nil {
			return nil, err
		}
		// updatedAt stays: it versions the provider's key settings, which have not changed.
		if _, err := tx.Put(ctx, "oidcProviders", provider.Spread(core.NewObject("sessionsRevokedBefore", sessionsRevokedBefore))); err != nil {
			return nil, err
		}
		revoked, err := deleteProviderSessions(ctx, tx, provider, sessionsRevokedBefore)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, call.Principal, "role:sessions-revoked", jsString(tenantID), jsString(provider.Get("id")),
			"allow", false, core.NewObject("sessionsRevokedBefore", sessionsRevokedBefore, "revoked", revoked)); err != nil {
			return nil, err
		}
		return core.NewObject("providerId", provider.Get("id"), "sessionsRevokedBefore", sessionsRevokedBefore, "revoked", revoked), nil
	}, false)
	return Out[apitypes.OidcProvidersRevokeSessionsOutput]{Value: result}, err
}

// stringifiedOrNull is JSON.stringify(value ?? null).
func stringifiedOrNull(value any) string {
	text, _, _ := core.Stringify(coalesce(value, nil))
	return text
}

// Update is POST {basePath}/oidcProviders/update. Changes a provider (iam:oidc-providers:update on the provider,
// recent authentication, the creator's authority or root). The issuer cannot change. Needs web identity enabled
// unless the update only disables the provider, which stays possible as a kill switch: a disabled provider admits no
// exchanges, and the sessions issued through it so far end for good (re-enabling it does not bring them back). Cached
// keys are dropped. Disabling, or changing the keys (`jwks`, `jwksUri`), algorithms, audiences,
// `maxTokenLifetimeSeconds` or `clockToleranceSeconds`, ends the sessions issued through the provider so far: its
// `sessionsRevokedBefore` watermark moves forward and their rows are deleted. An update that changes nothing is
// INVALID_INPUT.
func (api *OidcProvidersAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.OidcProvidersUpdateInput]) (Out[apitypes.OidcProvidersUpdateOutput], error) {
	fail := func(err error) (Out[apitypes.OidcProvidersUpdateOutput], error) {
		return Out[apitypes.OidcProvidersUpdateOutput]{}, err
	}
	server := api.server
	var changed []string
	for _, field := range oidcUpdatableFields {
		if !isUndefined(input.Get(field)) {
			changed = append(changed, field)
		}
	}
	onlyDisables := len(changed) == 1 && changed[0] == "enabled" && input.Get("enabled") == false
	if !server.Config.Sts.WebIdentity.Enabled && !onlyDisables {
		return fail(oidcFeatureDisabled())
	}
	if !isUndefined(input.Get("issuer")) {
		return fail(invalidInput("The issuer of a provider cannot change"))
	}
	providerID, err := Text(input.Get("providerId"), "providerId")
	if err != nil {
		return fail(err)
	}
	tenantID := input.Get("tenantId")
	updated, err := Operate(ctx, server.Operations, credential, tenantID, "iam:oidc-providers:update", providerID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		provider, err := server.Scoped(ctx, tx, "oidcProviders", providerID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := server.CanEditGrantResource(ctx, tx, call.Principal, provider); err != nil {
			return nil, err
		}
		next := provider.Spread()
		if given := input.Get("name"); !isUndefined(given) {
			name, err := Text(given, "name", 128)
			if err != nil {
				return nil, err
			}
			next.Set("name", name)
		}
		if given := input.Get("audiences"); !isUndefined(given) {
			audiences, err := WebIdentityAudiences(given)
			if err != nil {
				return nil, err
			}
			next.Set("audiences", stringsOf(audiences))
		}
		if given := input.Get("jwksUri"); given == nil {
			next.Delete("jwksUri")
		} else if !isUndefined(given) {
			uri, err := api.jwksURIValue(given)
			if err != nil {
				return nil, err
			}
			next.Set("jwksUri", uri)
		}
		if given := input.Get("jwks"); given == nil {
			next.Delete("jwks")
		} else if !isUndefined(given) {
			keys, err := WebIdentityKeys(given)
			if err != nil {
				return nil, err
			}
			next.Set("jwks", keys)
		}
		if !isUndefined(next.Get("jwksUri")) && !isUndefined(next.Get("jwks")) {
			return nil, invalidInput("Give jwks or jwksUri, not both")
		}
		if given := input.Get("algorithms"); !isUndefined(given) {
			algorithms, err := WebIdentityWebIdentityAlgorithms(given)
			if err != nil {
				return nil, err
			}
			next.Set("algorithms", stringsOf(algorithms))
		}
		if given := input.Get("maxTokenLifetimeSeconds"); !isUndefined(given) {
			value, err := oidcLifetimeValue(given)
			if err != nil {
				return nil, err
			}
			next.Set("maxTokenLifetimeSeconds", value)
		}
		if given := input.Get("clockToleranceSeconds"); !isUndefined(given) {
			value, err := oidcToleranceValue(given)
			if err != nil {
				return nil, err
			}
			next.Set("clockToleranceSeconds", value)
		}
		if given := input.Get("replayProtection"); !isUndefined(given) {
			value, err := oidcReplayProtectionValue(given)
			if err != nil {
				return nil, err
			}
			next.Set("replayProtection", value)
		}
		if given := input.Get("enabled"); !isUndefined(given) {
			value, err := oidcEnabledValue(given)
			if err != nil {
				return nil, err
			}
			next.Set("enabled", value)
		}
		if core.MustStringify(next) == core.MustStringify(provider) {
			return nil, invalidInput("The update changes nothing")
		}
		now := float64(server.Now())
		// Sessions verified under the old keys or claim rules would outlive them, so they end: the watermark
		// covers concurrent issuance, and the matching rows are deleted. Disabling is a kill switch and ends them
		// the same way (also with the feature off), so re-enabling the provider cannot bring them back.
		endsSessions := provider.Get("enabled") == true && next.Get("enabled") != true
		for _, field := range oidcVerificationFields {
			if !endsSessions && stringifiedOrNull(provider.Get(field)) != stringifiedOrNull(next.Get(field)) {
				endsSessions = true
			}
		}
		if endsSessions {
			watermark, err := NextWatermark(provider.Get("sessionsRevokedBefore"), core.Undefined, now)
			if err != nil {
				return nil, err
			}
			next.Set("sessionsRevokedBefore", watermark)
		}
		next.Set("updatedAt", now)
		stored, err := tx.Put(ctx, "oidcProviders", next)
		if err != nil {
			return nil, err
		}
		if endsSessions {
			if _, err := deleteProviderSessions(ctx, tx, stored, jsNumber(next.Get("sessionsRevokedBefore"))); err != nil {
				return nil, err
			}
		}
		return ToPublicOidcProvider(stored), nil
	}, false)
	if err != nil {
		return fail(err)
	}
	if err := api.forget(jsString(updated.Get("id"))); err != nil {
		return fail(err)
	}
	return Out[apitypes.OidcProvidersUpdateOutput]{Value: updated}, nil
}
