package server

// Port of packages/server/src/api/features.ts: feature flags at platform and tenant level. The root tenant's flags
// are platform flags; any organization or project can define flags for its own subtree. A flag's value for a tenant
// comes from, in order: its kill switch, the nearest target or tenant override along the ancestry (a tenant's own
// override beats a target on the same tenant; a locked target silences overrides beneath it), a percentage rollout,
// and its default. Values reach applications through `features.evaluate` (any session of the tenant),
// `iam.features` on the server, and policy conditions through the `tenant.features` context key.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// FeaturesAPI is the `features` API group (packages/server/src/api/features.ts createFeaturesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/features/{method} onto it.
type FeaturesAPI struct {
	server *ServerContext
}

// CreateFeaturesAPI builds the `features` API group.
func CreateFeaturesAPI(server *ServerContext) *FeaturesAPI {
	return &FeaturesAPI{server: server}
}

// featureDefinition is a flag's definition as the managers of its defining tenant see it.
func featureDefinition(flag *core.Object, rootID any) *core.Object {
	scope := "tenant"
	if flag.Get("tenantId") == rootID {
		scope = "platform"
	}
	out := core.NewObject("id", flag.Get("id"), "key", flag.Get("key"), "tenantId", flag.Get("tenantId"), "scope", scope)
	if description := flag.Get("description"); !isUndefined(description) {
		out.Set("description", description)
	}
	out.Set("defaultValue", flag.Get("defaultValue"))
	if percentage := flag.Get("rolloutPercentage"); !isUndefined(percentage) {
		out.Set("rolloutPercentage", percentage)
	}
	return out.Set("tenantOverridable", flag.Get("tenantOverridable")).
		Set("killSwitch", flag.Get("killSwitch")).
		Set("internal", flag.Get("internal")).
		Set("createdAt", flag.Get("createdAt")).
		Set("createdBy", flag.Get("createdBy")).
		Set("updatedAt", flag.Get("updatedAt")).
		Set("updatedBy", flag.Get("updatedBy"))
}

// featureSettingsMetadata is the audit metadata for a flag's settings.
func featureSettingsMetadata(flag *core.Object) *core.Object {
	percentage := flag.Get("rolloutPercentage")
	if nullish(percentage) {
		percentage = nil
	}
	return core.NewObject(
		"key", flag.Get("key"),
		"defaultValue", flag.Get("defaultValue"),
		"rolloutPercentage", percentage,
		"tenantOverridable", flag.Get("tenantOverridable"),
		"killSwitch", flag.Get("killSwitch"),
		"internal", flag.Get("internal"),
	)
}

// featureRootOf is the root tenant's id: the last tenant of an ancestry.
func featureRootOf(chain []*core.Object) any {
	return chain[len(chain)-1].Get("id")
}

// featureResource is the resource id of a flag (`features/{key}`).
func featureResource(key string) string { return "features/" + key }

// featureOwnFlag is the flag the tenant itself defines with the key (NOT_FOUND otherwise).
func featureOwnFlag(ctx context.Context, tx core.IamStore, tenantID any, key string) (*core.Object, error) {
	found, err := tx.Find(ctx, FeatureCollections.Flags, core.NewObject("tenantId", tenantID, "uniqueKey", key), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Feature flag not found", 404)
	}
	return found[0], nil
}

// featureWritable refuses changes to a deleted tenant.
func featureWritable(realm *core.Object) error {
	if realm.Get("status") == "deleted" {
		return core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot be updated")
	}
	return nil
}

// featureEntryAt is the target or override a tenant holds for a flag.
func featureEntryAt(ctx context.Context, tx core.IamStore, tenantID any, flag *core.Object, source string) (*core.Object, error) {
	found, err := tx.Find(ctx, FeatureCollections.Targets, core.NewObject("tenantId", tenantID, "uniqueKey", jsString(flag.Get("id"))+":"+source), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// view is one flag as a tenant's administrators see it (`features.list`).
func (api *FeaturesAPI) view(ctx context.Context, tx core.IamStore, state *core.Object, flag *core.Object, withDefinition bool) (*core.Object, error) {
	chain, _, _ := featureStateParts(state)
	realm := chain[0]
	evaluation, err := EvaluateFlag(state, flag)
	if err != nil {
		return nil, err
	}
	own := func(source string) (*core.Object, error) {
		if flag.Get("tenantId") == realm.Get("id") {
			return nil, nil
		}
		return featureEntryAt(ctx, tx, realm.Get("id"), flag, source)
	}
	override, err := own("override")
	if err != nil {
		return nil, err
	}
	target, err := own("target")
	if err != nil {
		return nil, err
	}
	out := core.NewObject("key", flag.Get("key"))
	if description := flag.Get("description"); !isUndefined(description) {
		out.Set("description", description)
	}
	out.Set("scope", evaluation.Get("scope")).Set("definedBy", flag.Get("tenantId"))
	if withDefinition {
		out.Set("definition", featureDefinition(flag, featureRootOf(chain)))
	}
	out.Set("tenantOverridable", flag.Get("tenantOverridable")).Set("evaluation", evaluation)
	if override != nil {
		out.Set("override", core.NewObject("value", override.Get("value"), "setAt", override.Get("setAt"), "setBy", override.Get("setBy")))
	}
	if target != nil {
		pinned := core.NewObject("value", target.Get("value"), "locked", target.Get("locked") == true)
		if expiresAt := target.Get("expiresAt"); !isUndefined(expiresAt) {
			pinned.Set("expiresAt", expiresAt)
		}
		out.Set("target", pinned)
	}
	return out, nil
}

// featureSettingsInput is the settings input without the addressing fields.
func featureSettingsInput(input *core.Object) (*core.Object, error) {
	checked, err := Object(input)
	if err != nil {
		return nil, err
	}
	rest := core.NewObject()
	checked.Entries(func(key string, value any) bool {
		if key != "tenantId" && key != "key" {
			rest.SetRaw(key, value)
		}
		return true
	})
	return rest, nil
}

// audit records a flag change in the tenant.
func (api *FeaturesAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action string, tenantID any, key string, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, jsString(tenantID), featureResource(key), "allow", false, metadata)
}

// List is POST {basePath}/features/list. The flags that reach the tenant, sorted by key, each with its value for the
// tenant, the reason, and this tenant's own override and target. `definition` holds the settings of flags the tenant
// defines itself; internal flags of ancestors are left out (root administrators see everything). `shadowed` lists
// flags this tenant defines whose key an ancestor also defines: the ancestor's flag applies. Requires
// iam:features:read.
func (api *FeaturesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesListInput]) (Out[apitypes.FeaturesListOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:read", "features",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm := call.Tx, call.Tenant
			root, err := server.RootPrincipal(ctx, tx, call.Principal)
			if err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			state, err := FeatureState(ctx, tx, chain, server.Now())
			if err != nil {
				return nil, err
			}
			_, flags, _ := featureStateParts(state)
			var reaching []*core.Object
			flags.Entries(func(_ string, value any) bool {
				if flag, ok := value.(*core.Object); ok {
					reaching = append(reaching, flag)
				}
				return true
			})
			sortStable(reaching, byFeatureKey)
			views := []any{}
			for _, flag := range reaching {
				definedHere := flag.Get("tenantId") == realm.Get("id")
				if truthy(flag.Get("internal")) && !definedHere && !root {
					continue
				}
				view, err := api.view(ctx, tx, state, flag, definedHere || root)
				if err != nil {
					return nil, err
				}
				views = append(views, view)
			}
			var own []*core.Object
			if list, ok := state.Get("shadowed").([]any); ok {
				for _, item := range list {
					if flag, ok := item.(*core.Object); ok && flag.Get("tenantId") == realm.Get("id") {
						own = append(own, flag)
					}
				}
			}
			sortStable(own, byFeatureKey)
			shadowed := make([]any, len(own))
			for index, flag := range own {
				shadowed[index] = featureDefinition(flag, featureRootOf(chain))
			}
			return core.NewObject("tenantId", realm.Get("id"), "flags", views, "shadowed", shadowed), nil
		}, false)
	return Out[apitypes.FeaturesListOutput]{Value: result}, err
}

// Create is POST {basePath}/features/create. Defines a flag in the tenant: on the root tenant a platform flag,
// elsewhere a flag for the tenant's subtree. Keys are unique per tenant and may not repeat a key an ancestor
// defines; at most 200 flags per tenant. Requires iam:features:manage on `iam/features/{key}`; audited as
// `feature:create`.
func (api *FeaturesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesCreateInput]) (Out[apitypes.FeaturesCreateOutput], error) {
	server := api.server
	key, err := FeatureKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.FeaturesCreateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:manage", featureResource(key),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := featureWritable(realm); err != nil {
				return nil, err
			}
			patch, err := featureSettingsInput(input.Body)
			if err != nil {
				return nil, err
			}
			settings, err := FeatureSettings(patch, nil)
			if err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			for _, ancestor := range chain[1:] {
				found, err := tx.Find(ctx, FeatureCollections.Flags, core.NewObject("tenantId", ancestor.Get("id"), "uniqueKey", key), nil)
				if err != nil {
					return nil, err
				}
				if len(found) > 0 {
					message := "An enclosing tenant already defines a flag with this key"
					if ancestor.Has("parentId") && ancestor.Get("parentId") == nil {
						message = "A platform flag already uses this key"
					}
					return nil, core.NewIamError("CONFLICT", message, 409)
				}
			}
			existing, err := tx.Find(ctx, FeatureCollections.Flags, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, flag := range existing {
				if flag.Get("key") == key {
					return nil, core.NewIamError("CONFLICT", "A flag with this key already exists", 409)
				}
			}
			if len(existing) >= MaxFeatureFlagsPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can define at most 200 feature flags", 409)
			}
			now := float64(server.Now())
			record := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "uniqueKey", key, "key", key).
				Assign(settings).
				Set("createdAt", now).Set("createdBy", principal.Identity.Get("id")).
				Set("updatedAt", now).Set("updatedBy", principal.Identity.Get("id"))
			flag, err := tx.Insert(ctx, FeatureCollections.Flags, record)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "feature:create", realm.Get("id"), key, featureSettingsMetadata(flag)); err != nil {
				return nil, err
			}
			return featureDefinition(flag, featureRootOf(chain)), nil
		}, false)
	return Out[apitypes.FeaturesCreateOutput]{Value: result}, err
}

// Update is POST {basePath}/features/update. Changes a flag's settings; fields left out keep their value and `null`
// clears `description` or `rolloutPercentage`. Turning `killSwitch` on switches the flag off everywhere at once.
// Requires iam:features:manage; audited as `feature:update` with the settings before and after.
func (api *FeaturesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesUpdateInput]) (Out[apitypes.FeaturesUpdateOutput], error) {
	server := api.server
	key, err := FeatureKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.FeaturesUpdateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:manage", featureResource(key),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := featureWritable(realm); err != nil {
				return nil, err
			}
			flag, err := featureOwnFlag(ctx, tx, realm.Get("id"), key)
			if err != nil {
				return nil, err
			}
			patch, err := featureSettingsInput(input.Body)
			if err != nil {
				return nil, err
			}
			settings, err := FeatureSettings(patch, flag)
			if err != nil {
				return nil, err
			}
			rest := flag.Clone()
			rest.Delete("description")
			rest.Delete("rolloutPercentage")
			next, err := tx.Put(ctx, FeatureCollections.Flags, rest.Assign(settings).
				Set("updatedAt", float64(server.Now())).Set("updatedBy", principal.Identity.Get("id")))
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "feature:update", realm.Get("id"), key, core.NewObject(
				"before", featureSettingsMetadata(flag), "after", featureSettingsMetadata(next),
			)); err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			return featureDefinition(next, featureRootOf(chain)), nil
		}, false)
	return Out[apitypes.FeaturesUpdateOutput]{Value: result}, err
}

// Delete is POST {basePath}/features/delete. Deletes a flag with every target and override set for it; code that
// still asks for the key gets `false`. Requires iam:features:manage; audited as `feature:delete`.
func (api *FeaturesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesDeleteInput]) (Out[apitypes.FeaturesDeleteOutput], error) {
	server := api.server
	key, err := FeatureKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.FeaturesDeleteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:manage", featureResource(key),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			flag, err := featureOwnFlag(ctx, tx, realm.Get("id"), key)
			if err != nil {
				return nil, err
			}
			entries, err := tx.Find(ctx, FeatureCollections.Targets, core.NewObject("flagId", flag.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if err := tx.Delete(ctx, FeatureCollections.Targets, jsString(entry.Get("id"))); err != nil {
					return nil, err
				}
			}
			if err := tx.Delete(ctx, FeatureCollections.Flags, jsString(flag.Get("id"))); err != nil {
				return nil, err
			}
			removed := float64(len(entries))
			if err := api.audit(ctx, tx, principal, "feature:delete", realm.Get("id"), key, core.NewObject("key", key, "removedTargets", removed)); err != nil {
				return nil, err
			}
			return core.NewObject("success", true, "removedTargets", removed), nil
		}, false)
	return Out[apitypes.FeaturesDeleteOutput]{Value: result}, err
}

// SetTarget is POST {basePath}/features/setTarget. Pins the flag's value for a tenant below the defining tenant
// (`tenantId`), and for that tenant's descendants unless they have a closer target or override. `locked` also keeps
// tenants in that subtree from overriding; `expiresAt` makes the target lapse by itself (a trial, a temporary
// block); `value: null` removes the target. Requires iam:features:manage in the defining tenant; audited as
// `feature:target`.
func (api *FeaturesAPI) SetTarget(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesSetTargetInput]) (Out[apitypes.FeaturesSetTargetOutput], error) {
	server := api.server
	key, err := FeatureKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.FeaturesSetTargetOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:manage", featureResource(key),
		func(ctx context.Context, call MutationContext) (any, error) {
			tx, definer, principal := call.Tx, call.Tenant, call.Principal
			flag, err := featureOwnFlag(ctx, tx, definer.Get("id"), key)
			if err != nil {
				return nil, err
			}
			targetTenantID, err := Text(input.Get("targetTenantId"), "targetTenantId")
			if err != nil {
				return nil, err
			}
			target, err := server.Tenant(ctx, tx, targetTenantID)
			if err != nil {
				return nil, err
			}
			chain, err := server.Ancestry(ctx, tx, target)
			if err != nil {
				return nil, err
			}
			below := false
			for _, realm := range chain {
				if realm.Get("id") == definer.Get("id") {
					below = true
					break
				}
			}
			if target.Get("id") == definer.Get("id") || !below {
				return nil, invalidInput("targetTenantId must be a tenant below the one that defines the flag; use defaultValue for the tenant itself")
			}
			existing, err := featureEntryAt(ctx, tx, target.Get("id"), flag, "target")
			if err != nil {
				return nil, err
			}
			value := input.Get("value")
			if value == nil {
				if existing != nil {
					if err := tx.Delete(ctx, FeatureCollections.Targets, jsString(existing.Get("id"))); err != nil {
						return nil, err
					}
				}
				if err := api.audit(ctx, tx, principal, "feature:target", definer.Get("id"), key, core.NewObject(
					"key", key, "targetTenantId", target.Get("id"), "value", nil,
				)); err != nil {
					return nil, err
				}
				return nil, nil
			}
			if err := featureWritable(target); err != nil {
				return nil, err
			}
			if _, ok := value.(bool); !ok {
				return nil, invalidInput("value must be a boolean or null")
			}
			locked := input.Get("locked")
			if _, ok := locked.(bool); !isUndefined(locked) && !ok {
				return nil, invalidInput("locked must be a boolean")
			}
			entryID := any(ID())
			if existing != nil {
				entryID = existing.Get("id")
			}
			entry := core.NewObject(
				"id", entryID,
				"tenantId", target.Get("id"),
				"uniqueKey", jsString(flag.Get("id"))+":target",
				"flagId", flag.Get("id"),
				"key", key,
				"definerId", definer.Get("id"),
				"source", "target",
				"value", value,
				"setAt", float64(server.Now()),
				"setBy", principal.Identity.Get("id"),
			)
			if locked == true {
				entry.Set("locked", true)
			}
			if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
				checked, err := server.BindingExpiry(expiresAt)
				if err != nil {
					return nil, err
				}
				entry.Set("expiresAt", checked)
			}
			if note := input.Get("note"); !isUndefined(note) {
				text, err := Text(note, "note", 512)
				if err != nil {
					return nil, err
				}
				entry.Set("note", core.JSTrim(text))
			}
			if existing != nil {
				_, err = tx.Put(ctx, FeatureCollections.Targets, entry)
			} else {
				_, err = tx.Insert(ctx, FeatureCollections.Targets, entry)
			}
			if err != nil {
				return nil, err
			}
			metadata := core.NewObject("key", key, "targetTenantId", target.Get("id"), "value", entry.Get("value"), "locked", entry.Get("locked") == true)
			if expiresAt := entry.Get("expiresAt"); !isUndefined(expiresAt) {
				metadata.Set("expiresAt", expiresAt)
			}
			if err := api.audit(ctx, tx, principal, "feature:target", definer.Get("id"), key, metadata); err != nil {
				return nil, err
			}
			view := core.NewObject(
				"id", entry.Get("id"),
				"tenantId", target.Get("id"),
				"tenantName", target.Get("name"),
				"tenantStatus", target.Get("status"),
				"source", "target",
				"value", entry.Get("value"),
				"locked", entry.Get("locked") == true,
			)
			if expiresAt := entry.Get("expiresAt"); !isUndefined(expiresAt) {
				view.Set("expiresAt", expiresAt)
			}
			view.Set("active", true)
			if note := entry.Get("note"); !isUndefined(note) {
				view.Set("note", note)
			}
			return view.Set("setAt", entry.Get("setAt")).Set("setBy", entry.Get("setBy")), nil
		}, false)
	return Out[apitypes.FeaturesSetTargetOutput]{Value: result}, err
}

// ListTargets is POST {basePath}/features/listTargets. Every target the defining tenant set for the flag and every
// override tenants below it chose, newest first, with the tenant's name and whether the entry currently counts.
// Requires iam:features:read.
func (api *FeaturesAPI) ListTargets(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesListTargetsInput]) (Out[apitypes.FeaturesListTargetsOutput], error) {
	server := api.server
	key, err := FeatureKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.FeaturesListTargetsOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:read", featureResource(key),
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, definer := call.Tx, call.Tenant
			flag, err := featureOwnFlag(ctx, tx, definer.Get("id"), key)
			if err != nil {
				return nil, err
			}
			now := float64(server.Now())
			found, err := tx.Find(ctx, FeatureCollections.Targets, core.NewObject("flagId", flag.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			var views []*core.Object
			for _, entry := range found {
				realm, err := tx.Get(ctx, "tenants", jsString(entry.Get("tenantId")))
				if err != nil {
					return nil, err
				}
				if realm == nil {
					continue
				}
				expiresAt := entry.Get("expiresAt")
				lapsed := !isUndefined(expiresAt) && jsNumber(expiresAt) <= now
				view := core.NewObject(
					"id", entry.Get("id"),
					"tenantId", realm.Get("id"),
					"tenantName", realm.Get("name"),
					"tenantStatus", realm.Get("status"),
					"source", entry.Get("source"),
					"value", entry.Get("value"),
					"locked", entry.Get("locked") == true,
				)
				if !isUndefined(expiresAt) {
					view.Set("expiresAt", expiresAt)
				}
				view.Set("active", !lapsed && (entry.Get("source") == "target" ||
					(truthy(flag.Get("tenantOverridable")) && !truthy(flag.Get("internal")))))
				if note := entry.Get("note"); !isUndefined(note) {
					view.Set("note", note)
				}
				views = append(views, view.Set("setAt", entry.Get("setAt")).Set("setBy", entry.Get("setBy")))
			}
			sortStable(views, func(a, b *core.Object) int {
				if difference := jsNumber(b.Get("setAt")) - jsNumber(a.Get("setAt")); difference != 0 && difference == difference {
					if difference < 0 {
						return -1
					}
					return 1
				}
				if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
					return -1
				}
				return 1
			})
			out := make([]any, len(views))
			for index, view := range views {
				out[index] = view
			}
			return out, nil
		}, false)
	return Out[apitypes.FeaturesListTargetsOutput]{Value: result}, err
}

// SetOverride is POST {basePath}/features/setOverride. The tenant's own choice for a flag an ancestor defines with
// `tenantOverridable`; it applies to the tenant and its descendants unless they are closer to a decision. Refused
// with FEATURE_LOCKED when the flag does not allow overrides or a locked target covers the tenant; `value: null`
// withdraws the choice (always allowed). Requires iam:features:override on `iam/features/{key}`; audited as
// `feature:override`. Returns the new evaluation.
func (api *FeaturesAPI) SetOverride(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesSetOverrideInput]) (Out[apitypes.FeaturesSetOverrideOutput], error) {
	server := api.server
	key, err := FeatureKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.FeaturesSetOverrideOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:features:override", featureResource(key),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			state, err := FeatureState(ctx, tx, chain, server.Now())
			if err != nil {
				return nil, err
			}
			_, flags, _ := featureStateParts(state)
			flag, _ := flags.Get(key).(*core.Object)
			if flag == nil || (truthy(flag.Get("internal")) && flag.Get("tenantId") != realm.Get("id")) {
				return nil, core.NewIamError("NOT_FOUND", "Feature flag not found", 404)
			}
			if flag.Get("tenantId") == realm.Get("id") {
				return nil, invalidInput("This tenant defines the flag; change its settings with features.update")
			}
			existing, err := featureEntryAt(ctx, tx, realm.Get("id"), flag, "override")
			if err != nil {
				return nil, err
			}
			value := input.Get("value")
			if value == nil {
				if existing != nil {
					if err := tx.Delete(ctx, FeatureCollections.Targets, jsString(existing.Get("id"))); err != nil {
						return nil, err
					}
				}
			} else {
				if err := featureWritable(realm); err != nil {
					return nil, err
				}
				if _, ok := value.(bool); !ok {
					return nil, invalidInput("value must be a boolean or null")
				}
				if !truthy(flag.Get("tenantOverridable")) {
					return nil, core.NewIamError("FEATURE_LOCKED", "This flag does not let tenants choose their own value", 409)
				}
				evaluation, err := EvaluateFlag(state, flag)
				if err != nil {
					return nil, err
				}
				if truthy(evaluation.Get("locked")) {
					return nil, core.NewIamError("FEATURE_LOCKED", "A locked target decides this flag for the tenant", 409)
				}
				entryID := any(ID())
				if existing != nil {
					entryID = existing.Get("id")
				}
				entry := core.NewObject(
					"id", entryID,
					"tenantId", realm.Get("id"),
					"uniqueKey", jsString(flag.Get("id"))+":override",
					"flagId", flag.Get("id"),
					"key", key,
					"definerId", flag.Get("tenantId"),
					"source", "override",
					"value", value,
					"setAt", float64(server.Now()),
					"setBy", principal.Identity.Get("id"),
				)
				if existing != nil {
					_, err = tx.Put(ctx, FeatureCollections.Targets, entry)
				} else {
					_, err = tx.Insert(ctx, FeatureCollections.Targets, entry)
				}
				if err != nil {
					return nil, err
				}
			}
			if err := api.audit(ctx, tx, principal, "feature:override", realm.Get("id"), key, core.NewObject(
				"key", key, "value", value, "definedBy", flag.Get("tenantId"),
			)); err != nil {
				return nil, err
			}
			fresh, err := FeatureState(ctx, tx, chain, server.Now())
			if err != nil {
				return nil, err
			}
			return EvaluateFlag(fresh, flag)
		}, false)
	return Out[apitypes.FeaturesSetOverrideOutput]{Value: result}, err
}

// featureKeys validates an optional list of flag keys (strings(keys).map(featureKey)); nil when absent.
func featureKeys(value any) ([]any, error) {
	if isUndefined(value) {
		return nil, nil
	}
	list, err := Strings(value, "keys")
	if err != nil {
		return nil, err
	}
	keys := make([]any, len(list))
	for index, item := range list {
		key, err := FeatureKey(item)
		if err != nil {
			return nil, err
		}
		keys[index] = key
	}
	return keys, nil
}

// featureValues is Object.fromEntries(evaluations.map(e => [e.key, e.value])).
func featureValues(evaluations []*core.Object) *core.Object {
	out := core.NewObject()
	for _, evaluation := range evaluations {
		out.Set(jsString(evaluation.Get("key")), evaluation.Get("value"))
	}
	return out
}

// Evaluate is POST {basePath}/features/evaluate. `{ key: value }` for the flags that reach the tenant (internal flags
// of ancestors excluded), or for `keys` only (at most 100; unknown keys are `false`). Needs only a session of the
// tenant, like the calls an application makes to decide what to show; root administrators may evaluate any tenant.
// Not audited.
func (api *FeaturesAPI) Evaluate(ctx context.Context, credential core.CredentialInput, input In[apitypes.FeaturesEvaluateInput]) (Out[apitypes.FeaturesEvaluateOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.FeaturesEvaluateOutput]{}, err
	}
	keys, err := featureKeys(input.Get("keys"))
	if err != nil {
		return Out[apitypes.FeaturesEvaluateOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.FeaturesEvaluateOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("tenantId") != realm.Get("id") {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, core.NewIamError("ACCESS_DENIED", "Feature flags are evaluated from a session of their tenant", 403)
			}
		}
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		state, err := FeatureState(ctx, tx, chain, server.Now())
		if err != nil {
			return nil, err
		}
		options := core.NewObject()
		if keys != nil {
			options.Set("keys", keys)
		}
		evaluations, err := EvaluateFeatures(state, options)
		if err != nil {
			return nil, err
		}
		return core.NewObject("tenantId", realm.Get("id"), "flags", featureValues(evaluations)), nil
	})
	return Out[apitypes.FeaturesEvaluateOutput]{Value: result}, err
}

// IamFeatures is api/features.ts IamFeatures: trusted, credential-free evaluation for the deployment's own code
// (`iam.features`).
type IamFeatures struct {
	server *ServerContext
}

// evaluate evaluates every flag that reaches the tenant (internal ones included), or only keys.
func (s *IamFeatures) evaluate(ctx context.Context, tenantID string, keys []any) ([]*core.Object, error) {
	server := s.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		id, err := Text(tenantID, "tenantId")
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		state, err := FeatureState(ctx, tx, chain, server.Now())
		if err != nil {
			return nil, err
		}
		options := core.NewObject("includeInternal", true)
		if keys != nil {
			options = core.NewObject("keys", keys, "includeInternal", true)
		}
		return EvaluateFeatures(state, options)
	})
}

// Evaluate (api/features.ts IamFeatures.evaluate): Every flag that reaches the tenant (internal ones included), or
// only `keys`, with values and reasons.
func (s *IamFeatures) Evaluate(ctx context.Context, tenantID string, options *core.Object) (result []*core.Object, err error) {
	var keys []any
	if options != nil {
		if keys, err = featureKeys(options.Get("keys")); err != nil {
			return nil, err
		}
	}
	return s.evaluate(ctx, tenantID, keys)
}

// Values (api/features.ts IamFeatures.values): `{ key: value }` for every flag that reaches the tenant, internal
// ones included.
func (s *IamFeatures) Values(ctx context.Context, tenantID string) (result *core.Object, err error) {
	evaluations, err := s.evaluate(ctx, tenantID, nil)
	if err != nil {
		return nil, err
	}
	return featureValues(evaluations), nil
}

// IsEnabled (api/features.ts IamFeatures.isEnabled): Whether one flag is on for the tenant; `false` when no flag
// with the key reaches it.
func (s *IamFeatures) IsEnabled(ctx context.Context, tenantID string, key string) (result bool, err error) {
	checked, err := FeatureKey(key)
	if err != nil {
		return false, err
	}
	evaluations, err := s.evaluate(ctx, tenantID, []any{checked})
	if err != nil {
		return false, err
	}
	return evaluations[0].Get("value") == true, nil
}

// CreateFeatureEvaluator builds the IamFeatures (api/features.ts createFeatureEvaluator): credential-free
// evaluation, shared by `iam.features` and tests.
func CreateFeatureEvaluator(server *ServerContext) *IamFeatures {
	return &IamFeatures{server: server}
}
