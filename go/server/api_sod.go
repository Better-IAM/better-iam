package server

// Port of packages/server/src/api/sod.ts: separation-of-duties rules (toxic role combinations). A `prevent` rule makes
// every granting operation — bindings, group membership, bulk onboarding, access-request approval, configuration
// apply, invitation acceptance — fail with `SOD_CONFLICT` when it would leave someone holding two of its roles;
// conflicts that predate the rule are reported by `violations` and the access analysis instead of blocking unrelated
// work.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// sodModes are the rule modes (api/sod.ts modes).
var sodModes = newOrderedSet("prevent", "detect")

// SodAPI is the `sod` API group (packages/server/src/api/sod.ts createSodApi): every method runs through the
// operation envelope; the router maps POST {basePath}/sod/{method} onto it.
type SodAPI struct {
	server *ServerContext
}

// CreateSodAPI builds the `sod` API group.
func CreateSodAPI(server *ServerContext) *SodAPI {
	return &SodAPI{server: server}
}

// validate applies the name, description, mode and roleIds members of input that are present onto rule, in that
// order (api/sod.ts validate).
func (api *SodAPI) validate(ctx context.Context, tx core.IamStore, tenantID string, input *core.Object, rule *core.Object) error {
	if name := input.Get("name"); !isUndefined(name) {
		text, err := Text(name, "name", 200)
		if err != nil {
			return err
		}
		rule.Set("name", core.JSTrim(text))
	}
	if description := input.Get("description"); !isUndefined(description) {
		text, err := Text(description, "description", 1000)
		if err != nil {
			return err
		}
		rule.Set("description", core.JSTrim(text))
	}
	if mode := input.Get("mode"); !isUndefined(mode) {
		value, ok := mode.(string)
		if !ok || !sodModes.Has(value) {
			return invalidInput("mode must be prevent or detect")
		}
		rule.Set("mode", value)
	}
	if raw := input.Get("roleIds"); !isUndefined(raw) {
		list, err := Strings(raw, "roleIds")
		if err != nil {
			return err
		}
		roleIDs := unique(list)
		if len(roleIDs) < 2 || len(roleIDs) > 20 {
			return invalidInput("A rule names 2 to 20 conflicting roles")
		}
		for _, roleID := range roleIDs {
			role, err := api.server.Scoped(ctx, tx, "roles", roleID, tenantID)
			if err != nil {
				return err
			}
			if truthy(role.Get("protected")) {
				return invalidInput("Owner roles cannot be part of a rule")
			}
		}
		rule.Set("roleIds", stringsOf(roleIDs))
	}
	return nil
}

// Create is POST {basePath}/sod/create. Declares 2 to 20 roles that nobody may hold together, and reports how many people already hold two of them.
// Requires iam:sod:manage.
func (api *SodAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodCreateInput]) (Out[apitypes.SodCreateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:sod:manage", "sod/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		rule := core.NewObject("mode", "prevent")
		if err := api.validate(ctx, tx, tenant, input.Body, rule); err != nil {
			return nil, err
		}
		if !truthy(rule.Get("name")) || isUndefined(rule.Get("roleIds")) {
			return nil, invalidInput("name and roleIds are required")
		}
		saved, err := tx.Insert(ctx, "sodRules", rule.Spread(core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"createdAt", float64(server.Now()),
			"createdBy", call.Principal.Identity.Get("id"),
		)))
		if err != nil {
			return nil, err
		}
		existing, err := SodViolations(ctx, server, tx, tenant, []*core.Object{saved}, nil)
		if err != nil {
			return nil, err
		}
		return saved.Spread(core.NewObject("existingViolations", float64(len(existing)))), nil
	}, false)
	return Out[apitypes.SodCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/sod/delete. Removes a rule, so the combination is no longer checked or reported.
// Requires iam:sod:manage.
func (api *SodAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodDeleteInput]) (Out[apitypes.SodDeleteOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	ruleID, err := Text(input.Get("ruleId"), "ruleId")
	if err != nil {
		return Out[apitypes.SodDeleteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:sod:manage", "sod/"+ruleID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := server.Scoped(ctx, tx, "sodRules", ruleID, jsString(tenantID)); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "sodRules", ruleID); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.SodDeleteOutput]{Value: result}, err
}

// List is POST {basePath}/sod/list. Lists the tenant's rules, newest first.
// Requires iam:sod:read.
func (api *SodAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodListInput]) (Out[apitypes.SodListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:sod:read", "sod/*", func(ctx context.Context, call MutationContext) ([]any, error) {
		rules, err := call.Tx.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(rules, func(i, j int) bool { return ByNewest(rules[i], rules[j]) < 0 })
		list := make([]any, len(rules))
		for index, rule := range rules {
			list[index] = rule
		}
		return list, nil
	}, false)
	return Out[apitypes.SodListOutput]{Value: result}, err
}

// Update is POST {basePath}/sod/update. Changes a rule's name, description, roles, or mode.
// Requires iam:sod:manage.
func (api *SodAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodUpdateInput]) (Out[apitypes.SodUpdateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	ruleID, err := Text(input.Get("ruleId"), "ruleId")
	if err != nil {
		return Out[apitypes.SodUpdateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:sod:manage", "sod/"+ruleID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		rule, err := server.Scoped(ctx, tx, "sodRules", ruleID, tenant)
		if err != nil {
			return nil, err
		}
		next := rule.Spread()
		if err := api.validate(ctx, tx, tenant, input.Body, next); err != nil {
			return nil, err
		}
		return tx.Put(ctx, "sodRules", next)
	}, false)
	return Out[apitypes.SodUpdateOutput]{Value: result}, err
}

// Violations is POST {basePath}/sod/violations. Lists everyone who currently holds two or more roles of a rule, with names for review screens.
// Requires iam:sod:read.
func (api *SodAPI) Violations(ctx context.Context, credential core.CredentialInput, input In[apitypes.SodViolationsInput]) (Out[apitypes.SodViolationsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:sod:read", "sod/*", func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		found, err := tx.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		rules := append([]*core.Object{}, found...)
		if ruleID := input.Get("ruleId"); !isUndefined(ruleID) {
			filtered := []*core.Object{}
			for _, rule := range rules {
				if rule.Get("id") == ruleID {
					filtered = append(filtered, rule)
				}
			}
			rules = filtered
		}
		roleRecords, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		roles := map[string]any{}
		for _, role := range roleRecords {
			roles[jsString(role.Get("id"))] = role.Get("name")
		}
		violations, err := SodViolations(ctx, server, tx, tenant, rules, nil)
		if err != nil {
			return nil, err
		}
		list := []any{}
		for _, violation := range violations {
			identityID := jsString(violation.Get("identityId"))
			identity, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			var name any = identityID
			if identity != nil {
				name = coalesce(identity.Get("email"), coalesce(identity.Get("name"), identityID))
			}
			roleIDs, _ := violation.Get("roleIds").([]any)
			roleNames := make([]any, len(roleIDs))
			for index, roleID := range roleIDs {
				known, ok := roles[jsString(roleID)]
				if !ok {
					known = core.Undefined
				}
				roleNames[index] = coalesce(known, roleID)
			}
			list = append(list, violation.Spread(core.NewObject("identityName", name, "roleNames", roleNames)))
		}
		return list, nil
	}, false)
	return Out[apitypes.SodViolationsOutput]{Value: result}, err
}
