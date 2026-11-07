package server

// Port of packages/server/src/api/quotas.ts: API usage plans and quotas. Managers define plans (`iam:quotas:manage`
// on `iam/quotas/{plan}`) and assign them to API keys, agents, people or groups, or make one the tenant's default for
// its meter; applications count use with `iam.quotas.consume` (or `quotas.consume` over HTTP with the caller's own
// credential) and show callers their remaining quota with `quotas.status`.

import (
	"context"
	"math"
	"net/http"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// QuotasAPI is the `quotas` API group (packages/server/src/api/quotas.ts createQuotasApi): every method runs through the
// operation envelope; the router maps POST {basePath}/quotas/{method} onto it.
type QuotasAPI struct {
	server *ServerContext
}

// CreateQuotasAPI builds the `quotas` API group.
func CreateQuotasAPI(server *ServerContext) *QuotasAPI {
	return &QuotasAPI{server: server}
}

// quotaPlanResource is the resource id of a plan (`quotas/{name}`).
func quotaPlanResource(name string) string { return "quotas/" + name }

// quotaPlanView is a plan as its managers see it.
func quotaPlanView(plan *core.Object, assignments int) *core.Object {
	out := core.NewObject("name", plan.Get("name"))
	if description := plan.Get("description"); !isUndefined(description) {
		out.Set("description", description)
	}
	out.Set("meter", plan.Get("meter"))
	if throttle := plan.Get("throttle"); truthy(throttle) {
		out.Set("throttle", throttle)
	}
	return out.Set("limits", plan.Get("limits")).
		Set("scope", plan.Get("scope")).
		Set("default", plan.Get("default")).
		Set("priority", plan.Get("priority")).
		Set("timeZone", plan.Get("timeZone")).
		Set("alertThresholds", plan.Get("alertThresholds")).
		Set("assignments", float64(assignments)).
		Set("createdAt", plan.Get("createdAt")).
		Set("createdBy", plan.Get("createdBy")).
		Set("updatedAt", plan.Get("updatedAt")).
		Set("updatedBy", plan.Get("updatedBy"))
}

// quotaCost is the units a call counts (default 1).
func quotaCost(value any) (float64, error) {
	if isUndefined(value) {
		return 1, nil
	}
	return Integer(value, "cost", 1, 1_000_000_000)
}

// findQuotaPlan is the tenant's plan with the name (NOT_FOUND otherwise).
func findQuotaPlan(ctx context.Context, tx core.IamStore, tenantID any, name string) (*core.Object, error) {
	found, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Quota plan not found", 404)
	}
	return found[0], nil
}

// quotaLimitsSummary is `limits.map((limit) => `${limit.limit}/${limit.period}`)`.
func quotaLimitsSummary(limits any) []any {
	list, _ := limits.([]any)
	out := make([]any, len(list))
	for index, limit := range list {
		out[index] = jsString(member(limit, "limit")) + "/" + jsString(member(limit, "period"))
	}
	return out
}

// quotaThrottleSummary is `${rate}/s burst ${burst}`, or null without a throttle.
func quotaThrottleSummary(throttle any) any {
	if !truthy(throttle) {
		return nil
	}
	return jsString(member(throttle, "ratePerSecond")) + "/s burst " + jsString(member(throttle, "burst"))
}

// quotaCallerDecision is the consumption of the caller's own session, which must belong to the tenant.
func quotaCallerDecision(ctx context.Context, server *ServerContext, credential core.CredentialInput, tenantIDValue, meterValue, costValue any, dryRun bool) (*core.Object, error) {
	tenantID, err := Text(tenantIDValue, "tenantId")
	if err != nil {
		return nil, err
	}
	meter, err := QuotaName(meterValue, "meter")
	if err != nil {
		return nil, err
	}
	units := 0.0
	if !dryRun {
		if units, err = quotaCost(costValue); err != nil {
			return nil, err
		}
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("tenantId") != realm.Get("id") {
			return nil, core.NewIamError("ACCESS_DENIED", "Quotas count in the session’s own tenant", 403)
		}
		subject, err := SubjectOf(principal)
		if err != nil {
			return nil, err
		}
		realmID := jsString(realm.Get("id"))
		return ConsumeQuota(ctx, server, tx, subject, meter, units,
			func(ctx context.Context, store core.IamStore, action string, metadata *core.Object) error {
				outcome := "allow"
				if action == "quota:exceeded" {
					outcome = "deny"
				}
				return server.Events.Audit(ctx, store, principal, action, realmID, quotaPlanResource(jsString(metadata.Get("plan"))), outcome, false, metadata)
			}, dryRun)
	})
}

// audit records a plan change in the tenant.
func (api *QuotasAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action string, tenantID any, name string, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, jsString(tenantID), quotaPlanResource(name), "allow", false, metadata)
}

// assignmentCount is how many subjects are assigned the plan directly.
func quotaAssignmentCount(ctx context.Context, tx core.IamStore, plan *core.Object) (int, error) {
	found, err := tx.Find(ctx, QuotaCollections.Assignments, core.NewObject("tenantId", plan.Get("tenantId"), "planId", plan.Get("id")), nil)
	return len(found), err
}

// quotaSubjectName is the label of an assignment's subject (core.Undefined when there is none).
func quotaSubjectName(ctx context.Context, tx core.IamStore, tenantID any, subjectType string, subjectID string) (any, error) {
	if subjectType == "group" {
		group, err := tx.Get(ctx, "groups", subjectID)
		if err != nil || group == nil || group.Get("tenantId") != tenantID {
			return core.Undefined, err
		}
		return group.Get("name"), nil
	}
	if subjectType == "identity" {
		identity, err := tx.Get(ctx, "identities", subjectID)
		if err != nil || identity == nil || identity.Get("tenantId") != tenantID {
			return core.Undefined, err
		}
		return identity.Get("name"), nil
	}
	session, err := tx.Get(ctx, "sessions", subjectID)
	if err != nil || session == nil {
		return core.Undefined, err
	}
	if label, ok := session.Get("name").(string); ok && session.Get("tenantId") == tenantID {
		return label, nil
	}
	return core.Undefined, nil
}

// validQuotaSubject refuses subjects outside the tenant, deleted identities, and sessions that are not API keys.
func (api *QuotasAPI) validQuotaSubject(ctx context.Context, tx core.IamStore, tenantID string, subjectType any, subjectID any) (string, string, error) {
	subject, err := Text(subjectID, "subjectId")
	if err != nil {
		return "", "", err
	}
	switch subjectType {
	case "identity":
		if _, err := api.server.ActiveIdentity(ctx, tx, subject, tenantID); err != nil {
			return "", "", err
		}
		return "identity", subject, nil
	case "group":
		if _, err := api.server.Scoped(ctx, tx, "groups", subject, tenantID); err != nil {
			return "", "", err
		}
		return "group", subject, nil
	case "apiKey":
		session, err := tx.Get(ctx, "sessions", subject)
		if err != nil {
			return "", "", err
		}
		if session == nil || session.Get("tenantId") != tenantID || session.Get("kind") != "api-key" {
			return "", "", core.NewIamError("NOT_FOUND", "API key not found", 404)
		}
		return "apiKey", subject, nil
	}
	return "", "", invalidInput("subjectType must be apiKey, identity or group")
}

// CreatePlan is POST {basePath}/quotas/createPlan. Defines a plan for a meter: a `throttle` (`ratePerSecond`,
// `burst`), period `limits` (minute to month), or both. `default: true` makes it the plan for everyone in the tenant
// without one of their own (one per meter); `scope: 'tenant'` makes everyone it covers share one set of counters.
// Requires iam:quotas:manage; audited as `quota:plan-create`.
func (api *QuotasAPI) CreatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasCreatePlanInput]) (Out[apitypes.QuotasCreatePlanOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("name"), "name")
	if err != nil {
		return Out[apitypes.QuotasCreatePlanOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:manage", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := quotaWritable(realm); err != nil {
				return nil, err
			}
			existing, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", realm.Get("id"), "uniqueKey", name), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) > 0 {
				return nil, core.NewIamError("CONFLICT", "A plan with this name already exists", 409)
			}
			meter, err := QuotaName(input.Get("meter"), "meter")
			if err != nil {
				return nil, err
			}
			throttle, err := QuotaThrottle(input.Get("throttle"))
			if err != nil {
				return nil, err
			}
			limits, err := QuotaLimits(input.Get("limits"))
			if err != nil {
				return nil, err
			}
			if throttle == nil && len(limits) == 0 {
				return nil, invalidInput("A plan needs a throttle, limits, or both")
			}
			scope := input.Get("scope")
			if !isUndefined(scope) && scope != "subject" && scope != "tenant" {
				return nil, invalidInput("scope must be subject or tenant")
			}
			isDefault := input.Get("default")
			if _, ok := isDefault.(bool); !isUndefined(isDefault) && !ok {
				return nil, invalidInput("default must be a boolean")
			}
			if isDefault == true {
				defaults, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", realm.Get("id"), "meter", meter, "default", true), nil)
				if err != nil {
					return nil, err
				}
				if len(defaults) > 0 {
					return nil, core.NewIamError("CONFLICT", "The tenant already has a default plan for "+meter, 409)
				}
			}
			now := float64(server.Now())
			if isUndefined(scope) {
				scope = "subject"
			}
			priority := 0.0
			if value := input.Get("priority"); !isUndefined(value) {
				if priority, err = Integer(value, "priority", -1000, 1000); err != nil {
					return nil, err
				}
			}
			zone, err := TimeZone(input.Get("timeZone"))
			if err != nil {
				return nil, err
			}
			thresholds, err := AlertThresholds(input.Get("alertThresholds"))
			if err != nil {
				return nil, err
			}
			plan := core.NewObject("id", ID(), "tenantId", realm.Get("id"), "uniqueKey", name, "name", name, "meter", meter)
			if throttle != nil {
				plan.Set("throttle", throttle)
			}
			plan.Set("limits", quotaLimitsModel(limits)).
				Set("scope", scope).
				Set("default", isDefault == true).
				Set("priority", priority).
				Set("timeZone", zone).
				Set("alertThresholds", quotaThresholdsModel(thresholds)).
				Set("createdAt", now).
				Set("createdBy", principal.Identity.Get("id")).
				Set("updatedAt", now).
				Set("updatedBy", principal.Identity.Get("id"))
			if description := input.Get("description"); !isUndefined(description) {
				text, err := Text(description, "description", 512)
				if err != nil {
					return nil, err
				}
				plan.Set("description", core.JSTrim(text))
			}
			if _, err := tx.Insert(ctx, QuotaCollections.Plans, plan); err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "quota:plan-create", realm.Get("id"), name, core.NewObject(
				"name", name,
				"meter", meter,
				"limits", quotaLimitsSummary(plan.Get("limits")),
				"throttle", quotaThrottleSummary(plan.Get("throttle")),
				"default", plan.Get("default"),
			)); err != nil {
				return nil, err
			}
			return quotaPlanView(plan, 0), nil
		}, false)
	return Out[apitypes.QuotasCreatePlanOutput]{Value: result}, err
}

// quotaLimitsModel is a list of limits as a model array.
func quotaLimitsModel(limits []*core.Object) []any {
	out := make([]any, len(limits))
	for index, limit := range limits {
		out[index] = limit
	}
	return out
}

// quotaThresholdsModel is a list of thresholds as a model array.
func quotaThresholdsModel(thresholds []float64) []any {
	out := make([]any, len(thresholds))
	for index, threshold := range thresholds {
		out[index] = threshold
	}
	return out
}

// UpdatePlan is POST {basePath}/quotas/updatePlan. Changes a plan: fields left out keep their value; `throttle: null`
// and `description: null` clear them; `limits` replaces the whole list. The meter cannot change. Counters in progress
// keep counting under the new limits. Requires iam:quotas:manage; audited as `quota:plan-update`.
func (api *QuotasAPI) UpdatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasUpdatePlanInput]) (Out[apitypes.QuotasUpdatePlanOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("name"), "name")
	if err != nil {
		return Out[apitypes.QuotasUpdatePlanOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:manage", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := quotaWritable(realm); err != nil {
				return nil, err
			}
			plan, err := findQuotaPlan(ctx, tx, realm.Get("id"), name)
			if err != nil {
				return nil, err
			}
			next := plan.Clone()
			next.Delete("description")
			next.Delete("throttle")
			next.Set("updatedAt", float64(server.Now())).Set("updatedBy", principal.Identity.Get("id"))
			if description := input.Get("description"); isUndefined(description) {
				if current := plan.Get("description"); !isUndefined(current) {
					next.Set("description", current)
				}
			} else if description != nil {
				text, err := Text(description, "description", 512)
				if err != nil {
					return nil, err
				}
				next.Set("description", core.JSTrim(text))
			}
			throttle := plan.Get("throttle")
			if value := input.Get("throttle"); !isUndefined(value) {
				checked, err := QuotaThrottle(value)
				if err != nil {
					return nil, err
				}
				throttle = core.Undefined
				if checked != nil {
					throttle = checked
				}
			}
			if truthy(throttle) {
				next.Set("throttle", throttle)
			}
			if value := input.Get("limits"); !isUndefined(value) {
				limits, err := QuotaLimits(value)
				if err != nil {
					return nil, err
				}
				next.Set("limits", quotaLimitsModel(limits))
			}
			if list, _ := next.Get("limits").([]any); !truthy(next.Get("throttle")) && len(list) == 0 {
				return nil, invalidInput("A plan needs a throttle, limits, or both")
			}
			if scope := input.Get("scope"); !isUndefined(scope) {
				if scope != "subject" && scope != "tenant" {
					return nil, invalidInput("scope must be subject or tenant")
				}
				next.Set("scope", scope)
			}
			if isDefault := input.Get("default"); !isUndefined(isDefault) {
				if _, ok := isDefault.(bool); !ok {
					return nil, invalidInput("default must be a boolean")
				}
				if isDefault == true && !truthy(plan.Get("default")) {
					defaults, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", realm.Get("id"), "meter", plan.Get("meter"), "default", true), nil)
					if err != nil {
						return nil, err
					}
					if len(defaults) > 0 {
						return nil, core.NewIamError("CONFLICT", "The tenant already has a default plan for "+jsString(plan.Get("meter")), 409)
					}
				}
				next.Set("default", isDefault)
			}
			if value := input.Get("priority"); !isUndefined(value) {
				priority, err := Integer(value, "priority", -1000, 1000)
				if err != nil {
					return nil, err
				}
				next.Set("priority", priority)
			}
			if value := input.Get("timeZone"); !isUndefined(value) {
				zone, err := TimeZone(value)
				if err != nil {
					return nil, err
				}
				next.Set("timeZone", zone)
			}
			if value := input.Get("alertThresholds"); !isUndefined(value) {
				thresholds, err := AlertThresholds(value)
				if err != nil {
					return nil, err
				}
				next.Set("alertThresholds", quotaThresholdsModel(thresholds))
			}
			stored, err := tx.Put(ctx, QuotaCollections.Plans, next)
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "quota:plan-update", realm.Get("id"), name, core.NewObject(
				"name", name,
				"limits", quotaLimitsSummary(stored.Get("limits")),
				"throttle", quotaThrottleSummary(stored.Get("throttle")),
				"default", stored.Get("default"),
				"scope", stored.Get("scope"),
			)); err != nil {
				return nil, err
			}
			count, err := quotaAssignmentCount(ctx, tx, stored)
			if err != nil {
				return nil, err
			}
			return quotaPlanView(stored, count), nil
		}, false)
	return Out[apitypes.QuotasUpdatePlanOutput]{Value: result}, err
}

// DeletePlan is POST {basePath}/quotas/deletePlan. Deletes a plan with its assignments and counters. Requires
// iam:quotas:manage; audited as `quota:plan-delete`.
func (api *QuotasAPI) DeletePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasDeletePlanInput]) (Out[apitypes.QuotasDeletePlanOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("name"), "name")
	if err != nil {
		return Out[apitypes.QuotasDeletePlanOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:manage", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			plan, err := findQuotaPlan(ctx, tx, realm.Get("id"), name)
			if err != nil {
				return nil, err
			}
			removed := 0
			for _, collection := range []string{QuotaCollections.Assignments, QuotaCollections.Counters} {
				found, err := tx.Find(ctx, collection, core.NewObject("tenantId", realm.Get("id"), "planId", plan.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				for _, record := range found {
					if err := tx.Delete(ctx, collection, jsString(record.Get("id"))); err != nil {
						return nil, err
					}
					if collection == QuotaCollections.Assignments {
						removed++
					}
				}
			}
			if err := tx.Delete(ctx, QuotaCollections.Plans, jsString(plan.Get("id"))); err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "quota:plan-delete", realm.Get("id"), name, core.NewObject("name", name, "assignments", float64(removed))); err != nil {
				return nil, err
			}
			return core.NewObject("deleted", true, "assignments", float64(removed)), nil
		}, false)
	return Out[apitypes.QuotasDeletePlanOutput]{Value: result}, err
}

// quotaByPlanName orders plans by name ((a, b) => (a.name < b.name ? -1 : 1)).
func quotaByPlanName(a, b *core.Object) int {
	if compareUTF16(jsString(a.Get("name")), jsString(b.Get("name"))) < 0 {
		return -1
	}
	return 1
}

// ListPlans is POST {basePath}/quotas/listPlans. Every plan of the tenant, by name. Requires iam:quotas:read on
// `iam/quotas`.
func (api *QuotasAPI) ListPlans(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasListPlansInput]) (Out[apitypes.QuotasListPlansOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:read", "quotas",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			plans, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			sortStable(plans, quotaByPlanName)
			views := make([]any, 0, len(plans))
			for _, plan := range plans {
				count, err := quotaAssignmentCount(ctx, tx, plan)
				if err != nil {
					return nil, err
				}
				views = append(views, quotaPlanView(plan, count))
			}
			return views, nil
		}, false)
	return Out[apitypes.QuotasListPlansOutput]{Value: result}, err
}

// GetPlan is POST {basePath}/quotas/getPlan. One plan. Requires iam:quotas:read.
func (api *QuotasAPI) GetPlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasGetPlanInput]) (Out[apitypes.QuotasGetPlanOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("name"), "name")
	if err != nil {
		return Out[apitypes.QuotasGetPlanOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:read", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			plan, err := findQuotaPlan(ctx, call.Tx, call.Tenant.Get("id"), name)
			if err != nil {
				return nil, err
			}
			count, err := quotaAssignmentCount(ctx, call.Tx, plan)
			if err != nil {
				return nil, err
			}
			return quotaPlanView(plan, count), nil
		}, false)
	return Out[apitypes.QuotasGetPlanOutput]{Value: result}, err
}

// Assign is POST {basePath}/quotas/assign. Assigns a plan to an API key (a session id of kind `api-key`), an
// identity (a person, service account or agent) or a group, replacing the subject's plan for the same meter.
// Requires iam:quotas:manage on the plan; audited as `quota:assign`.
func (api *QuotasAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasAssignInput]) (Out[apitypes.QuotasAssignOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("plan"), "plan")
	if err != nil {
		return Out[apitypes.QuotasAssignOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:manage", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := quotaWritable(realm); err != nil {
				return nil, err
			}
			plan, err := findQuotaPlan(ctx, tx, realm.Get("id"), name)
			if err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			subjectType, subjectID, err := api.validQuotaSubject(ctx, tx, realmID, input.Get("subjectType"), input.Get("subjectId"))
			if err != nil {
				return nil, err
			}
			uniqueKey := jsString(plan.Get("meter")) + ":" + subjectType + ":" + subjectID
			existing, err := tx.Find(ctx, QuotaCollections.Assignments, core.NewObject("tenantId", realm.Get("id"), "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			recordID := any(ID())
			if len(existing) > 0 {
				recordID = existing[0].Get("id")
			}
			record := core.NewObject(
				"id", recordID,
				"tenantId", realm.Get("id"),
				"uniqueKey", uniqueKey,
				"planId", plan.Get("id"),
				"meter", plan.Get("meter"),
				"subjectType", subjectType,
				"subjectId", subjectID,
				"createdAt", float64(server.Now()),
				"createdBy", principal.Identity.Get("id"),
			)
			if len(existing) > 0 {
				_, err = tx.Put(ctx, QuotaCollections.Assignments, record)
			} else {
				_, err = tx.Insert(ctx, QuotaCollections.Assignments, record)
			}
			if err != nil {
				return nil, err
			}
			if err := api.audit(ctx, tx, principal, "quota:assign", realm.Get("id"), name, core.NewObject(
				"plan", name, "meter", plan.Get("meter"), "subjectType", subjectType, "subjectId", subjectID,
			)); err != nil {
				return nil, err
			}
			label, err := quotaSubjectName(ctx, tx, realm.Get("id"), subjectType, subjectID)
			if err != nil {
				return nil, err
			}
			out := core.NewObject("plan", name, "meter", plan.Get("meter"), "subjectType", subjectType, "subjectId", subjectID)
			if !isUndefined(label) {
				out.Set("subjectName", label)
			}
			return out.Set("createdAt", record.Get("createdAt")).Set("createdBy", record.Get("createdBy")), nil
		}, false)
	return Out[apitypes.QuotasAssignOutput]{Value: result}, err
}

// Unassign is POST {basePath}/quotas/unassign. Removes a subject's plan for a meter. Requires iam:quotas:manage on
// `iam/quotas`; audited as `quota:unassign`.
func (api *QuotasAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasUnassignInput]) (Out[apitypes.QuotasUnassignOutput], error) {
	server := api.server
	meter, err := QuotaName(input.Get("meter"), "meter")
	if err != nil {
		return Out[apitypes.QuotasUnassignOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:manage", "quotas",
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			subjectType := jsString(input.Get("subjectType"))
			subjectID, err := Text(input.Get("subjectId"), "subjectId")
			if err != nil {
				return nil, err
			}
			uniqueKey := meter + ":" + subjectType + ":" + subjectID
			existing, err := tx.Find(ctx, QuotaCollections.Assignments, core.NewObject("tenantId", realm.Get("id"), "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) == 0 {
				return core.NewObject("removed", false), nil
			}
			assignment := existing[0]
			if err := tx.Delete(ctx, QuotaCollections.Assignments, jsString(assignment.Get("id"))); err != nil {
				return nil, err
			}
			plan, err := tx.Get(ctx, QuotaCollections.Plans, jsString(assignment.Get("planId")))
			if err != nil {
				return nil, err
			}
			resourceName, planName := meter, any(nil)
			if plan != nil && !nullish(plan.Get("name")) {
				resourceName, planName = jsString(plan.Get("name")), plan.Get("name")
			}
			if err := api.audit(ctx, tx, principal, "quota:unassign", realm.Get("id"), resourceName, core.NewObject(
				"plan", planName,
				"meter", meter,
				"subjectType", assignment.Get("subjectType"),
				"subjectId", assignment.Get("subjectId"),
			)); err != nil {
				return nil, err
			}
			return core.NewObject("removed", true), nil
		}, false)
	return Out[apitypes.QuotasUnassignOutput]{Value: result}, err
}

// ListAssignments is POST {basePath}/quotas/listAssignments. Assignments, optionally of one plan, with their
// subjects' names. Requires iam:quotas:read on `iam/quotas`.
func (api *QuotasAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasListAssignmentsInput]) (Out[apitypes.QuotasListAssignmentsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:read", "quotas",
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			found, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			plans := map[string]*core.Object{}
			for _, plan := range found {
				plans[jsString(plan.Get("id"))] = plan
			}
			only, filtered := "", false
			if value := input.Get("plan"); !isUndefined(value) {
				if only, err = QuotaName(value, "plan"); err != nil {
					return nil, err
				}
				filtered = true
			}
			assignments, err := tx.Find(ctx, QuotaCollections.Assignments, core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			var views []*core.Object
			for _, assignment := range assignments {
				plan := plans[jsString(assignment.Get("planId"))]
				if plan == nil || (filtered && plan.Get("name") != only) {
					continue
				}
				label, err := quotaSubjectName(ctx, tx, realm.Get("id"), jsString(assignment.Get("subjectType")), jsString(assignment.Get("subjectId")))
				if err != nil {
					return nil, err
				}
				view := core.NewObject(
					"plan", plan.Get("name"),
					"meter", assignment.Get("meter"),
					"subjectType", assignment.Get("subjectType"),
					"subjectId", assignment.Get("subjectId"),
				)
				if !isUndefined(label) {
					view.Set("subjectName", label)
				}
				views = append(views, view.Set("createdAt", assignment.Get("createdAt")).Set("createdBy", assignment.Get("createdBy")))
			}
			sortStable(views, func(a, b *core.Object) int {
				if order := compareUTF16(jsString(a.Get("plan")), jsString(b.Get("plan"))); order != 0 {
					return order
				}
				if compareUTF16(jsString(a.Get("subjectId")), jsString(b.Get("subjectId"))) < 0 {
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
	return Out[apitypes.QuotasListAssignmentsOutput]{Value: result}, err
}

// quotaSlice is String.prototype.slice(start, end) with JavaScript's negative indexes.
func quotaSlice(s string, start, end int) string {
	units := core.ToUTF16(s)
	length := len(units)
	clamp := func(index int) int {
		if index < 0 {
			index += length
			if index < 0 {
				index = 0
			}
		}
		if index > length {
			index = length
		}
		return index
	}
	from, to := clamp(start), clamp(end)
	if from >= to {
		return ""
	}
	return core.FromUTF16(units[from:to])
}

// quotaIndexOf is String.prototype.indexOf for a single-unit needle, in UTF-16 units.
func quotaIndexOf(s string, needle string) int {
	index := strings.Index(s, needle)
	if index < 0 {
		return -1
	}
	return utf16Len(s[:index])
}

// Usage is POST {basePath}/quotas/usage. Every subject's use of a plan in the current windows, most used first.
// Requires iam:quotas:read.
func (api *QuotasAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasUsageInput]) (Out[apitypes.QuotasUsageOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("plan"), "plan")
	if err != nil {
		return Out[apitypes.QuotasUsageOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:read", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx, realm := call.Tx, call.Tenant
			plan, err := findQuotaPlan(ctx, tx, realm.Get("id"), name)
			if err != nil {
				return nil, err
			}
			now := float64(server.Now())
			type bounds struct{ start, end float64 }
			current := map[string]bounds{}
			limits, _ := plan.Get("limits").([]any)
			for _, limit := range limits {
				period := jsString(member(limit, "period"))
				start, end, err := quotaWindowBounds(period, now, jsString(plan.Get("timeZone")))
				if err != nil {
					return nil, err
				}
				current[period] = bounds{start, end}
			}
			counters, err := tx.Find(ctx, QuotaCollections.Counters, core.NewObject("tenantId", realm.Get("id"), "planId", plan.Get("id"), "kind", "window"), nil)
			if err != nil {
				return nil, err
			}
			var order []string
			bySubject := map[string][]*core.Object{}
			for _, counter := range counters {
				period := counter.Get("period")
				if !truthy(period) {
					continue
				}
				window, ok := current[jsString(period)]
				if !ok || counter.Get("windowStart") != window.start {
					continue
				}
				key := jsString(counter.Get("subjectKey"))
				if _, seen := bySubject[key]; !seen {
					order = append(order, key)
				}
				bySubject[key] = append(bySubject[key], counter)
			}
			type usageView struct {
				subject string
				shares  []float64
				view    *core.Object
			}
			var views []usageView
			for _, subject := range order {
				subjectCounters := bySubject[subject]
				colon := quotaIndexOf(subject, ":")
				kind, subjectID := quotaSlice(subject, 0, colon), quotaSlice(subject, colon+1, utf16Len(subject))
				var label any = core.Undefined
				switch kind {
				case "identity":
					if label, err = quotaSubjectName(ctx, tx, realm.Get("id"), "identity", subjectID); err != nil {
						return nil, err
					}
				case "key":
					if label, err = quotaSubjectName(ctx, tx, realm.Get("id"), "apiKey", subjectID); err != nil {
						return nil, err
					}
				}
				var exceeded []float64
				for _, counter := range subjectCounters {
					if at := counter.Get("exceededAt"); !isUndefined(at) {
						exceeded = append(exceeded, jsNumber(at))
					}
				}
				view := core.NewObject("subject", subject)
				if !isUndefined(label) {
					view.Set("subjectName", label)
				}
				statuses := make([]any, len(limits))
				var shares []float64
				for index, limit := range limits {
					period := member(limit, "period")
					amount := jsNumber(member(limit, "limit"))
					used := 0.0
					for _, counter := range subjectCounters {
						if counter.Get("period") == period {
							used = quotaCounterUsed(counter)
							break
						}
					}
					statuses[index] = core.NewObject(
						"period", period,
						"limit", member(limit, "limit"),
						"used", used,
						"remaining", math.Max(0, amount-used),
						"resetAt", current[jsString(period)].end,
					)
					shares = append(shares, used/amount)
				}
				view.Set("limits", statuses)
				if len(exceeded) > 0 {
					earliest := math.Inf(1)
					for _, at := range exceeded {
						if math.IsNaN(at) || at < earliest {
							earliest = at
							if math.IsNaN(at) {
								break
							}
						}
					}
					view.Set("exceededAt", earliest)
				}
				views = append(views, usageView{subject: subject, shares: shares, view: view})
			}
			share := func(view usageView) float64 {
				result := 0.0
				for _, value := range view.shares {
					if math.IsNaN(value) {
						return math.NaN()
					}
					result = math.Max(result, value)
				}
				return result
			}
			sortStable(views, func(a, b usageView) int {
				if difference := share(b) - share(a); difference != 0 && !math.IsNaN(difference) {
					if difference < 0 {
						return -1
					}
					return 1
				}
				if compareUTF16(a.subject, b.subject) < 0 {
					return -1
				}
				return 1
			})
			out := make([]any, len(views))
			for index, view := range views {
				out[index] = view.view
			}
			return out, nil
		}, false)
	return Out[apitypes.QuotasUsageOutput]{Value: result}, err
}

// Reset is POST {basePath}/quotas/reset. Starts a subject's counters (and throttle) over, or every subject's with no
// subject given. Requires iam:quotas:manage; audited as `quota:reset`.
func (api *QuotasAPI) Reset(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasResetInput]) (Out[apitypes.QuotasResetOutput], error) {
	server := api.server
	name, err := QuotaName(input.Get("plan"), "plan")
	if err != nil {
		return Out[apitypes.QuotasResetOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:quotas:manage", quotaPlanResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			plan, err := findQuotaPlan(ctx, tx, realm.Get("id"), name)
			if err != nil {
				return nil, err
			}
			var subject any
			hasSubject := false
			if value := input.Get("subject"); !isUndefined(value) {
				text, err := Text(value, "subject")
				if err != nil {
					return nil, err
				}
				subject, hasSubject = text, true
			}
			counters, err := tx.Find(ctx, QuotaCollections.Counters, core.NewObject("tenantId", realm.Get("id"), "planId", plan.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			removed := 0
			for _, counter := range counters {
				if !hasSubject || counter.Get("subjectKey") == subject {
					if err := tx.Delete(ctx, QuotaCollections.Counters, jsString(counter.Get("id"))); err != nil {
						return nil, err
					}
					removed++
				}
			}
			if err := api.audit(ctx, tx, principal, "quota:reset", realm.Get("id"), name, core.NewObject(
				"plan", name, "subject", subject, "counters", float64(removed),
			)); err != nil {
				return nil, err
			}
			return core.NewObject("reset", float64(removed)), nil
		}, false)
	return Out[apitypes.QuotasResetOutput]{Value: result}, err
}

// Status is POST {basePath}/quotas/status. The caller's own quota for a meter without counting anything: the plan
// that applies, what is left in each window, and the throttle's tokens. Needs only a session of the tenant; not
// audited.
func (api *QuotasAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasStatusInput]) (Out[apitypes.QuotasStatusOutput], error) {
	result, err := quotaCallerDecision(ctx, api.server, credential, input.Get("tenantId"), input.Get("meter"), core.Undefined, true)
	return Out[apitypes.QuotasStatusOutput]{Value: result}, err
}

// Consume is POST {basePath}/quotas/consume. Counts `cost` (default 1) units of a meter for the caller's own
// session, or refuses without counting when the plan's throttle or a period limit would be exceeded (`allowed:
// false`, with `reason` and `retryAfterMs`). Needs only a session of the tenant. Thresholds crossed are audited as
// `quota:threshold`, and a window's first refusal as `quota:exceeded`.
func (api *QuotasAPI) Consume(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasConsumeInput]) (Out[apitypes.QuotasConsumeOutput], error) {
	result, err := quotaCallerDecision(ctx, api.server, credential, input.Get("tenantId"), input.Get("meter"), input.Get("cost"), false)
	return Out[apitypes.QuotasConsumeOutput]{Value: result}, err
}

// IamQuotas is api/quotas.ts IamQuotas: trusted quota checks for the deployment's own request handlers
// (`iam.quotas`). A request is a model value { tenantId, meter, cost?, token?, headers? }: the credential members
// are the rest of the request.
type IamQuotas struct {
	server *ServerContext
}

// quotaRequestCredential is the credential of a request: the members other than tenantId, meter and cost (`token`, and
// `headers` as a Headers value or a plain object of header values).
func quotaRequestCredential(request *core.Object) core.CredentialInput {
	credential := core.CredentialInput{}
	if request == nil {
		return credential
	}
	if token, ok := request.Get("token").(string); ok {
		credential.Token = token
	}
	switch headers := request.Get("headers").(type) {
	case http.Header:
		credential.Headers = headers
	case map[string]string:
		credential.Headers = http.Header{}
		for key, value := range headers {
			credential.Headers.Add(key, value)
		}
	case *core.Object:
		if headers != nil {
			credential.Headers = http.Header{}
			for _, key := range headers.Keys() {
				credential.Headers.Add(key, jsString(headers.Get(key)))
			}
		}
	}
	return credential
}

// Consume (api/quotas.ts IamQuotas.consume): Counts use for the request's credential (as `quotas.consume`) and
// returns the decision.
func (s *IamQuotas) Consume(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	if request == nil {
		request = core.NewObject()
	}
	return quotaCallerDecision(ctx, s.server, quotaRequestCredential(request), request.Get("tenantId"), request.Get("meter"), request.Get("cost"), false)
}

// Enforce (api/quotas.ts IamQuotas.enforce): As `consume`, but throws QUOTA_EXCEEDED (429, with `retryAfterMs` for
// the Retry-After header) when refused.
func (s *IamQuotas) Enforce(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	decision, err := s.Consume(ctx, request)
	if err != nil {
		return nil, err
	}
	if !truthy(decision.Get("allowed")) {
		var retryAfterMs *float64
		if value, ok := decision.Get("retryAfterMs").(float64); ok {
			retryAfterMs = &value
		}
		return nil, NewQuotaExceededError(decision, retryAfterMs)
	}
	return decision, nil
}

// Status (api/quotas.ts IamQuotas.status): The request credential's quota for a meter without counting.
func (s *IamQuotas) Status(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	if request == nil {
		request = core.NewObject()
	}
	return quotaCallerDecision(ctx, s.server, quotaRequestCredential(request), request.Get("tenantId"), request.Get("meter"), core.Undefined, true)
}

// ConsumeFor (api/quotas.ts IamQuotas.consumeFor): Counts use for a subject your code identified itself (a
// background job, a webhook sender): an identity of the tenant, optionally through one of its API keys. No
// credential; events are recorded as `deployment-operator`.
func (s *IamQuotas) ConsumeFor(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	if input == nil {
		input = core.NewObject()
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	meter, err := QuotaName(input.Get("meter"), "meter")
	if err != nil {
		return nil, err
	}
	units, err := quotaCost(input.Get("cost"))
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		realmID := jsString(realm.Get("id"))
		identityID, err := Text(input.Get("identityId"), "identityId")
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, identityID, realmID)
		if err != nil {
			return nil, err
		}
		subject := core.NewObject("tenantId", realm.Get("id"), "identityId", identity.Get("id"))
		if value := input.Get("apiKeyId"); !isUndefined(value) {
			apiKeyID, err := Text(value, "apiKeyId")
			if err != nil {
				return nil, err
			}
			session, err := tx.Get(ctx, "sessions", apiKeyID)
			if err != nil {
				return nil, err
			}
			if session == nil || session.Get("kind") != "api-key" || session.Get("identityId") != identity.Get("id") {
				return nil, core.NewIamError("NOT_FOUND", "API key not found", 404)
			}
			if id := session.Get("id"); truthy(id) {
				subject.Set("apiKeyId", id)
			}
		}
		return ConsumeQuota(ctx, server, tx, subject, meter, units,
			func(ctx context.Context, store core.IamStore, action string, metadata *core.Object) error {
				outcome := "allow"
				if action == "quota:exceeded" {
					outcome = "deny"
				}
				return server.Events.RecordAudit(ctx, store, core.NewObject(
					"id", ID(),
					"tenantId", realmID,
					"actorId", "deployment-operator",
					"action", action,
					"resourceId", quotaPlanResource(jsString(metadata.Get("plan"))),
					"timestamp", float64(server.Now()),
					"outcome", outcome,
					"metadata", metadata,
				))
			}, false)
	})
}

// CreateQuotasRuntime builds the IamQuotas (api/quotas.ts createQuotasRuntime).
func CreateQuotasRuntime(server *ServerContext) *IamQuotas {
	return &IamQuotas{server: server}
}

// quotaWritable refuses changes to a deleted tenant.
func quotaWritable(realm *core.Object) error {
	if realm.Get("status") == "deleted" {
		return core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot be updated")
	}
	return nil
}
