package server

// Port of packages/server/src/invariants.ts: access invariants (guardrails), their evaluation, the scheduled check,
// and the enforcement snapshot/verify pair the operation envelope runs around access-changing operations.

import (
	"context"
	"errors"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// invariantMaxSubjects is the evaluation cap of reports (invariants.ts maxSubjects).
const invariantMaxSubjects = 500

// invariantAttributeEquals is `attributes[name] === value` for an invariant's primitive attribute value.
func invariantAttributeEquals(attribute any, value any) bool {
	switch expected := value.(type) {
	case string:
		actual, ok := attribute.(string)
		return ok && actual == expected
	case float64:
		actual, ok := attribute.(float64)
		return ok && actual == expected
	case bool:
		actual, ok := attribute.(bool)
		return ok && actual == expected
	}
	return false
}

// invariantSubjects are the live identities an invariant's subject names (invariants.ts subjects).
func invariantSubjects(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, subject any) ([]*core.Object, error) {
	live := func(identity *core.Object) bool {
		return identity != nil && identity.Get("tenantId") == tenantID && identity.Get("status") == "active" && !server.IdentityExpired(identity)
	}
	record, _ := subject.(*core.Object)
	if record == nil {
		return nil, errors.New("Cannot use 'in' operator to search for 'identityId' in " + jsString(subject))
	}
	if record.Has("identityId") {
		identity, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if identity == nil || identity.Get("tenantId") != tenantID {
			return nil, core.NewIamError("NOT_FOUND", "The invariant names an identity that no longer exists", 404)
		}
		if live(identity) {
			return []*core.Object{identity}, nil
		}
		return []*core.Object{}, nil
	}
	if record.Has("groupId") {
		group, err := tx.Get(ctx, "groups", jsString(record.Get("groupId")))
		if err != nil {
			return nil, err
		}
		if group == nil || group.Get("tenantId") != tenantID {
			return nil, core.NewIamError("NOT_FOUND", "The invariant names a group that no longer exists", 404)
		}
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", record.Get("groupId")), nil)
		if err != nil {
			return nil, err
		}
		people := []*core.Object{}
		for _, member := range members {
			if !server.LiveMembership(member) {
				continue
			}
			identity, err := tx.Get(ctx, "identities", jsString(member.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if live(identity) {
				people = append(people, identity)
			}
		}
		return people, nil
	}
	all, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	everyone := []*core.Object{}
	for _, identity := range all {
		if live(identity) {
			everyone = append(everyone, identity)
		}
	}
	if record.Has("everyone") {
		return everyone, nil
	}
	attribute, ok := record.Get("attribute").(*core.Object)
	if !ok || attribute == nil {
		return nil, errors.New("Cannot destructure property 'name' of 'subject.attribute' as it is " + jsString(record.Get("attribute")) + ".")
	}
	name, value := jsString(attribute.Get("name")), attribute.Get("value")
	matching := []*core.Object{}
	for _, identity := range everyone {
		if invariantAttributeEquals(member(identity.Get("attributes"), name), value) {
			matching = append(matching, identity)
		}
	}
	return matching, nil
}

// EvaluateInvariants (invariants.ts evaluateInvariants): Evaluates invariants against the current state of the
// transaction. Enforcement (`options.unlimited`) evaluates every subject; reports stop at 500.
func EvaluateInvariants(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, invariants []*core.Object, options *core.Object) ([]*core.Object, error) {
	unlimited := truthy(member(options, "unlimited"))
	tenantID := jsString(tenant.Get("id"))
	resources := map[string]*ResolvedResource{}
	results := []*core.Object{}
	for _, invariant := range invariants {
		reference := invariant.Get("resource")
		summary := core.NewObject(
			"id", invariant.Get("id"), "name", invariant.Get("name"), "mode", invariant.Get("mode"),
			"expect", invariant.Get("expect"), "action", invariant.Get("action"), "resource", reference,
		)
		result, err := func() (*core.Object, error) {
			if !isPlainObject(reference) {
				return nil, errors.New("Cannot read properties of " + jsString(reference) + " (reading 'type')")
			}
			resourceType, resourceID := jsString(member(reference, "type")), jsString(member(reference, "id"))
			key := resourceType + "/" + resourceID
			resource := resources[key]
			if resource == nil {
				resolved, err := server.Decisions.Resolve(ctx, tx, core.ResourceRef{TenantID: tenantID, Type: resourceType, ID: resourceID}, true, "", nil)
				if err != nil {
					return nil, err
				}
				resource = resolved
				resources[key] = resource
			}
			people, err := invariantSubjects(ctx, server, tx, tenantID, invariant.Get("subject"))
			if err != nil {
				return nil, err
			}
			sortStable(people, func(a, b *core.Object) int {
				return localeCompare(jsString(a.Get("id")), jsString(b.Get("id")))
			})
			checked := people
			if !unlimited && len(people) > invariantMaxSubjects {
				checked = people[:invariantMaxSubjects]
			}
			action := jsString(invariant.Get("action"))
			violations := []any{}
			for _, identity := range checked {
				principal := server.Decisions.SimulatedPrincipal(identity, invariant.Get("assumeMfa") == true)
				prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, action)
				if err != nil {
					return nil, err
				}
				decision, err := DecideOn(prepared, *resource, action)
				if err != nil {
					return nil, err
				}
				if decision.Allowed != (invariant.Get("expect") == "allow") {
					violations = append(violations, core.NewObject(
						"identity", core.NewObject("id", identity.Get("id"), "name", coalesce(identity.Get("email"), identity.Get("name"))),
						"reason", decision.Reason,
					))
				}
			}
			return core.NewObject(
				"invariant", summary, "passed", len(violations) == 0, "evaluated", len(checked),
				"truncated", len(people) > len(checked), "violations", violations,
			), nil
		}()
		if err != nil {
			known, ok := asIamError(err)
			if !ok {
				return nil, err
			}
			result = core.NewObject(
				"invariant", summary, "passed", false, "evaluated", 0, "truncated", false, "violations", []any{},
				"error", core.NewObject("code", known.Code, "message", known.Message),
			)
		}
		results = append(results, result)
	}
	return results, nil
}

// invariantArray is a model array, or nil for anything else.
func invariantArray(value any) []any {
	list, _ := value.([]any)
	return list
}

// CheckInvariants (invariants.ts checkInvariants): The scheduled invariant check: evaluates every invariant of every
// active tenant (or one `tenantId`), remembers the outcome on the invariant, and records `invariant:broken` when an
// invariant starts failing or gains violators and `invariant:restored` when it passes again, so monitored invariants
// reach webhooks and audit exports. A deployment operation: no credential, one transaction per tenant.
func CheckInvariants(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	checked := 0
	broken := []any{}
	restoredList := []any{}
	filter := core.NewObject()
	if tenantID := member(input, "tenantId"); truthy(tenantID) {
		filter = core.NewObject("tenantId", tenantID)
	}
	tenantIDs, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]string, error) {
		invariants, err := tx.Find(ctx, "accessInvariants", filter, nil)
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(invariants))
		for _, invariant := range invariants {
			ids = append(ids, jsString(invariant.Get("tenantId")))
		}
		ids = unique(ids)
		sortStable(ids, compareUTF16)
		return ids, nil
	})
	if err != nil {
		return nil, err
	}
	for _, tenantID := range tenantIDs {
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			tenant, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil {
				return err
			}
			if tenant == nil || tenant.Get("status") != "active" {
				return nil
			}
			invariants, err := tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return err
			}
			sortStable(invariants, func(a, b *core.Object) int {
				return localeCompare(jsString(a.Get("id")), jsString(b.Get("id")))
			})
			outcomes, err := EvaluateInvariants(ctx, server, tx, tenant, invariants, nil)
			if err != nil {
				return err
			}
			now := server.Now()
			for index, invariant := range invariants {
				outcome := outcomes[index]
				checked++
				violations := []string{}
				for _, violation := range invariantArray(outcome.Get("violations")) {
					violations = append(violations, jsString(member(member(violation, "identity"), "id")))
				}
				sortStable(violations, compareUTF16)
				previous, hasPrevious := invariant.Get("lastCheck").(*core.Object)
				hasPrevious = hasPrevious && previous != nil
				known := map[string]bool{}
				if hasPrevious {
					for _, identityID := range invariantArray(previous.Get("violations")) {
						known[jsString(identityID)] = true
					}
				}
				fresh := []string{}
				for _, identityID := range violations {
					if !known[identityID] {
						fresh = append(fresh, identityID)
					}
				}
				failedNow := outcome.Get("passed") != true
				previousPassed := hasPrevious && truthy(previous.Get("passed"))
				// Reported once per change: a failure after a pass (or the first check), or new people violating it.
				newlyBroken := failedNow && (!hasPrevious || previousPassed || len(fresh) > 0)
				restored := !failedNow && hasPrevious && !previousPassed
				failure, hasError := outcome.Get("error").(*core.Object)
				hasError = hasError && failure != nil
				if newlyBroken {
					reported := violations
					if len(fresh) > 0 {
						reported = fresh
					}
					metadata := core.NewObject("name", invariant.Get("name"), "mode", invariant.Get("mode"), "violations", stringsOf(reported))
					if hasError {
						metadata.Set("error", failure.Get("code"))
					}
					if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
						"id", ID(), "tenantId", tenantID, "actorId", "deployment-operator", "action", "invariant:broken",
						"resourceId", invariant.Get("id"), "timestamp", now, "outcome", "deny", "metadata", metadata,
					)); err != nil {
						return err
					}
					broken = append(broken, core.NewObject(
						"tenantId", tenantID, "invariantId", invariant.Get("id"), "name", invariant.Get("name"), "violations", stringsOf(violations),
					))
				} else if restored {
					if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
						"id", ID(), "tenantId", tenantID, "actorId", "deployment-operator", "action", "invariant:restored",
						"resourceId", invariant.Get("id"), "timestamp", now, "outcome", "allow",
						"metadata", core.NewObject("name", invariant.Get("name"), "mode", invariant.Get("mode")),
					)); err != nil {
						return err
					}
					restoredList = append(restoredList, core.NewObject("tenantId", tenantID, "invariantId", invariant.Get("id"), "name", invariant.Get("name")))
				}
				lastCheck := core.NewObject("at", now, "passed", outcome.Get("passed"), "violations", stringsOf(violations))
				if hasError {
					lastCheck.Set("error", failure.Get("message"))
				}
				if _, err := tx.Put(ctx, "accessInvariants", invariant.Spread(core.NewObject("lastCheck", lastCheck))); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("checked", checked, "broken", broken, "restored", restoredList), nil
}

// InvariantSnapshotState is what InvariantSnapshot keeps: the enforced invariants, the violations that already
// existed, and the invariants that could not be evaluated.
type InvariantSnapshotState struct {
	Invariants  []*core.Object
	Existing    map[string]bool
	Unevaluable map[string]bool
}

// invariantChangingActions are the operations that can change who may do what (invariants.ts accessChangingActions).
var invariantChangingActions = func() *orderedSet {
	set := newOrderedSet()
	for _, action := range []string{
		"roles:update", "roles:delete", "policies:update", "policies:delete", "bindings:create", "bindings:delete",
		"bindings:activate", "bindings:approve", "groups:update", "groups:delete", "identities:create",
		"identities:update", "packages:update", "packages:assign", "packages:approve", "config:apply",
		"access-requests:review", "relationships:create", "relationships:delete", "resources:update",
		"boundaries:update", "authorities:revoke", "resources:delete", "root:grant", "certifications:manage",
		"agreements:manage", "onboarding:manage", "analysis:update", "roles:assume", "trust:create", "trust:update",
		"session-tokens:create", "oidc-providers:create", "oidc-providers:update", "teams:create", "teams:update",
		"teams:delete", "departments:manage", "packages:create", "features:manage", "features:override",
		"billing:manage", "licenses:assign", "licenses:manage", "guests:manage", "guests:settings",
		"clearances:adjudicate", "classifications:manage", "classifications:declassify",
	} {
		set.Add("iam:" + action)
	}
	return set
}()

// narrowingOnly marks the running operation's transaction as one that only narrows access (invariants.ts
// narrowingOnly, a WeakSet of transactions).
var narrowingOnly sync.Map

// NarrowsAccessOnly (invariants.ts narrowsAccessOnly): marks the running operation (inside Operation) as one that
// only narrows access; the mark lives for one operation.
func NarrowsAccessOnly(tx core.IamStore) {
	narrowingOnly.Store(tx, true)
}

// violationKeys are `{invariantId}:{identityId}` of every violation of the results.
func violationKeys(results []*core.Object) map[string]bool {
	keys := map[string]bool{}
	for _, result := range results {
		invariantID := jsString(member(result.Get("invariant"), "id"))
		violations, _ := result.Get("violations").([]any)
		for _, violation := range violations {
			keys[invariantID+":"+jsString(member(member(violation, "identity"), "id"))] = true
		}
	}
	return keys
}

// InvariantSnapshot (invariants.ts invariantSnapshot): before an access-changing operation, the enforced invariants
// and the violations that already exist (nil when there is nothing to enforce).
func InvariantSnapshot(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, action string) (*InvariantSnapshotState, error) {
	narrowingOnly.Delete(tx)
	if !invariantChangingActions.Has(action) {
		return nil, nil
	}
	all, err := tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var invariants []*core.Object
	for _, invariant := range all {
		if invariant.Get("mode") == "enforce" {
			invariants = append(invariants, invariant)
		}
	}
	if len(invariants) == 0 {
		return nil, nil
	}
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	results, err := EvaluateInvariants(ctx, server, tx, tenant, invariants, core.NewObject("unlimited", true))
	if err != nil {
		return nil, err
	}
	unevaluable := map[string]bool{}
	for _, result := range results {
		if truthy(result.Get("error")) {
			unevaluable[jsString(member(result.Get("invariant"), "id"))] = true
		}
	}
	return &InvariantSnapshotState{Invariants: invariants, Existing: violationKeys(results), Unevaluable: unevaluable}, nil
}

// InvariantVerify (invariants.ts invariantVerify): after the operation, refuses (rolling the transaction back) when it
// newly broke an enforced invariant.
func InvariantVerify(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, snapshot *InvariantSnapshotState) error {
	_, narrowing := narrowingOnly.LoadAndDelete(tx)
	if snapshot == nil {
		return nil
	}
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	results, err := EvaluateInvariants(ctx, server, tx, tenant, snapshot.Invariants, core.NewObject("unlimited", true))
	if err != nil {
		return err
	}
	for _, result := range results {
		invariant, _ := result.Get("invariant").(*core.Object)
		// Taking access away for cause is never blocked by an invariant that expects it to remain.
		if narrowing && member(invariant, "expect") == "allow" {
			continue
		}
		id := jsString(member(invariant, "id"))
		// Deleting an invariant's group or resource would otherwise switch enforcement off silently.
		if failure := result.Get("error"); truthy(failure) && !snapshot.Unevaluable[id] {
			return core.NewIamError("INVARIANT_VIOLATION", "Access invariant \""+jsString(member(invariant, "name"))+"\" could no longer be evaluated ("+jsString(member(failure, "message"))+"); change or delete the invariant first", 409)
		}
		violations, _ := result.Get("violations").([]any)
		for _, violation := range violations {
			identity := member(violation, "identity")
			if snapshot.Existing[id+":"+jsString(member(identity, "id"))] {
				continue
			}
			verb := "no longer be allowed"
			if member(invariant, "expect") == "deny" {
				verb = "be allowed"
			}
			resource := member(invariant, "resource")
			return core.NewIamError("INVARIANT_VIOLATION", "Access invariant \""+jsString(member(invariant, "name"))+"\": "+jsString(member(identity, "name"))+" would "+verb+" "+jsString(member(invariant, "action"))+" on "+jsString(member(resource, "type"))+"/"+jsString(member(resource, "id")), 409)
		}
	}
	return nil
}
