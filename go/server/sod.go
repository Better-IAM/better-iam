package server

// Port of packages/server/src/sod.ts: separation-of-duties rules. Nobody may hold two or more roles of a rule at once
// (directly, through groups, or as eligible just-in-time bindings); `prevent` refuses grants that would create a
// conflict, `detect` only reports it.

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// SodAssertIdentity (sod.ts sodAssertIdentity): For flows outside the operation envelope (invitation acceptance): a
// newly granted identity must not conflict.
func SodAssertIdentity(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityID string) error {
	all, err := tx.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	var rules []*core.Object
	for _, rule := range all {
		if rule.Get("mode") == "prevent" {
			rules = append(rules, rule)
		}
	}
	if len(rules) > 0 {
		return SodVerify(ctx, server, tx, tenantID, &SodSnapshotState{Rules: rules, Existing: map[string]bool{}}, []string{identityID})
	}
	return nil
}

// sodInheritedRoles is sod.ts inheritedRoles: each role with every role it inherits, transitively (a role inheriting
// Approver holds Approver).
func sodInheritedRoles(roles []*core.Object) func(roleID string) []string {
	byID := map[string]*core.Object{}
	for _, role := range roles {
		byID[jsString(role.Get("id"))] = role
	}
	cache := map[string][]string{}
	return func(roleID string) []string {
		if cached, ok := cache[roleID]; ok {
			return cached
		}
		seen := newOrderedSet()
		for pending := []string{roleID}; len(pending) > 0; {
			next := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if seen.Has(next) {
				continue
			}
			seen.Add(next)
			if role := byID[next]; role != nil {
				inherits, _ := role.Get("inherits").([]any)
				for _, inherited := range inherits {
					pending = append(pending, jsString(inherited))
				}
			}
		}
		all := seen.Values()
		cache[roleID] = all
		return all
	}
}

// SodSnapshotState is what SodSnapshot keeps: the prevent rules and the conflicts that already existed.
type SodSnapshotState struct {
	Rules    []*core.Object
	Existing map[string]bool
}

// sodGrantingActions are the actions that can grant (sod.ts grantingActions).
var sodGrantingActions = newOrderedSet(
	"iam:bindings:create", "iam:groups:update", "iam:identities:create", "iam:access-requests:review",
	"iam:config:apply", "iam:packages:assign", "iam:packages:approve", "iam:teams:create", "iam:teams:update",
	"iam:roles:update",
)

// SodSnapshot (sod.ts sodSnapshot): before a granting operation, the prevent-rule conflicts that already exist, so a
// rule added after the fact never blocks unrelated work. nil when the action cannot grant or the tenant has no
// prevent rules.
func SodSnapshot(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, action string) (*SodSnapshotState, error) {
	if !sodGrantingActions.Has(action) {
		return nil, nil
	}
	all, err := tx.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var rules []*core.Object
	for _, rule := range all {
		if rule.Get("mode") == "prevent" {
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}
	violations, err := SodViolations(ctx, server, tx, tenantID, rules, nil)
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, violation := range violations {
		existing[jsString(violation.Get("ruleId"))+":"+jsString(violation.Get("identityId"))] = true
	}
	return &SodSnapshotState{Rules: rules, Existing: existing}, nil
}

// SodVerify (sod.ts sodVerify): after the operation, refuses (rolling the transaction back) when it created a new
// prevent-rule conflict. identityIDs (nil: everyone) limits the check.
func SodVerify(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, snapshot *SodSnapshotState, identityIDs []string) error {
	if snapshot == nil {
		return nil
	}
	violations, err := SodViolations(ctx, server, tx, tenantID, snapshot.Rules, identityIDs)
	if err != nil {
		return err
	}
	for _, violation := range violations {
		if snapshot.Existing[jsString(violation.Get("ruleId"))+":"+jsString(violation.Get("identityId"))] {
			continue
		}
		var names []string
		roleIDs, _ := violation.Get("roleIds").([]any)
		for _, roleID := range roleIDs {
			role, err := tx.Get(ctx, "roles", jsString(roleID))
			if err != nil {
				return err
			}
			if role != nil && !isUndefined(role.Get("name")) && role.Get("name") != nil {
				names = append(names, jsString(role.Get("name")))
			} else {
				names = append(names, jsString(roleID))
			}
		}
		return core.NewIamError("SOD_CONFLICT", "Separation of duties ("+jsString(violation.Get("ruleName"))+"): one person cannot hold "+strings.Join(names, " and "), 409)
	}
	return nil
}

// SodViolations (sod.ts sodViolations): Every identity (optionally only `identityIds`) that holds two or more roles
// of a rule. rules nil reads the tenant's rules (an empty, non-nil slice checks none); identityIDs nil checks every
// identity that is not deleted.
func SodViolations(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, rules []*core.Object, identityIDs []string) ([]*core.Object, error) {
	active := rules
	if active == nil {
		found, err := tx.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		active = found
	}
	violations := []*core.Object{}
	if len(active) == 0 {
		return violations, nil
	}
	// Future-dated bindings count: a prevent rule must also stop a conflict that is scheduled to start.
	allBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var bindings []*core.Object
	for _, binding := range allBindings {
		if !server.ExpiredBinding(binding) {
			bindings = append(bindings, binding)
		}
	}
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	groupsOf := map[string]map[string]bool{}
	for _, member := range members {
		if !server.LiveMembership(member) {
			continue
		}
		identityID := jsString(member.Get("identityId"))
		set := groupsOf[identityID]
		if set == nil {
			set = map[string]bool{}
			groupsOf[identityID] = set
		}
		set[jsString(member.Get("groupId"))] = true
	}
	subjects := identityIDs
	if subjects == nil {
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		subjects = []string{}
		for _, identity := range identities {
			if identity.Get("status") != "deleted" {
				subjects = append(subjects, jsString(identity.Get("id")))
			}
		}
	}
	roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	expand := sodInheritedRoles(roles)
	for _, identityID := range subjects {
		memberOf := groupsOf[identityID]
		held := map[string]bool{}
		for _, binding := range bindings {
			subjectID := jsString(binding.Get("subjectId"))
			var holds bool
			if binding.Get("subjectType") == "identity" {
				holds = binding.Get("subjectId") == identityID
			} else {
				holds = memberOf[subjectID]
			}
			if !holds {
				continue
			}
			for _, roleID := range expand(jsString(binding.Get("roleId"))) {
				held[roleID] = true
			}
		}
		for _, rule := range active {
			roleIDs, _ := rule.Get("roleIds").([]any)
			conflicting := []any{}
			for _, roleID := range roleIDs {
				if id, ok := roleID.(string); ok && held[id] {
					conflicting = append(conflicting, id)
				}
			}
			if len(conflicting) >= 2 {
				violations = append(violations, core.NewObject(
					"ruleId", rule.Get("id"),
					"ruleName", rule.Get("name"),
					"mode", rule.Get("mode"),
					"identityId", identityID,
					"roleIds", conflicting,
				))
			}
		}
	}
	return violations, nil
}
