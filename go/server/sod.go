package server

// Skeleton of packages/server/src/sod.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// SodAssertIdentity (sod.ts sodAssertIdentity): For flows outside the operation envelope (invitation acceptance): a
// newly granted identity must not conflict.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SodAssertIdentity(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityID string) (err error) {
	err = notImplemented("sod.ts sodAssertIdentity")
	return
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
// of a rule.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SodViolations(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, rules []*core.Object, identityIDs []string) (result []*core.Object, err error) {
	err = notImplemented("sod.ts sodViolations")
	return
}
