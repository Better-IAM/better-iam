package server

// Port of packages/server/src/grant-deadline.ts: how long something a grant allowed may outlive it. Credentials
// minted from access (SSH certificates, verifiable credentials) are capped at the earliest end among the
// time-limited sources that can allow the action.

import (
	"context"
	"math"

	"github.com/Better-IAM/better-iam/go/core"
)

// documentsGrant reports whether a policy document can allow action.
func documentsGrant(documents []any, action string) bool {
	for _, document := range documents {
		statements, _ := member(core.PolicyValue(document), "statements").([]any)
		for _, statement := range statements {
			if member(statement, "effect") != "allow" {
				continue
			}
			actions, _ := member(statement, "actions").([]any)
			for _, pattern := range actions {
				if text, ok := pattern.(string); ok && core.MatchPattern(text, action, nil) {
					return true
				}
			}
		}
	}
	return false
}

const fiveMinutes = 5 * 60_000

// windowClose is when a recurring window that is open at now closes, searched in five-minute steps up to horizon.
func windowClose(window *core.Object, now, horizon float64) (float64, error) {
	for at := now + fiveMinutes; at < horizon; at += fiveMinutes {
		inside, err := InsideWindow(window, at)
		if err != nil {
			return 0, err
		}
		if !inside {
			return at, nil
		}
	}
	return horizon, nil
}

// GrantDeadline is the latest something may stay valid given the caller's time-limited grants of action: the
// earliest end among the bindings, just-in-time activations, group memberships and access windows that can grant
// it (a grant that ends takes it along; a standing one sets no limit). Assumed roles and temporary sessions are
// bounded by their session instead.
func GrantDeadline(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, horizon float64, action string) (float64, error) {
	kind := principal.Session.Get("kind")
	if (kind != "user" && kind != "api-key") || principal.Identity.Get("tenantId") != tenantID {
		return horizon, nil
	}
	now := float64(server.Now())
	deadline := horizon
	identityID := jsString(principal.Identity.Get("id"))
	bindings, err := server.Decisions.EffectiveBindings(ctx, tx, tenantID, identityID)
	if err != nil {
		return 0, err
	}
	for _, effective := range bindings {
		binding := effective.Binding
		if effective.Role == nil || !server.LiveBinding(binding) || (truthy(binding.Get("eligible")) && effective.Activation == nil) {
			continue
		}
		end := math.Inf(1)
		if expiresAt := binding.Get("expiresAt"); !nullish(expiresAt) {
			end = jsNumber(expiresAt)
		}
		if effective.Activation != nil {
			end = math.Min(end, jsNumber(effective.Activation.Get("expiresAt")))
		}
		if effective.ViaGroupID != "" {
			memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("groupId", effective.ViaGroupID, "identityId", identityID), nil)
			if err != nil {
				return 0, err
			}
			if len(memberships) > 0 {
				if expiresAt := memberships[0].Get("expiresAt"); !isUndefined(expiresAt) {
					end = math.Min(end, jsNumber(expiresAt))
				}
			}
		}
		if window, ok := binding.Get("window").(*core.Object); ok {
			closes, err := windowClose(window, now, horizon)
			if err != nil {
				return 0, err
			}
			end = math.Min(end, closes)
		}
		if end >= deadline {
			continue
		}
		paths, err := server.Decisions.RoleGrants(ctx, tx, effective.Role, tenantID, []any{}, jsString(binding.Get("authorityId")), nil, nil)
		if err != nil {
			return 0, err
		}
		var grants []any
		for _, path := range paths {
			grants = append(grants, path.Grants...)
		}
		if documentsGrant(grants, action) {
			deadline = end
		}
	}
	return deadline, nil
}
