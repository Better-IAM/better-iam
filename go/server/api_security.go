package server

// Port of packages/server/src/api/security.ts: incident response, network blocks. A block refuses every
// authentication flow and every live session whose recorded client IP it covers, and every API key or assumed-role
// token presented from it, for one tenant or, when root administrators set it on the root tenant with `platform`,
// for the whole installation. Lapsed blocks are deleted by the retention worker (`purgeDeleted`).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	securityMinDurationMs = 60_000
	securityMaxDurationMs = 365 * 24 * 60 * 60_000
)

// SecurityAPI is the `security` API group (packages/server/src/api/security.ts createSecurityApi): every method runs through the
// operation envelope; the router maps POST {basePath}/security/{method} onto it.
type SecurityAPI struct {
	server *ServerContext
}

// CreateSecurityAPI builds the `security` API group.
func CreateSecurityAPI(server *ServerContext) *SecurityAPI {
	return &SecurityAPI{server: server}
}

// blockChange runs a block change and clears the cached block lists again once its transaction has committed: the
// clear inside the transaction alone can race a concurrent read that caches the pre-change list for a few seconds.
func (api *SecurityAPI) blockChange(ctx context.Context, credential core.CredentialInput, tenantID any, fn func(ctx context.Context, call MutationContext) (*core.Object, error)) (*core.Object, error) {
	defer api.server.Auth.InvalidateNetworkBlocks()
	return Operate(ctx, api.server.Operations, credential, tenantID, "iam:security:manage", "security/networks", fn, false)
}

// withStatus is the block with `active` (not yet lapsed).
func (api *SecurityAPI) withStatus(block *core.Object) *core.Object {
	expiresAt := block.Get("expiresAt")
	active := isUndefined(expiresAt) || jsNumber(expiresAt) > float64(api.server.Now())
	return block.Spread(core.NewObject("active", active))
}

// platformScope refuses platform-wide blocks to anyone but root administrators acting on the root tenant.
func (api *SecurityAPI) platformScope(ctx context.Context, tx core.IamStore, tenantID any, principal *Principal) error {
	realm, err := api.server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if realm.Get("parentId") != nil {
		return core.NewIamError("ACCESS_DENIED", "Platform-wide blocks are set by root administrators on the root tenant", 403)
	}
	root, err := api.server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return err
	}
	if !root {
		return core.NewIamError("ACCESS_DENIED", "Platform-wide blocks are set by root administrators on the root tenant", 403)
	}
	return nil
}

// rootTenantScope keeps the root tenant's own blocks root administrators' alone: they decide whether root
// administrators can sign in.
func (api *SecurityAPI) rootTenantScope(ctx context.Context, tx core.IamStore, realm *core.Object, principal *Principal) error {
	if realm.Get("parentId") != nil {
		return nil
	}
	root, err := api.server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return err
	}
	if !root {
		return core.NewIamError("ACCESS_DENIED", "Blocks on the root tenant are set by root administrators", 403)
	}
	return nil
}

// BlockNetwork is POST {basePath}/security/blockNetwork. Blocks an IP address or CIDR range for the tenant, or for
// the whole platform, optionally for a limited time. Requires iam:security:manage and recent authentication;
// audited as `security:network-block`.
func (api *SecurityAPI) BlockNetwork(ctx context.Context, credential core.CredentialInput, input In[apitypes.SecurityBlockNetworkInput]) (Out[apitypes.SecurityBlockNetworkOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := api.blockChange(ctx, credential, rawTenantID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := api.rootTenantScope(ctx, tx, call.Tenant, principal); err != nil {
			return nil, err
		}
		rawNetwork, err := Text(input.Get("network"), "network", 64)
		if err != nil {
			return nil, err
		}
		network := core.JSTrim(rawNetwork)
		if !core.IsIPRange(network) {
			return nil, invalidInput("network must be an IPv4/IPv6 address or CIDR block")
		}
		rawReason, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(rawReason)
		if reason == "" {
			return nil, invalidInput("reason is required")
		}
		var durationMs any = core.Undefined
		if raw := input.Get("durationMs"); !isUndefined(raw) {
			value, err := Integer(raw, "durationMs", securityMinDurationMs, securityMaxDurationMs)
			if err != nil {
				return nil, err
			}
			durationMs = value
		}
		platform := input.Get("platform") == true
		if platform {
			if err := api.platformScope(ctx, tx, rawTenantID, principal); err != nil {
				return nil, err
			}
		}
		// Neither the address this session was issued from nor the one this request comes from may be blocked: the
		// first would end the caller's session, the second would refuse their next sign-in and the reauthentication
		// they need to lift the block.
		own := []any{member(principal.Session.Get("client"), "ip")}
		if client := server.Auth.CurrentClient(ctx); client != nil && client.IP != "" {
			own = append(own, client.IP)
		}
		for _, ip := range own {
			if !isUndefined(ip) && core.IPMatches(jsString(ip), network) {
				return nil, invalidInput("That network includes your own address")
			}
		}
		now := server.Now()
		tenantID := jsString(rawTenantID)
		blocks, err := tx.Find(ctx, "authBlocks", core.NewObject("tenantId", rawTenantID), nil)
		if err != nil {
			return nil, err
		}
		var existing *core.Object
		for _, block := range blocks {
			if block.Get("network") == network && truthy(block.Get("platform")) == platform {
				existing = block
				break
			}
		}
		blockID := ID()
		if existing != nil {
			blockID = jsString(existing.Get("id"))
		}
		block := core.NewObject(
			"id", blockID, "tenantId", rawTenantID, "network", network, "reason", reason, "createdAt", now,
			"createdBy", principal.Identity.Get("id"),
		)
		if !isUndefined(durationMs) {
			block.Set("expiresAt", float64(now)+durationMs.(float64))
		}
		if platform {
			block.Set("platform", true)
		}
		if existing != nil {
			if _, err := tx.Put(ctx, "authBlocks", block); err != nil {
				return nil, err
			}
		} else if _, err := tx.Insert(ctx, "authBlocks", block); err != nil {
			return nil, err
		}
		server.Auth.InvalidateNetworkBlocks()
		metadata := core.NewObject("network", network, "reason", reason, "platform", platform)
		if expiresAt := block.Get("expiresAt"); !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		metadata.Set("renewed", existing != nil)
		if err := server.Events.Audit(ctx, tx, principal, "security:network-block", tenantID, blockID, "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.withStatus(block), nil
	})
	return Out[apitypes.SecurityBlockNetworkOutput]{Value: result}, err
}

// ListBlocks is POST {basePath}/security/listBlocks. Lists the tenant's network blocks, newest first, each with
// active telling whether it still applies. Requires iam:security:read.
func (api *SecurityAPI) ListBlocks(ctx context.Context, credential core.CredentialInput, input In[apitypes.SecurityListBlocksInput]) (Out[apitypes.SecurityListBlocksOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:security:read", "security/networks", func(ctx context.Context, call MutationContext) ([]any, error) {
		blocks, err := call.Tx.Find(ctx, "authBlocks", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sortStable(blocks, ByNewest)
		list := make([]any, len(blocks))
		for index, block := range blocks {
			list[index] = api.withStatus(block)
		}
		return list, nil
	}, false)
	return Out[apitypes.SecurityListBlocksOutput]{Value: result}, err
}

// UnblockNetwork is POST {basePath}/security/unblockNetwork. Lifts a network block before it lapses. Requires
// iam:security:manage and recent authentication; audited as `security:network-unblock`.
func (api *SecurityAPI) UnblockNetwork(ctx context.Context, credential core.CredentialInput, input In[apitypes.SecurityUnblockNetworkInput]) (Out[apitypes.SecurityUnblockNetworkOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := api.blockChange(ctx, credential, rawTenantID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := api.rootTenantScope(ctx, tx, call.Tenant, principal); err != nil {
			return nil, err
		}
		blockID, err := Text(input.Get("blockId"), "blockId")
		if err != nil {
			return nil, err
		}
		block, err := server.Scoped(ctx, tx, "authBlocks", blockID, jsString(rawTenantID))
		if err != nil {
			return nil, err
		}
		if truthy(block.Get("platform")) {
			if err := api.platformScope(ctx, tx, rawTenantID, principal); err != nil {
				return nil, err
			}
		}
		if err := tx.Delete(ctx, "authBlocks", jsString(block.Get("id"))); err != nil {
			return nil, err
		}
		server.Auth.InvalidateNetworkBlocks()
		if err := server.Events.Audit(ctx, tx, principal, "security:network-unblock", jsString(rawTenantID), jsString(block.Get("id")), "allow", false,
			core.NewObject("network", block.Get("network"), "platform", truthy(block.Get("platform")))); err != nil {
			return nil, err
		}
		return core.NewObject("success", true), nil
	})
	return Out[apitypes.SecurityUnblockNetworkOutput]{Value: result}, err
}
