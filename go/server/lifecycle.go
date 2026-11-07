package server

// Port of packages/server/src/lifecycle.ts: deployment operations (migrations, root bootstrap and recovery, audit
// retention, and the scheduler jobs). None are HTTP endpoints.
//
// PARTIAL: initialize, bootstrap, recoverRoot and pruneAudit are ported; purgeDeleted, sendAccessDigest,
// sendExpiryReminders and reconcilePackages are stubs returning NOT_IMPLEMENTED.

import (
	"context"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// TenantCollections is every tenant-scoped collection; purging a tenant sweeps each of them.
var TenantCollections = []string{
	"tenants", "identities", "sessions", "grantAuthorities", "policies", "policyVersions", "roles", "bindings", "groups",
	"groupMembers", "accessPackages", "packageAssignments", "packageRequests", "packageRuleIssues", "expiryReminderMarks",
	"trusts", "ownerInvitations", "memberInvitations", "principalBoundaries", "actions", "resourceTypes", "resources",
	"tenantAliases", "tenantDomains", "domainOwners", "tenantHostnames", "licenseSettings", "guestInvitations",
	"guestAccounts", "crossTenantAccess", "classificationSchemes", "clearances", "resourceLabels",
}

// Lifecycle holds the deployment operations (createLifecycle).
type Lifecycle struct {
	server *ServerContext
}

// CreateLifecycle builds the deployment operations.
func CreateLifecycle(server *ServerContext) *Lifecycle { return &Lifecycle{server: server} }

// Initialize runs the migrations and the plugins' migrations, starts the retention window of tenants deleted before
// deletedAt existed, and chains audit events recorded before the hash chain existed.
func (l *Lifecycle) Initialize(ctx context.Context) error {
	server := l.server
	store := server.Store
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	for _, plugin := range server.Plugins {
		if plugin.Migrate == nil {
			continue
		}
		if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error { return plugin.Migrate(ctx, tx) }); err != nil {
			return err
		}
	}
	// Tenants deleted before deletedAt existed start their retention window now.
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		deleted, err := tx.Find(ctx, "tenants", core.NewObject("status", "deleted"), nil)
		if err != nil {
			return err
		}
		for _, realm := range deleted {
			if _, isNumber := realm.Get("deletedAt").(float64); !isNumber {
				if _, err := tx.Put(ctx, "tenants", realm.Spread(core.NewObject("deletedAt", float64(server.Wall())))); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// Audit events recorded before the hash chain existed are chained once, in timestamp order per tenant. Only a
	// tenant without a chain yet is backfilled.
	return store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		found, err := tx.Find(ctx, "audit", core.NewObject("sequence", core.Undefined), nil)
		if err != nil {
			return err
		}
		var loose []*core.Object
		for _, event := range found {
			if _, isNumber := event.Get("sequence").(float64); !isNumber {
				loose = append(loose, event)
			}
		}
		chainless := map[string]bool{}
		checked := map[string]bool{}
		for _, event := range loose {
			tenantID := jsString(event.Get("tenantId"))
			if checked[tenantID] {
				continue
			}
			checked[tenantID] = true
			chain, err := tx.Get(ctx, "auditChains", tenantID)
			if err != nil {
				return err
			}
			if chain == nil {
				chainless[tenantID] = true
			}
		}
		var pending []*core.Object
		for _, event := range loose {
			if chainless[jsString(event.Get("tenantId"))] {
				pending = append(pending, event)
			}
		}
		sort.SliceStable(pending, func(i, j int) bool {
			a, b := pending[i], pending[j]
			if order := compareUTF16(jsString(a.Get("tenantId")), jsString(b.Get("tenantId"))); order != 0 {
				return order < 0
			}
			if left, right := jsNumber(a.Get("timestamp")), jsNumber(b.Get("timestamp")); left != right {
				return left < right
			}
			return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		for _, event := range pending {
			chained, err := core.ChainAuditEvent(ctx, tx, event)
			if err != nil {
				return err
			}
			if _, err := tx.Put(ctx, "audit", chained); err != nil {
				return err
			}
		}
		return nil
	})
}

// Bootstrap creates the installation root tenant and its first root administrator ({ email, name, password,
// rootName?, slug? }). It answers { tenant, identity, mfaEnrollmentRequired: true }.
func (l *Lifecycle) Bootstrap(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := l.server
	if input == nil {
		input = core.NewObject()
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		roots, err := tx.Find(ctx, "tenants", core.NewObject("parentId", nil), nil)
		if err != nil {
			return nil, err
		}
		if len(roots) > 0 {
			return nil, core.NewIamError("ALREADY_INITIALIZED", "Root already exists", 409)
		}
		rootName := input.Get("rootName")
		if nullish(rootName) {
			rootName = "Platform"
		}
		id := ID()
		realm := core.NewObject(
			"id", id, "tenantId", id, "uniqueKey", "installation-root", "name", rootName, "type", "root", "parentId", nil,
			"status", "active", "createdAt", float64(server.Wall()),
		)
		if slug := input.Get("slug"); !isUndefined(slug) {
			alias, err := server.ClaimSlug(ctx, tx, id, slug)
			if err != nil {
				return nil, err
			}
			realm.Set("slug", alias)
		}
		if _, err := tx.Insert(ctx, "tenants", realm); err != nil {
			return nil, err
		}
		email, err := Email(input.Get("email"))
		if err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name")
		if err != nil {
			return nil, err
		}
		identity, err := server.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: id, Email: email, Name: name, Password: input.Get("password"), HasPassword: true,
			Owner: true, RootAdmin: true, EmailVerified: true,
		})
		if err != nil {
			return nil, err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject(
			"id", ID(), "tenantId", id, "identityId", identity.Get("id"), "ceiling", All(), "revoked", false,
		))
		if err != nil {
			return nil, err
		}
		if err := server.OwnerSetup(ctx, tx, realm, identity, authority); err != nil {
			return nil, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", id, "actorId", "deployment-operator", "action", "root:bootstrap",
			"resourceId", identity.Get("id"), "timestamp", float64(server.Wall()), "outcome", "allow",
		)); err != nil {
			return nil, err
		}
		return core.NewObject("tenant", realm, "identity", PublicIdentity(identity), "mfaEnrollmentRequired", true), nil
	})
}

// RecoverRoot adds a root administrator to the installation root ({ email, name, password }): the deployment
// operator's recovery path when every root administrator is lost.
func (l *Lifecycle) RecoverRoot(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := l.server
	if input == nil {
		input = core.NewObject()
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		roots, err := tx.Find(ctx, "tenants", core.NewObject("parentId", nil), nil)
		if err != nil {
			return nil, err
		}
		if len(roots) == 0 {
			return nil, core.NewIamError("NOT_INITIALIZED", "Bootstrap first")
		}
		realm := roots[0]
		email, err := Email(input.Get("email"))
		if err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name")
		if err != nil {
			return nil, err
		}
		identity, err := server.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: realm.Get("id"), Email: email, Name: name, Password: input.Get("password"), HasPassword: true,
			RootAdmin: true, EmailVerified: true,
		})
		if err != nil {
			return nil, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", realm.Get("id"), "actorId", "deployment-operator", "action", "root:recover",
			"resourceId", identity.Get("id"), "timestamp", float64(server.Wall()), "outcome", "allow",
		)); err != nil {
			return nil, err
		}
		return core.NewObject("identity", PublicIdentity(identity), "tenantId", realm.Get("id"), "mfaEnrollmentRequired", true), nil
	})
}

// PruneAudit deletes a tenant's oldest chained events (the longest prefix older than the cutoff, and only what the
// audit archive already holds) and appends an `audit:prune` checkpoint ({ tenantId, retentionMs }).
func (l *Lifecycle) PruneAudit(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := l.server
	if input == nil {
		input = core.NewObject()
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	retentionMs, err := Integer(input.Get("retentionMs"), "retentionMs", 0, 100*365*86400000)
	if err != nil {
		return nil, err
	}
	cutoff := float64(server.Wall()) - retentionMs
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		var last *core.Object
		deleted, held := 0.0, false
		// Once a tenant is being archived (a cursor exists), or wherever an archive is configured, only events the
		// archive already holds may leave the database.
		cursor, err := tx.Get(ctx, "auditArchiveCursors", tenantID)
		if err != nil {
			return nil, err
		}
		archivedThrough := math.Inf(1)
		if cursor != nil || server.Options.AuditArchive != nil {
			archivedThrough = 0
			if cursor != nil {
				archivedThrough = jsNumber(cursor.Get("sequence"))
			}
		}
		limit := 1000
		for from, done := 1.0, false; !done; {
			start := from
			page, err := core.FindOrdered(ctx, tx, "audit", core.NewObject("tenantId", tenantID), core.OrderOptions{Field: "sequence", From: &start, Limit: &limit}, nil)
			if err != nil {
				return nil, err
			}
			for _, event := range page {
				if jsNumber(event.Get("timestamp")) >= cutoff {
					done = true
					break
				}
				if jsNumber(event.Get("sequence")) > archivedThrough {
					held, done = true, true
					break
				}
				if err := tx.Delete(ctx, "audit", jsString(event.Get("id"))); err != nil {
					return nil, err
				}
				last = event
				deleted++
			}
			if len(page) < 1000 {
				done = true
			} else {
				from = jsNumber(page[len(page)-1].Get("sequence")) + 1
			}
		}
		if last == nil {
			result := core.NewObject("deleted", 0.0)
			if held {
				result.Set("heldForArchive", true)
			}
			return result, nil
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", tenantID, "actorId", "deployment-operator", "action", "audit:prune",
			"resourceId", tenantID, "timestamp", float64(server.Wall()), "outcome", "allow",
			"metadata", core.NewObject("deleted", deleted, "before", cutoff, "prunedThroughSequence", last.Get("sequence"), "prunedThroughHash", last.Get("hash")),
		)); err != nil {
			return nil, err
		}
		result := core.NewObject("deleted", deleted, "prunedThroughSequence", last.Get("sequence"), "prunedThroughHash", last.Get("hash"))
		if held {
			result.Set("heldForArchive", true)
		}
		return result, nil
	})
}

// PurgeDeleted is the retention worker: purges tenants deleted longer ago than the retention window and expires
// bindings, requests, identities, activations, memberships and assignments past their end.
//
// STUB: returns NOT_IMPLEMENTED until lifecycle.ts purgeDeleted is ported.
func (l *Lifecycle) PurgeDeleted(ctx context.Context, input *core.Object) (*core.Object, error) {
	return nil, notImplemented("lifecycle.ts purgeDeleted")
}

// SendAccessDigest emails each organization's owners its access report when there is something to report.
//
// STUB: returns NOT_IMPLEMENTED until lifecycle.ts sendAccessDigest is ported.
func (l *Lifecycle) SendAccessDigest(ctx context.Context, input *core.Object) (*core.Object, error) {
	return nil, notImplemented("lifecycle.ts sendAccessDigest")
}

// SendExpiryReminders emails each person whose access ends soon a reminder listing it, once per item.
//
// STUB: returns NOT_IMPLEMENTED until lifecycle.ts sendExpiryReminders is ported.
func (l *Lifecycle) SendExpiryReminders(ctx context.Context, input *core.Object) (*core.Object, error) {
	return nil, notImplemented("lifecycle.ts sendExpiryReminders")
}

// ReconcilePackages assigns and removes rule-based (birthright) access packages under each rule owner's authority.
//
// STUB: returns NOT_IMPLEMENTED until lifecycle.ts reconcilePackages is ported.
func (l *Lifecycle) ReconcilePackages(ctx context.Context, input *core.Object) (*core.Object, error) {
	return nil, notImplemented("lifecycle.ts reconcilePackages")
}
