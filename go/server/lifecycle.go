package server

// Port of packages/server/src/lifecycle.ts: deployment operations (migrations, root bootstrap and recovery, audit
// retention, and the scheduler jobs). None are HTTP endpoints.

import (
	"context"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// TenantCollections is every tenant-scoped collection; purging a tenant sweeps each of them.
var TenantCollections = []string{
	"tenants", "identities", "sessions", "grantAuthorities", "policies", "policyVersions", "roles", "bindings",
	"groups", "groupMembers", "accessPackages", "packageAssignments", "packageRequests", "packageRuleIssues",
	"expiryReminderMarks", "trusts", "ownerInvitations", "memberInvitations", "principalBoundaries", "actions",
	"resourceTypes", "resources", "tenantAliases", "tenantDomains", "domainOwners", "tenantHostnames",
	"hostnameOwners", "analysisSuppressions", "certificationCampaigns", "certificationItems", "sodRules",
	"externalIdentities", "authMfa", "passwordHistory", "authChallenges", "authPasskeys", "authDevices",
	"authSignIns", "authBlocks", "authRateLimits", "outbox", "accessRequests", "bindingActivations", "webhooks",
	"relationships", "scimConnections", "scimUsers", "scimGroups", "oauthClients", "oauthArtifacts",
	"oauthGrantSessions", "oauthLoginStates", "oauthRegistrationTokens", "samlRequests", "samlRelays",
	"samlConnections", "samlAssertions", "provisioningTargets", "provisioningLinks", "provisioningGroupLinks",
	"ssfStreams", "ssfDeliveries", "accessUsage", "accessUsageTracking", "accessInvariants", "agreements",
	"agreementAcceptances", "oidcProviders", "webIdentityReplays", "featureFlags", "featureTargets",
	"onboardingFlows", "onboardingSettings", "onboardingProgress", "delegations", "delegationConfirmations",
	"delegationTokens", "agentCards", "inferenceProviders", "inferenceModels", "inferenceBudgets",
	"inferenceCounters", "inferenceUsage", "inferenceTickets", "inferenceResponses", "teams", "teamMembers",
	"teamJoinRequests", "teamReviews", "teamReviewItems", "departments", "departmentMembers", "billingMeters",
	"billingPrices", "billingUsage", "billingRollups", "billingBudgets", "billingBudgetAlerts", "billingCredits",
	"billingProfiles", "billingStatements", "billingTerms", "billingInvoiceItems", "billingCreditNotes",
	"billingPlans", "billingSubscriptions", "billingCoupons", "billingDiscounts", "kmsKeys", "kmsKeyVersions",
	"kmsAliases", "kmsGrants", "pkiAuthorities", "pkiCertificates", "protectionProfiles", "protectionTokens",
	"vaultSecrets", "vaultVersions", "vaultLeases", "vaultAccess", "quotaPlans", "quotaAssignments", "quotaCounters",
	"privacyPurposes", "privacyConsents", "privacyConsentEvents", "privacyRequests", "privacyExports", "privacyHolds",
	"privacyRestrictions", "privacySettings", "workflows", "workflowRuns", "workflowSubjects", "complianceControls",
	"complianceExceptions", "complianceResults", "complianceRuns", "complianceCheckpoints", "applications",
	"appAssignments", "appLaunches", "sshSettings", "sshAuthorities", "sshHosts", "sshCertificates", "vcIssuerKeys",
	"vcCredentialTypes", "vcIssued", "vcStatusLists", "vcOffers", "vcNonces", "ldapSettings", "ldapBases",
	"threatDetections", "threatIncidents", "threatNotes", "identityRisk", "threatBaselines", "threatCursors",
	"threatSettings", "threatPlaybooks", "threatResponses", "registeredDevices", "deviceKeys", "deviceEnrollments",
	"deviceIntegrations", "deviceSettings", "signalSources", "signalEvents", "licenseProducts", "licensePools",
	"licenseAssignments", "licenseSeats", "licenseSettings", "guestInvitations", "guestAccounts", "crossTenantAccess",
	"classificationSchemes", "clearances", "resourceLabels",
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

// lengthAt is `value.length` of a report list (0 when it is not a list).
func lengthAt(value any) float64 {
	if items, ok := value.([]any); ok {
		return float64(len(items))
	}
	return 0
}

// scheduledTenants is the tenants a scheduler job visits: the one `tenantId` names, else every active tenant by ID.
func scheduledTenants(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) ([]*core.Object, error) {
	if requested := input.Get("tenantId"); truthy(requested) {
		tenantID, err := Text(requested, "tenantId")
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		return []*core.Object{tenant}, nil
	}
	tenants, err := tx.Find(ctx, "tenants", core.NewObject("status", "active"), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(tenants, func(i, j int) bool {
		return compareUTF16(jsString(tenants[i].Get("id")), jsString(tenants[j].Get("id"))) < 0
	})
	return tenants, nil
}

// requireEmailDelivery refuses a scheduler job that emails people when no email delivery callback is configured.
func (l *Lifecycle) requireEmailDelivery(message string) error {
	if authentication := l.server.Options.Authentication; authentication == nil || authentication.SendEmail == nil {
		return core.NewIamError("DELIVERY_REQUIRED", message)
	}
	return nil
}

// SendAccessDigest is the access digest: it emails the owners of every active tenant (or one `tenantId`) whose access
// report has findings (`access-digest` template with the counts and the full report as JSON), at most once per
// `minimumIntervalMs` (20 hours by default) per tenant, recorded as `tenant:access-digest`. A deployment operation for
// schedulers: no credential, every report section included. Requires an email delivery callback.
func (l *Lifecycle) SendAccessDigest(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := l.server
	if input == nil {
		input = core.NewObject()
	}
	windows, err := ReportWindows(input)
	if err != nil {
		return nil, err
	}
	minimumIntervalMs, err := Integer(coalesce(input.Get("minimumIntervalMs"), 20*3_600_000.0), "minimumIntervalMs", 0, 365*86400000)
	if err != nil {
		return nil, err
	}
	if err := l.requireEmailDelivery("The access digest requires an email delivery callback"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenants, err := scheduledTenants(ctx, server, tx, input)
		if err != nil {
			return nil, err
		}
		sent := []any{}
		inactive, recent, quiet, noOwners := 0.0, 0.0, 0.0, 0.0
		for _, tenant := range tenants {
			if tenant.Get("status") != "active" {
				inactive++
				continue
			}
			tenantID := jsString(tenant.Get("id"))
			since := float64(server.Now()) - minimumIntervalMs
			digests, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "action", "tenant:access-digest"), nil)
			if err != nil {
				return nil, err
			}
			digested := false
			for _, event := range digests {
				if jsNumber(event.Get("timestamp")) > since {
					digested = true
					break
				}
			}
			if digested {
				recent++
				continue
			}
			report, err := BuildAccessReport(ctx, server, tx, tenantID, windows, core.NewObject("bindings", true, "credentials", true))
			if err != nil {
				return nil, err
			}
			findings, err := ReportHasFindings(report)
			if err != nil {
				return nil, err
			}
			if !findings {
				quiet++
				continue
			}
			candidates, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "owner", true, "status", "active"), nil)
			if err != nil {
				return nil, err
			}
			var owners []*core.Object
			for _, owner := range candidates {
				if truthy(owner.Get("email")) {
					owners = append(owners, owner)
				}
			}
			if len(owners) == 0 {
				noOwners++
				continue
			}
			bindings, credentials := report.Get("bindings"), report.Get("credentials")
			counts := core.NewObject(
				"expiringIdentities", lengthAt(member(report.Get("identities"), "expiring")),
				"expiringBindings", lengthAt(member(bindings, "expiring")),
				"startingBindings", lengthAt(member(bindings, "starting")),
				"expiringMemberships", lengthAt(member(bindings, "expiringMemberships")),
				"activations", lengthAt(member(bindings, "activations")),
				"pendingRequests", coalesce(member(bindings, "pendingRequests"), 0.0),
				"unusedKeys", lengthAt(member(credentials, "unused")),
				"expiringKeys", lengthAt(member(credentials, "expiring")),
			)
			reportJSON, _, err := core.Stringify(report)
			if err != nil {
				return nil, err
			}
			payload := core.NewObject(
				"tenantId", tenantID, "tenantName", tenant.Get("name"), "generatedAt", jsString(report.Get("generatedAt")),
				"withinMs", jsString(windows.Get("withinMs")), "unusedForMs", jsString(windows.Get("unusedForMs")),
			)
			counts.Entries(func(key string, value any) bool {
				payload.Set(key, jsString(value))
				return true
			})
			payload.Set("report", reportJSON)
			for _, owner := range owners {
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: tenantID, Kind: "email", To: jsString(owner.Get("email")), Template: "access-digest", Payload: payload,
				}); err != nil {
					return nil, err
				}
			}
			recipients := float64(len(owners))
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(), "tenantId", tenantID, "actorId", "deployment-operator", "action", "tenant:access-digest",
				"resourceId", tenantID, "timestamp", float64(server.Now()), "outcome", "allow",
				"metadata", core.NewObject("recipients", recipients).Assign(counts),
			)); err != nil {
				return nil, err
			}
			sent = append(sent, core.NewObject("tenantId", tenantID, "recipients", recipients).Assign(counts))
		}
		return core.NewObject("sent", sent, "skipped", core.NewObject(
			"inactive", inactive, "recent", recent, "quiet", quiet, "noOwners", noOwners,
		)), nil
	})
}

// expiryItem is one thing an expiry reminder lists.
type expiryItem struct {
	key       string
	kind      string
	name      any
	expiresAt float64
}

// SendExpiryReminders emails each person whose account, direct role bindings, group memberships, or package
// assignments end within `withinMs` (seven days by default) one `expiry-reminder` message listing them, once per item
// and end date (moving the end triggers a fresh reminder), recorded as `identity:expiry-reminder`. Group bindings are
// left to the owners' digest. A deployment operation for schedulers; requires an email delivery callback.
func (l *Lifecycle) SendExpiryReminders(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := l.server
	if input == nil {
		input = core.NewObject()
	}
	withinMs, err := Integer(coalesce(input.Get("withinMs"), 7*86400000.0), "withinMs", 60_000, 365*86400000)
	if err != nil {
		return nil, err
	}
	if err := l.requireEmailDelivery("Expiry reminders require an email delivery callback"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenants, err := scheduledTenants(ctx, server, tx, input)
		if err != nil {
			return nil, err
		}
		sent := []any{}
		inactive, quiet := 0.0, 0.0
		for _, tenant := range tenants {
			if tenant.Get("status") != "active" {
				inactive++
				continue
			}
			reminders, err := l.remindTenant(ctx, tx, tenant, withinMs)
			if err != nil {
				return nil, err
			}
			if len(reminders) == 0 {
				quiet++
			}
			sent = append(sent, reminders...)
		}
		return core.NewObject("sent", sent, "skipped", core.NewObject("inactive", inactive, "quiet", quiet)), nil
	})
}

// remindTenant sends one tenant's expiry reminders and answers the `sent` entries.
func (l *Lifecycle) remindTenant(ctx context.Context, tx core.IamStore, tenant *core.Object, withinMs float64) ([]any, error) {
	server := l.server
	tenantID := jsString(tenant.Get("id"))
	now := float64(server.Now())
	horizon := now + withinMs
	ending := func(expiresAt any) bool {
		if isUndefined(expiresAt) {
			return false
		}
		at := jsNumber(expiresAt)
		return at > now && at <= horizon
	}
	// What was already reminded: marks kept until the item ends (they survive audit pruning), plus the audit trail of
	// runs made before marks existed.
	reminded := map[string]bool{}
	marks, err := tx.Find(ctx, "expiryReminderMarks", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, mark := range marks {
		reminded[jsString(mark.Get("uniqueKey"))] = true
	}
	events, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "action", "identity:expiry-reminder"), nil)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		keys, _ := member(event.Get("metadata"), "items").([]any)
		for _, key := range keys {
			if text, ok := key.(string); ok {
				reminded[text] = true
			}
		}
	}
	assignments, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	// A package's own bindings and memberships are reminded as the package, while it still exists.
	assignmentIDs := map[string]bool{}
	for _, assignment := range assignments {
		assignmentIDs[jsString(assignment.Get("id"))] = true
	}
	packaged := func(record *core.Object) bool {
		assignmentID := record.Get("packageAssignmentId")
		return !isUndefined(assignmentID) && assignmentIDs[jsString(assignmentID)]
	}
	items := map[string][]expiryItem{}
	var order []string
	add := func(identityID string, item expiryItem) {
		if reminded[item.key] {
			return
		}
		if _, seen := items[identityID]; !seen {
			order = append(order, identityID)
		}
		items[identityID] = append(items[identityID], item)
	}
	identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "status", "active"), nil)
	if err != nil {
		return nil, err
	}
	byID := map[string]*core.Object{}
	for _, identity := range identities {
		byID[jsString(identity.Get("id"))] = identity
	}
	for _, identity := range identities {
		if expiresAt := identity.Get("expiresAt"); ending(expiresAt) {
			add(jsString(identity.Get("id")), expiryItem{
				key: "identity:" + jsString(identity.Get("id")) + ":" + jsString(expiresAt), kind: "account",
				name: identity.Get("name"), expiresAt: jsNumber(expiresAt),
			})
		}
	}
	names := func(collection string) (map[string]any, error) {
		records, err := tx.Find(ctx, collection, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		result := map[string]any{}
		for _, record := range records {
			result[jsString(record.Get("id"))] = record.Get("name")
		}
		return result, nil
	}
	// nameOr is `names.get(id) ?? id`.
	nameOr := func(table map[string]any, id any) any {
		if name, ok := table[jsString(id)]; ok && !nullish(name) {
			return name
		}
		return id
	}
	roles, err := names("roles")
	if err != nil {
		return nil, err
	}
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity"), nil)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		expiresAt := binding.Get("expiresAt")
		if ending(expiresAt) && server.LiveBinding(binding) && !truthy(binding.Get("eligible")) && !packaged(binding) {
			add(jsString(binding.Get("subjectId")), expiryItem{
				key: "binding:" + jsString(binding.Get("id")) + ":" + jsString(expiresAt), kind: "role",
				name: nameOr(roles, binding.Get("roleId")), expiresAt: jsNumber(expiresAt),
			})
		}
	}
	groups, err := names("groups")
	if err != nil {
		return nil, err
	}
	memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, membership := range memberships {
		expiresAt := membership.Get("expiresAt")
		if ending(expiresAt) && server.LiveMembership(membership) && !packaged(membership) {
			add(jsString(membership.Get("identityId")), expiryItem{
				key: "membership:" + jsString(membership.Get("id")) + ":" + jsString(expiresAt), kind: "group",
				name: nameOr(groups, membership.Get("groupId")), expiresAt: jsNumber(expiresAt),
			})
		}
	}
	packages, err := names("accessPackages")
	if err != nil {
		return nil, err
	}
	for _, assignment := range assignments {
		if expiresAt := assignment.Get("expiresAt"); ending(expiresAt) {
			add(jsString(assignment.Get("identityId")), expiryItem{
				key: "package:" + jsString(assignment.Get("id")) + ":" + jsString(expiresAt), kind: "package",
				name: nameOr(packages, assignment.Get("packageId")), expiresAt: jsNumber(expiresAt),
			})
		}
	}
	sent := []any{}
	sort.SliceStable(order, func(i, j int) bool { return compareUTF16(order[i], order[j]) < 0 })
	for _, identityID := range order {
		list := items[identityID]
		identity := byID[identityID]
		if identity == nil || !truthy(identity.Get("email")) {
			continue
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].expiresAt < list[j].expiresAt })
		summary := make([]any, 0, len(list))
		keys := make([]any, 0, len(list))
		for _, item := range list {
			summary = append(summary, core.NewObject("kind", item.kind, "name", item.name, "expiresAt", item.expiresAt))
			keys = append(keys, item.key)
		}
		itemsJSON, _, err := core.Stringify(summary)
		if err != nil {
			return nil, err
		}
		count := float64(len(list))
		if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID, Kind: "email", To: jsString(identity.Get("email")), Template: "expiry-reminder",
			Payload: core.NewObject(
				"tenantId", tenantID, "tenantName", tenant.Get("name"), "identityName", identity.Get("name"),
				"count", jsString(count), "earliest", jsString(list[0].expiresAt), "items", itemsJSON,
			),
		}); err != nil {
			return nil, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(), "tenantId", tenantID, "actorId", "deployment-operator", "action", "identity:expiry-reminder",
			"resourceId", identity.Get("id"), "timestamp", now, "outcome", "allow",
			"metadata", core.NewObject("count", count, "earliest", list[0].expiresAt, "items", keys),
		)); err != nil {
			return nil, err
		}
		for _, item := range list {
			if _, err := tx.Insert(ctx, "expiryReminderMarks", core.NewObject(
				"id", ID(), "tenantId", tenantID, "uniqueKey", item.key, "identityId", identityID, "expiresAt", item.expiresAt,
			)); err != nil {
				return nil, err
			}
		}
		sent = append(sent, core.NewObject("tenantId", tenantID, "identityId", identityID, "items", count))
	}
	return sent, nil
}

// ReconcilePackages is birthright access: it applies every access-package rule (or one tenant's, or one package's)
// under its owner's grant authority. At most `limit` changes per organization (1000); `truncated` means run again.
// Unusually large changes are held back unless `confirm` (with `packageId`). A scheduler job: no credential.
func (l *Lifecycle) ReconcilePackages(ctx context.Context, input *core.Object) (*core.Object, error) {
	if input == nil {
		input = core.NewObject()
	}
	tenantID, packageID := "", ""
	if value := input.Get("tenantId"); !isUndefined(value) {
		text, err := Text(value, "tenantId")
		if err != nil {
			return nil, err
		}
		tenantID = text
	}
	if value := input.Get("packageId"); !isUndefined(value) {
		text, err := Text(value, "packageId")
		if err != nil {
			return nil, err
		}
		packageID = text
	}
	if packageID != "" && tenantID == "" {
		return nil, invalidInput("packageId needs tenantId")
	}
	confirm := input.Get("confirm")
	if !isUndefined(confirm) && typeOf(confirm) != "boolean" {
		return nil, invalidInput("confirm must be boolean")
	}
	if confirm == true && packageID == "" {
		return nil, invalidInput("confirm needs packageId")
	}
	limit, err := Integer(coalesce(input.Get("limit"), 1000.0), "limit", 1, 10000)
	if err != nil {
		return nil, err
	}
	options := core.NewObject()
	if tenantID != "" {
		options.Set("tenantId", tenantID)
	}
	if packageID != "" {
		options.Set("packageId", packageID)
	}
	options.Set("limit", limit)
	options.Set("trigger", "schedule")
	if confirm == true {
		options.Set("confirmedBy", "deployment-operator")
	}
	return ReconcilePackageRules(ctx, l.server, options)
}

// PurgeDeleted is the retention worker: it removes tombstoned tenants past the retention window, deletes expired
// temporary bindings and ended role activations, marks pending access requests past their lifetime as expired, and
// disables identities past their scheduled deactivation (`identity:expire`, sessions revoked). Audit records are
// preserved. It also deletes authentication bookkeeping past its end in every tenant, known or not: rate-limit
// counters past their window, challenges past their expiry, and lapsed network blocks.
func (l *Lifecycle) PurgeDeleted(ctx context.Context, input *core.Object) (*core.Object, error) {
	server := l.server
	if input == nil {
		input = core.NewObject()
	}
	retentionMs, err := Integer(coalesce(input.Get("retentionMs"), 2592000000.0), "retentionMs", 0, 315360000000)
	if err != nil {
		return nil, err
	}
	cutoff := float64(server.Wall()) - retentionMs
	if err := sweepExpiredAuthRecords(ctx, server); err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		expiredBindings, expiredRequests, expiredIdentities := 0.0, 0.0, 0.0
		expiredActivations, expiredMemberships, expiredAssignments := 0.0, 0.0, 0.0
		now := func() float64 { return float64(server.Now()) }
		deleteActivations := func(filter *core.Object) (float64, error) {
			activations, err := tx.Find(ctx, "bindingActivations", filter, nil)
			if err != nil {
				return 0, err
			}
			for _, activation := range activations {
				if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
					return 0, err
				}
			}
			return float64(len(activations)), nil
		}
		bindings, err := tx.Find(ctx, "bindings", nil, nil)
		if err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if !server.ExpiredBinding(binding) {
				continue
			}
			// Activations of a binding that is gone could never grant again.
			removed, err := deleteActivations(core.NewObject("tenantId", binding.Get("tenantId"), "bindingId", binding.Get("id")))
			if err != nil {
				return nil, err
			}
			expiredActivations += removed
			if err := tx.Delete(ctx, "bindings", jsString(binding.Get("id"))); err != nil {
				return nil, err
			}
			expiredBindings++
		}
		activations, err := tx.Find(ctx, "bindingActivations", nil, nil)
		if err != nil {
			return nil, err
		}
		for _, activation := range activations {
			if jsNumber(activation.Get("expiresAt")) <= now() {
				if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
					return nil, err
				}
				expiredActivations++
			}
		}
		// A lapsed membership ends the person's activations of that group's eligible bindings too.
		memberships, err := tx.Find(ctx, "groupMembers", nil, nil)
		if err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			if server.LiveMembership(membership) {
				continue
			}
			groupBindings, err := tx.Find(ctx, "bindings", core.NewObject(
				"tenantId", membership.Get("tenantId"), "subjectType", "group", "subjectId", membership.Get("groupId"),
			), nil)
			if err != nil {
				return nil, err
			}
			for _, binding := range groupBindings {
				if _, err := deleteActivations(core.NewObject(
					"tenantId", membership.Get("tenantId"), "bindingId", binding.Get("id"), "identityId", membership.Get("identityId"),
				)); err != nil {
					return nil, err
				}
			}
			if err := tx.Delete(ctx, "groupMembers", jsString(membership.Get("id"))); err != nil {
				return nil, err
			}
			expiredMemberships++
		}
		assignments, err := tx.Find(ctx, "packageAssignments", nil, nil)
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			if expiresAt := assignment.Get("expiresAt"); !isUndefined(expiresAt) && jsNumber(expiresAt) <= now() {
				if err := tx.Delete(ctx, "packageAssignments", jsString(assignment.Get("id"))); err != nil {
					return nil, err
				}
				expiredAssignments++
			}
		}
		for _, collection := range []string{"accessRequests", "packageRequests"} {
			requests, err := tx.Find(ctx, collection, core.NewObject("status", "pending"), nil)
			if err != nil {
				return nil, err
			}
			for _, request := range requests {
				if jsNumber(request.Get("expiresAt")) <= now() {
					if _, err := tx.Put(ctx, collection, request.Spread(core.NewObject("status", "expired"))); err != nil {
						return nil, err
					}
					expiredRequests++
				}
			}
		}
		// Reminder marks are only needed until the item they remember has ended.
		marks, err := tx.Find(ctx, "expiryReminderMarks", nil, nil)
		if err != nil {
			return nil, err
		}
		for _, mark := range marks {
			if jsNumber(mark.Get("expiresAt")) <= now() {
				if err := tx.Delete(ctx, "expiryReminderMarks", jsString(mark.Get("id"))); err != nil {
					return nil, err
				}
			}
		}
		identities, err := tx.Find(ctx, "identities", core.NewObject("status", "active"), nil)
		if err != nil {
			return nil, err
		}
		for _, identity := range identities {
			if !server.IdentityExpired(identity) {
				continue
			}
			if _, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("status", "disabled"))); err != nil {
				return nil, err
			}
			if err := server.RevokeAll(ctx, tx, jsString(identity.Get("id"))); err != nil {
				return nil, err
			}
			removed, err := deleteActivations(core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")))
			if err != nil {
				return nil, err
			}
			expiredActivations += removed
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(), "tenantId", identity.Get("tenantId"), "actorId", "deployment-operator", "action", "identity:expire",
				"resourceId", identity.Get("id"), "timestamp", float64(server.Wall()), "outcome", "allow",
				"metadata", core.NewObject("kind", identity.Get("kind"), "expiresAt", identity.Get("expiresAt")),
			)); err != nil {
				return nil, err
			}
			expiredIdentities++
		}
		result := func(purgedTenants []any, deletedRecords float64) *core.Object {
			return core.NewObject(
				"purgedTenants", purgedTenants, "deletedRecords", deletedRecords, "expiredBindings", expiredBindings,
				"expiredRequests", expiredRequests, "expiredIdentities", expiredIdentities,
				"expiredActivations", expiredActivations, "expiredMemberships", expiredMemberships,
				"expiredAssignments", expiredAssignments,
			)
		}
		realms, err := tx.Find(ctx, "tenants", nil, nil)
		if err != nil {
			return nil, err
		}
		var roots []*core.Object
		for _, realm := range realms {
			deletedAt, isNumber := realm.Get("deletedAt").(float64)
			if realm.Get("status") == "deleted" && isNumber && deletedAt <= cutoff {
				roots = append(roots, realm)
			}
		}
		if len(roots) == 0 {
			return result([]any{}, 0), nil
		}
		maxDepth := server.Config.MaxDepth
		subtreeOf := func(ids ...string) *orderedSet {
			set := newOrderedSet(ids...)
			for depth := 0; depth < maxDepth; depth++ {
				for _, realm := range realms {
					if parentID := realm.Get("parentId"); truthy(parentID) && set.Has(jsString(parentID)) {
						set.Add(jsString(realm.Get("id")))
					}
				}
			}
			return set
		}
		rootIDs := make([]string, 0, len(roots))
		for _, root := range roots {
			rootIDs = append(rootIDs, jsString(root.Get("id")))
		}
		purged := subtreeOf(rootIDs...)
		identityIDs := map[string]bool{}
		for _, tenantID := range purged.Values() {
			found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return nil, err
			}
			for _, identity := range found {
				identityIDs[jsString(identity.Get("id"))] = true
			}
		}
		deletedRecords := 0.0
		remove := func(collection string, record *core.Object) error {
			if err := tx.Delete(ctx, collection, jsString(record.Get("id"))); err != nil {
				return err
			}
			deletedRecords++
			return nil
		}
		for _, tenantID := range purged.Values() {
			for _, collection := range TenantCollections {
				rows, err := tx.Find(ctx, collection, core.NewObject("tenantId", tenantID), nil)
				if err != nil {
					return nil, err
				}
				for _, row := range rows {
					if err := remove(collection, row); err != nil {
						return nil, err
					}
				}
			}
		}
		// Records in surviving tenants that reference purged tenants or identities become dead references.
		dangling := []struct {
			collection string
			dead       func(record *core.Object) bool
		}{
			{"sessions", func(session *core.Object) bool {
				source := session.Get("sourceTenantId")
				return truthy(source) && purged.Has(jsString(source))
			}},
			{"trusts", func(trust *core.Object) bool {
				source, ok := trust.Get("sourceTenantId").(string)
				return ok && purged.Has(source)
			}},
			{"identityLinks", func(link *core.Object) bool {
				left, leftOK := link.Get("leftId").(string)
				right, rightOK := link.Get("rightId").(string)
				return (leftOK && identityIDs[left]) || (rightOK && identityIDs[right])
			}},
			{"oauthArtifacts", func(artifact *core.Object) bool {
				account, ok := artifact.Get("accountId").(string)
				return ok && identityIDs[account]
			}},
		}
		for _, sweep := range dangling {
			rows, err := tx.Find(ctx, sweep.collection, nil, nil)
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				if sweep.dead(row) {
					if err := remove(sweep.collection, row); err != nil {
						return nil, err
					}
				}
			}
		}
		for _, plugin := range server.Plugins {
			if plugin.Purge != nil {
				if err := plugin.Purge(ctx, tx, purged.Values()); err != nil {
					return nil, err
				}
			}
		}
		// Audit records survive the purge so the deletion trail remains queryable.
		for _, root := range roots {
			subtree := subtreeOf(jsString(root.Get("id")))
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(), "tenantId", root.Get("id"), "actorId", "deployment-operator", "action", "tenants:purge",
				"resourceId", root.Get("id"), "timestamp", float64(server.Wall()), "outcome", "allow",
				"metadata", core.NewObject("tenantIds", stringsOf(subtree.Values()), "deletedRecords", deletedRecords),
			)); err != nil {
				return nil, err
			}
		}
		purgedTenants := purged.Values()
		sort.SliceStable(purgedTenants, func(i, j int) bool { return compareUTF16(purgedTenants[i], purgedTenants[j]) < 0 })
		return result(stringsOf(purgedTenants), deletedRecords), nil
	})
}

// sweepBatch is the rows deleted per transaction by sweepExpiredAuthRecords, so the write lock is never held for long.
const sweepBatch = 500

// sweepExpiredAuthRecords deletes authentication bookkeeping that nothing else removes: rate-limit counters past
// their window, challenges past their expiry, and lapsed network blocks. Rows are listed once, then deleted in
// bounded batches of short transactions; each row is re-read first, so a counter or a block renewed in the meantime
// survives.
func sweepExpiredAuthRecords(ctx context.Context, server *ServerContext) error {
	now := float64(server.Now())
	ended := func(field string) func(row *core.Object) bool {
		return func(row *core.Object) bool {
			value, ok := row.Get(field).(float64)
			return ok && value <= now
		}
	}
	sweeps := []struct {
		collection string
		expired    func(row *core.Object) bool
	}{
		{"authRateLimits", ended("resetAt")},
		{"authChallenges", ended("expiresAt")},
		{"authBlocks", ended("expiresAt")},
	}
	for _, sweep := range sweeps {
		rows, err := server.Store.Find(ctx, sweep.collection, nil, nil)
		if err != nil {
			return err
		}
		var ids []string
		for _, row := range rows {
			if sweep.expired(row) {
				ids = append(ids, jsString(row.Get("id")))
			}
		}
		for start := 0; start < len(ids); start += sweepBatch {
			batch := ids[start:min(start+sweepBatch, len(ids))]
			if err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				for _, rowID := range batch {
					row, err := tx.Get(ctx, sweep.collection, rowID)
					if err != nil {
						return err
					}
					if row != nil && sweep.expired(row) {
						if err := tx.Delete(ctx, sweep.collection, rowID); err != nil {
							return err
						}
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		// Cached block lists may still hold the removed rows; they no longer apply, but need not be kept.
		if sweep.collection == "authBlocks" && len(ids) > 0 {
			server.Auth.InvalidateNetworkBlocks()
		}
	}
	return nil
}
