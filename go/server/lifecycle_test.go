package server

// Ports of tests/server.test.ts ("purges deleted tenants after the retention window and keeps audit records"), the
// worker parts of tests/lifecycle-review.test.ts, tests/identity-expiry.test.ts, tests/membership-expiry.test.ts and
// tests/expiry-reminders.test.ts, and the validation of the scheduler jobs in packages/server/src/lifecycle.ts.
// Records the TypeScript tests create through other API groups are seeded directly.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const lifecycleDay = 86_400_000.0

// seed inserts records in one transaction.
func (f *tenantsFixture) seed(collection string, records ...*core.Object) {
	f.t.Helper()
	err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, record := range records {
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

// change rewrites a stored record.
func (f *tenantsFixture) change(collection, id string, members ...any) {
	f.t.Helper()
	err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		record, err := tx.Get(ctx, collection, id)
		if err != nil {
			return err
		}
		for index := 0; index+1 < len(members); index += 2 {
			record.Set(members[index].(string), members[index+1])
		}
		_, err = tx.Put(ctx, collection, record)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *tenantsFixture) now() float64 { return float64(f.clock.Load()) }

const emptyPurge = `{"purgedTenants":[],"deletedRecords":0,"expiredBindings":0,"expiredRequests":0,"expiredIdentities":0,` +
	`"expiredActivations":0,"expiredMemberships":0,"expiredAssignments":0}`

func TestPurgeDeletedPurgesTenantsAfterTheRetentionWindowAndKeepsAudit(t *testing.T) {
	f := newTenantsFixture(t, nil)
	a, b := f.createTenant("gone", "", ""), f.createTenant("kept", "", "")
	// A pending project of the doomed organization, with its invitation in the outbox.
	project := f.call(f.tenants().Create(f.ctx, a.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", a.id, "type", "project", "name", "Web", "ownerEmail", "web@gone.test",
	)))).(*core.Object)
	projectID := jsString(member(project.Get("tenant"), "id"))
	ownerID := jsString(a.owner.Get("id"))
	// Records elsewhere that point at the doomed tenants or their people.
	f.seed("identityLinks", core.NewObject("id", "link", "tenantId", b.id, "leftId", ownerID, "rightId", jsString(b.owner.Get("id"))))
	f.seed("oauthArtifacts", core.NewObject("id", "artifact", "tenantId", b.id, "accountId", ownerID))
	f.seed("trusts", core.NewObject("id", "trust", "tenantId", b.id, "sourceTenantId", a.id))
	f.seed("sessions", session("role-session", jsString(b.owner.Get("id")), b.id, "role", "sourceTenantId", a.id))
	f.change("tenants", a.id, "status", "deleted", "deletedAt", f.now())

	result := must(f.iam.PurgeDeleted(f.ctx, nil))
	if got := core.MustStringify(result); got != emptyPurge {
		t.Fatalf("inside the retention window: %s", got)
	}
	purged := must(f.iam.PurgeDeleted(f.ctx, core.NewObject("retentionMs", 0.0)))
	wantIDs := []string{a.id, projectID}
	if compareUTF16(wantIDs[0], wantIDs[1]) > 0 {
		wantIDs[0], wantIDs[1] = wantIDs[1], wantIDs[0]
	}
	if got := core.MustStringify(purged.Get("purgedTenants")); got != core.MustStringify(stringsOf(wantIDs)) {
		t.Fatalf("purged %s, want %v", got, wantIDs)
	}
	if jsNumber(purged.Get("deletedRecords")) <= 0 {
		t.Fatal("records were deleted")
	}
	for _, tenantID := range []string{a.id, projectID} {
		if f.record("tenants", tenantID) != nil {
			t.Fatalf("tenant %s survived", tenantID)
		}
		for _, collection := range []string{"identities", "policies", "roles", "bindings", "grantAuthorities", "ownerInvitations", "outbox", "sessions"} {
			if rows := f.find(collection, core.NewObject("tenantId", tenantID)); len(rows) != 0 {
				t.Fatalf("%s of %s survived: %d", collection, tenantID, len(rows))
			}
		}
	}
	for _, dangling := range [][2]string{{"identityLinks", "link"}, {"oauthArtifacts", "artifact"}, {"trusts", "trust"}, {"sessions", "role-session"}} {
		if f.record(dangling[0], dangling[1]) != nil {
			t.Fatalf("dangling %s survived", dangling[0])
		}
	}
	if f.record("tenants", b.id) == nil || len(f.find("identities", core.NewObject("tenantId", b.id))) != 1 {
		t.Fatal("the other organization is untouched")
	}
	events := f.auditTrail(a.id, "tenants:purge")
	if len(events) != 1 {
		t.Fatalf("expected one purge event, got %d", len(events))
	}
	metadata := events[0].Get("metadata").(*core.Object)
	if got := core.MustStringify(metadata.Get("tenantIds")); got != core.MustStringify(stringsOf([]string{a.id, projectID})) ||
		metadata.Get("deletedRecords") != purged.Get("deletedRecords") || events[0].Get("actorId") != "deployment-operator" {
		t.Fatalf("unexpected purge event %s", core.MustStringify(events[0]))
	}
	if got := core.MustStringify(must(f.iam.PurgeDeleted(f.ctx, core.NewObject("retentionMs", 0.0)))); got != emptyPurge {
		t.Fatalf("a second purge finds nothing: %s", got)
	}
	_, err := f.iam.PurgeDeleted(f.ctx, core.NewObject("retentionMs", -1.0))
	expectError(t, err, "INVALID_INPUT", "Invalid retentionMs")
}

func TestPurgeDeletedExpiresTemporaryAccess(t *testing.T) {
	f := newTenantsFixture(t, nil)
	org := f.createTenant("acme", "", "")
	now := f.now()
	past, future := now-1, now+lifecycleDay
	ownerID := jsString(org.owner.Get("id"))
	member := must(core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: org.id, Email: "temp@acme.test", Name: "Temp", EmailVerified: true})
	}))
	memberID := jsString(member.Get("id"))
	f.seed("sessions", session("temp-session", memberID, org.id, "user"))
	f.change("identities", memberID, "expiresAt", past)
	f.seed("bindings",
		core.NewObject("id", "expired", "tenantId", org.id, "subjectType", "identity", "subjectId", ownerID, "roleId", "r", "expiresAt", past),
		core.NewObject("id", "current", "tenantId", org.id, "subjectType", "identity", "subjectId", ownerID, "roleId", "r", "expiresAt", future),
		core.NewObject("id", "group-binding", "tenantId", org.id, "subjectType", "group", "subjectId", "g", "roleId", "r", "eligible", true),
	)
	f.seed("bindingActivations",
		core.NewObject("id", "of-expired", "tenantId", org.id, "bindingId", "expired", "identityId", ownerID, "expiresAt", future),
		core.NewObject("id", "ended", "tenantId", org.id, "bindingId", "current", "identityId", ownerID, "expiresAt", past),
		core.NewObject("id", "of-member", "tenantId", org.id, "bindingId", "current", "identityId", memberID, "expiresAt", future),
		core.NewObject("id", "of-group", "tenantId", org.id, "bindingId", "group-binding", "identityId", ownerID, "expiresAt", future),
	)
	f.seed("groupMembers", core.NewObject("id", "lapsed", "tenantId", org.id, "groupId", "g", "identityId", ownerID, "expiresAt", past))
	f.seed("packageAssignments", core.NewObject("id", "assignment", "tenantId", org.id, "packageId", "p", "identityId", ownerID, "expiresAt", past))
	f.seed("accessRequests",
		core.NewObject("id", "stale", "tenantId", org.id, "status", "pending", "expiresAt", past),
		core.NewObject("id", "fresh", "tenantId", org.id, "status", "pending", "expiresAt", future),
	)
	f.seed("packageRequests", core.NewObject("id", "stale-package", "tenantId", org.id, "status", "pending", "expiresAt", past))
	f.seed("expiryReminderMarks", core.NewObject("id", "mark", "tenantId", org.id, "uniqueKey", "binding:x:1", "identityId", ownerID, "expiresAt", past))

	result := must(f.iam.PurgeDeleted(f.ctx, nil))
	want := `{"purgedTenants":[],"deletedRecords":0,"expiredBindings":1,"expiredRequests":2,"expiredIdentities":1,` +
		`"expiredActivations":3,"expiredMemberships":1,"expiredAssignments":1}`
	if got := core.MustStringify(result); got != want {
		t.Fatalf("purge answered %s", got)
	}
	for _, gone := range [][2]string{
		{"bindings", "expired"}, {"bindingActivations", "of-expired"}, {"bindingActivations", "ended"},
		{"bindingActivations", "of-member"}, {"bindingActivations", "of-group"}, {"groupMembers", "lapsed"},
		{"packageAssignments", "assignment"}, {"expiryReminderMarks", "mark"}, {"sessions", "temp-session"},
	} {
		if f.record(gone[0], gone[1]) != nil {
			t.Fatalf("%s %s survived", gone[0], gone[1])
		}
	}
	if f.record("bindings", "current") == nil || f.record("accessRequests", "fresh").Get("status") != "pending" {
		t.Fatal("live access is kept")
	}
	if f.record("accessRequests", "stale").Get("status") != "expired" || f.record("packageRequests", "stale-package").Get("status") != "expired" {
		t.Fatal("stale requests expire")
	}
	if f.record("identities", memberID).Get("status") != "disabled" {
		t.Fatal("the identity past its deadline is disabled")
	}
	events := f.auditTrail(org.id, "identity:expire")
	if len(events) != 1 || events[0].Get("resourceId") != memberID ||
		core.MustStringify(events[0].Get("metadata")) != `{"kind":"user","expiresAt":`+jsString(past)+`}` {
		t.Fatalf("unexpected expiry audit %v", events)
	}
}

func TestPurgeDeletedSweepsLapsedAuthenticationBookkeeping(t *testing.T) {
	f := newTenantsFixture(t, nil)
	now := f.now()
	f.seed("authRateLimits",
		core.NewObject("id", "old-limit", "tenantId", "anywhere", "count", 3.0, "resetAt", now-1),
		core.NewObject("id", "live-limit", "tenantId", "anywhere", "count", 3.0, "resetAt", now+60_000),
	)
	f.seed("authChallenges",
		core.NewObject("id", "old-challenge", "tenantId", "anywhere", "expiresAt", now),
		core.NewObject("id", "live-challenge", "tenantId", "anywhere", "expiresAt", now+60_000),
	)
	f.seed("authBlocks",
		core.NewObject("id", "old-block", "tenantId", "anywhere", "expiresAt", now-1),
		core.NewObject("id", "permanent-block", "tenantId", "anywhere"),
	)
	must(f.iam.PurgeDeleted(f.ctx, nil))
	for _, gone := range [][2]string{{"authRateLimits", "old-limit"}, {"authChallenges", "old-challenge"}, {"authBlocks", "old-block"}} {
		if f.record(gone[0], gone[1]) != nil {
			t.Fatalf("%s survived", gone[1])
		}
	}
	for _, kept := range [][2]string{{"authRateLimits", "live-limit"}, {"authChallenges", "live-challenge"}, {"authBlocks", "permanent-block"}} {
		if f.record(kept[0], kept[1]) == nil {
			t.Fatalf("%s was removed", kept[1])
		}
	}
}

func TestSendExpiryRemindersRemindsOncePerItemAndEndDate(t *testing.T) {
	f := newTenantsFixture(t, nil)
	org := f.createTenant("acme", "", "")
	now := f.now()
	ownerID := jsString(org.owner.Get("id"))
	accountEnd, roleEnd, groupEnd := now+3*lifecycleDay, now+2*lifecycleDay, now+lifecycleDay
	f.change("identities", ownerID, "expiresAt", accountEnd)
	f.seed("roles", core.NewObject("id", "editor", "tenantId", org.id, "name", "Editor", "uniqueKey", "editor", "policyIds", []any{}))
	f.seed("groups", core.NewObject("id", "eng", "tenantId", org.id, "name", "Engineering", "uniqueKey", "eng"))
	f.seed("bindings",
		core.NewObject("id", "temporary", "tenantId", org.id, "subjectType", "identity", "subjectId", ownerID, "roleId", "editor", "expiresAt", roleEnd),
		core.NewObject("id", "eligible", "tenantId", org.id, "subjectType", "identity", "subjectId", ownerID, "roleId", "editor", "expiresAt", roleEnd, "eligible", true),
		core.NewObject("id", "later", "tenantId", org.id, "subjectType", "identity", "subjectId", ownerID, "roleId", "editor", "expiresAt", now+30*lifecycleDay),
	)
	f.seed("groupMembers", core.NewObject("id", "membership", "tenantId", org.id, "groupId", "eng", "identityId", ownerID, "expiresAt", groupEnd))

	_, err := f.iam.SendExpiryReminders(f.ctx, core.NewObject("withinMs", 1000.0))
	expectError(t, err, "INVALID_INPUT", "Invalid withinMs")
	result := must(f.iam.SendExpiryReminders(f.ctx, nil))
	want := `{"sent":[{"tenantId":"` + org.id + `","identityId":"` + ownerID + `","items":3}],"skipped":{"inactive":0,"quiet":1}}`
	if got := core.MustStringify(result); got != want {
		t.Fatalf("reminders answered %s, want %s", got, want)
	}
	f.dispatch()
	messages := f.messages(org.id, "expiry-reminder")
	if len(messages) != 1 || messages[0].To != "acme@example.test" || messages[0].Payload["count"] != "3" ||
		messages[0].Payload["earliest"] != jsString(groupEnd) || messages[0].Payload["identityName"] != "acme owner" ||
		messages[0].Payload["tenantName"] != "acme" {
		t.Fatalf("unexpected reminder %+v", messages)
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(messages[0].Payload["items"]), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || items[0]["kind"] != "group" || items[0]["name"] != "Engineering" || items[1]["kind"] != "role" ||
		items[1]["name"] != "Editor" || items[2]["kind"] != "account" || items[2]["name"] != "acme owner" {
		t.Fatalf("items in end order: %v", items)
	}
	events := f.auditTrail(org.id, "identity:expiry-reminder")
	if len(events) != 1 {
		t.Fatalf("expected one reminder event, got %d", len(events))
	}
	keys := core.MustStringify(member(events[0].Get("metadata"), "items"))
	for _, key := range []string{"membership:membership:" + jsString(groupEnd), "binding:temporary:" + jsString(roleEnd), "identity:" + ownerID + ":" + jsString(accountEnd)} {
		if !strings.Contains(keys, key) {
			t.Fatalf("reminded keys %s lack %s", keys, key)
		}
	}
	if marks := f.find("expiryReminderMarks", core.NewObject("tenantId", org.id)); len(marks) != 3 {
		t.Fatalf("expected three marks, got %d", len(marks))
	}
	// Nothing new: quiet. Moving an end date reminds again, once.
	if got := core.MustStringify(must(f.iam.SendExpiryReminders(f.ctx, nil))); !strings.Contains(got, `"sent":[]`) {
		t.Fatalf("a second run sends nothing: %s", got)
	}
	f.change("bindings", "temporary", "expiresAt", roleEnd+60_000)
	again := must(f.iam.SendExpiryReminders(f.ctx, core.NewObject("tenantId", org.id)))
	if got := core.MustStringify(again.Get("sent")); got != `[{"tenantId":"`+org.id+`","identityId":"`+ownerID+`","items":1}]` {
		t.Fatalf("a moved end date reminds again: %s", got)
	}
	// A named tenant that is not active is skipped.
	f.call(f.tenants().SetStatus(f.ctx, f.credential, Input[apitypes.TenantsSetStatusInput](core.NewObject("tenantId", org.id, "status", "suspended"))))
	if got := core.MustStringify(must(f.iam.SendExpiryReminders(f.ctx, core.NewObject("tenantId", org.id))).Get("skipped")); got != `{"inactive":1,"quiet":0}` {
		t.Fatalf("inactive tenant: %s", got)
	}
}

func TestSchedulerJobsThatEmailNeedADeliveryCallback(t *testing.T) {
	f := newTenantsFixture(t, func(options *BetterIamOptions) { options.Authentication.SendEmail = nil })
	_, err := f.iam.SendExpiryReminders(f.ctx, nil)
	expectError(t, err, "DELIVERY_REQUIRED", "Expiry reminders require an email delivery callback")
	_, err = f.iam.SendAccessDigest(f.ctx, nil)
	if known := iamError(t, err); known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	expectError(t, err, "DELIVERY_REQUIRED", "The access digest requires an email delivery callback")
}

func TestReconcilePackagesValidatesItsInput(t *testing.T) {
	f := newTenantsFixture(t, nil)
	for _, c := range []struct {
		input   *core.Object
		message string
	}{
		{core.NewObject("tenantId", 5.0), "Invalid tenantId"},
		{core.NewObject("packageId", "p"), "packageId needs tenantId"},
		{core.NewObject("tenantId", f.rootID, "confirm", "yes"), "confirm must be boolean"},
		{core.NewObject("tenantId", f.rootID, "confirm", true), "confirm needs packageId"},
		{core.NewObject("limit", 0.0), "Invalid limit"},
		{core.NewObject("limit", 10001.0), "Invalid limit"},
	} {
		_, err := f.iam.ReconcilePackages(f.ctx, c.input)
		expectError(t, err, "INVALID_INPUT", c.message)
	}
}

func TestBootstrapAndRecoverRoot(t *testing.T) {
	f := newTenantsFixture(t, nil)
	_, err := f.iam.Bootstrap(f.ctx, core.NewObject("email", "again@example.test", "name", "Again", "password", "a strong root test password"))
	expectError(t, err, "ALREADY_INITIALIZED", "Root already exists")
	recovered := must(f.iam.RecoverRoot(f.ctx, core.NewObject("email", "rescue@example.test", "name", "Rescue", "password", "a strong rescue test password")))
	identity := recovered.Get("identity").(*core.Object)
	if recovered.Get("tenantId") != f.rootID || identity.Get("rootAdmin") != true || identity.Has("passwordHash") ||
		recovered.Get("mfaEnrollmentRequired") != true {
		t.Fatalf("unexpected recovery %s", core.MustStringify(recovered))
	}
	if events := f.auditTrail(f.rootID, "root:recover"); len(events) != 1 {
		t.Fatal("recovery is audited")
	}
	empty, err := New(&BetterIamOptions{Database: newStore(t), Secret: "tenants-test-secret-with-at-least-32-characters", BaseURL: "http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(empty.Close)
	_, err = empty.RecoverRoot(f.ctx, core.NewObject("email", "rescue@example.test", "name", "Rescue", "password", "a strong rescue test password"))
	expectError(t, err, "NOT_INITIALIZED", "Bootstrap first")
}
