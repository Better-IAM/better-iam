package server

// Port of tests/retention.test.ts: the retention sweep (what it deletes and keeps, batches, limits, the walk over
// records it keeps, option validation) and countDue, the dry run the self-check reports on.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const retentionTestDay = 86_400_000.0
const retentionTestNow = 1_900_000_000_000.0

type retentionFixture struct {
	t         *testing.T
	ctx       context.Context
	database  core.IamStore
	retention *Retention
	mu        sync.Mutex
	calls     []core.StoreCall
	clock     int64
}

func newRetentionFixture(t *testing.T) *retentionFixture {
	f := &retentionFixture{t: t, ctx: context.Background(), database: newStore(t), clock: int64(retentionTestNow)}
	store := core.InstrumentStore(f.database, func(call core.StoreCall) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, call)
	}, nil)
	clock := func() int64 { return f.clock }
	f.retention = CreateRetention(&ServerContext{Store: store, NowFunc: clock, WallFunc: clock})
	return f
}

func retentionRecord(id string, members ...any) *core.Object {
	record := core.NewObject("id", id, "tenantId", "t")
	for index := 0; index+1 < len(members); index += 2 {
		record.Set(members[index].(string), members[index+1])
	}
	return record
}

func (f *retentionFixture) seed(collection string, records ...*core.Object) {
	f.t.Helper()
	err := f.database.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
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

func (f *retentionFixture) ids(collection string) string {
	f.t.Helper()
	records, err := f.database.Find(f.ctx, collection, core.NewObject(), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	ids := make([]string, len(records))
	for index, record := range records {
		ids[index] = jsString(record.Get("id"))
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func (f *retentionFixture) sweep(options *core.Object) *core.Object {
	f.t.Helper()
	result, err := f.retention.SweepExpired(f.ctx, options)
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

func (f *retentionFixture) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *retentionFixture) callsOf(method, collection string) []core.StoreCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []core.StoreCall
	for _, call := range f.calls {
		if call.Method == method && (collection == "" || call.Collection == collection) {
			out = append(out, call)
		}
	}
	return out
}

func TestRetentionSweepsProtocolArtifactsDevicesTuplesAndDispatchedHooks(t *testing.T) {
	f := newRetentionFixture(t)
	now := retentionTestNow
	past, future := now-10*60_000, now+60_000
	for _, collection := range []string{"oauthArtifacts", "oauthLoginStates", "samlRequests", "samlRelays", "samlAssertions", "authDevices", "relationships"} {
		f.seed(collection, retentionRecord("old", "expiresAt", past), retentionRecord("live", "expiresAt", future))
	}
	f.seed("relationships", retentionRecord("forever"))
	f.seed("sessions",
		retentionRecord("role-old", "kind", "role", "tokenHash", "r", "expiresAt", past),
		retentionRecord("key-old", "kind", "api-key", "tokenHash", "k", "expiresAt", past),
		retentionRecord("future-kind", "kind", "federated", "tokenHash", "f", "expiresAt", past),
	)
	// Grants outlive their expiry by 31 days so back-channel logout can still find the client.
	f.seed("oauthArtifacts",
		retentionRecord("grant-recent", "model", "Grant", "expiresAt", now-30*retentionTestDay),
		retentionRecord("grant-old", "model", "Grant", "expiresAt", now-32*retentionTestDay),
	)
	f.seed("ssfDeliveries",
		retentionRecord("failed-old", "status", "failed", "createdAt", now-41*retentionTestDay, "failedAt", now-40*retentionTestDay),
		// Queued long ago, abandoned yesterday: kept for the retention from when it failed.
		retentionRecord("failed-new", "status", "failed", "createdAt", now-60*retentionTestDay, "failedAt", now-retentionTestDay),
		retentionRecord("failed-legacy", "status", "failed", "createdAt", now-40*retentionTestDay),
		retentionRecord("pending-old", "status", "pending", "createdAt", now-40*retentionTestDay),
	)
	f.seed("auditHooks",
		retentionRecord("done", "delivered", true, "deliveredAt", past),
		retentionRecord("done-legacy", "delivered", true),
		retentionRecord("waiting", "delivered", false),
	)
	// Collections the sweep leaves alone even past expiry: history, or renewable.
	f.seed("ownerInvitations", retentionRecord("invite", "expiresAt", past, "consumed", false))
	f.seed("scimConnections", retentionRecord("scim", "expiresAt", past))
	f.seed("accessRequests", retentionRecord("request", "expiresAt", past, "status", "pending"))
	f.clock = 0 // `now` overrides both clocks.
	expectJSON(t, f.sweep(core.NewObject("now", now)),
		`{"deleted":{"sessions":1,"authDevices":1,"relationships":1,"oauthArtifacts":2,"oauthLoginStates":1,"samlRequests":1,"samlRelays":1,"samlAssertions":1,"ssfDeliveries":2,"auditHooks":2},"total":13,"truncated":false}`)
	for collection, want := range map[string]string{
		"sessions": "future-kind,key-old", "relationships": "forever,live", "oauthArtifacts": "grant-recent,live",
		"ssfDeliveries": "failed-new,pending-old", "auditHooks": "waiting", "ownerInvitations": "invite",
		"scimConnections": "scim", "accessRequests": "request",
	} {
		if got := f.ids(collection); got != want {
			t.Errorf("%s: %s, want %s", collection, got, want)
		}
	}
}

func TestRetentionSweepsSessionTokensAndWebIdentityReplaysKeepingAPIKeys(t *testing.T) {
	f := newRetentionFixture(t)
	now := retentionTestNow
	past, future := now-10*60_000, now+60_000
	f.seed("sessions",
		retentionRecord("sts-old", "kind", "session-token", "tokenHash", "s1", "expiresAt", past),
		retentionRecord("sts-live", "kind", "session-token", "tokenHash", "s2", "expiresAt", future),
		retentionRecord("key-old", "kind", "api-key", "tokenHash", "k", "expiresAt", past),
	)
	f.seed("webIdentityReplays",
		retentionRecord("replay-old", "providerId", "p", "expiresAt", past),
		retentionRecord("replay-live", "providerId", "p", "expiresAt", future),
	)
	expectJSON(t, f.sweep(core.NewObject("now", now)), `{"deleted":{"sessions":1,"webIdentityReplays":1},"total":2,"truncated":false}`)
	if got := f.ids("sessions"); got != "key-old,sts-live" {
		t.Fatalf("sessions: %s", got)
	}
	if got := f.ids("webIdentityReplays"); got != "replay-live" {
		t.Fatalf("replays: %s", got)
	}
	// Within the grace period nothing is due yet.
	f.seed("webIdentityReplays", retentionRecord("replay-recent", "providerId", "p", "expiresAt", now-1000))
	expectJSON(t, f.sweep(core.NewObject("now", now)).Get("deleted"), `{}`)
}

func TestRetentionHonorsTheGracePeriodAndTheDeliveryRetention(t *testing.T) {
	f := newRetentionFixture(t)
	now := float64(f.clock)
	f.seed("outbox",
		retentionRecord("delivered", "kind", "email", "createdAt", now, "attempts", 1, "deliveredAt", now),
		retentionRecord("failed", "kind", "email", "createdAt", now, "attempts", 25, "failedAt", now),
		retentionRecord("pending", "kind", "email", "createdAt", now-60*retentionTestDay, "attempts", 3),
	)
	f.seed("sessions", retentionRecord("just-expired", "identityId", "x", "kind", "user", "tokenHash", "h1", "createdAt", now-retentionTestDay,
		"lastSeenAt", now-retentionTestDay, "authenticatedAt", now-retentionTestDay, "expiresAt", now-60_000, "mfa", false))
	expectJSON(t, f.sweep(nil).Get("deleted"), `{}`)
	expectJSON(t, f.sweep(core.NewObject("graceMs", 0)).Get("deleted"), `{"sessions":1}`)
	f.clock += int64(29 * retentionTestDay)
	if f.sweep(nil).Get("deleted").(*core.Object).Has("outbox") {
		t.Fatal("deliveries swept inside the retention")
	}
	f.clock += int64(2 * retentionTestDay)
	if deleted := f.sweep(nil).Get("deleted").(*core.Object).Get("outbox"); deleted != 2.0 {
		t.Fatalf("outbox deleted %v", deleted)
	}
	if got := f.ids("outbox"); got != "pending" {
		t.Fatalf("outbox: %s", got)
	}
	// A shorter retention applies at once; pending messages are never swept.
	f.seed("outbox", retentionRecord("sent", "kind", "sms", "createdAt", float64(f.clock), "attempts", 1, "deliveredAt", float64(f.clock)))
	expectJSON(t, f.sweep(core.NewObject("deliveryRetentionMs", 0)).Get("deleted"), `{"outbox":1}`)
	if got := f.ids("outbox"); got != "pending" {
		t.Fatalf("outbox: %s", got)
	}
}

func TestRetentionWorksInShortBatchesStopsAtTheLimitAndContinues(t *testing.T) {
	f := newRetentionFixture(t)
	now := retentionTestNow
	var records []*core.Object
	for index := 0; index < 23; index++ {
		records = append(records, retentionRecord(fmt.Sprintf("a%02d", index), "expiresAt", now-float64(index+1)*retentionTestDay))
	}
	f.seed("oauthArtifacts", records...)
	f.resetCalls()
	expectJSON(t, f.sweep(core.NewObject("now", now, "batchSize", 5, "limit", 12)), `{"deleted":{"oauthArtifacts":12},"total":12,"truncated":true}`)
	// Oldest first, and never more than one batch per read.
	var kept []string
	for index := 0; index < 11; index++ {
		kept = append(kept, fmt.Sprintf("a%02d", index))
	}
	if got := f.ids("oauthArtifacts"); got != strings.Join(kept, ",") {
		t.Fatalf("kept: %s", got)
	}
	for _, call := range f.callsOf("findOrdered", "") {
		if call.Page == nil || call.Page.Limit == nil || *call.Page.Limit > 5 {
			t.Fatalf("a read was larger than a batch: %+v", call)
		}
	}
	deletes := f.callsOf("delete", "")
	if len(deletes) != 12 {
		t.Fatalf("deletes: %d", len(deletes))
	}
	for _, call := range deletes {
		if !call.InTransaction {
			t.Fatal("a delete ran outside a transaction")
		}
	}
	expectJSON(t, f.sweep(core.NewObject("now", now, "batchSize", 5)), `{"deleted":{"oauthArtifacts":11},"total":11,"truncated":false}`)
}

func TestRetentionStepsOverRecordsItKeeps(t *testing.T) {
	f := newRetentionFixture(t)
	now := retentionTestNow
	var records []*core.Object
	for index := 0; index < 24; index++ {
		kind := "user"
		if index%2 == 1 {
			kind = "api-key"
		}
		records = append(records, retentionRecord(fmt.Sprintf("s%02d", index), "kind", kind, "tokenHash", fmt.Sprintf("h%d", index),
			"expiresAt", now-retentionTestDay-float64(index/6)*60_000))
	}
	f.seed("sessions", records...)
	f.resetCalls()
	expectJSON(t, f.sweep(core.NewObject("now", now, "batchSize", 5)), `{"deleted":{"sessions":12},"total":12,"truncated":false}`)
	remaining, err := f.database.Find(f.ctx, "sessions", core.NewObject(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range remaining {
		if session.Get("kind") != "api-key" {
			t.Fatalf("kept %s", core.MustStringify(session))
		}
	}
	if len(remaining) != 12 {
		t.Fatalf("remaining %d", len(remaining))
	}
	// 24 due records in batches of 5: four full reads and one short one, never a re-read.
	reads := f.callsOf("findOrdered", "sessions")
	total := 0
	for _, call := range reads {
		total += call.Records
	}
	if total != 24 || len(reads) != 5 {
		t.Fatalf("session reads: %d calls, %d records", len(reads), total)
	}
}

func TestRetentionValidatesItsOptions(t *testing.T) {
	f := newRetentionFixture(t)
	for options, message := range map[string]string{
		`{"batchSize":0}`:                      "batchSize must be an integer between 1 and 5000",
		`{"batchSize":5001}`:                   "batchSize must be an integer between 1 and 5000",
		`{"batchSize":"5"}`:                    "batchSize must be an integer between 1 and 5000",
		`{"limit":0}`:                          "limit must be an integer between 1 and 1000000",
		`{"limit":1.5}`:                        "limit must be an integer between 1 and 1000000",
		`{"graceMs":-1}`:                       "graceMs must be an integer between 0 and 86400000",
		`{"graceMs":172800000}`:                "graceMs must be an integer between 0 and 86400000",
		`{"deliveryRetentionMs":315446400000}`: "deliveryRetentionMs must be an integer between 0 and 315360000000",
		`{"now":"soon"}`:                       "now must be a finite number of milliseconds",
		`{"now":null}`:                         "now must be a finite number of milliseconds",
	} {
		_, err := f.retention.SweepExpired(f.ctx, obj(t, options))
		expectError(t, err, "INVALID_INPUT", message)
	}
	_, err := f.retention.CountDue(f.ctx, core.NewObject("cap", 10, "overdueMs", 0, "graceMs", -1))
	expectError(t, err, "INVALID_INPUT", "graceMs must be an integer between 0 and 86400000")
}

func TestRetentionCountDueCountsOverdueRecordsUpToTheCap(t *testing.T) {
	f := newRetentionFixture(t)
	now := float64(f.clock)
	var sessions []*core.Object
	for index := 0; index < 8; index++ {
		kind := "user"
		if index == 0 {
			kind = "api-key"
		}
		sessions = append(sessions, retentionRecord(fmt.Sprintf("s%d", index), "kind", kind, "tokenHash", fmt.Sprintf("h%d", index), "expiresAt", now-3*retentionTestDay))
	}
	sessions = append(sessions, retentionRecord("recent", "kind", "user", "tokenHash", "hr", "expiresAt", now-retentionTestDay))
	f.seed("sessions", sessions...)
	f.seed("outbox",
		retentionRecord("d1", "deliveredAt", now-40*retentionTestDay),
		retentionRecord("d2", "failedAt", now-40*retentionTestDay),
	)
	counts, err := f.retention.CountDue(f.ctx, core.NewObject("cap", 5, "overdueMs", 2*retentionTestDay))
	if err != nil {
		t.Fatal(err)
	}
	if counts.Get("sessions") != 5.0 || counts.Get("outbox") != 2.0 || counts.Get("authDevices") != 0.0 {
		t.Fatalf("counts: %s", core.MustStringify(counts))
	}
	counts, err = f.retention.CountDue(f.ctx, core.NewObject("cap", 100, "overdueMs", 2*retentionTestDay))
	if err != nil {
		t.Fatal(err)
	}
	// The recent session is due but not overdue; the API key is never swept.
	if counts.Get("sessions") != 7.0 {
		t.Fatalf("counts: %s", core.MustStringify(counts))
	}
	// Reads only.
	if len(f.callsOf("delete", "")) != 0 || f.ids("sessions") == "" {
		t.Fatal("countDue deleted records")
	}
}

func TestRetentionDeletesExpiredSessionsKeepingLiveSessionsAndRenewableAPIKeys(t *testing.T) {
	f := newOpsFixture(t, nil)
	f.member("alice")
	// The root administrator holds the grant authority over the organization the fixture delegates with.
	admin := f.rootCredential()
	_, err := f.iam.API.ServiceAccounts.Create(f.ctx, admin, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", f.tenantID, "name", "ci")))
	idAfterChange(t, err)
	var account *core.Object
	for _, identity := range f.find("identities", core.NewObject("tenantId", f.tenantID, "kind", "service")) {
		if identity.Get("name") == "ci" {
			account = identity
		}
	}
	if account == nil {
		t.Fatal("the service account was not created")
	}
	_, err = f.iam.API.Credentials.Create(f.ctx, admin, Input[apitypes.CredentialsCreateInput](core.NewObject(
		"tenantId", f.tenantID, "identityId", account.Get("id"), "name", "short", "expiresInSeconds", 60.0)))
	if message, stubbed := idStubbed(err); stubbed {
		t.Skip("blocked by a stub of another unit: " + message)
	}
	if err != nil {
		t.Fatal(err)
	}
	stale := f.signIn("alice@acme.test", opsMemberPassword)
	before := f.find("sessions", core.NewObject("kind", "user"))
	if len(before) < 3 {
		t.Fatalf("user sessions before: %d", len(before))
	}

	f.advance(8 * int64(retentionTestDay))
	fresh := f.signIn("alice@acme.test", opsMemberPassword)
	result := must(f.iam.SweepExpired(f.ctx, nil))
	if result.Get("truncated") != false || member(result.Get("deleted"), "sessions") != float64(len(before)) {
		t.Fatalf("sweep: %s (before %d)", core.MustStringify(result), len(before))
	}
	remaining := f.find("sessions", core.NewObject())
	kinds := make([]string, len(remaining))
	for index, session := range remaining {
		kinds[index] = jsString(session.Get("kind"))
	}
	sort.Strings(kinds)
	if strings.Join(kinds, ",") != "api-key,user" {
		t.Fatalf("remaining session kinds: %v", kinds)
	}
	if _, err := f.iam.API.Auth.GetSession(f.ctx, core.CredentialInput{Token: fresh}, Input[apitypes.AuthGetSessionInput](core.NewObject())); err != nil {
		t.Fatalf("the fresh session: %v", err)
	}
	_, err = f.iam.API.Auth.GetSession(f.ctx, core.CredentialInput{Token: stale}, Input[apitypes.AuthGetSessionInput](core.NewObject()))
	expectCode(t, err, "UNAUTHENTICATED")
	// The expired key is still listed, so an administrator can see it and renew it.
	owner := f.memberCredential("owner")
	keys, err := f.iam.API.Credentials.List(f.ctx, owner, Input[apitypes.CredentialsListInput](core.NewObject("tenantId", f.tenantID)))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := keys.Value.([]any)
	if len(list) != 1 || member(list[0], "name") != "short" || member(list[0], "expired") != true {
		t.Fatalf("keys: %s", core.MustStringify(keys.Value))
	}

	// Nothing else expired: a second run deletes nothing.
	if again := core.MustStringify(must(f.iam.SweepExpired(f.ctx, nil))); again != `{"deleted":{},"total":0,"truncated":false}` {
		t.Fatalf("second sweep: %s", again)
	}
}

func TestRetentionStampsDispatchedAuditHooksAndToleratesRowsRemovedByAnOverlappingDispatcher(t *testing.T) {
	var database core.IamStore
	removeFirst := true
	fixture := newIam(t, "http://localhost:3000", func(options *BetterIamOptions) {
		database = options.Database
		options.Events = &EventOptions{
			// Meanwhile another dispatcher delivered the first row and a sweep deleted it.
			OnEvent: func(ctx context.Context, event *core.Object) error {
				if !removeFirst {
					return nil
				}
				removeFirst = false
				return database.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
					return tx.Delete(ctx, "auditHooks", jsString(event.Get("id")))
				})
			},
		}
	})
	ctx := context.Background()
	pending := must(database.Find(ctx, "auditHooks", core.NewObject("delivered", false), nil))
	if len(pending) <= 1 {
		t.Fatalf("pending hooks: %d", len(pending))
	}
	if dispatched := must(fixture.iam.DispatchAuditHooks(ctx)); dispatched != len(pending) {
		t.Fatalf("dispatched %d of %d", dispatched, len(pending))
	}
	rows := must(database.Find(ctx, "auditHooks", core.NewObject(), nil))
	if len(rows) != len(pending)-1 {
		t.Fatalf("rows: %d, pending %d", len(rows), len(pending))
	}
	for _, row := range rows {
		if _, isNumber := row.Get("deliveredAt").(float64); row.Get("delivered") != true || !isNumber {
			t.Fatalf("row not stamped: %s", core.MustStringify(row))
		}
	}
	later := float64(time.Now().UnixMilli() + 3_600_000)
	if deleted := member(must(fixture.iam.SweepExpired(ctx, core.NewObject("now", later))).Get("deleted"), "auditHooks"); deleted != float64(len(pending)-1) {
		t.Fatalf("swept hooks: %v", deleted)
	}
}
