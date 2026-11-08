package server

// Engine coverage (tests/threats-engine.test.ts and the engine parts of tests/threat-rules.test.ts): chain
// verification and tampering, pruned trails, rolled-back heads, malformed events, the per-run baseline budget, the
// settings re-check, idempotent re-reads, incidents and risk. Events are appended to the tenant's chain as the
// recorders write them. Steps that reach another unit's NOT_IMPLEMENTED stub (threats.go, threat-response.go) skip
// the rest of the test.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// teFixture is a kernel with the org tenant, an owner, and a span recorder for detection runs.
type teFixture struct {
	*kernel
	mu    sync.Mutex
	spans []IamSpan
}

func newThreatFixture(t *testing.T) *teFixture {
	t.Helper()
	threatsPorted(t)
	f := &teFixture{}
	f.kernel = newKernel(t, func(options *BetterIamOptions) {
		options.Observability = &ObservabilityOptions{OnSpan: func(span IamSpan) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.spans = append(f.spans, span)
		}}
	})
	f.tenantTree()
	f.insert("identities",
		identity("owner", "org", "name", "Olivia", "email", "olivia@acme.test", "owner", true),
		identity("carol", "org", "name", "Carol", "email", "carol@acme.test"),
	)
	return f
}

// detect runs detection (one tenant, or all when tenantID is empty); a tenant run that failed fails the test, or
// skips it when it reached another unit's stub.
func (f *teFixture) detect(tenantID string, members ...any) *core.Object {
	f.t.Helper()
	input := core.NewObject()
	if tenantID != "" {
		input.Set("tenantId", tenantID)
	}
	for index := 0; index+1 < len(members); index += 2 {
		input.Set(members[index].(string), members[index+1])
	}
	f.mu.Lock()
	f.spans = nil
	f.mu.Unlock()
	run, err := DetectThreats(f.ctx, f.server, input)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, span := range f.spans {
		if span.Name != "threats:detect" || span.Outcome == "ok" {
			continue
		}
		if span.Code == "NOT_IMPLEMENTED" {
			f.t.Skip("detection reached another unit's stub")
		}
		f.t.Fatalf("detection failed for %s: %s", span.TenantID, span.Code)
	}
	return run
}

// appendEvents appends events to the org tenant's chain (no fan-out), stamped with the clock unless they carry a
// timestamp.
func (f *teFixture) appendEvents(events ...*core.Object) {
	f.t.Helper()
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		for _, event := range events {
			if !event.Has("tenantId") {
				event.Set("tenantId", "org")
			}
			if !event.Has("timestamp") {
				event.Set("timestamp", float64(f.clock.Load()))
			}
			if _, err := core.AppendAuditEvent(ctx, tx, event); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

// teEvent is an allowed event of actor on resource.
func teEvent(id, actorID, action, resourceID string, members ...any) *core.Object {
	event := core.NewObject("id", id, "actorId", actorID, "action", action, "resourceId", resourceID, "outcome", "allow")
	for index := 0; index+1 < len(members); index += 2 {
		event.Set(members[index].(string), members[index+1])
	}
	return event
}

func (f *teFixture) find(collection string, filter ...any) []*core.Object {
	f.t.Helper()
	records, err := f.store.Find(f.ctx, collection, core.NewObject(filter...), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return records
}

func (f *teFixture) get(collection, id string) *core.Object {
	f.t.Helper()
	record, err := f.store.Get(f.ctx, collection, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func teCount(t *testing.T, run *core.Object, pairs ...any) {
	t.Helper()
	for index := 0; index+1 < len(pairs); index += 2 {
		name := pairs[index].(string)
		if got, want := run.Get(name), core.Normalize(pairs[index+1]); got != want {
			t.Errorf("%s = %v, want %v (run %s)", name, got, want, trJSON(run))
		}
	}
}

func (f *teFixture) newest(tenantID string) *core.Object {
	f.t.Helper()
	var newest *core.Object
	for _, event := range f.find("audit", "tenantId", tenantID) {
		if newest == nil || jsNumber(event.Get("sequence")) > jsNumber(newest.Get("sequence")) {
			newest = event
		}
	}
	return newest
}

func TestThreatEngineChainTamperingAndPrune(t *testing.T) {
	f := newThreatFixture(t)
	f.appendEvents(teEvent("e1", "owner", "iam:roles:create", "role-1"))
	first := f.detect("")
	teCount(t, first, "chainBreaks", 0)
	if jsNumber(first.Get("tenants")) < 2 {
		t.Fatalf("tenants %v", first.Get("tenants"))
	}
	teCount(t, f.detect(""), "chainBreaks", 0)

	f.appendEvents(teEvent("e2", "owner", "identity:create", "alice"))
	newest := f.newest("org")
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Put(ctx, "audit", newest.Spread(core.NewObject("metadata", core.NewObject("forged", true))))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tampered := f.detect("org")
	teCount(t, tampered, "chainBreaks", 1, "detections", 1, "incidentsOpened", 1)
	detections := f.find(ThreatCollections.Detections, "tenantId", "org")
	if len(detections) != 1 || detections[0].Get("ruleId") != "audit-tampering" {
		t.Fatalf("detections %s", trJSON(trObjects(detections)))
	}
	trExpect(t, detections[0],
		"severity", "critical",
		"subject", core.NewObject("type", "tenant", "id", "org", "name", "Acme"),
		"metadata", core.NewObject("reason", "hash-mismatch", "sequence", newest.Get("sequence")),
		"evidence.eventIds", []string{"e2"},
		"evidence.actions", []string{"identity:create"},
		"status", "open",
		"summary", "The audit trail of Acme no longer verifies at event 2: its content no longer matches its hash.",
	)
	teCount(t, f.detect("org"), "chainBreaks", 0)
	actions := map[string]bool{}
	for _, event := range f.find("audit", "tenantId", "org") {
		actions[jsString(event.Get("action"))] = true
	}
	if !actions["threat:detection"] || !actions["threat:incident-open"] {
		t.Fatalf("audit actions %v", actions)
	}

	f.appendEvents(teEvent("e3", "owner", "identity:create", "bob"))
	f.advance(5)
	if _, err := CreateLifecycle(f.server).PruneAudit(f.ctx, core.NewObject("tenantId", "org", "retentionMs", 0.0)); err != nil {
		t.Fatal(err)
	}
	afterPrune := f.detect("org")
	teCount(t, afterPrune, "chainBreaks", 0)
	if jsNumber(afterPrune.Get("eventsScanned")) < 1 {
		t.Fatalf("after prune %s", trJSON(afterPrune))
	}
	// Rolling the chain head back behind the cursor is reported.
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		head, err := tx.Get(ctx, "auditChains", "org")
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "auditChains", head.Spread(core.NewObject("sequence", 1.0)))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	teCount(t, f.detect("org"), "chainBreaks", 1, "detections", 1)
}

func TestThreatEngineBruteForceThroughRules(t *testing.T) {
	f := newThreatFixture(t)
	f.detect("")
	for attempt := 0; attempt < 10; attempt++ {
		f.appendEvents(teEvent(fmt.Sprintf("fail-%d", attempt), "carol", "auth:signin:fail", "carol",
			"metadata", core.NewObject("reason", "password", "ip", "198.51.100.20", "userAgent", "test")))
		f.advance(1000)
	}
	run := f.detect("org")
	if jsNumber(run.Get("detections")) < 1 {
		t.Fatalf("run %s", trJSON(run))
	}
	found := f.find(ThreatCollections.Detections, "tenantId", "org", "ruleId", "brute-force")
	if len(found) != 1 {
		t.Fatalf("detections %s", trJSON(trObjects(f.find(ThreatCollections.Detections, "tenantId", "org"))))
	}
	trExpect(t, found[0],
		"identityId", "carol",
		"network", "198.51.100.20",
		"subject", core.NewObject("type", "identity", "id", "carol", "name", "Carol (carol@acme.test)"),
	)
	risk := f.find(ThreatCollections.Risk, "tenantId", "org")
	if len(risk) != 1 {
		t.Fatalf("risk %s", trJSON(trObjects(risk)))
	}
	trExpect(t, risk[0],
		"id", "carol",
		"identityId", "carol",
		"contributions", []any{core.NewObject("detectionId", found[0].Get("id"), "ruleId", "brute-force", "severity", "medium",
			"points", RiskPoints.Medium, "at", float64(f.clock.Load()))},
	)
	incidents := f.find(ThreatCollections.Incidents, "tenantId", "org")
	if len(incidents) != 1 {
		t.Fatalf("incidents %s", trJSON(trObjects(incidents)))
	}
	trExpect(t, incidents[0],
		"uniqueKey", "open:identity:carol",
		"identityId", "carol",
		"status", "open",
		"detectionIds", []any{found[0].Get("id")},
		"detectionCount", 1,
		"ruleIds", []string{"brute-force"},
	)
	if found[0].Get("incidentId") != incidents[0].Get("id") {
		t.Error("the detection names its incident")
	}
	// Idempotent: a re-run raises nothing; a full re-read of the trail (cursor removed) neither.
	teCount(t, f.detect("org"), "detections", 0)
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, ThreatCollections.Cursors, "org")
	}); err != nil {
		t.Fatal(err)
	}
	teCount(t, f.detect("org"), "detections", 0)
	if got := f.find(ThreatCollections.Detections, "tenantId", "org"); len(got) != 1 {
		t.Fatalf("re-read raised %d detections", len(got))
	}
}

func TestThreatEngineWebIdentityRefusals(t *testing.T) {
	f := newThreatFixture(t)
	f.insert("identities", identity("sa-ci", "org", "kind", "service"))
	f.detect("org")
	f.detect("org")
	denials := func(action string, from int) []*core.Object {
		events := make([]*core.Object, 40)
		for index := range events {
			events[index] = teEvent(fmt.Sprintf("%s-%d", action, from+index), "sa-ci", action, "role-deploy",
				"timestamp", float64(f.clock.Load()+int64(from+index)), "outcome", "deny", "rootOverride", false,
				"metadata", core.NewObject("reason", "malformed"))
		}
		return events
	}
	// Anyone may post junk tokens for a trust: they are recorded under its service account, never as its burst.
	f.appendEvents(denials("role:assumed-with-web-identity", 0)...)
	teCount(t, f.detect("org"), "detections", 0)
	// The account's own refusals still are.
	f.appendEvents(denials("documents:read", 100)...)
	teCount(t, f.detect("org"), "detections", 1)
	burst := f.find(ThreatCollections.Detections, "tenantId", "org", "ruleId", "denial-burst")
	if len(burst) != 1 {
		t.Fatalf("bursts %s", trJSON(trObjects(burst)))
	}
	trExpect(t, burst[0], "evidence.count", 40)
}

func TestThreatEngineStrippedEvent(t *testing.T) {
	f := newThreatFixture(t)
	f.detect("org")
	f.appendEvents(teEvent("alice-created", "owner", "identity:create", "alice"))
	newest := f.newest("org")
	stripped := newest.Spread()
	stripped.Delete("timestamp")
	stripped.Delete("action")
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Put(ctx, "audit", stripped)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	teCount(t, f.detect("org"), "chainBreaks", 1, "detections", 1)
	tampering := f.find(ThreatCollections.Detections, "tenantId", "org", "ruleId", "audit-tampering")
	if len(tampering) != 1 {
		t.Fatal("no tampering detection")
	}
	if _, ok := tampering[0].Get("occurredAt").(float64); !ok {
		t.Fatalf("occurredAt %v", tampering[0].Get("occurredAt"))
	}
	// The cursor moved past it: the next run reads new events.
	f.appendEvents(teEvent("bob-created", "owner", "identity:create", "bob"))
	next := f.detect("org")
	teCount(t, next, "chainBreaks", 0)
	if jsNumber(next.Get("eventsScanned")) <= 0 {
		t.Fatalf("next %s", trJSON(next))
	}
}

func TestThreatEngineBaselineBudget(t *testing.T) {
	f := newThreatFixture(t)
	f.detect("org")
	f.detect("org")
	events := make([]*core.Object, 501)
	for index := range events {
		person := fmt.Sprintf("person-%d", index)
		events[index] = teEvent("sign-in-"+core.NumberString(float64(index)), person, "auth:session:create", person,
			"metadata", core.NewObject("ip", "192.0.2.10"))
	}
	f.appendEvents(events...)
	teCount(t, f.detect("org"), "eventsScanned", 500, "pending", 1)
	teCount(t, f.detect("org"), "eventsScanned", 1, "pending", 0)
	// People unknown to the tenant get no baseline (identity deletion took theirs, or there never was one).
	if got := f.find(ThreatCollections.Baselines, "tenantId", "org"); len(got) != 0 {
		t.Fatalf("baselines %d", len(got))
	}
}

func TestThreatEngineBaselinesAndRiskySignIn(t *testing.T) {
	f := newThreatFixture(t)
	f.detect("org")
	for attempt := 0; attempt < 5; attempt++ {
		f.appendEvents(teEvent(fmt.Sprintf("fail-%d", attempt), "carol", "auth:signin:fail", "carol",
			"metadata", core.NewObject("reason", "password", "ip", "198.51.100.7")))
		f.advance(1000)
	}
	f.appendEvents(teEvent("carol-in", "carol", "auth:session:create", "carol", "metadata", core.NewObject("ip", "198.51.100.7", "userAgent", "browser")))
	teCount(t, f.detect("org"), "detections", 1, "incidentsOpened", 1)
	detection := f.find(ThreatCollections.Detections, "tenantId", "org", "ruleId", "brute-force-success")
	if len(detection) != 1 {
		t.Fatal("no brute-force-success detection")
	}
	baseline := f.get(ThreatCollections.Baselines, "carol")
	if baseline == nil {
		t.Fatal("no baseline")
	}
	trExpect(t, baseline,
		"tenantId", "org",
		"identityId", "carol",
		"networks", []any{core.NewObject("key", "198.51.100.7", "lastAt", float64(f.clock.Load()))},
		"userAgents", []any{core.NewObject("value", "browser", "lastAt", float64(f.clock.Load()))},
		"riskySignIn", core.NewObject("at", float64(f.clock.Load()), "detectionId", detection[0].Get("id"), "ruleId", "brute-force-success"),
	)
	// A password change within the window reads the risky sign-in the earlier run stored.
	f.advance(2 * 60_000)
	f.appendEvents(teEvent("carol-change", "carol", "auth:password:change", "carol"))
	teCount(t, f.detect("org"), "detections", 1, "incidentsOpened", 0)
	takeover := f.find(ThreatCollections.Detections, "tenantId", "org", "ruleId", "account-takeover-persistence")
	if len(takeover) != 1 {
		t.Fatal("no takeover detection")
	}
	trExpect(t, takeover[0], "metadata.riskySignInDetectionId", detection[0].Get("id"))
	incidents := f.find(ThreatCollections.Incidents, "tenantId", "org")
	if len(incidents) != 1 {
		t.Fatalf("incidents %d", len(incidents))
	}
	trExpect(t, incidents[0],
		"detectionCount", 2,
		"ruleIds", []string{"brute-force-success", "account-takeover-persistence"},
		"title", "2 detections for Carol (carol@acme.test)",
		"severity", "high",
	)
	risk := f.get(ThreatCollections.Risk, "carol")
	if risk == nil || len(threatList(risk.Get("contributions"))) != 2 {
		t.Fatalf("risk %s", trJSON(risk))
	}
}

func TestThreatEngineSettingsChangedDuringRun(t *testing.T) {
	f := newThreatFixture(t)
	f.insert(ThreatCollections.Settings, trStored("id", "org", "tenantId", "org",
		"rules", core.NewObject("brute-force", core.NewObject("threshold", 5.0))))
	f.detect("org")
	for attempt := 0; attempt < 6; attempt++ {
		f.appendEvents(teEvent(fmt.Sprintf("fail-%d", attempt), "carol", "auth:signin:fail", "carol",
			"metadata", core.NewObject("reason", "password", "ip", "198.51.100.31")))
		f.advance(1000)
	}
	// An administrator turns the rule off after the run read the settings and before it writes.
	changed := false
	f.server.Store = &teSettingsRace{IamStore: f.store, tenantID: "org", onTransaction: func(ctx context.Context) error {
		if changed {
			return nil
		}
		changed = true
		return f.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			stored, err := tx.Get(ctx, ThreatCollections.Settings, "org")
			if err != nil {
				return err
			}
			rules := stored.Get("rules").(*core.Object).Spread(core.NewObject("brute-force", core.NewObject("enabled", false)))
			_, err = tx.Put(ctx, ThreatCollections.Settings, stored.Spread(core.NewObject("rules", rules, "updatedAt", jsNumber(stored.Get("updatedAt"))+1)))
			return err
		})
	}}
	run := f.detect("org")
	f.server.Store = f.store
	if !changed {
		t.Fatal("the settings were not changed during the run")
	}
	teCount(t, run, "detections", 0, "responses", 0, "eventsScanned", 0)
	// The next run reads the same events under the new settings: the rule is off.
	next := f.detect("org")
	if jsNumber(next.Get("eventsScanned")) <= 0 {
		t.Fatalf("next %s", trJSON(next))
	}
	teCount(t, next, "detections", 0)
}

// teSettingsRace runs onTransaction before the first transaction that follows a read of the tenant's settings.
type teSettingsRace struct {
	core.IamStore
	tenantID      string
	settingsRead  bool
	onTransaction func(ctx context.Context) error
}

func (s *teSettingsRace) Get(ctx context.Context, collection, id string) (*core.Object, error) {
	if collection == ThreatCollections.Settings && id == s.tenantID {
		s.settingsRead = true
	}
	return s.IamStore.Get(ctx, collection, id)
}

func (s *teSettingsRace) Transaction(ctx context.Context, fn core.TxFunc) error {
	if s.settingsRead {
		if err := s.onTransaction(ctx); err != nil {
			return err
		}
	}
	return s.IamStore.Transaction(ctx, fn)
}

func (s *teSettingsRace) FindOrdered(ctx context.Context, collection string, filter *core.Object, order core.OrderOptions) ([]*core.Object, error) {
	if ordered, ok := s.IamStore.(core.OrderedFinder); ok {
		return ordered.FindOrdered(ctx, collection, filter, order)
	}
	return core.FindOrdered(ctx, s.IamStore, collection, filter, order, nil)
}

func TestThreatEngineRecordDetectionAndRisk(t *testing.T) {
	f := newThreatFixture(t)
	settings := trSettings(t, nil)
	now := f.clock.Load()
	candidate := func(dedupe, identityID string) *core.Object {
		record := core.NewObject("ruleId", "denial-burst", "severity", "medium", "title", "Burst", "summary", "A burst.",
			"subject", core.NewObject("type", "tenant", "id", "org", "name", "Acme"))
		if identityID != "" {
			record.Set("identityId", identityID)
		}
		record.Set("dedupeKey", dedupe)
		record.Set("occurredAt", float64(now))
		record.Set("evidence", core.NewObject("eventIds", []any{"e1"}, "count", 1.0, "firstAt", float64(now), "lastAt", float64(now)))
		return record
	}
	var first, second, third, again *core.Object
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		if first, err = RecordDetection(ctx, f.server, tx, "org", candidate("k1", "carol"), settings, now); err != nil {
			return err
		}
		if second, err = RecordDetection(ctx, f.server, tx, "org", candidate("k2", "owner"), settings, now); err != nil {
			return err
		}
		if third, err = RecordDetection(ctx, f.server, tx, "org", candidate(strings.Repeat("x", 600), ""), settings, now); err != nil {
			return err
		}
		again, err = RecordDetection(ctx, f.server, tx, "org", candidate("k1", "carol"), settings, now)
		return err
	}); err != nil {
		if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
			t.Skip("reached another unit's stub: " + known.Message)
		}
		t.Fatal(err)
	}
	teCount(t, first, "created", true, "incidentOpened", true)
	teCount(t, second, "created", true, "incidentOpened", false)
	teCount(t, again, "created", false, "incidentOpened", false)
	// An incident about the tenant names no identity once two different ones acted.
	incident := second.Get("incident").(*core.Object)
	trExpect(t, incident, "severalIdentities", true, "detectionCount", 2, "ruleIds", []string{"denial-burst"}, "title", "Burst")
	if !isUndefined(incident.Get("identityId")) {
		t.Error("an incident of several identities names none")
	}
	// A key too long for the store is kept as its hash.
	key := jsString(third.Get("detection").(*core.Object).Get("uniqueKey"))
	if !strings.HasPrefix(key, "denial-burst:sha256:") || len(key) != len("denial-burst:sha256:")+64 {
		t.Errorf("long key %q", key)
	}
	if threatStorageKey("plain:key") != "plain:key" || !strings.HasPrefix(threatStorageKey("bad\x01"), "key:sha256:") {
		t.Error("storage keys")
	}
	// Dropping a detection's contribution recomputes the risk (and audits the level change).
	var risk *core.Object
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		risk, err = RecomputeRisk(ctx, f.server, tx, "org", "carol", settings, now, "owner", core.NewObject("drop", []any{first.Get("detection").(*core.Object).Get("id")}))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	trExpect(t, risk, "contributions", []any{}, "score", 0, "level", "none")
	changes := f.find("audit", "tenantId", "org", "action", "threat:risk-change", "resourceId", "carol")
	if len(changes) != 2 {
		t.Fatalf("risk changes %s", trJSON(trObjects(changes)))
	}
	// Nothing to record for an identity of another tenant, or without a record and nothing to add.
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		if got, err := RecomputeRisk(ctx, f.server, tx, "project", "carol", settings, now, "", nil); err != nil || got != nil {
			return fmt.Errorf("other tenant: %v %v", got, err)
		}
		if got, err := RecomputeRisk(ctx, f.server, tx, "org", "owner-none", settings, now, "", nil); err != nil || got != nil {
			return fmt.Errorf("unknown: %v %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestThreatEngineUnknownTenant(t *testing.T) {
	f := newKernel(t, nil)
	_, err := DetectThreats(f.ctx, f.server, core.NewObject("tenantId", "missing"))
	expectError(t, err, "NOT_FOUND", "Tenant not found")
	_, err = DetectThreats(f.ctx, f.server, core.NewObject("maxEvents", 0.0))
	expectError(t, err, "INVALID_INPUT", "Invalid maxEvents")
	_, err = DetectThreats(f.ctx, f.server, core.NewObject("tenantId", nil))
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
}

func TestThreatEnginePlaybooksContainAndBrake(t *testing.T) {
	f := newThreatFixture(t)
	f.insert("identities", identity("erin", "org", "name", "Erin", "email", "erin@acme.test"), identity("frank", "org", "name", "Frank", "email", "frank@acme.test"))
	f.insert(ThreatCollections.Settings, trStored("id", "org", "tenantId", "org", "maxAutomaticContainments", 1.0,
		"rules", core.NewObject("brute-force", core.NewObject("threshold", 5.0))))
	f.insert(ThreatCollections.Playbooks, core.NewObject("id", "playbook-1", "tenantId", "org", "name", "Contain guessing",
		"enabled", true, "trigger", core.NewObject("ruleIds", []any{"brute-force"}),
		"actions", []any{core.NewObject("kind", "revoke-sessions"), core.NewObject("kind", "contain")},
		"createdAt", 1.0, "createdBy", "owner", "updatedAt", 1.0, "updatedBy", "owner", "runs", 0.0))
	f.detect("")
	for _, person := range []string{"erin", "frank", "owner"} {
		for attempt := 0; attempt < 6; attempt++ {
			f.appendEvents(teEvent(fmt.Sprintf("%s-fail-%d", person, attempt), person, "auth:signin:fail", person,
				"metadata", core.NewObject("reason", "password", "ip", "198.51.100.30", "userAgent", "test")))
			f.advance(100)
		}
	}
	run := f.detect("org")
	teCount(t, run, "braked", 1, "detections", 3)
	var contains []string
	for _, response := range f.find(ThreatCollections.Responses, "tenantId", "org", "action", "contain") {
		contains = append(contains, jsString(coalesce(response.Get("reason"), response.Get("outcome"))))
	}
	if strings.Join(teSortedStrings(contains), ",") != "applied,braked,protected" {
		t.Fatalf("contain responses %v", contains)
	}
	count := func(action string) int { return len(f.find("audit", "tenantId", "org", "action", action)) }
	if count("threat:response-braked") != 1 || count("threat:contain") != 1 || count("threat:revoke-sessions") != 3 {
		t.Fatalf("audit braked %d contain %d revoke %d", count("threat:response-braked"), count("threat:contain"), count("threat:revoke-sessions"))
	}
	if risky := f.find(ThreatCollections.Risk, "tenantId", "org"); len(risky) != 3 {
		t.Fatalf("risk records %d", len(risky))
	}
	if count("threat:risk-change") < 3 {
		t.Fatalf("risk changes %d", count("threat:risk-change"))
	}
	playbook := f.get(ThreatCollections.Playbooks, "playbook-1")
	trExpect(t, playbook, "runs", 3, "lastRunAt", float64(f.clock.Load()))
	teCount(t, f.detect("org"), "detections", 0)
}

func teSortedStrings(values []string) []string {
	sorted := append([]string{}, values...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted
}
