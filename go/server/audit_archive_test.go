package server

// Port of tests/audit-archive.test.ts: continuous audit archiving (verified, ordered, incremental batches, leases
// against overlapping runs, gaps and broken chains, the write-once JSON Lines sink, limits) and its contract with
// pruneAudit.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// archivedEvents reads every archived event of one tenant back from the JSON Lines files, by sequence.
func archivedEvents(t *testing.T, root, tenantID string) []*core.Object {
	t.Helper()
	folder := filepath.Join(root, tenantID)
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".jsonl") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	bySequence := map[float64]*core.Object{}
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(folder, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
			event := obj(t, line)
			bySequence[event.Get("sequence").(float64)] = event
		}
	}
	events := make([]*core.Object, 0, len(bySequence))
	for _, event := range bySequence {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Get("sequence").(float64) < events[j].Get("sequence").(float64) })
	return events
}

func (f *opsFixture) archive(input *core.Object) *core.Object {
	f.t.Helper()
	result, err := f.iam.ArchiveAudit(f.ctx, input)
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

func (f *opsFixture) head(tenantID string) *core.Object {
	f.t.Helper()
	head := f.get("auditChains", tenantID)
	if head == nil {
		f.t.Fatalf("no chain for %s", tenantID)
	}
	return head
}

func verifiesAsWholeChain(t *testing.T, events []*core.Object, head *core.Object) {
	t.Helper()
	verification := core.VerifyAuditChain(events, core.VerifyAuditChainOptions{Head: &core.AuditChainHeadRef{
		Sequence: head.Get("sequence").(float64), Hash: jsString(head.Get("hash")),
	}})
	if !verification.Valid || verification.First == nil || *verification.First != 1 || *verification.Last != head.Get("sequence").(float64) {
		t.Fatalf("the archived chain does not verify: %+v", verification)
	}
}

func TestAuditArchiveArchivesEveryChainVerifiedAndInOrderIntoJsonLines(t *testing.T) {
	root := t.TempDir()
	f := newOpsFixture(t, func(options *BetterIamOptions) { options.AuditArchive = CreateJsonlAuditArchive(root) })
	heads := f.find("auditChains", core.NewObject())
	first := f.archive(nil)
	expectJSON(t, []any{first.Get("failed"), first.Get("gaps"), first.Get("truncated")}, `[[],[],false]`)
	archived := first.Get("archived").(*core.Object)
	for _, head := range heads {
		if archived.Get(jsString(head.Get("id"))) != head.Get("sequence") {
			t.Fatalf("archived %s: %v of %v", head.Get("id"), archived.Get(jsString(head.Get("id"))), head.Get("sequence"))
		}
	}
	// Only the new events go out on the next run, and the files add up to the whole chain.
	f.member("alice")
	second := f.archive(nil)
	head := f.head(f.tenantID)
	var before *core.Object
	for _, entry := range heads {
		if entry.Get("id") == f.tenantID {
			before = entry
		}
	}
	if got := member(second.Get("archived"), f.tenantID); got != head.Get("sequence").(float64)-before.Get("sequence").(float64) {
		t.Fatalf("second run archived %v", got)
	}
	verifiesAsWholeChain(t, archivedEvents(t, root, f.tenantID), head)
	cursor, err := f.iam.auditArchive.ArchiveCursor(f.ctx, f.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Get("sequence") != head.Get("sequence") || cursor.Get("hash") != head.Get("hash") || cursor.Has("leaseId") {
		t.Fatalf("cursor: %s", core.MustStringify(cursor))
	}
	third := f.archive(nil)
	expectJSON(t, []any{third.Get("archived"), third.Get("batches")}, `[{},0]`)
}

func TestAuditArchiveKeepsEventsTheArchiveDoesNotHoldWhenPruning(t *testing.T) {
	var written []AuditArchiveBatch
	failing := false
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.AuditArchive = &AuditArchiveOptions{BatchSize: float(3), Write: func(ctx context.Context, batch AuditArchiveBatch) error {
			if failing {
				return errors.New("bucket unavailable")
			}
			written = append(written, batch)
			return nil
		}}
	})
	prune := func() *core.Object {
		t.Helper()
		f.advance(1)
		return must(f.iam.PruneAudit(f.ctx, core.NewObject("tenantId", f.tenantID, "retentionMs", 0)))
	}
	// Nothing archived yet: pruning everything older than now deletes nothing.
	expectJSON(t, prune(), `{"deleted":0,"heldForArchive":true}`)
	// A failing sink leaves the cursor where it was.
	failing = true
	failed := f.archive(core.NewObject("tenantId", f.tenantID))
	expectJSON(t, failed.Get("failed"), `[{"tenantId":"`+f.tenantID+`","code":"ARCHIVE_WRITE_FAILED","message":"bucket unavailable"}]`)
	if prune().Get("deleted") != 0.0 {
		t.Fatal("pruned events the archive does not hold")
	}
	failing = false
	// Batches of three, chained to each other.
	archived := f.archive(core.NewObject("tenantId", f.tenantID))
	expectJSON(t, archived.Get("failed"), `[]`)
	for index, batch := range written {
		if len(batch.Events) > 3 {
			t.Fatalf("batch %d has %d events", index, len(batch.Events))
		}
		if index > 0 && batch.PreviousHash != written[index-1].LastHash {
			t.Fatalf("batch %d does not chain", index)
		}
		if index == 0 && batch.FromSequence != 1 {
			t.Fatalf("first batch starts at %v", batch.FromSequence)
		}
	}
	through := written[len(written)-1].ToSequence
	// Now pruning removes exactly what the archive holds.
	pruned := prune()
	if pruned.Get("deleted") != through || pruned.Get("prunedThroughSequence") != through {
		t.Fatalf("pruned: %s (through %v)", core.MustStringify(pruned), through)
	}
	// The prune checkpoint event itself is new, so it is archived next.
	if got := member(f.archive(core.NewObject("tenantId", f.tenantID)).Get("archived"), f.tenantID); got != 1.0 {
		t.Fatalf("archived after prune: %v", got)
	}
	if action := written[len(written)-1].Events[0].Get("action"); action != "audit:prune" {
		t.Fatalf("last archived action %v", action)
	}
}

func TestAuditArchiveRefusesABrokenChainAndReportsGaps(t *testing.T) {
	var written []AuditArchiveBatch
	sink := func(options *BetterIamOptions) {
		options.AuditArchive = &AuditArchiveOptions{Write: func(ctx context.Context, batch AuditArchiveBatch) error {
			written = append(written, batch)
			return nil
		}}
	}
	f := newOpsFixture(t, sink)
	victims := f.find("audit", core.NewObject("tenantId", f.tenantID, "sequence", 2))
	f.put("audit", victims[0].Spread(core.NewObject("action", "tampered")))
	result := f.archive(core.NewObject("tenantId", f.tenantID))
	failures := result.Get("failed").([]any)
	if len(failures) != 1 || member(failures[0], "code") != "AUDIT_CHAIN_BROKEN" || member(failures[0], "message") != "The chain does not verify at sequence 2" {
		t.Fatalf("failed: %s", core.MustStringify(failures))
	}
	if len(written) != 0 {
		t.Fatal("a broken chain was written")
	}
	if must(f.iam.PruneAudit(f.ctx, core.NewObject("tenantId", f.tenantID, "retentionMs", 0))).Get("deleted") != 0.0 {
		t.Fatal("pruned an unarchived chain")
	}

	// Events deleted outside the archive show up as a gap; the rest is archived from there.
	g := newOpsFixture(t, sink)
	g.member("alice")
	err := g.iam.Store.Transaction(g.ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, sequence := range []float64{1, 2} {
			events, err := tx.Find(ctx, "audit", core.NewObject("tenantId", g.tenantID, "sequence", sequence), nil)
			if err != nil {
				return err
			}
			for _, event := range events {
				if err := tx.Delete(ctx, "audit", jsString(event.Get("id"))); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	resumed := g.archive(core.NewObject("tenantId", g.tenantID))
	expectJSON(t, resumed.Get("failed"), `[]`)
	expectJSON(t, resumed.Get("gaps"), `[{"tenantId":"`+g.tenantID+`","fromSequence":1,"toSequence":2}]`)
}

func TestAuditArchiveLetsOneRunAtATimeArchiveATenant(t *testing.T) {
	root := t.TempDir()
	files := CreateJsonlAuditArchive(root)
	release := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.AuditArchive = &AuditArchiveOptions{BatchSize: float(2), Write: func(ctx context.Context, batch AuditArchiveBatch) error {
			blocked := false
			once.Do(func() { blocked = true })
			if blocked {
				close(entered)
				<-release
			}
			return files.Write(ctx, batch)
		}}
	})
	type outcome struct {
		result *core.Object
		err    error
	}
	slow := make(chan outcome, 1)
	go func() {
		result, err := f.iam.ArchiveAudit(f.ctx, core.NewObject("tenantId", f.tenantID))
		slow <- outcome{result, err}
	}()
	<-entered
	// New events arrive while the first run is stuck in its sink; a second run must not race it.
	f.member("alice")
	second := f.archive(core.NewObject("tenantId", f.tenantID))
	expectJSON(t, []any{second.Get("archived"), second.Get("busy")}, `[{},["`+f.tenantID+`"]]`)
	close(release)
	first := <-slow
	if first.err != nil {
		t.Fatal(first.err)
	}
	expectJSON(t, first.result.Get("failed"), `[]`)
	f.archive(core.NewObject("tenantId", f.tenantID))
	head := f.head(f.tenantID)
	// Everything pruned is in the archive: the files hold the whole chain.
	f.advance(1)
	pruned := must(f.iam.PruneAudit(f.ctx, core.NewObject("tenantId", f.tenantID, "retentionMs", 0)))
	if pruned.Get("prunedThroughSequence") != head.Get("sequence") {
		t.Fatalf("pruned: %s", core.MustStringify(pruned))
	}
	verifiesAsWholeChain(t, archivedEvents(t, root, f.tenantID), head)
}

func TestAuditArchiveNeverOverwritesAnArchivedFile(t *testing.T) {
	root := t.TempDir()
	files := CreateJsonlAuditArchive(root)
	ctx := context.Background()
	batch := func(action string) AuditArchiveBatch {
		return AuditArchiveBatch{TenantID: "t", FromSequence: 1, ToSequence: 2, PreviousHash: core.AuditGenesis, LastHash: "x", Events: []*core.Object{
			core.NewObject("id", "e1", "tenantId", "t", "sequence", 1, "action", action),
			core.NewObject("id", "e2", "tenantId", "t", "sequence", 2, "action", action),
		}}
	}
	if err := files.Write(ctx, batch("original")); err != nil {
		t.Fatal(err)
	}
	if err := files.Write(ctx, batch("original")); err != nil {
		t.Fatal(err)
	}
	expectError(t, files.Write(ctx, batch("forged")), "ARCHIVE_CONFLICT", "t/000000000001-000000000002.jsonl already holds different events")
	if stored := archivedEvents(t, root, "t")[0]; stored.Get("action") != "original" {
		t.Fatalf("stored: %s", core.MustStringify(stored))
	}
	// No temporary files are left behind.
	entries, err := os.ReadDir(filepath.Join(root, "t"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary file left: %s", entry.Name())
		}
	}
	content, err := os.ReadFile(filepath.Join(root, "t", "000000000001-000000000002.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != `{"id":"e1","tenantId":"t","sequence":1,"action":"original"}`+"\n"+`{"id":"e2","tenantId":"t","sequence":2,"action":"original"}`+"\n" {
		t.Fatalf("content: %q", content)
	}
	for _, unsafe := range []string{"../escape", ".hidden", "a/b", ""} {
		escape := batch("x")
		escape.TenantID = unsafe
		expectError(t, files.Write(ctx, escape), "INVALID_INPUT", "Tenant id is not a safe file name")
	}
}

func TestAuditArchiveStopsAtTheLimitAndValidates(t *testing.T) {
	var written []AuditArchiveBatch
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.AuditArchive = &AuditArchiveOptions{BatchSize: float(2), Write: func(ctx context.Context, batch AuditArchiveBatch) error {
			written = append(written, batch)
			return nil
		}}
	})
	limited := f.archive(core.NewObject("limit", 3))
	if limited.Get("truncated") != true {
		t.Fatalf("limited: %s", core.MustStringify(limited))
	}
	total := 0.0
	limited.Get("archived").(*core.Object).Entries(func(_ string, value any) bool {
		total += value.(float64)
		return true
	})
	if total != 3 {
		t.Fatalf("archived %v events", total)
	}
	if selfCheckChecks(t, f).has("audit-archive-behind") {
		t.Fatal("a fresh archive is reported behind")
	}
	f.advance(2 * 86_400_000)
	late := must(f.iam.SelfCheck(f.ctx, nil))
	found := false
	for _, finding := range late.Get("findings").([]any) {
		if member(finding, "check") == "audit-archive-behind" && member(finding, "severity") == "warning" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the self-check misses the archive falling behind: %s", core.MustStringify(late))
	}
	if f.archive(nil).Get("truncated") != false {
		t.Fatal("the second run was truncated")
	}
	if selfCheckChecks(t, f).has("audit-archive-behind") {
		t.Fatal("a caught-up archive is reported behind")
	}
	for _, limit := range []any{0.0, 1.5, 10_000_001.0, "5"} {
		_, err := f.iam.ArchiveAudit(f.ctx, core.NewObject("limit", limit))
		expectError(t, err, "INVALID_INPUT", "limit must be between 1 and 10000000")
	}
	// Without a sink there is nothing to archive to.
	plain := newOpsFixture(t, nil)
	_, err := plain.iam.ArchiveAudit(plain.ctx, nil)
	expectError(t, err, "NO_AUDIT_ARCHIVE", "Configure auditArchive (for example createJsonlAuditArchive) to archive audit events")
	if cursor := must(plain.iam.auditArchive.ArchiveCursor(plain.ctx, plain.tenantID)); cursor != nil {
		t.Fatal("a cursor exists without an archive")
	}
}

type checkSet map[string]bool

func (set checkSet) has(check string) bool { return set[check] }

// selfCheckChecks is the set of checks the self-check reports findings for.
func selfCheckChecks(t *testing.T, f *opsFixture) checkSet {
	t.Helper()
	set := checkSet{}
	for _, finding := range must(f.iam.SelfCheck(f.ctx, nil)).Get("findings").([]any) {
		set[jsString(member(finding, "check"))] = true
	}
	return set
}

func TestAuditArchiveKeepsUnarchivedEventsFromAProcessWithoutTheArchive(t *testing.T) {
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.AuditArchive = &AuditArchiveOptions{BatchSize: float(2), Write: func(ctx context.Context, batch AuditArchiveBatch) error { return nil }}
	})
	// More events than the run below archives (the organization fixture of the TypeScript suite writes several).
	f.memberCredential("owner")
	f.memberCredential("owner")
	if events := f.find("audit", core.NewObject("tenantId", f.tenantID)); len(events) <= 2 {
		t.Fatalf("only %d audit events", len(events))
	}
	f.archive(core.NewObject("tenantId", f.tenantID, "limit", 2))
	// Another process, say a retention worker, runs without the auditArchive option.
	worker, err := New(&BetterIamOptions{Database: f.iam.Store, Secret: f.iam.Context.Options.Secret, BaseURL: "http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	pruned := must(worker.PruneAudit(f.ctx, core.NewObject("tenantId", f.tenantID, "retentionMs", 0)))
	if pruned.Get("deleted") != 2.0 || pruned.Get("prunedThroughSequence") != 2.0 || pruned.Get("heldForArchive") != true {
		t.Fatalf("pruned: %s", core.MustStringify(pruned))
	}
}

func TestAuditArchiveValidatesItsOption(t *testing.T) {
	write := func(ctx context.Context, batch AuditArchiveBatch) error { return nil }
	for _, testCase := range []struct {
		options *AuditArchiveOptions
		message string
	}{
		{&AuditArchiveOptions{Write: write, BatchSize: float(0)}, "auditArchive.batchSize must be between 1 and 10000"},
		{&AuditArchiveOptions{Write: write, BatchSize: float(10_001)}, "auditArchive.batchSize must be between 1 and 10000"},
		{&AuditArchiveOptions{Write: write, BatchSize: float(2.5)}, "auditArchive.batchSize must be between 1 and 10000"},
		{&AuditArchiveOptions{Write: write, LeaseMs: float(59_999)}, "auditArchive.leaseMs must be between 60000 and 3600000"},
		{&AuditArchiveOptions{Write: write, LeaseMs: float(3_600_001)}, "auditArchive.leaseMs must be between 60000 and 3600000"},
	} {
		_, err := New(&BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: "http://localhost:3000", AuditArchive: testCase.options})
		expectError(t, err, "INVALID_CONFIG", testCase.message)
	}
}
