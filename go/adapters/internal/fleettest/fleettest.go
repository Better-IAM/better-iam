// Package fleettest is the Go side of the mixed-fleet check: one database file written and read alternately by the
// TypeScript adapter (scripts/conformance/fleet/go-fleet.mjs) and a Go adapter, compared byte for byte.
package fleettest

import (
	"bytes"
	"context"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// Node returns the node binary to use: BETTER_IAM_NODE, or node on PATH.
func Node() string {
	if node := os.Getenv("BETTER_IAM_NODE"); node != "" {
		return node
	}
	return "node"
}

func script(t *testing.T) string {
	root, err := spectest.Root()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "scripts", "conformance", "fleet", "go-fleet.mjs")
}

// runNode runs the TypeScript side; the test is skipped (unless BETTER_IAM_FLEET=required) when Node or the built
// TypeScript packages are unavailable.
func runNode(t *testing.T, command, file, kind string) *core.Object {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(Node(), script(t), command, file, kind)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := "fleet script failed: " + err.Error() + "\n" + stderr.String()
		if command == "create" && os.Getenv("BETTER_IAM_FLEET") != "required" {
			t.Skip(message + "\n(set BETTER_IAM_NODE to a Node with the workspace built; BETTER_IAM_FLEET=required makes this fatal)")
		}
		t.Fatal(message)
	}
	parsed, err := core.ParseJSON(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		t.Fatalf("fleet script output: %v\n%s", err, stdout.String())
	}
	return parsed.(*core.Object)
}

func exportLines(t *testing.T, store core.IamStore) []any {
	t.Helper()
	var lines []any
	if _, err := core.ExportStore(context.Background(), store, func(line string) error {
		lines = append(lines, line)
		return nil
	}, core.SnapshotOptions{}); err != nil {
		t.Fatal(err)
	}
	header, _ := core.ParseJSONString(lines[0].(string))
	header.(*core.Object).Delete("createdAt")
	lines[0] = core.MustStringify(header)
	return lines
}

func sameLines(t *testing.T, label string, got []any, want any) {
	t.Helper()
	expected, _ := want.([]any)
	if len(got) != len(expected) {
		t.Fatalf("%s: %d snapshot lines, expected %d\n got  %v\n want %v", label, len(got), len(expected), got, expected)
	}
	for index := range expected {
		if got[index] != expected[index] {
			t.Errorf("%s line %d differs:\n  ts %s\n  go %s", label, index, expected[index], got[index])
		}
	}
}

func verifyChains(t *testing.T, store core.IamStore) *core.Object {
	t.Helper()
	ctx := context.Background()
	out := core.NewObject()
	for _, tenantID := range []string{"tnt_a", "tnt_b"} {
		events, err := store.Find(ctx, "audit", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			t.Fatal(err)
		}
		head, err := store.Get(ctx, "auditChains", tenantID)
		if err != nil {
			t.Fatal(err)
		}
		options := core.VerifyAuditChainOptions{}
		if head != nil {
			sequence, _ := head.Number("sequence")
			hash, _ := head.String("hash")
			options.Head = &core.AuditChainHeadRef{Sequence: sequence, Hash: hash}
		}
		result := core.VerifyAuditChain(events, options)
		if !result.Valid {
			t.Errorf("Go verification of %s failed: %+v", tenantID, result.Failure)
		}
		out.Set(tenantID, result)
	}
	return out
}

func lone(units ...uint16) string { return core.FromUTF16(units) }

// pointOne + pointTwo is computed in float64, as JavaScript computes 0.1 + 0.2.
var pointOne, pointTwo = 0.1, 0.2

// Run drives the whole exchange. open opens the file with the Go adapter; rawData reads one row's data column text.
func Run(t *testing.T, kind string, open func(path string) core.IamStore, rawData func(store core.IamStore, collection, id string) string) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fleet-"+kind+".db")

	// 1. TypeScript creates the database.
	created := runNode(t, "create", path, kind)

	// 2. Go reads it exactly as TypeScript does.
	store := open(path)
	sameLines(t, "Go export of the TypeScript database", exportLines(t, store), created.Get("snapshot"))
	chains := verifyChains(t, store)
	if !spectest.Equal(spectest.Model(chains), created.Get("chains")) {
		t.Errorf("chain verification differs:\n  ts %s\n  go %s", spectest.Show(created.Get("chains")), spectest.Show(spectest.Model(chains)))
	}

	// 3. Go writes records that must serialize exactly as JSON.stringify would, and continues the audit chains.
	odd, err := store.Get(ctx, "oddities", "odd_1")
	if err != nil || odd == nil {
		t.Fatalf("odd_1: %v %v", odd, err)
	}
	goRecord := core.NewObject("id", "go_1", "tenantId", "tnt_a", "lone", lone('g', 0xdc00), "nul", "x\u0000",
		"numbers", []any{1e21, 1e-7, pointOne + pointTwo, math.Pow(2, 60), math.Copysign(0, -1), 5e-324, 123456789.125},
		"map", core.NewObject("b", 1, "10", 2, "a", 3, "2", 4), "html", "<a href=\"x\">&</a>", "line", " ")
	err = store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if _, err := tx.Insert(ctx, "copies", odd); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "fromGo", goRecord); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "identities", core.NewObject("id", "idn_go", "tenantId", "tnt_a", "kind", "user", "email", "go@example.com",
			"uniqueKey", "go@example.com", "name", "Go", "status", "active", "emailVerified", false, "rootAdmin", false, "owner", false, "createdAt", 1767225600000.0)); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "oddities", core.NewObject("id", "odd_go", "tenantId", "tnt_a", "big", math.Pow(2, 60), "lone", lone('x', 0xd800, 'y'))); err != nil {
			return err
		}
		identity, err := tx.Get(ctx, "identities", "idn_ts")
		if err != nil {
			return err
		}
		if _, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("touchedByGo", true))); err != nil {
			return err
		}
		for n, tenantID := range []string{"tnt_a", "tnt_a", "tnt_b"} {
			event := core.NewObject("id", "evt_go_"+tenantID+"_"+core.NumberString(float64(n)), "tenantId", tenantID, "actorId", "idn_go",
				"action", "iam:roles:create", "resourceId", "role_go", "outcome", "allow", "rootOverride", false,
				"timestamp", 1767225700000.0+float64(n), "metadata", core.NewObject("by", "go", "z", []any{3.0, 1.0}, "ünï", "😀"))
			if _, err := core.AppendAuditEvent(ctx, tx, event); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A record Go re-serialized has the exact data text TypeScript wrote.
	if original, copy := rawData(store, "oddities", "odd_1"), rawData(store, "copies", "odd_1"); original != copy {
		t.Errorf("Go serialization differs from JSON.stringify:\n  ts %s\n  go %s", original, copy)
	}
	written := exportLines(t, store)
	verifyChains(t, store)
	if err := store.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// 4. TypeScript reads what Go wrote, queries it, and writes on top.
	checked := runNode(t, "check", path, kind)
	sameLines(t, "TypeScript export of the Go-written database", written, checked.Get("before"))
	tsChains, _ := checked.Object("chains")
	for _, tenantID := range []string{"tnt_a", "tnt_b"} {
		result, _ := tsChains.Object(tenantID)
		if valid, _ := result.Bool("valid"); !valid {
			t.Errorf("TypeScript verification of %s failed: %s", tenantID, spectest.Show(result))
		}
	}
	queries, _ := checked.Object("queries")
	expectations := map[string][]any{
		"byEmail":       {"idn_go"},
		"byNumber":      {"odd_1"},
		"byLargeNumber": {"odd_go"},
		"byBoolean":     {"idn_ts"},
		"byLone":        {"odd_1", "odd_go"},
	}
	for name, want := range expectations {
		if !spectest.Equal(queries.Get(name), want) {
			t.Errorf("TypeScript query %s on Go data: got %s, want %s", name, spectest.Show(queries.Get(name)), spectest.Show(want))
		}
	}
	if ordered, _ := queries.Array("ordered"); len(ordered) != 6 || ordered[0] != "evt_ts_tnt_a_100" {
		t.Errorf("TypeScript ordered audit read: %s", spectest.Show(ordered))
	}
	reread, _ := core.ParseJSONString(core.MustStringify(goRecord.Spread(core.NewObject("touchedByTs", true))))
	if !spectest.Equal(queries.Get("goRecord"), reread) {
		t.Errorf("TypeScript read of the Go record:\n  got  %s\n  want %s", spectest.Show(queries.Get("goRecord")), spectest.Show(reread))
	}

	// 5. Go reads TypeScript's writes on top of its own.
	store = open(path)
	defer store.Close(ctx)
	sameLines(t, "Go export after TypeScript's writes", exportLines(t, store), checked.Get("snapshot"))
	verifyChains(t, store)
	touched, err := store.Get(ctx, "fromGo", "go_1")
	if err != nil || touched == nil || touched.Get("touchedByTs") != true {
		t.Errorf("TypeScript's put of the Go record: %v %v", touched, err)
	}
	if !strings.Contains(rawData(store, "fromGo", "go_1"), `"touchedByTs":true`) {
		t.Errorf("unexpected data %s", rawData(store, "fromGo", "go_1"))
	}
}

// RunShared drives the shared TypeScript fleet script (scripts/conformance/fleet/sqlite-fleet.mjs, also used by the
// Rust adapter): TypeScript writes records and audit events, Go reads and checks them, adds its own, and TypeScript
// verifies everything (including that every stored data text is exactly JSON.stringify output). Skipped when that
// script is absent or reports it cannot run.
func RunShared(t *testing.T, open func(path string) core.IamStore) {
	root, err := spectest.Root()
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(root, "scripts", "conformance", "fleet", "sqlite-fleet.mjs")
	if _, err := os.Stat(shared); err != nil {
		t.Skip("scripts/conformance/fleet/sqlite-fleet.mjs is absent")
	}
	run := func(args ...string) *core.Object {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(Node(), append([]string{shared}, args...)...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			if os.Getenv("BETTER_IAM_FLEET") != "required" {
				t.Skip("shared fleet script failed: " + err.Error() + "\n" + stderr.String())
			}
			t.Fatal(err, stderr.String())
		}
		parsed, err := core.ParseJSON(bytes.TrimSpace(stdout.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		return parsed.(*core.Object)
	}
	if probe := run("probe", "-"); probe.Get("ok") != true {
		t.Skip("shared fleet script cannot run here: " + spectest.Show(probe))
	}
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.db")
	written := run("write", path, "ts")
	records, _ := written.Array("records")
	if len(records) == 0 {
		t.Skip("shared fleet script wrote no records (protocol changed?)")
	}
	store := open(path)
	expected := []any{}
	var tenantID string
	for _, item := range records {
		record := item.(*core.Object)
		id, _ := record.String("id")
		tenantID, _ = record.String("tenantId")
		read, err := store.Get(ctx, "fleet", id)
		if err != nil || !spectest.Equal(read, record) {
			t.Errorf("Go read of %s: %s (%v), TypeScript wrote %s", id, spectest.Show(read), err, spectest.Show(record))
		}
		expected = append(expected, record)
	}
	events, err := store.Find(ctx, "audit", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := store.Get(ctx, "auditChains", tenantID)
	if head == nil {
		t.Fatal("no audit chain head")
	}
	sequence, _ := head.Number("sequence")
	hash, _ := head.String("hash")
	if result := core.VerifyAuditChain(events, core.VerifyAuditChainOptions{Head: &core.AuditChainHeadRef{Sequence: sequence, Hash: hash}}); !result.Valid {
		t.Fatalf("Go verification of the TypeScript chain: %+v", result.Failure)
	}
	err = store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, item := range records {
			record := item.(*core.Object).Spread()
			id, _ := record.String("id")
			record.Set("id", "go-"+id)
			if key, ok := record.String("uniqueKey"); ok {
				record.Set("uniqueKey", "go-"+key)
			}
			record.Set("writer", "go")
			if _, err := tx.Insert(ctx, "fleet", record); err != nil {
				return err
			}
			expected = append(expected, record)
		}
		for n := 1; n <= 2; n++ {
			if _, err := core.AppendAuditEvent(ctx, tx, core.NewObject("id", "go-evt-"+core.NumberString(float64(n)), "tenantId", tenantID,
				"actorId", "idn_go", "action", "iam:groups:create", "resourceId", "grp_go", "timestamp", 1767225800000.0+float64(n),
				"outcome", "allow", "rootOverride", false, "metadata", core.NewObject("writer", "go", "n", n))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx); err != nil {
		t.Fatal(err)
	}
	expectations := core.NewObject("records", expected, "auditEvents", float64(len(events)+2), "deleted", []any{})
	expectedPath := filepath.Join(dir, "expected.json")
	if err := os.WriteFile(expectedPath, []byte(core.MustStringify(expectations)), 0o600); err != nil {
		t.Fatal(err)
	}
	verified := run("verify", path, expectedPath)
	if verified.Get("ok") != true {
		t.Fatalf("TypeScript verification of the Go writes: %s", spectest.Show(verified.Get("problems")))
	}
}
