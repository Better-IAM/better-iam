package cli

// Port of tests/cli-config.test.ts, tests/cli-analyze.test.ts and tests/cli-detect-threats.test.ts (their CLI
// parts).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestConfigCommandsAsTokenHolder(t *testing.T) {
	folder := t.TempDir()
	config := writeJSONConfig(t, folder, "better-iam.json")
	tenantID, token := rootSession(t, config)
	r := newRecorder(folder)
	io := func() *CliIO { return r.io(rootEnv) }
	asRoot := func() *CliIO { return r.io(merge(rootEnv, map[string]string{"BETTER_IAM_TOKEN": token})) }

	// Argument validation and the token requirement.
	expectCode(t, run([]string{"config-export", "--config", config}, io()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"config-plan", "--config", config, "--tenant", tenantID}, asRoot()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"config-export", "--config", config, "--tenant", tenantID, "--input", "x"}, asRoot()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"config-export", "--config", config, "--tenant", tenantID}, io()), "MISSING_ENV")
	// The root tenant starts with nothing but its protected owner role, which is never exported.
	mustRun(t, []string{"config-export", "--config", config, "--tenant", tenantID}, asRoot())
	expectEqual(t, r.last(t), core.NewObject("version", 1.0, "resourceTypes", []any{}, "policies", []any{}, "roles", []any{},
		"groups", []any{}, "bindings", []any{}, "packages", []any{}))
	input := filepath.Join(folder, "tenant.json")
	if err := os.WriteFile(input, []byte(`{"version":1,"roles":[{"name":"Reader","permissions":["documents:read"]}],"groups":[{"name":"Readers"}],"bindings":[{"group":"Readers","role":"Reader"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, []string{"config-plan", "--config", config, "--tenant", tenantID, "--input", input}, asRoot())
	expectEqual(t, at(r.last(t), "summary"), core.NewObject("create", 3.0, "update", 0.0, "delete", 0.0, "unchanged", 0.0))
	if !core.IsUndefined(at(r.last(t), "applied")) {
		t.Fatal("a plan is not applied")
	}
	mustRun(t, []string{"config-apply", "--config", config, "--tenant", tenantID, "--input", input, "--prune"}, asRoot())
	if at(r.last(t), "applied") != true || at(r.last(t), "prune") != true {
		t.Fatalf("apply %s", r.lastLine(t))
	}
	exported := filepath.Join(folder, "exported.json")
	mustRun(t, []string{"config-export", "--config", config, "--tenant", tenantID, "--output", exported}, asRoot())
	expectEqual(t, r.last(t), core.NewObject("tenantId", tenantID, "output", exported))
	text, _ := os.ReadFile(exported)
	document, _ := core.ParseJSON(text)
	if at(document, "roles", "0", "name") != "Reader" || at(document, "groups", "0", "name") != "Readers" ||
		core.MustStringify(at(document, "groups", "0", "members")) != "[]" || at(document, "bindings", "0", "role") != "Reader" {
		t.Fatalf("export %s", text)
	}
	// Applying the export is a no-op.
	mustRun(t, []string{"config-apply", "--config", config, "--tenant", tenantID, "--input", exported}, asRoot())
	expectEqual(t, at(r.last(t), "summary"), core.NewObject("create", 0.0, "update", 0.0, "delete", 0.0, "unchanged", 3.0))
	// --fail-on-drift turns a plan into a check: clean passes, drift exits non-zero after printing the plan.
	mustRun(t, []string{"config-plan", "--config", config, "--tenant", tenantID, "--input", exported, "--fail-on-drift"}, asRoot())
	if at(r.last(t), "summary", "unchanged") != 3.0 {
		t.Fatalf("plan %s", r.lastLine(t))
	}
	if err := os.WriteFile(input, []byte(`{"version":1,"roles":[{"name":"Reader","permissions":["documents:read"]},{"name":"Writer","permissions":["documents:read"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	expectCode(t, run([]string{"config-plan", "--config", config, "--tenant", tenantID, "--input", input, "--fail-on-drift"}, asRoot()), "CONFIG_DRIFT")
	if at(r.last(t), "summary", "create") != 1.0 {
		t.Fatalf("plan %s", r.lastLine(t))
	}
	// The digest is a deployment operation; this configuration has no mail transport.
	expectCode(t, run([]string{"digest", "--config", config, "--within-days", "7"}, io()), "DELIVERY_REQUIRED")
	expectCode(t, run([]string{"digest", "--config", config, "--input", "x"}, io()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"remind", "--config", config, "--within-days", "7"}, io()), "DELIVERY_REQUIRED")
	expectCode(t, run([]string{"remind", "--config", config, "--unused-days", "3"}, io()), "INVALID_ARGUMENT")
	// The access report runs as the token holder too.
	expectCode(t, run([]string{"report", "--config", config, "--tenant", tenantID, "--within-days", "x"}, asRoot()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"config-export", "--config", config, "--tenant", tenantID, "--unused-days", "3"}, asRoot()), "INVALID_ARGUMENT")
	mustRun(t, []string{"report", "--config", config, "--tenant", tenantID, "--within-days", "7", "--unused-days", "1"}, asRoot())
	report := r.lastObject(t)
	if at(report, "withinMs") != 7*day || at(report, "unusedForMs") != day || core.MustStringify(at(report, "omitted")) != "[]" ||
		core.MustStringify(at(report, "identities", "expiring")) != "[]" || at(report, "bindings", "pendingRequests") != 0.0 ||
		core.MustStringify(at(report, "credentials", "unused")) != "[]" {
		t.Fatalf("report %s", r.lastLine(t))
	}
	if strings.Contains(strings.Join(r.output, "\n"), token) {
		t.Fatal("the token was printed")
	}
}

func TestAnalyzeFailsAtTheChosenSeverity(t *testing.T) {
	folder := t.TempDir()
	config := writeJSONConfig(t, folder, "better-iam.json")
	tenantID, token := rootSession(t, config)
	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Config: config, Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	callRoute(t, iam, token, "roles/create", core.NewObject("tenantId", tenantID, "name", "Idle", "permissions", []any{"documents:read"}))
	_ = closeInstance(context.Background(), iam)
	r := newRecorder(folder)
	io := func() *CliIO { return r.io(rootEnv) }
	asRoot := func() *CliIO { return r.io(merge(rootEnv, map[string]string{"BETTER_IAM_TOKEN": token})) }

	expectCode(t, run([]string{"analyze", "--config", config}, asRoot()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"analyze", "--config", config, "--tenant", tenantID, "--fail-on", "urgent"}, asRoot()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"migrate", "--config", config, "--fail-on", "high"}, asRoot()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"analyze", "--config", config, "--tenant", tenantID}, io()), "MISSING_ENV")

	// Only a low finding (the unused role): a high threshold passes, a low threshold fails.
	mustRun(t, []string{"analyze", "--config", config, "--tenant", tenantID, "--fail-on", "high"}, asRoot())
	if core.MustStringify(at(r.last(t), "findings", "0", "kind")) != `"unused-role"` || len(at(r.last(t), "findings").([]any)) != 1 {
		t.Fatalf("findings %s", r.lastLine(t))
	}
	expectCode(t, run([]string{"analyze", "--config", config, "--tenant", tenantID, "--fail-on", "low"}, asRoot()), "FINDINGS")
	mustRun(t, []string{"analyze", "--config", config, "--tenant", tenantID, "--dormant-days", "30"}, asRoot())
	if at(r.last(t), "dormantDays") != 30.0 {
		t.Fatalf("analyze %s", r.lastLine(t))
	}
	if strings.Contains(strings.Join(r.output, "\n"), token) {
		t.Fatal("the token was printed")
	}

	// The certification worker is a deployment operation: no token, optional tenant filter.
	mustRun(t, []string{"close-certifications", "--config", config, "--tenant", tenantID}, io())
	expectEqual(t, r.last(t), core.NewObject("closed", []any{}, "skipped", 0.0))
	expectCode(t, run([]string{"close-certifications", "--config", config, "--fail-on", "high"}, io()), "INVALID_ARGUMENT")
}

func TestDetectThreatsAsDeploymentOperation(t *testing.T) {
	folder := t.TempDir()
	config := writeJSONConfig(t, folder, "better-iam.json")
	r := newRecorder(folder)
	io := func() *CliIO { return r.io(rootEnv) }
	mustRun(t, []string{"migrate", "--config", config}, io())
	mustRun(t, []string{"bootstrap", "--config", config}, io())
	tenantID := at(r.last(t), "tenant", "id").(string)

	// No credential: the first run reads the day's events of every active tenant, and a quiet trail raises nothing.
	mustRun(t, []string{"detect-threats", "--config", config}, io())
	first := r.lastObject(t)
	for key, want := range map[string]float64{"tenants": 1, "detections": 0, "incidentsOpened": 0, "responses": 0, "braked": 0, "chainBreaks": 0, "pending": 0} {
		if at(first, key) != want {
			t.Fatalf("%s: %s", key, r.lastLine(t))
		}
	}
	if at(first, "eventsScanned").(float64) <= 0 {
		t.Fatal("no events were scanned")
	}
	mustRun(t, []string{"detect-threats", "--config", config, "--tenant", tenantID}, io())
	if at(r.last(t), "tenants") != 1.0 || at(r.last(t), "eventsScanned") != 0.0 {
		t.Fatalf("second run %s", r.lastLine(t))
	}
	for _, flags := range [][]string{{"--max-events", "0"}, {"--max-events", "20001"}, {"--max-events", "many"}, {"--fail-on", "high"}} {
		expectCode(t, run(append([]string{"detect-threats", "--config", config}, flags...), io()), "INVALID_ARGUMENT")
	}
	expectCode(t, run([]string{"detect-threats", "--config", config, "--tenant", "no-such-tenant"}, io()), "NOT_FOUND")
}
