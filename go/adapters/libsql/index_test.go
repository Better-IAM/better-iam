package libsql

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func open(t *testing.T, url string) *Store {
	t.Helper()
	store, err := New(Options{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func runConformance(t *testing.T, create func(t *testing.T) *Store) {
	ctx := context.Background()
	for _, test := range core.AdapterConformanceCases() {
		t.Run(test.Name, func(t *testing.T) {
			store := create(t)
			if err := store.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			defer store.Close(ctx)
			if err := test.Run(ctx, store); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConformanceMemory(t *testing.T) {
	runConformance(t, func(t *testing.T) *Store { return open(t, ":memory:") })
}

func TestConformanceFileURL(t *testing.T) {
	dir := t.TempDir()
	count := 0
	runConformance(t, func(t *testing.T) *Store {
		count++
		return open(t, "file:"+filepath.Join(dir, "libsql-"+core.NumberString(float64(count))+".db"))
	})
}

func TestConformancePlainPath(t *testing.T) {
	dir := t.TempDir()
	count := 0
	runConformance(t, func(t *testing.T) *Store {
		count++
		return open(t, filepath.Join(dir, "plain-"+core.NumberString(float64(count))+".db"))
	})
}

// TestRemoteConformance runs against a sqld / Turso database when BETTER_IAM_LIBSQL_URL is set (an empty database:
// every case drops its records again by using fresh collection names is not possible, so point it at a scratch
// database). BETTER_IAM_LIBSQL_TOKEN is the bearer token.
func TestRemoteConformance(t *testing.T) {
	url := os.Getenv("BETTER_IAM_LIBSQL_URL")
	if url == "" {
		t.Skip("BETTER_IAM_LIBSQL_URL is not set")
	}
	ctx := context.Background()
	runConformance(t, func(t *testing.T) *Store {
		store, err := New(Options{URL: url, AuthToken: os.Getenv("BETTER_IAM_LIBSQL_TOKEN")})
		if err != nil {
			t.Fatal(err)
		}
		// Start every case from an empty table.
		_, _ = store.shared.conn.ExecContext(ctx, "DROP TABLE IF EXISTS iam_records")
		_, _ = store.shared.conn.ExecContext(ctx, "DROP TABLE IF EXISTS iam_migrations")
		_, _ = store.shared.conn.ExecContext(ctx, "DROP TABLE IF EXISTS iam_schema_version")
		return store
	})
}

func TestOptionsValidation(t *testing.T) {
	for _, item := range []struct {
		options Options
		code    string
		message string
	}{
		{Options{}, "INVALID_CONFIG", "libSQL requires a url: :memory:, file:, libsql:, https:, or wss:"},
		{Options{URL: "postgres://x"}, "INVALID_CONFIG", "Unsupported libSQL URL scheme"},
		{Options{URL: ":memory:", BusyTimeoutMs: core.Ptr(70_000)}, "INVALID_CONFIG", "busyTimeoutMs must be between 0 and 60000"},
		{Options{URL: ":memory:", EncryptionKey: "k"}, "NOT_IMPLEMENTED", ""},
		{Options{URL: "file:x.db", SyncURL: "libsql://x"}, "NOT_IMPLEMENTED", ""},
	} {
		_, err := New(item.options)
		iamError, ok := err.(*core.IamError)
		if !ok || iamError.Code != item.code || (item.message != "" && iamError.Message != item.message) {
			t.Errorf("%+v: got %v", item.options, err)
		}
	}
	// A Windows drive letter is a path, not a scheme.
	if !scheme.MatchString("libsql:x") || scheme.MatchString(`C:\x.db`) {
		t.Error("scheme detection differs from the TypeScript adapter")
	}
}

func TestMigrationStatementsMatchSpec(t *testing.T) {
	data, err := os.ReadFile(spectest.Path(t, "storage", "migrations", "libsql", "runner.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	runner := parsed.(*core.Object)
	clock, _ := runner.Number("appliedAtClock")
	var recorded []*core.Object
	trace = func(text string, values []any) {
		// The client's own statements (opening check, BEGIN IMMEDIATE, COMMIT) are events in the runner file.
		switch {
		case text == "BEGIN IMMEDIATE", text == "COMMIT", strings.HasPrefix(text, "PRAGMA busy_timeout"), strings.HasPrefix(text, "SELECT 1 AS"):
			return
		}
		params := make([]any, len(values))
		for index, value := range values {
			params[index] = core.Normalize(value)
		}
		recorded = append(recorded, core.NewObject("sql", text, "params", params))
	}
	defer func() { trace = nil }()
	ctx := context.Background()
	store := open(t, ":memory:")
	defer store.Close(ctx)
	for _, phase := range []string{"fresh", "current"} {
		recorded = nil
		if err := store.migrate(ctx, core.MigrationOptions{Now: int64(clock)}); err != nil {
			t.Fatal(err)
		}
		events, _ := runner.Array(phase)
		var expected []*core.Object
		for _, item := range events {
			event := item.(*core.Object)
			if event.Has("sql") {
				expected = append(expected, core.NewObject("sql", event.Get("sql"), "params", event.Get("params")))
			}
		}
		if len(recorded) != len(expected) {
			t.Fatalf("%s: %d statements, spec has %d", phase, len(recorded), len(expected))
		}
		for index := range expected {
			if !spectest.Equal(recorded[index], expected[index]) {
				t.Errorf("%s statement %d:\n  expected %s\n  received %s", phase, index, spectest.Show(expected[index]), spectest.Show(recorded[index]))
			}
		}
	}
}

func TestDescribe(t *testing.T) {
	ctx := context.Background()
	store := open(t, "file:"+filepath.Join(t.TempDir(), "describe.db"))
	defer store.Close(ctx)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	description, err := store.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if description.Adapter != "libsql" || *description.SchemaVersion != 1 || len(description.Migrations) != 6 {
		t.Fatalf("described %+v", description)
	}
	if location, _ := description.Settings.String("location"); location != "file" {
		t.Errorf("location %q", location)
	}
	if keys := strings.Join(description.Settings.Keys(), ","); keys != "location,inMemory,journalMode" {
		t.Errorf("settings keys %s", keys)
	}
}
