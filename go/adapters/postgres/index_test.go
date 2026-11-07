package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// The PostgreSQL tests need a server: set BETTER_IAM_POSTGRES_URL (CI does) to a scratch database. Every case starts
// from dropped tables.

func connection(t *testing.T) string {
	t.Helper()
	url := os.Getenv("BETTER_IAM_POSTGRES_URL")
	if url == "" {
		t.Skip("BETTER_IAM_POSTGRES_URL is not set")
	}
	return url
}

func fresh(t *testing.T, url string) *Store {
	t.Helper()
	store, err := New(Options{ConnectionString: url})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, table := range []string{"iam_records", "iam_migrations", "iam_schema_version"} {
		if _, err := store.shared.pool.Exec(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestPostgresOptionsValidation(t *testing.T) {
	for _, item := range []struct {
		options Options
		message string
	}{
		{Options{}, "A PostgreSQL connection string is required"},
		{Options{ConnectionString: "mysql://x"}, "A PostgreSQL connection string is required"},
		{Options{ConnectionString: "postgres://localhost/x", PoolSize: core.Ptr(0)}, "Invalid PostgreSQL pool size or lock timeout"},
		{Options{ConnectionString: "postgres://localhost/x", PoolSize: core.Ptr(101)}, "Invalid PostgreSQL pool size or lock timeout"},
		{Options{ConnectionString: "postgresql://localhost/x", LockTimeoutMs: core.Ptr(0)}, "Invalid PostgreSQL pool size or lock timeout"},
		{Options{ConnectionString: "postgresql://localhost/x", LockTimeoutMs: core.Ptr(60_001)}, "Invalid PostgreSQL pool size or lock timeout"},
	} {
		_, err := New(item.options)
		iamError, ok := err.(*core.IamError)
		if !ok || iamError.Code != "INVALID_CONFIG" || iamError.Message != item.message {
			t.Errorf("%+v: got %v", item.options, err)
		}
	}
	// Construction does not connect.
	store, err := New(Options{ConnectionString: "postgres://nobody@127.0.0.1:1/none"})
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close(context.Background())
}

func TestPostgresConformance(t *testing.T) {
	url := connection(t)
	ctx := context.Background()
	for _, test := range core.AdapterConformanceCases() {
		t.Run(test.Name, func(t *testing.T) {
			store := fresh(t, url)
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

func TestPostgresMigrationStatementsMatchSpec(t *testing.T) {
	url := connection(t)
	data, err := os.ReadFile(spectest.Path(t, "storage", "migrations", "postgres", "runner.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	runner := parsed.(*core.Object)
	clock, _ := runner.Number("appliedAtClock")
	store := fresh(t, url)
	defer store.Close(context.Background())
	var recorded []*core.Object
	trace = func(text string, values []any) {
		params := make([]any, len(values))
		for index, value := range values {
			params[index] = core.Normalize(value)
		}
		recorded = append(recorded, core.NewObject("sql", text, "params", params))
	}
	defer func() { trace = nil }()
	for _, phase := range []string{"fresh", "current"} {
		recorded = nil
		if err := store.migrate(context.Background(), core.MigrationOptions{Now: int64(clock), Before: core.EncodeLegacyPostgresRows}); err != nil {
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

func TestPostgresDescribe(t *testing.T) {
	url := connection(t)
	ctx := context.Background()
	store := fresh(t, url)
	defer store.Close(ctx)
	before, err := store.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.SchemaVersion != nil || len(before.Collections) != 0 {
		t.Fatalf("unmigrated: %+v", before)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := store.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Adapter != "postgres" || after.SchemaVersion == nil || *after.SchemaVersion != 1 || len(after.Migrations) != 6 {
		t.Fatalf("described %+v", after)
	}
}
