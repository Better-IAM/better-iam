package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func open(t *testing.T, filename string) *Store {
	t.Helper()
	store, err := New(Options{Filename: filename})
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

func TestConformanceFile(t *testing.T) {
	dir := t.TempDir()
	count := 0
	runConformance(t, func(t *testing.T) *Store {
		count++
		return open(t, filepath.Join(dir, "conformance-"+core.NumberString(float64(count))+".db"))
	})
}

func TestOptionsValidation(t *testing.T) {
	for _, item := range []struct {
		options Options
		message string
	}{
		{Options{}, "SQLite requires a filename or :memory:; URI filenames are unsupported"},
		{Options{Filename: "file:x.db"}, "SQLite requires a filename or :memory:; URI filenames are unsupported"},
		{Options{Filename: ":memory:", BusyTimeoutMs: core.Ptr(-1)}, "busyTimeoutMs must be between 0 and 60000"},
		{Options{Filename: ":memory:", BusyTimeoutMs: core.Ptr(60_001)}, "busyTimeoutMs must be between 0 and 60000"},
		{Options{Filename: ":memory:", JournalMode: "truncate"}, "journalMode must be wal or delete"},
		{Options{Filename: ":memory:", Durability: "off"}, "durability must be full or normal"},
	} {
		_, err := New(item.options)
		iamError, ok := err.(*core.IamError)
		if !ok || iamError.Code != "INVALID_CONFIG" || iamError.Status != 400 || iamError.Message != item.message {
			t.Errorf("%+v: got %v", item.options, err)
		}
	}
}

// TestMigrationStatementsMatchSpec replays migrate() against spec/storage/migrations/sqlite/runner.json: the same
// statements with the same bound values, for a fresh database and an up-to-date one.
func TestMigrationStatementsMatchSpec(t *testing.T) {
	data, err := os.ReadFile(spectest.Path(t, "storage", "migrations", "sqlite", "runner.json"))
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
	var mu sync.Mutex
	trace = func(text string, values []any) {
		mu.Lock()
		defer mu.Unlock()
		// better-sqlite3 sets the busy timeout through its API (the `timeout` option), not as a statement.
		if strings.HasPrefix(text, "PRAGMA busy_timeout") {
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
	// The runner records the adapter's construction (its pragmas) as part of the fresh run.
	store := open(t, ":memory:")
	defer store.Close(ctx)
	for _, phase := range []string{"fresh", "current"} {
		if phase == "current" {
			recorded = nil
		}
		if err := store.migrate(ctx, core.MigrationOptions{Now: int64(clock)}); err != nil {
			t.Fatal(err)
		}
		events, _ := runner.Array(phase)
		var expected []*core.Object
		for _, item := range events {
			event := item.(*core.Object)
			if !event.Has("sql") {
				continue
			}
			expected = append(expected, core.NewObject("sql", event.Get("sql"), "params", event.Get("params")))
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
	store := open(t, filepath.Join(t.TempDir(), "describe.db"))
	defer store.Close(ctx)
	before, err := store.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.SchemaVersion != nil || len(before.Migrations) != 0 || len(before.Collections) != 0 {
		t.Fatalf("unmigrated database: %+v", before)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "tenants", core.NewObject("id", "t", "tenantId", "t"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	after, err := store.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Adapter != "sqlite" || after.SchemaVersion == nil || *after.SchemaVersion != 1 || len(after.Migrations) != 6 ||
		len(after.Collections) != 1 || after.Collections[0].Records != 1 {
		t.Fatalf("described %+v", after)
	}
	if mode, _ := after.Settings.String("journalMode"); mode != "wal" {
		t.Errorf("journal mode %q", mode)
	}
	if mode, _ := after.Settings.String("synchronous"); mode != "full" {
		t.Errorf("synchronous %q", mode)
	}
	keys := strings.Join(after.Settings.Keys(), ",")
	if keys != "journalMode,synchronous,sizeBytes,freeBytes,inMemory" {
		t.Errorf("settings keys %s", keys)
	}
}

func TestSameFileSharesLockAcrossInstances(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shared.db")
	first := open(t, path)
	defer first.Close(ctx)
	second := open(t, path)
	defer second.Close(ctx)
	if err := first.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// A second instance on the same file inside the first's transaction fails instead of deadlocking.
	err := first.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := second.Get(ctx, "items", "x")
		return err
	})
	if iamError, ok := err.(*core.IamError); !ok || iamError.Code != "DATABASE_IN_USE" || iamError.Status != 409 {
		t.Fatalf("expected DATABASE_IN_USE, got %v", err)
	}
	// CopyStore onto itself reports SAME_DATABASE.
	_, err = core.CopyStore(ctx, first, second, core.SnapshotOptions{})
	if iamError, ok := err.(*core.IamError); !ok || iamError.Code != "SAME_DATABASE" {
		t.Fatalf("expected SAME_DATABASE, got %v", err)
	}
	// Outside a transaction the instances simply take turns.
	done := make(chan error, 1)
	go func() {
		done <- second.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			_, err := tx.Insert(ctx, "items", core.NewObject("id", "b", "tenantId", "t"))
			return err
		})
	}()
	if err := first.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		time.Sleep(10 * time.Millisecond)
		_, err := tx.Insert(ctx, "items", core.NewObject("id", "a", "tenantId", "t"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	records, err := second.Find(ctx, "items", nil, nil)
	if err != nil || len(records) != 2 {
		t.Fatalf("records %v %v", records, err)
	}
}

func TestInstrumentedStoreKeepsOptionalMethods(t *testing.T) {
	ctx := context.Background()
	store := open(t, ":memory:")
	var calls []core.StoreCall
	wrapped := core.InstrumentStore(store, func(call core.StoreCall) { calls = append(calls, call) }, nil)
	if _, ok := wrapped.(core.OrderedFinder); !ok {
		t.Fatal("instrumented store lost FindOrdered")
	}
	if _, ok := wrapped.(core.CollectionLister); !ok {
		t.Fatal("instrumented store lost Collections")
	}
	if _, ok := wrapped.(core.Describer); !ok {
		t.Fatal("instrumented store lost Describe")
	}
	if err := wrapped.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "items", core.NewObject("id", "a", "tenantId", "t"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.Find(ctx, "items", core.NewObject("tenantId", "t", "a", 1), &core.FindOptions{Limit: core.Ptr(5), After: core.Ptr("")}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0].Method != "insert" || !calls[0].InTransaction || calls[1].Method != "find" ||
		strings.Join(calls[1].FilterKeys, ",") != "a,tenantId" || !calls[1].Page.Keyset || calls[1].Records != 0 {
		t.Fatalf("calls %+v", calls)
	}
	summary, keys := core.SummarizeStoreCalls(calls)
	if strings.Join(keys, ",") != "insert:items,find:items" || summary["insert:items"].Calls != 1 {
		t.Fatalf("summary %+v %v", summary, keys)
	}
	_ = wrapped.Close(ctx)
}

// brokenStore drops the last record of every find: the conformance suite must notice.
type brokenStore struct{ *Store }

func (b brokenStore) Find(ctx context.Context, collection string, filter *core.Object, options *core.FindOptions) ([]*core.Object, error) {
	records, err := b.Store.Find(ctx, collection, filter, options)
	if len(records) > 0 {
		records = records[:len(records)-1]
	}
	return records, err
}

func TestConformanceDetectsBrokenStores(t *testing.T) {
	result := core.RunAdapterConformance(context.Background(), func() (core.IamStore, error) {
		store, err := New(Options{Filename: ":memory:"})
		return brokenStore{store}, err
	})
	if len(result.Failed) < 5 {
		t.Fatalf("only %d cases failed for a store that drops records", len(result.Failed))
	}
}

func lines(value any) []string {
	list, _ := value.([]any)
	out := make([]string, len(list))
	for index, item := range list {
		out[index] = item.(string)
	}
	return out
}

// TestSnapshotVectors reproduces spec/vectors/snapshot.json (exportStore / importStore on a fresh :memory: store).
func TestSnapshotVectors(t *testing.T) {
	ctx := context.Background()
	fixed := func() time.Time { return time.UnixMilli(1767225600000) }
	for _, c := range spectest.Load(t, "snapshot").Cases {
		store := open(t, ":memory:")
		if err := store.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(c.Name, "export ") {
			records := c.Input.Get("records").(*core.Object)
			if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				for _, collection := range records.Keys() {
					for _, item := range records.Get(collection).([]any) {
						if _, err := tx.Insert(ctx, collection, item.(*core.Object)); err != nil {
							return err
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			options := core.SnapshotOptions{Clock: fixed}
			if o, ok := c.Input.Object("options"); ok {
				if list, ok := o.Array("collections"); ok {
					options.Collections = lines(list)
				}
				if size, ok := o.Number("pageSize"); ok {
					options.PageSize = core.Ptr(int(size))
				}
			}
			var written []any
			summary, err := core.ExportStore(ctx, store, func(line string) error { written = append(written, line); return nil }, options)
			if err != nil {
				spectest.Check(t, c, spectest.ErrorValue(err))
			} else {
				spectest.Check(t, c, core.NewObject("lines", written, "summary", summary.ToValue()))
			}
		} else {
			if existing, ok := c.Input.Object("existing"); ok {
				if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
					_, err := tx.Insert(ctx, "tenants", existing)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			summary, err := core.ImportStore(ctx, store, lines(c.Input.Get("lines")))
			if err != nil {
				spectest.Check(t, c, spectest.ErrorValue(err))
			} else {
				stored := core.NewObject()
				names, err := store.Collections(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range names {
					records, err := store.Find(ctx, name, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					ids := []any{}
					for _, record := range records {
						id, _ := record.String("id")
						ids = append(ids, id)
					}
					stored.Set(name, ids)
				}
				spectest.Check(t, c, core.NewObject("summary", summary.ToValue(), "stored", stored))
			}
		}
		_ = store.Close(ctx)
	}
}
