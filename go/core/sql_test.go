package core_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// TestEmbeddedMigrationsMatchSpec keeps go/core/migrations (embedded) identical to spec/storage/migrations. If it
// fails after regenerating spec/, copy spec/storage/migrations/{sqlite,postgres}/*.sql into go/core/migrations/.
func TestEmbeddedMigrationsMatchSpec(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "libsql"} {
		embedded := "sqlite"
		if dialect == "postgres" {
			embedded = "postgres"
		}
		for _, name := range core.MigrationNames {
			data, err := os.ReadFile(spectest.Path(t, "storage", "migrations", dialect, name+".sql"))
			if err != nil {
				t.Fatal(err)
			}
			var statements []string
			for _, line := range strings.Split(string(data), "\n") {
				if line = strings.TrimSuffix(line, ";"); line != "" {
					statements = append(statements, line)
				}
			}
			if got := core.MigrationStatements(embedded, name); strings.Join(got, "\n") != strings.Join(statements, "\n") {
				t.Errorf("%s/%s: embedded statements differ from spec", dialect, name)
			}
		}
	}
	// The index lists the same migration names in the same order.
	data, err := os.ReadFile(spectest.Path(t, "storage", "migrations", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := core.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	names, _ := index.(*core.Object).Array("names")
	if len(names) != len(core.MigrationNames) {
		t.Fatalf("index.json lists %d migrations, Go %d", len(names), len(core.MigrationNames))
	}
	for position, name := range names {
		if name != core.MigrationNames[position] {
			t.Errorf("migration %d: spec %v, Go %s", position, name, core.MigrationNames[position])
		}
	}
}

// TestStorageConstantsMatchSpec checks the storage constants against spec/storage/collections.json.
func TestStorageConstantsMatchSpec(t *testing.T) {
	data, err := os.ReadFile(spectest.Path(t, "storage", "collections.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	spec := parsed.(*core.Object)
	list := func(values []string) []any {
		out := make([]any, len(values))
		for index, value := range values {
			out[index] = value
		}
		return out
	}
	found := 0
	var walk func(key string, value any)
	walk = func(key string, value any) {
		switch key {
		case "indexedFields", "INDEXED_FIELDS":
			found++
			if !spectest.Equal(value, list(core.IndexedFields)) {
				t.Errorf("%s: spec %s, Go %v", key, spectest.Show(value), core.IndexedFields)
			}
		case "orderedFields", "ORDERED_FIELDS":
			found++
			if !spectest.Equal(value, list(core.OrderedFields)) {
				t.Errorf("%s: spec %s, Go %v", key, spectest.Show(value), core.OrderedFields)
			}
		case "expiryFields", "EXPIRY_FIELDS":
			found++
			if !spectest.Equal(value, list(core.ExpiryFields)) {
				t.Errorf("%s: spec %s, Go %v", key, spectest.Show(value), core.ExpiryFields)
			}
		case "maxQueryConditions", "MAX_QUERY_CONDITIONS":
			found++
			if value != float64(core.MaxQueryConditions) {
				t.Errorf("%s: spec %s, Go %d", key, spectest.Show(value), core.MaxQueryConditions)
			}
		}
		if o, ok := value.(*core.Object); ok && key != "collections" {
			for _, child := range o.Keys() {
				walk(child, o.Get(child))
			}
		}
	}
	for _, key := range spec.Keys() {
		walk(key, spec.Get(key))
	}
	if found < 4 {
		t.Errorf("found only %d of the storage constants in collections.json (keys %v)", found, spec.Keys())
	}
}
