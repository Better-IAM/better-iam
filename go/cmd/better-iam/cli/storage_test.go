package cli

// The store-export, store-import and store-copy commands (tests/store-snapshot.test.ts, CLI part).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestStoreSnapshots(t *testing.T) {
	folder := t.TempDir()
	source := writeJSONConfig(t, folder, "source.json")
	r := newRecorder(folder)
	mustRun(t, []string{"migrate", "--config", source}, r.io(rootEnv))
	mustRun(t, []string{"bootstrap", "--config", source}, r.io(rootEnv))
	tenantID := at(r.last(t), "tenant", "id").(string)

	snapshot := filepath.Join(folder, "snapshot.jsonl")
	mustRun(t, []string{"store-export", "--config", source, "--output", snapshot}, r.io(nil))
	exported := r.lastObject(t)
	if at(exported, "output") != snapshot || at(exported, "records").(float64) < 5 {
		t.Fatalf("export %s", r.lastLine(t))
	}
	text, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(text)), "\n")
	if float64(len(lines)) != at(exported, "records").(float64)+2 {
		t.Fatalf("%d lines for %v records", len(lines), at(exported, "records"))
	}
	expectCode(t, run([]string{"store-export", "--config", source, "--output", snapshot}, r.io(nil)), "EEXIST")

	// Into an empty database, then a copy into another.
	targetFolder := t.TempDir()
	target := writeJSONConfig(t, targetFolder, "target.json")
	expectCode(t, run([]string{"store-import", "--config", target, "--input", filepath.Join(folder, "missing.jsonl")}, r.io(nil)), "ENOENT")
	mustRun(t, []string{"store-import", "--config", target, "--input", snapshot}, r.io(nil))
	imported := r.lastObject(t)
	if at(imported, "records") != at(exported, "records") || at(imported, "next") != "Run migrate to apply plugin migrations." {
		t.Fatalf("import %s", r.lastLine(t))
	}
	expectCode(t, run([]string{"store-import", "--config", target, "--input", snapshot}, r.io(nil)), "STORE_NOT_EMPTY")
	mustRun(t, []string{"audit-verify", "--config", target, "--tenant", tenantID}, r.io(nil))
	if at(r.last(t), "valid") != true {
		t.Fatal("the imported chain does not verify")
	}

	copyFolder := t.TempDir()
	copied := writeJSONConfig(t, copyFolder, "copy.json")
	expectCode(t, run([]string{"store-copy", "--config", source, "--target-config", source}, r.io(nil)), "INVALID_ARGUMENT")
	mustRun(t, []string{"store-copy", "--config", source, "--target-config", copied}, r.io(nil))
	if at(r.last(t), "records") != at(exported, "records") || at(r.last(t), "target") != copied {
		t.Fatalf("copy %s", r.lastLine(t))
	}
	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Config: copied, Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeInstance(context.Background(), iam)
	roots, err := iam.Store.Find(context.Background(), "tenants", core.NewObject("parentId", nil), nil)
	if err != nil || len(roots) != 1 || roots[0].Get("id") != tenantID {
		t.Fatalf("copied roots %v %v", roots, err)
	}
}
