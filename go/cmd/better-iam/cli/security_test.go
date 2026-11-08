package cli

// Port of tests/security-cli.test.ts: help and shell completion never load a configuration they merely found, CI
// gates fail on a chain that proves nothing, destructive retention flags ignore shared defaults, and server text
// cannot drive the terminal.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestDiscoveryNeverLoadsForHelpOrCompletion(t *testing.T) {
	for _, argv := range [][]string{{"help"}, {"--help"}, {"help", "login"}, {"completion", "bash"}} {
		top := t.TempDir()
		var loaded atomic.Int32
		program := CreateCli(CreateCliOptions{LoadModule: func(ctx context.Context, path string, env map[string]string) (*ConfigModule, error) {
			loaded.Add(1)
			return &ConfigModule{}, nil
		}})
		placeholderConfig(t, top)
		deep := filepath.Join(top, "a", "b")
		if err := os.MkdirAll(deep, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = program.Run(context.Background(), argv, newRecorder(deep).io(nil))
		if loaded.Load() != 0 {
			t.Fatalf("better-iam %s loaded a found configuration", strings.Join(argv, " "))
		}
	}
}

func TestDiscoveryStopsAtTheRepositoryRoot(t *testing.T) {
	top := t.TempDir()
	var loaded atomic.Int32
	program := CreateCli(CreateCliOptions{LoadModule: func(ctx context.Context, path string, env map[string]string) (*ConfigModule, error) {
		loaded.Add(1)
		return &ConfigModule{}, nil
	}})
	placeholderConfig(t, top)
	repository := filepath.Join(top, "repo")
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectCode(t, program.Run(context.Background(), []string{"migrate"}, newRecorder(repository).io(nil)), "CONFIG_NOT_FOUND")
	if loaded.Load() != 0 {
		t.Fatal("discovery left the repository")
	}
	if found := FindConfigFile(repository); found != "" {
		t.Fatalf("found %s", found)
	}
	if found := FindConfigFile(filepath.Join(top)); found != filepath.Join(top, "better-iam.json") {
		t.Fatalf("found %q", found)
	}
}

func TestAuditGates(t *testing.T) {
	directory := t.TempDir()
	database := filepath.Join(directory, "iam.db")
	env := merge(map[string]string{"BETTER_IAM_DATABASE_URL": "sqlite:" + database, "BETTER_IAM_SECRET": testSecret}, rootEnv)
	r := newRecorder(directory)
	mustRun(t, []string{"migrate"}, r.io(env))
	mustRun(t, []string{"bootstrap"}, r.io(env))
	tenantID := at(r.last(t), "tenant", "id").(string)
	expectCode(t, run([]string{"audit-verify", "--tenant", "no-such-tenant"}, r.io(env)), "NOT_FOUND")
	mustRun(t, []string{"audit-verify", "--tenant", tenantID}, r.io(env))
	if at(r.last(t), "valid") != true {
		t.Fatal("a fresh chain must verify")
	}
	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Cwd: directory, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	err = iam.Store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		events, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := tx.Delete(ctx, "audit", event.Get("id").(string)); err != nil {
				return err
			}
		}
		return nil
	})
	_ = closeInstance(context.Background(), iam)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, run([]string{"audit-verify", "--tenant", tenantID}, r.io(env)), "AUDIT_CHAIN_BROKEN")
	archive := t.TempDir()
	if err := os.Mkdir(filepath.Join(archive, "ten_1"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectCode(t, run([]string{"audit-verify-archive", "--directory", archive, "--tenant", "ten_1"}, r.io(env)), "AUDIT_ARCHIVE_INVALID")
	expectCode(t, run([]string{"audit-verify-archive", "--directory", archive, "--tenant", "../x"}, r.io(env)), "INVALID_ARGUMENT")
}

func TestSharedDefaultsNeverShortenRetention(t *testing.T) {
	// The flag specs: audit-prune and purge only take their own command's defaults.
	for _, name := range []string{"audit-prune", "purge"} {
		spec := findCommand(builtinCommands, name)
		flag, _ := findFlag(spec.Flags, "retention-days")
		if !flag.NoWildcardDefault {
			t.Fatalf("%s --retention-days takes '*' defaults", name)
		}
	}
	// The mechanism: a '*' default fills a flag unless it refuses shared defaults; the command's own default does.
	echo := func(name string) *CommandSpec {
		return DefineCommand(CommandSpec{
			Name: name, Summary: "Print the retention it received", Target: "config", NoConfigDefaults: false,
			Flags: []FlagSpec{
				func() FlagSpec {
					flag := boundedInteger("retention-days", "Keep", 0, 36500, 365.0)
					flag.NoWildcardDefault = name == "guarded"
					return flag
				}(),
			},
			Run: func(ctx context.Context, c *CommandContext) (any, error) {
				days, _ := c.Flags.Int("retention-days")
				if !c.Flags.Has("retention-days") {
					days = 365
				}
				return core.NewObject("retentionMs", float64(days)*day), nil
			},
		})
	}
	folder := t.TempDir()
	writeJSONConfig(t, folder, "better-iam.json", "cli", core.NewObject("defaults", core.NewObject("*", core.NewObject("retention-days", 7.0))))
	program := CreateCli(CreateCliOptions{Commands: []*CommandSpec{echo("guarded"), echo("open")}})
	r := newRecorder(folder)
	if err := program.Run(context.Background(), []string{"guarded"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if at(r.last(t), "retentionMs") != 365*day {
		t.Fatalf("guarded %s", r.lastLine(t))
	}
	if err := program.Run(context.Background(), []string{"open"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if at(r.last(t), "retentionMs") != 7*day {
		t.Fatalf("open %s", r.lastLine(t))
	}
	// audit-prune itself keeps a year with the shared default in place.
	mustRun(t, []string{"migrate"}, r.io(map[string]string{}))
	mustRun(t, []string{"bootstrap"}, r.io(rootEnv))
	tenantID := at(r.last(t), "tenant", "id").(string)
	mustRun(t, []string{"audit-prune", "--tenant", tenantID}, r.io(nil))
	if r.lastLine(t) != `{"deleted":0}` {
		t.Fatalf("prune %s", r.lastLine(t))
	}
}

func TestOutputShowsControlSequencesAsReplacementCharacters(t *testing.T) {
	evil := "Mallory\x1b]52;c;cHduZWQ=\x07\x1b[2K"
	for _, item := range []struct {
		value  any
		format string
		query  string
	}{
		{core.NewObject("rows", []any{core.NewObject("name", evil)}), "table", ""},
		{core.NewObject("name", evil), "json", "name"},
		// JSON output escapes them already.
		{core.NewObject("name", evil), "json", ""},
	} {
		text, err := FormatResult(item.value, item.format, item.query, item.query != "")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "\x1b") {
			t.Fatalf("%q carries an escape", text)
		}
	}
}

func TestLiteralAtValues(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "secret.txt"), []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolve := func(value string) string { return filepath.Join(directory, value) }
	body, err := RequestBody(&CliIO{Env: map[string]string{}}, resolve, nil, []string{`displayName=\@secret.txt`})
	if err != nil {
		t.Fatal(err)
	}
	expectEqual(t, body, core.NewObject("displayName", "@secret.txt"))
	body, err = RequestBody(&CliIO{Env: map[string]string{}}, resolve, nil, []string{"content=@secret.txt", "tags[]=a", "tags[]=b", "nested.value:=1"})
	if err != nil {
		t.Fatal(err)
	}
	expectEqual(t, body, core.NewObject("content", "TOP-SECRET", "tags", []any{"a", "b"}, "nested", core.NewObject("value", 1.0)))
	data := `{"name":"x","__proto__":{"polluted":true},"nested":{"constructor":1,"keep":2}}`
	body, err = RequestBody(&CliIO{Env: map[string]string{}}, resolve, &data, nil)
	if err != nil {
		t.Fatal(err)
	}
	expectEqual(t, body, core.NewObject("name", "x", "nested", core.NewObject("keep", 2.0)))
}

func TestSelectPathAndTables(t *testing.T) {
	value := core.NewObject("summary", core.NewObject("create", 2.0), "findings", []any{core.NewObject("kind", "a"), core.NewObject("kind", "b")})
	for _, item := range []struct {
		path string
		want string
	}{
		{"summary.create", "2"},
		{"findings[].kind", `["a","b"]`},
		{"findings.0.kind", `"a"`},
		{"findings[1].kind", `"b"`},
		{"findings.length", "2"},
		{"missing.deep", "null"},
		{"findings.9.kind", "null"},
	} {
		selected, err := SelectPath(value, item.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := core.MustStringify(selected); got != item.want {
			t.Fatalf("%s selected %s, want %s", item.path, got, item.want)
		}
	}
	for _, path := range []string{"__proto__", "a[x]", "a.constructor"} {
		if _, err := SelectPath(value, path); codeOf(err) != "INVALID_ARGUMENT" {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if got := RenderTable([]any{}); got != "(no rows)" {
		t.Fatal(got)
	}
	if got := RenderTable(core.NewObject("a", 1.0, "long", "x")); got != "a     1\nlong  x" {
		t.Fatalf("%q", got)
	}
	wide := core.NewObject()
	for _, key := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		wide.Set(key, key)
	}
	expectContains(t, RenderTable([]any{wide}), "(1 more column(s); use --format json to see them)")
	text, _ := FormatResult(core.NewObject("empty", core.NewObject(), "list", []any{}), "json", "", false)
	if text != "{\n  \"empty\": {},\n  \"list\": []\n}" {
		t.Fatalf("%q", text)
	}
}
