package cli

// Port of tests/cli.test.ts and tests/cli-dx.test.ts.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

func TestInitDoesNotOverwrite(t *testing.T) {
	config := filepath.Join(t.TempDir(), "better-iam.json")
	r := newRecorder("")
	mustRun(t, []string{"init", "--config", config}, r.io(nil))
	text, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	expectContains(t, string(text), "BETTER_IAM_SECRET")
	expectCode(t, run([]string{"init", "--config", config}, newRecorder("").io(nil)), "CONFIG_EXISTS")
	if len(r.output) != 1 {
		t.Fatalf("printed %d lines", len(r.output))
	}
}

func TestMigrateBootstrapDiagnoseRecover(t *testing.T) {
	folder := t.TempDir()
	config := writeJSONConfig(t, folder, "better-iam.json")
	r := newRecorder(folder)
	io := func(env ...map[string]string) *CliIO {
		return r.io(merge(append([]map[string]string{rootEnv}, env...)...))
	}
	mustRun(t, []string{"migrate", "--config", config}, io())
	mustRun(t, []string{"bootstrap", "--config", config}, io())
	bootstrap := r.lastObject(t)
	if at(bootstrap, "mfaEnrollmentRequired") != true {
		t.Fatal("root must enroll MFA")
	}
	if strings.Contains(strings.Join(r.output, "\n"), rootEnv["BETTER_IAM_ROOT_PASSWORD"]) {
		t.Fatal("the password was printed")
	}
	mustRun(t, []string{"doctor", "--config", config}, io())
	if at(r.last(t), "rootInitialized") != true {
		t.Fatal("root not initialized")
	}
	expectCode(t, run([]string{"bootstrap", "--config", config}, io()), "ALREADY_INITIALIZED")
	mustRun(t, []string{"recover-root", "--config", config}, io(map[string]string{"BETTER_IAM_ROOT_EMAIL": "recovery@example.test"}))
	if at(r.last(t), "identity", "rootAdmin") != true {
		t.Fatal("recovered identity is not root")
	}
	mustRun(t, []string{"outbox", "--config", config}, io())
	if r.lastLine(t) != `{"delivered":0,"failed":0,"abandoned":0}` {
		t.Fatalf("outbox printed %s", r.lastLine(t))
	}
	emptyPurge := `{"purgedTenants":[],"deletedRecords":0,"expiredBindings":0,"expiredRequests":0,"expiredIdentities":0,"expiredActivations":0,"expiredMemberships":0,"expiredAssignments":0}`
	mustRun(t, []string{"purge", "--config", config}, io())
	if r.lastLine(t) != emptyPurge {
		t.Fatalf("purge printed %s", r.lastLine(t))
	}
	mustRun(t, []string{"purge", "--config", config, "--retention-days", "0"}, io())
	if r.lastLine(t) != emptyPurge {
		t.Fatalf("purge printed %s", r.lastLine(t))
	}
	// Audit chain operations read storage directly and never record events themselves.
	tenantID := at(bootstrap, "tenant", "id").(string)
	mustRun(t, []string{"audit-verify", "--config", config, "--tenant", tenantID}, io())
	verification := r.lastObject(t)
	if at(verification, "valid") != true || at(verification, "first") != 1.0 || at(verification, "unchained") != 0.0 || at(verification, "tenantId") != tenantID {
		t.Fatalf("verification: %s", core.MustStringify(verification))
	}
	checked := at(verification, "checked").(float64)
	if checked < 3 {
		t.Fatalf("checked %v", checked)
	}
	exportPath := filepath.Join(folder, "audit.jsonl")
	mustRun(t, []string{"audit-export", "--config", config, "--tenant", tenantID, "--output", exportPath}, io())
	exported := r.lastObject(t)
	if at(exported, "count") != checked || at(exported, "firstSequence") != 1.0 {
		t.Fatalf("export: %s", core.MustStringify(exported))
	}
	text, _ := os.ReadFile(exportPath)
	lines := strings.Split(strings.TrimSpace(string(text)), "\n")
	if float64(len(lines)) != checked {
		t.Fatalf("exported %d lines", len(lines))
	}
	first, _ := core.ParseJSONString(lines[0])
	if at(first, "sequence") != 1.0 {
		t.Fatal("first exported event is not sequence 1")
	}
	mustRun(t, []string{"doctor", "--config", config}, io())
	if at(r.last(t), "auditChains") != 1.0 {
		t.Fatal("expected one audit chain")
	}
	// Pruning after archiving keeps the chain verifiable from the checkpoint.
	mustRun(t, []string{"audit-prune", "--config", config, "--tenant", tenantID}, io())
	if r.lastLine(t) != `{"deleted":0}` {
		t.Fatalf("prune printed %s", r.lastLine(t))
	}
	mustRun(t, []string{"audit-prune", "--config", config, "--tenant", tenantID, "--retention-days", "0"}, io())
	if at(r.last(t), "deleted") != checked {
		t.Fatalf("prune printed %s", r.lastLine(t))
	}
	mustRun(t, []string{"audit-verify", "--config", config, "--tenant", tenantID}, io())
	after := r.lastObject(t)
	if at(after, "valid") != true || at(after, "checked") != 1.0 || at(after, "first") != checked+1 {
		t.Fatalf("after prune: %s", core.MustStringify(after))
	}
	expectCode(t, run([]string{"audit-export", "--config", config, "--tenant", tenantID, "--output", exportPath}, io()), "EEXIST")
	expectCode(t, run([]string{"audit-verify", "--config", config}, io()), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"purge", "--config", config, "--tenant", tenantID}, io()), "INVALID_ARGUMENT")
}

func TestHelpAndManifest(t *testing.T) {
	r := newRecorder("")
	mustRun(t, []string{"help", "--json"}, r.io(nil))
	manifest := r.lastObject(t)
	expectEqual(t, manifest, Manifest())
	commands, _ := manifest.Get("commands").([]any)
	var names []string
	for _, command := range commands {
		names = append(names, at(command, "name").(string))
		name := at(command, "name").(string)
		if !regexp.MustCompile(`^better-iam ` + regexp.QuoteMeta(name) + `\b`).MatchString(at(command, "usage").(string)) {
			t.Fatalf("usage of %s: %s", name, at(command, "usage"))
		}
		if len(at(command, "summary").(string)) <= 10 {
			t.Fatalf("summary of %s is too short", name)
		}
	}
	for _, name := range []string{"init", "migrate", "whoami", "store-copy", "api", "login", "can", "completion"} {
		found := false
		for _, item := range names {
			found = found || item == name
		}
		if !found {
			t.Fatalf("manifest lacks %s", name)
		}
	}
	var analyze any
	for _, command := range commands {
		if at(command, "name") == "analyze" {
			analyze = command
		}
	}
	flags := at(analyze, "flags").([]any)
	tenant, failOn := false, false
	for _, flag := range flags {
		if at(flag, "flag") == "--tenant" && at(flag, "value") == "TENANT_ID" && at(flag, "optional") == false && at(flag, "env") == "BETTER_IAM_TENANT" {
			tenant = true
		}
		if at(flag, "flag") == "--fail-on" && core.MustStringify(at(flag, "choices")) == `["high","medium","low"]` {
			failOn = true
		}
	}
	if !tenant || !failOn {
		t.Fatal("analyze flags are incomplete")
	}

	mustRun(t, []string{"help", "can"}, r.io(nil))
	help := r.lastLine(t)
	expectContains(t, help, "better-iam can - Check whether")
	expectContains(t, help, "Examples")
	mustRun(t, []string{"can", "--help"}, r.io(nil))
	if r.lastLine(t) != help {
		t.Fatal("can --help differs from help can")
	}
	mustRun(t, []string{"--version"}, r.io(nil))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+`).MatchString(r.lastLine(t)) {
		t.Fatalf("version %s", r.lastLine(t))
	}
	err := run([]string{"analyse"}, r.io(nil))
	expectCode(t, err, "INVALID_COMMAND")
	expectContains(t, err.Error(), "Did you mean analyze?")
	expectCode(t, run([]string{"help", "analyse"}, r.io(nil)), "INVALID_COMMAND")
	err = run([]string{"analyze", "--tenat", "x"}, r.io(nil))
	expectCode(t, err, "INVALID_ARGUMENT")
	expectContains(t, err.Error(), "Did you mean --tenant?")
	if hintOf(err) != "Run better-iam help analyze for its flags." {
		t.Fatalf("hint %q", hintOf(err))
	}
}

func TestFlagParsing(t *testing.T) {
	r := newRecorder("")
	mustRun(t, []string{"secret", "--bytes=24"}, r.io(nil))
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`).MatchString(r.lastLine(t)) {
		t.Fatalf("secret %s", r.lastLine(t))
	}
	mustRun(t, []string{"secret", "--env"}, r.io(nil))
	if !regexp.MustCompile(`^BETTER_IAM_SECRET=[A-Za-z0-9_-]{64}$`).MatchString(r.lastLine(t)) {
		t.Fatalf("secret %s", r.lastLine(t))
	}
	for _, argv := range [][]string{
		{"secret", "--bytes=10"},
		{"secret", "--bytes", "many"},
		{"secret", "--env=maybe"},
		{"secret", "extra"},
		{"secret", "--bytes", "30", "--bytes", "40"},
		{"secret", "-x"},
		{"sweep", "--limit"},
	} {
		expectCode(t, run(argv, r.io(nil)), "INVALID_ARGUMENT")
	}
}

func TestCompletionScripts(t *testing.T) {
	r := newRecorder("")
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		mustRun(t, []string{"completion", shell}, r.io(nil))
		script := r.lastLine(t)
		expectContains(t, script, "analyze")
		if shell == "fish" {
			expectContains(t, script, "-l fail-on")
		} else {
			expectContains(t, script, "--fail-on")
		}
		expectContains(t, script, "high")
	}
	expectContains(t, r.output[0], "complete -o default -F _better_iam better-iam")
	expectContains(t, r.output[1], "bashcompinit")
	expectContains(t, r.output[3], "Register-ArgumentCompleter")
	expectCode(t, run([]string{"completion", "tcsh"}, r.io(nil)), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"completion"}, r.io(nil)), "INVALID_ARGUMENT")

	// Flag values complete before flag names in bash.
	script := r.output[0]
	analyze := script[strings.Index(script, "    analyze)"):]
	value := strings.Index(analyze, "--fail-on) COMPREPLY=( $(compgen -W 'high medium low'")
	if value <= 0 || value > strings.Index(analyze, "-*) COMPREPLY") {
		t.Fatal("flag values must complete before flag names")
	}
	if strings.Contains(script, "*) return ;;") {
		t.Fatal("bash completion must fall back to file names")
	}
}

func TestInitDiscovery(t *testing.T) {
	folder := t.TempDir()
	r := newRecorder(folder)
	mustRun(t, []string{"init"}, r.io(nil))
	written, err := os.ReadFile(filepath.Join(folder, "better-iam.json"))
	if err != nil {
		t.Fatal(err)
	}
	expectContains(t, string(written), `"cli"`)
	mustRun(t, []string{"init", "--typescript", "--database", "postgres"}, r.io(nil))
	ts, err := os.ReadFile(filepath.Join(folder, "better-iam.config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	expectContains(t, string(ts), "postgresAdapter")
	expectContains(t, string(ts), "CliSettings")
	expectContains(t, string(ts), "defineConfig(")
	expectCode(t, run([]string{"init"}, r.io(nil)), "CONFIG_EXISTS")
	expectCode(t, run([]string{"init", "--database", "mysql"}, r.io(nil)), "INVALID_ARGUMENT")

	// The generated configuration runs as written, found without --config from a subdirectory (its relative
	// database path resolves against the working directory).
	project := filepath.Join(folder, "app")
	deep := filepath.Join(project, "src", "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "better-iam.json"), written, 0o644); err != nil {
		t.Fatal(err)
	}
	nested := newRecorder(deep)
	env := map[string]string{"BETTER_IAM_SECRET": testSecret}
	mustRun(t, []string{"migrate"}, nested.io(env))
	if nested.lastLine(t) != "Database and plugin migrations applied." {
		t.Fatalf("migrate printed %s", nested.lastLine(t))
	}
	if _, err := os.Stat(filepath.Join(deep, "better-iam.db")); err != nil {
		t.Fatalf("the database was not created in the working directory: %v", err)
	}
	mustRun(t, []string{"doctor"}, nested.io(env))
	if at(nested.last(t), "database") != "connected" || at(nested.last(t), "rootInitialized") != false {
		t.Fatalf("doctor printed %s", nested.lastLine(t))
	}
	// The defaults in the file fill sweep's flag.
	mustRun(t, []string{"sweep"}, nested.io(env))
	// A JavaScript configuration needs the TypeScript CLI.
	expectCode(t, run([]string{"migrate", "--config", filepath.Join(folder, "better-iam.config.ts")}, r.io(env)), "CONFIG_LOAD_FAILED")
}

// projectModules is the Go form of a configuration module with project commands and CLI defaults (cli-dx's
// projectConfig): every path whose base name is better-iam.json loads it, on that folder's iam.db.
func projectLoader(extra ...*CommandSpec) ModuleLoader {
	return func(ctx context.Context, path string, env map[string]string) (*ConfigModule, error) {
		if filepath.Base(path) != "better-iam.json" {
			return nil, nil
		}
		folder := filepath.Dir(path)
		module := &ConfigModule{
			Default: ConfigFactory(func(ctx context.Context, config ConfigContext) (any, error) {
				store, err := storeAdapters(folder).SQLite(server.StoreConfig{Path: filepath.Join(folder, "iam.db")})
				if err != nil {
					return nil, err
				}
				return &server.BetterIamOptions{Database: store, Secret: testSecret, BaseURL: "http://localhost:3000",
					Permissions: &core.PermissionsConfig{Actions: []string{"documents:read"}}}, nil
			}),
			Cli: &CliSettings{Defaults: core.NewObject("echo-flags", core.NewObject("level", 5.0), "*", core.NewObject("format", "compact"))},
			Commands: []*CommandSpec{
				DefineCommand(CommandSpec{
					Name:    "echo-flags",
					Summary: "Print the flags a project command received",
					Target:  "config",
					Flags: []FlagSpec{
						boundedInteger("level", "A level", 0, 10, nil),
						{Name: "who", Type: "string", Required: true, Description: "A name"},
					},
					Run: func(ctx context.Context, c *CommandContext) (any, error) {
						iam, err := c.Iam(ctx)
						if err != nil {
							return nil, err
						}
						return core.NewObject("name", c.Name, "level", c.Flags["level"], "who", c.Flags["who"], "basePath", iam.Endpoint.BasePath), nil
					},
				}),
				DefineCommand(CommandSpec{
					Name:    "rows",
					Summary: "Print two rows",
					Run: func(ctx context.Context, c *CommandContext) (any, error) {
						return core.NewObject("rows", []any{core.NewObject("name", "a", "size", 1.0), core.NewObject("name", "b", "size", 2.0)}), nil
					},
				}),
			},
		}
		module.Commands[0].Flags[0].Env = "ECHO_LEVEL"
		module.Commands = append(module.Commands, extra...)
		return module, nil
	}
}

func placeholderConfig(t *testing.T, folder string) string {
	t.Helper()
	path := filepath.Join(folder, "better-iam.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProjectCommands(t *testing.T) {
	folder := t.TempDir()
	config := placeholderConfig(t, folder)
	program := CreateCli(CreateCliOptions{LoadModule: projectLoader()})
	runIn := func(argv []string, io *CliIO) error { return program.Run(context.Background(), argv, io) }
	r := newRecorder(folder)
	if err := runIn([]string{"echo-flags", "--who", "ada"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.lastLine(t), "\n") {
		t.Fatal("the '*' format default was not applied")
	}
	expectEqual(t, r.last(t), core.NewObject("name", "echo-flags", "level", 5.0, "who", "ada", "basePath", "/api/iam"))
	if err := runIn([]string{"echo-flags", "--who", "ada"}, r.io(map[string]string{"ECHO_LEVEL": "7"})); err != nil {
		t.Fatal(err)
	}
	if at(r.last(t), "level") != 7.0 {
		t.Fatal("environment did not beat the configuration default")
	}
	if err := runIn([]string{"echo-flags", "--who=ada", "--level=9", "--format", "json"}, r.io(map[string]string{"ECHO_LEVEL": "7"})); err != nil {
		t.Fatal(err)
	}
	expectContains(t, r.lastLine(t), "\n  \"level\": 9")
	if err := runIn([]string{"echo-flags", "--who", "ada", "--query", "who"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if r.lastLine(t) != "ada" {
		t.Fatalf("query printed %s", r.lastLine(t))
	}
	expectCode(t, runIn([]string{"echo-flags"}, r.io(nil)), "INVALID_ARGUMENT")
	expectCode(t, runIn([]string{"echo-flags", "--who", "a", "--level", "11"}, r.io(nil)), "INVALID_ARGUMENT")
	err := runIn([]string{"echo-flags", "--who", "a"}, r.io(map[string]string{"ECHO_LEVEL": "high"}))
	expectCode(t, err, "INVALID_ARGUMENT")
	expectContains(t, err.Error(), "ECHO_LEVEL")

	// Found through --config from elsewhere, BETTER_IAM_CONFIG, or discovery from a subdirectory.
	elsewhere := newRecorder(t.TempDir())
	if err := runIn([]string{"rows", "--config", config, "--format", "table"}, elsewhere.io(nil)); err != nil {
		t.Fatal(err)
	}
	if elsewhere.lastLine(t) != "NAME  SIZE\na     1\nb     2" {
		t.Fatalf("table %q", elsewhere.lastLine(t))
	}
	if err := runIn([]string{"rows", "--query", "rows[].name"}, elsewhere.io(map[string]string{"BETTER_IAM_CONFIG": config})); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, elsewhere.last(t), []any{"a", "b"})
	if err := os.Mkdir(filepath.Join(folder, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runIn([]string{"echo-flags", "--who", "x"}, newRecorder(filepath.Join(folder, "sub")).io(nil)); err != nil {
		t.Fatal(err)
	}
	expectCode(t, runIn([]string{"rows"}, elsewhere.io(nil)), "INVALID_COMMAND")

	if err := runIn([]string{"help", "--config", config}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	expectContains(t, r.lastLine(t), "echo-flags")
	if err := runIn([]string{"help", "echo-flags", "--config", config}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	expectContains(t, r.lastLine(t), "--level N")
	if err := runIn([]string{"completion", "fish"}, r.io(map[string]string{"BETTER_IAM_CONFIG": config})); err != nil {
		t.Fatal(err)
	}
	expectContains(t, r.lastLine(t), "-a echo-flags")
	// Help and completion (which shells run at startup) never load a configuration they merely found.
	if err := runIn([]string{"help"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.lastLine(t), "echo-flags") {
		t.Fatal("help loaded a found configuration")
	}
	if err := runIn([]string{"completion", "fish"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.lastLine(t), "echo-flags") {
		t.Fatal("completion loaded a found configuration")
	}
	err = runIn([]string{"echo-flag", "--who", "x"}, r.io(nil))
	expectContains(t, err.Error(), "Did you mean echo-flags?")
}

func TestEnvironmentOnlyDeployment(t *testing.T) {
	folder := t.TempDir()
	r := newRecorder(folder)
	env := merge(map[string]string{"BETTER_IAM_DATABASE_URL": "sqlite:" + filepath.Join(folder, "env.db"), "BETTER_IAM_SECRET": testSecret}, rootEnv)
	mustRun(t, []string{"migrate"}, r.io(env))
	mustRun(t, []string{"bootstrap"}, r.io(env))
	if at(r.last(t), "identity", "rootAdmin") != true {
		t.Fatal("bootstrap did not create root")
	}
	mustRun(t, []string{"doctor"}, r.io(env))
	if at(r.last(t), "rootInitialized") != true {
		t.Fatal("doctor does not see root")
	}
	expectCode(t, run([]string{"migrate"}, r.io(nil)), "CONFIG_NOT_FOUND")
	expectCode(t, run([]string{"migrate"}, r.io(map[string]string{"BETTER_IAM_DATABASE_URL": "mysql://db", "BETTER_IAM_SECRET": testSecret})), "INVALID_CONFIG")
	expectCode(t, run([]string{"migrate"}, r.io(map[string]string{"BETTER_IAM_DATABASE_URL": "sqlite:" + filepath.Join(folder, "x.db")})), "MISSING_ENV")

	options, err := ConfigFromEnv(map[string]string{
		"BETTER_IAM_DATABASE_URL":    "sqlite:" + filepath.Join(folder, "env.db"),
		"BETTER_IAM_SECRET":          testSecret,
		"BETTER_IAM_TRUSTED_ORIGINS": "https://a.test, https://b.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.BaseURL != "http://localhost:3000" || strings.Join(options.TrustedOrigins, ",") != "https://a.test,https://b.test" {
		t.Fatalf("options %+v", options)
	}
	_ = options.Database.Close(context.Background())

	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Cwd: folder, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	defer closeInstance(context.Background(), iam)
	roots, err := iam.Store.Find(context.Background(), "tenants", core.NewObject("parentId", nil), nil)
	if err != nil || len(roots) != 1 {
		t.Fatalf("roots %d %v", len(roots), err)
	}
}

func TestApiInProcessAndConfigurationAsCode(t *testing.T) {
	folder := t.TempDir()
	config := writeJSONConfig(t, folder, "better-iam.json")
	tenantID, token := rootSession(t, config)
	r := newRecorder(folder)
	asRoot := map[string]string{"BETTER_IAM_TOKEN": token}

	mustRun(t, []string{"api", "auth.getSession", "--format", "json"}, r.io(asRoot))
	if at(r.last(t), "identity", "rootAdmin") != true {
		t.Fatal("getSession is not root")
	}
	mustRun(t, []string{"api", "roles.create", "name=Auditor", "permissions[]=documents:read", "--tenant", tenantID}, r.io(asRoot))
	if at(r.last(t), "name") != "Auditor" || at(r.last(t), "tenantId") != tenantID {
		t.Fatalf("role %s", r.lastLine(t))
	}
	mustRun(t, []string{"api", "roles.list", "--query", "[].name"}, r.io(merge(asRoot, map[string]string{"BETTER_IAM_TENANT": tenantID})))
	expectContains(t, r.lastLine(t), "Auditor")
	mustRun(t, []string{"api", "--list", "config"}, r.io(asRoot))
	expectContains(t, r.lastLine(t), "config.apply")

	tenantConfig := filepath.Join(folder, "tenant.json")
	if err := os.WriteFile(tenantConfig, []byte(`{"version":1,"roles":[{"name":"Viewer","description":"For readers","permissions":["documents:read"]}],"groups":[{"name":"Readers"}],"bindings":[{"group":"Readers","role":"Viewer"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, []string{"config-validate", "--input", tenantConfig, "--tenant", tenantID}, r.io(nil))
	expectEqual(t, r.last(t), core.NewObject("valid", true, "items", core.NewObject("roles", 1.0, "groups", 1.0, "bindings", 1.0), "warnings", []any{}))
	mustRun(t, []string{"config-plan", "--tenant", tenantID, "--input", tenantConfig}, r.io(asRoot))
	expectEqual(t, at(r.last(t), "summary"), core.NewObject("create", 3.0, "update", 0.0, "delete", 0.0, "unchanged", 0.0))
	mustRun(t, []string{"config-apply", "--tenant", tenantID, "--input", tenantConfig}, r.io(asRoot))
	if at(r.last(t), "applied") != true {
		t.Fatalf("apply %s", r.lastLine(t))
	}

	// Exported back as JSON that plans as unchanged, and as typed modules for TypeScript projects.
	output := filepath.Join(folder, "exported.json")
	mustRun(t, []string{"config-export", "--tenant", tenantID, "--output", output}, r.io(asRoot))
	expectEqual(t, r.last(t), core.NewObject("tenantId", tenantID, "output", output))
	mustRun(t, []string{"config-plan", "--tenant", tenantID, "--input", output, "--fail-on-drift"}, r.io(asRoot))
	if at(r.last(t), "summary", "create") != 0.0 || at(r.last(t), "summary", "update") != 0.0 || at(r.last(t), "summary", "delete") != 0.0 {
		t.Fatalf("plan %s", r.lastLine(t))
	}
	for _, name := range []string{"exported.config.ts", "exported.config.mjs"} {
		path := filepath.Join(folder, name)
		mustRun(t, []string{"config-export", "--tenant", tenantID, "--output", path}, r.io(asRoot))
		text, _ := os.ReadFile(path)
		if strings.HasSuffix(name, ".ts") {
			expectContains(t, string(text), "defineTenantConfig(")
		} else {
			expectContains(t, string(text), "@type {import('better-iam/server').TenantConfig}")
		}
		expectCode(t, run([]string{"config-plan", "--tenant", tenantID, "--input", path}, r.io(asRoot)), "CONFIG_LOAD_FAILED")
	}
	expectCode(t, run([]string{"config-export", "--tenant", tenantID, "--output", output}, r.io(asRoot)), "EEXIST")

	// Offline validation: shape errors fail, unresolved names warn (and fail with --strict).
	loose := filepath.Join(folder, "loose.json")
	if err := os.WriteFile(loose, []byte(`{"version":1,"roles":[{"name":"A","policies":["Missing"],"permissions":["documents:read"]}],"bindings":[{"group":"Nobody","role":"A"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, []string{"config-validate", "--input", loose}, r.io(nil))
	expectEqual(t, at(r.last(t), "warnings"), []any{
		`Role "A" names policy "Missing", which this file does not define`,
		`Binding Nobody -> A names group "Nobody", which this file does not define`,
	})
	expectCode(t, run([]string{"config-validate", "--input", loose, "--strict"}, r.io(nil)), "CONFIG_WARNINGS")
	if err := os.WriteFile(loose, []byte(`{"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	expectCode(t, run([]string{"config-validate", "--input", loose}, r.io(nil)), "INVALID_INPUT")
}

func TestLocalProfilesAndFlagSources(t *testing.T) {
	folder := t.TempDir()
	config := placeholderConfig(t, folder)
	probe := DefineCommand(CommandSpec{
		Name:    "show-tenant",
		Summary: "Print the tenant a token command resolved",
		Target:  "token",
		Flags:   []FlagSpec{{Name: "tenant", Type: "string", Env: "BETTER_IAM_TENANT", Profile: "tenantId", Description: "Tenant"}},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			if c.Flags.Has("tenant") {
				return core.NewObject("tenant", c.Flags["tenant"]), nil
			}
			return core.NewObject("tenant", nil), nil
		},
	})
	base := projectLoader(probe)
	loader := func(ctx context.Context, path string, env map[string]string) (*ConfigModule, error) {
		module, err := base(ctx, path, env)
		if module != nil {
			module.Cli.Defaults.Set("show-tenant", core.NewObject("tenant", "from-defaults"))
		}
		return module, err
	}
	program := CreateCli(CreateCliOptions{LoadModule: loader})
	runIn := func(argv []string, io *CliIO) error { return program.Run(context.Background(), argv, io) }

	// Migrate, bootstrap and sign root in through the project configuration.
	setup := newRecorder(folder)
	if err := runIn([]string{"migrate", "--config", config}, setup.io(rootEnv)); err != nil {
		t.Fatal(err)
	}
	if err := runIn([]string{"bootstrap", "--config", config}, setup.io(rootEnv)); err != nil {
		t.Fatal(err)
	}
	tenantID := at(setup.last(t), "tenant", "id").(string)
	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Config: config, Env: map[string]string{}, LoadModule: loader})
	if err != nil {
		t.Fatal(err)
	}
	token := rootMfaSession(t, iam, tenantID, rootEnv["BETTER_IAM_ROOT_EMAIL"], rootEnv["BETTER_IAM_ROOT_PASSWORD"])
	_ = closeInstance(context.Background(), iam)

	credentials := map[string]string{"BETTER_IAM_CREDENTIALS": filepath.Join(folder, "credentials.json")}
	elsewhere := newRecorder(t.TempDir())
	// Saved through the configuration: later commands use it from anywhere, without --config.
	if err := runIn([]string{"login", "--with-token", "--config", config}, elsewhere.io(credentials, withStdin(token))); err != nil {
		t.Fatal(err)
	}
	if at(elsewhere.last(t), "profile") != "default" || at(elsewhere.last(t), "config") != config || at(elsewhere.last(t), "tenantId") != tenantID {
		t.Fatalf("login %s", elsewhere.lastLine(t))
	}
	if err := runIn([]string{"whoami", "--format", "json"}, elsewhere.io(credentials)); err != nil {
		t.Fatal(err)
	}
	if at(elsewhere.last(t), "tenantId") != tenantID {
		t.Fatal("whoami did not use the saved session")
	}
	// Another configuration is another deployment.
	other := placeholderConfig(t, t.TempDir())
	expectCode(t, runIn([]string{"whoami", "--config", other}, elsewhere.io(credentials)), "MISSING_ENV")
	// An explicit --config beats BETTER_IAM_URL; both from the environment is ambiguous.
	if err := runIn([]string{"whoami", "--config", config}, elsewhere.io(merge(credentials, map[string]string{"BETTER_IAM_URL": "http://localhost:9"}))); err != nil {
		t.Fatal(err)
	}
	expectCode(t, runIn([]string{"whoami"}, elsewhere.io(merge(credentials, map[string]string{"BETTER_IAM_URL": "http://localhost:9", "BETTER_IAM_CONFIG": config}))), "INVALID_ARGUMENT")

	// Flag sources: command line, then environment, then configuration defaults, then the saved session.
	r := newRecorder(folder)
	if err := runIn([]string{"show-tenant"}, r.io(credentials)); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, r.last(t), core.NewObject("tenant", "from-defaults"))
	if err := runIn([]string{"show-tenant"}, r.io(merge(credentials, map[string]string{"BETTER_IAM_TENANT": "from-env"}))); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, r.last(t), core.NewObject("tenant", "from-env"))
	if err := runIn([]string{"show-tenant", "--tenant", "from-flag"}, r.io(merge(credentials, map[string]string{"BETTER_IAM_TENANT": "from-env"}))); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, r.last(t), core.NewObject("tenant", "from-flag"))
	// Without defaults for it, --tenant falls back to the saved session's tenant.
	if err := runIn([]string{"api", "roles.create", "name=Probe", "--query", "tenantId"}, r.io(credentials)); err != nil {
		t.Fatal(err)
	}
	if r.lastLine(t) != tenantID {
		t.Fatalf("tenant %s", r.lastLine(t))
	}

	if err := runIn([]string{"logout"}, elsewhere.io(credentials)); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, elsewhere.last(t), core.NewObject("profile", "default", "revoked", true, "forgotten", true))
	expectCode(t, runIn([]string{"whoami", "--config", config}, elsewhere.io(map[string]string{"BETTER_IAM_TOKEN": token})), "UNAUTHENTICATED")
}

func TestEnvironmentOnlySessions(t *testing.T) {
	folder := t.TempDir()
	filename := filepath.Join(folder, "env.db")
	env := merge(map[string]string{"BETTER_IAM_DATABASE_URL": "sqlite:" + filename, "BETTER_IAM_SECRET": testSecret}, rootEnv)
	r := newRecorder(folder)
	mustRun(t, []string{"migrate"}, r.io(env))
	mustRun(t, []string{"bootstrap"}, r.io(env))
	tenantID := at(r.last(t), "tenant", "id").(string)
	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Cwd: folder, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	token := rootMfaSession(t, iam, tenantID, rootEnv["BETTER_IAM_ROOT_EMAIL"], rootEnv["BETTER_IAM_ROOT_PASSWORD"])
	_ = closeInstance(context.Background(), iam)
	saved := merge(env, map[string]string{"BETTER_IAM_CREDENTIALS": filepath.Join(folder, "credentials.json")})
	mustRun(t, []string{"login", "--with-token"}, r.io(saved, withStdin(token)))
	text, _ := os.ReadFile(saved["BETTER_IAM_CREDENTIALS"])
	file, _ := core.ParseJSON(text)
	if at(file, "profiles", "default", "envConfig") != true {
		t.Fatalf("credentials %s", text)
	}
	mustRun(t, []string{"whoami", "--format", "json"}, r.io(saved))
	if at(r.last(t), "tenantId") != tenantID {
		t.Fatal("whoami did not use the saved session")
	}
	mustRun(t, []string{"logout"}, r.io(saved))
	if at(r.last(t), "revoked") != true {
		t.Fatal("logout did not revoke")
	}
}

func TestCreateCliAndExitCodes(t *testing.T) {
	hello := DefineCommand(CommandSpec{
		Name:    "hello",
		Summary: "Greet someone by name",
		Args:    []ArgSpec{{Name: "who", Description: "Who to greet", Required: true}},
		Flags:   []FlagSpec{{Name: "shout", Type: "boolean", Description: "Upper case"}},
		Output:  "text",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			if c.Flags.Bool("shout") {
				return "HELLO " + strings.ToUpper(c.Args[0]), nil
			}
			return "hello " + c.Args[0], nil
		},
	})
	only := CreateCli(CreateCliOptions{NoBuiltins: true, Commands: []*CommandSpec{hello}, Version: "9.9.9"})
	r := newRecorder("")
	if err := only.Run(context.Background(), []string{"hello", "world", "--shout"}, r.io(nil)); err != nil {
		t.Fatal(err)
	}
	if r.lastLine(t) != "HELLO WORLD" {
		t.Fatalf("printed %s", r.lastLine(t))
	}
	if len(only.Manifest().Commands) != 1 || only.Manifest().Commands[0].Name != "hello" {
		t.Fatal("manifest of a builtins-free program")
	}
	overview, _ := only.Help("")
	if strings.Contains(overview, "migrate") {
		t.Fatal("help lists built-ins")
	}
	detail, _ := only.Help("hello")
	expectContains(t, detail, "better-iam hello WHO [--shout]")
	expectCode(t, only.Run(context.Background(), []string{"migrate"}, r.io(nil)), "INVALID_COMMAND")
	if len(CreateCli(CreateCliOptions{Commands: []*CommandSpec{hello}}).Commands) != len(Manifest().Commands)+1 {
		t.Fatal("custom commands are not added to the built-ins")
	}

	devnull, _ := os.Open(os.DevNull)
	stderr, stdout := os.Stderr, os.Stdout
	os.Stderr, os.Stdout = devnull, devnull
	defer func() { os.Stderr, os.Stdout = stderr, stdout }()
	if status := Main([]string{"analyse"}, nil); status != 2 {
		t.Fatalf("unknown command exits %d", status)
	}
	if status := Main([]string{"migrate", "--config", filepath.Join(t.TempDir(), "missing.json")}, nil); status != 1 {
		t.Fatalf("missing configuration exits %d", status)
	}
	if status := Main([]string{"hello", "x"}, only); status != 0 {
		t.Fatalf("hello exits %d", status)
	}
}

// The file init writes carries the CLI's "cli" member, which the standalone server refuses (as the TypeScript server
// refuses it, with the same message): the same document without "cli" is accepted.
func TestInitFileIsNotAStandaloneServerConfiguration(t *testing.T) {
	text := JSONConfigTemplate("sqlite")
	runtime := server.ConfigRuntime{Adapters: storeAdapters(t.TempDir()), Env: map[string]string{"BETTER_IAM_SECRET": "init-template-secret-with-at-least-32-characters"}}
	_, err := server.LoadStandaloneConfig([]byte(text), runtime)
	known, ok := err.(*core.IamError)
	if !ok || known.Code != "INVALID_CONFIG" || known.Message != `Invalid better-iam.json: unknown member "cli"` {
		t.Fatalf("refusal: %v", err)
	}
	parsed, err := core.ParseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	document := parsed.(*core.Object)
	document.Delete("cli")
	options, err := server.OptionsFromConfig(document, runtime)
	if err != nil {
		t.Fatal(err)
	}
	_ = options.Database.Close(context.Background())
}
