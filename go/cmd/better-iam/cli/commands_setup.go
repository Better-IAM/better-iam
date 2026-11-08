package cli

// Port of packages/cli/src/commands/setup.ts.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

type templateAdapter struct {
	imports string
	factory string
	store   *core.Object
}

var templateAdapters = map[string]templateAdapter{
	"sqlite": {
		imports: `import { sqliteAdapter } from 'better-iam/adapter-sqlite';`,
		factory: `sqliteAdapter({ filename: env.BETTER_IAM_DATABASE ?? './better-iam.db' })`,
		store:   core.NewObject("kind", "sqlite", "path", "./better-iam.db"),
	},
	"libsql": {
		imports: `import { libsqlAdapter } from 'better-iam/adapter-libsql';`,
		factory: `libsqlAdapter({ url: env.BETTER_IAM_DATABASE_URL ?? 'file:./better-iam.db', authToken: env.BETTER_IAM_DATABASE_TOKEN })`,
		store:   core.NewObject("kind", "libsql", "url", core.NewObject("env", "BETTER_IAM_DATABASE_URL")),
	},
	"postgres": {
		imports: `import { postgresAdapter } from 'better-iam/adapter-postgres';`,
		factory: `postgresAdapter({ connectionString: env.DATABASE_URL })`,
		store:   core.NewObject("kind", "postgres", "url", core.NewObject("env", "DATABASE_URL")),
	},
}

// ConfigTemplate is the starter JavaScript/TypeScript configuration `init --typescript` writes for a TypeScript
// application (the same module the TypeScript CLI writes): a side-effect-free factory, CLI defaults, and a slot for
// project commands.
func ConfigTemplate(database string, typescript bool) string {
	adapter := templateAdapters[database]
	cliType, commandsType, extension, typesImport, secretFallback := "", "", ".mjs", "", ""
	if typescript {
		cliType, commandsType, extension = ": CliSettings", ": CommandSpec<any>[]", ""
		typesImport = "import type { CliSettings, CommandSpec } from 'better-iam/cli';\n"
		secretFallback = ` ?? ""`
	}
	return `// Better IAM deployment configuration, loaded by the better-iam CLI and by your server:
//   import config from './better-iam.config` + extension + `';
//   const iam = betterIam(await configOptions(config));   // both from 'better-iam/server'
` + typesImport + `import { defineConfig } from 'better-iam/server';
` + adapter.imports + `

// A factory keeps importing this file free of side effects (the CLI imports it for help and flag defaults).
// It receives { command, env, cwd } when the CLI calls it, so settings can depend on the command.
const createOptions = defineConfig(({ env = process.env } = {}) => ({
  database: ` + adapter.factory + `,
  baseURL: env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
  // At least 32 random characters; generate one with: better-iam secret
  secret: env.BETTER_IAM_SECRET` + secretFallback + `,
  // During a secret rotation, the old value(s), comma-separated (see the deployment guide).
  previousSecrets: env.BETTER_IAM_PREVIOUS_SECRETS?.split(',').filter(Boolean),
  authentication: {
    // Add sendEmail/sendSms callbacks before enabling delivery-dependent features.
    signUpEnabled: false,
  },
  // Add plugins: [createProjectsPlugin()] from 'better-iam/projects' to serve the projects actions.
  permissions: {
    mode: 'catalog', // 'tenant-defined' lets organizations register their own resource types and actions
    actions: ['projects:read', 'projects:write'],
    // Declare resource types to validate policies and describe attributes; managed types are registered with IAM.
    resourceTypes: {
      workspace: {
        managed: true,
        actions: ['workspaces:read', 'workspaces:manage'],
        attributes: { archived: 'boolean' },
      },
    },
  },
}));
export default createOptions;

// Defaults for CLI flags when neither the flag nor its environment variable is set: per command, or '*' for every
// command that has the flag (better-iam help <command> lists them).
export const cli` + cliType + ` = {
  defaults: {
    sweep: { 'retention-days': 30 },
  },
};

// Project commands: ` + "`better-iam <name>`" + ` runs them with the same flag parsing, help, and output as the built-in ones.
// import { defineCommand } from 'better-iam/cli';
export const commands` + commandsType + ` = [];
`
}

// JSONConfigTemplate is the starter better-iam.json `init` writes: the same deployment as ConfigTemplate in the
// standalone JSON form (spec/conformance/CONFIG.md), with the secret from BETTER_IAM_SECRET and CLI flag defaults in
// a "cli" member. That member makes it a CLI configuration only: the standalone servers (better-iam-server and
// the TypeScript and Rust ones) refuse it as an unknown member, just as the TypeScript server cannot read the
// TypeScript CLI's better-iam.config module, so a server needs its own copy without "cli".
func JSONConfigTemplate(database string) string {
	adapter := templateAdapters[database]
	document := core.NewObject(
		"store", core.CloneValue(adapter.store),
		"baseURL", "http://localhost:3000",
		"secret", core.NewObject("env", "BETTER_IAM_SECRET"),
		"authentication", core.NewObject("signUpEnabled", false),
		"permissions", core.NewObject(
			"mode", "catalog",
			"actions", []any{"projects:read", "projects:write"},
			"resourceTypes", core.NewObject("workspace", core.NewObject(
				"managed", true,
				"actions", []any{"workspaces:read", "workspaces:manage"},
				"attributes", core.NewObject("archived", "boolean"),
			)),
		),
		"cli", core.NewObject("defaults", core.NewObject("sweep", core.NewObject("retention-days", 30.0))),
	)
	return stringifyIndented(document, "  ", "") + "\n"
}

func rootInput(env map[string]string) (*core.Object, error) {
	email, password := env["BETTER_IAM_ROOT_EMAIL"], env["BETTER_IAM_ROOT_PASSWORD"]
	name, ok := env["BETTER_IAM_ROOT_NAME"]
	if !ok {
		name = "Root administrator"
	}
	if email == "" || password == "" {
		return nil, NewCliError("MISSING_ENV", "Set BETTER_IAM_ROOT_EMAIL and BETTER_IAM_ROOT_PASSWORD",
			"The password is read from the environment only, never from a flag.")
	}
	return core.NewObject("email", email, "name", name, "password", password), nil
}

func intFlag(minimum, maximum float64) (*float64, *float64) { return &minimum, &maximum }

func boundedInteger(name, description string, minimum, maximum float64, defaultValue any) FlagSpec {
	low, high := intFlag(minimum, maximum)
	return FlagSpec{Name: name, Type: "integer", Min: low, Max: high, Default: defaultValue, Description: description}
}

var setupCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "init",
		Group:       "Setup",
		Summary:     "Write a starter configuration file for SQLite, PostgreSQL, or libSQL",
		Description: "init writes a starter better-iam.json (or, with --typescript, the better-iam.config.ts module a TypeScript application loads): the deployment for the chosen database with the secret read from BETTER_IAM_SECRET, and CLI flag defaults. It never overwrites an existing file.",
		Usage:       "better-iam init [--config better-iam.json] [--database sqlite|postgres|libsql] [--typescript]",
		Output:      "text",
		Flags: []FlagSpec{
			{Name: "config", Type: "string", Value: "PATH", Description: "Where to write the configuration"},
			{Name: "database", Type: "string", Choices: []string{"sqlite", "postgres", "libsql"}, Default: "sqlite", Description: "Database adapter to configure"},
			{Name: "typescript", Type: "boolean", Description: "Write a typed better-iam.config.ts for a TypeScript application"},
		},
		Examples: []string{"better-iam init", "better-iam init --database postgres --typescript"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			name := c.Flags.String("config")
			if name == "" {
				name = ConfigFileNames[0]
				if c.Flags.Bool("typescript") {
					name = "better-iam.config.ts"
				}
			}
			target := c.Path(name)
			if _, err := os.Stat(target); err == nil {
				return nil, core.NewIamError("CONFIG_EXISTS", "Configuration already exists; it was not overwritten")
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, systemError(err)
			}
			database := c.Flags.String("database")
			if database == "" {
				database = "sqlite"
			}
			body := JSONConfigTemplate(database)
			if c.Flags.Bool("typescript") {
				body = ConfigTemplate(database, true)
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
			if err != nil {
				return nil, systemError(err)
			}
			if _, err := file.WriteString(body); err != nil {
				_ = file.Close()
				return nil, systemError(err)
			}
			if err := file.Close(); err != nil {
				return nil, systemError(err)
			}
			c.IO.Out("Created " + target + ". Set BETTER_IAM_SECRET to a stable high-entropy secret (at least 32 characters; better-iam secret prints one), then run migrate.")
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "migrate",
		Group:       "Setup",
		Summary:     "Create or upgrade the database schema and apply plugin migrations",
		Description: "migrate creates or upgrades the database schema and applies plugin migrations. Run it on every deploy before the application starts.",
		Target:      "config",
		Output:      "text",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			iam, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			if err := iam.Initialize(ctx); err != nil {
				return nil, err
			}
			return "Database and plugin migrations applied.", nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "bootstrap",
		Group:       "Setup",
		Summary:     "Create the root administrator from environment variables",
		Description: "bootstrap creates the root administrator from BETTER_IAM_ROOT_EMAIL, BETTER_IAM_ROOT_NAME, and BETTER_IAM_ROOT_PASSWORD (secrets are never accepted in command-line arguments). The root must enroll MFA before use.",
		Target:      "config",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			iam, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			input, err := rootInput(c.Env)
			if err != nil {
				return nil, err
			}
			return iam.Bootstrap(ctx, input)
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "recover-root",
		Group:       "Setup",
		Summary:     "Create a new root administrator when every root credential is lost",
		Description: "recover-root creates a new root administrator from the same environment variables as bootstrap, for when every root credential is lost; the action is audited as root:recover.",
		Target:      "config",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			iam, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			input, err := rootInput(c.Env)
			if err != nil {
				return nil, err
			}
			return iam.RecoverRoot(ctx, input)
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "doctor",
		Group:       "Setup",
		Summary:     "Check the database, schema, secrets, transports, and scheduled jobs",
		Description: "doctor connects to the database and lists findings (schema behind, not bootstrapped, weak secret, risky durability, missing email transport, jobs that are not running); --strict exits non-zero when any error or warning is found; pass the --retention-days your sweep uses so its backlog is judged the same way.",
		Target:      "config",
		Flags: []FlagSpec{
			{Name: "strict", Type: "boolean", Description: "Exit non-zero when any error or warning is found"},
			boundedInteger("retention-days", "Delivery retention your sweep uses, to judge its backlog the same way", 0, 3650, nil),
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			iam, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			// Schema, durability, secrets, transports, and scheduled jobs (iam.SelfCheck); first, so a database
			// without the IAM schema is reported instead of failing the reads below.
			options := core.NewObject()
			if days, ok := c.Flags.Int("retention-days"); ok {
				options.Set("deliveryRetentionMs", float64(days)*86400000)
			}
			check, err := iam.SelfCheck(ctx, options)
			if err != nil {
				return nil, err
			}
			storage := check.Get("storage")
			schema := storage == nil
			if object, ok := storage.(*core.Object); ok && object != nil {
				schema = object.Get("schemaVersion") != nil
			}
			roots, chains := []*core.Object{}, []*core.Object{}
			if schema {
				if roots, err = iam.Store.Find(ctx, "tenants", core.NewObject("parentId", nil), nil); err != nil {
					return nil, err
				}
				if chains, err = iam.Store.Find(ctx, "auditChains", nil, nil); err != nil {
					return nil, err
				}
			}
			events := 0.0
			for _, chain := range chains {
				sequence, _ := chain.Get("sequence").(float64)
				events += sequence
			}
			findings, _ := check.Get("findings").([]any)
			if err := c.Print(core.NewObject(
				"go", runtime.Version(),
				"database", "connected",
				"rootInitialized", len(roots) == 1,
				"rootCount", float64(len(roots)),
				"auditChains", float64(len(chains)),
				"auditEvents", events,
				// Adapter, schema version, applied migrations, record counts, and durability settings.
				"storage", storage,
				"ok", check.Get("ok"),
				"findings", check.Get("findings"),
			)); err != nil {
				return nil, err
			}
			var serious []string
			for _, finding := range findings {
				object, _ := finding.(*core.Object)
				if object != nil && object.Get("severity") != "info" {
					serious = append(serious, jsString(object.Get("check")))
				}
			}
			if c.Flags.Bool("strict") && len(serious) > 0 {
				return nil, core.NewIamError("DOCTOR_FINDINGS", strconv.Itoa(len(serious))+" finding(s): "+strings.Join(serious, ", "))
			}
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "secret",
		Group:       "Setup",
		Summary:     "Print a new random secret for BETTER_IAM_SECRET",
		Description: "secret prints a new random value for BETTER_IAM_SECRET (64 URL-safe characters by default) from the operating system random generator; --env prints it as a BETTER_IAM_SECRET= line for a .env file. It reads no configuration and stores nothing.",
		Output:      "text",
		Flags: []FlagSpec{
			boundedInteger("bytes", "Random bytes (the secret is their base64url form)", 24, 256, 48.0),
			{Name: "env", Type: "boolean", Description: "Print BETTER_IAM_SECRET=value"},
		},
		Examples: []string{"better-iam secret --env >> .env"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			size := int64(48)
			if bytes, ok := c.Flags.Int("bytes"); ok {
				size = bytes
			}
			random := make([]byte, size)
			if _, err := rand.Read(random); err != nil {
				return nil, err
			}
			value := base64.RawURLEncoding.EncodeToString(random)
			if c.Flags.Bool("env") {
				return "BETTER_IAM_SECRET=" + value, nil
			}
			return value, nil
		},
	}),
}
