package cli

// Port of packages/cli/src/config.ts.
//
// The TypeScript CLI imports a JavaScript configuration module (better-iam.config.mjs). A Go program cannot run
// JavaScript, so the Go CLI reads the standalone JSON configuration every implementation shares
// (better-iam.json, spec/conformance/CONFIG.md) plus an optional "cli" member for flag defaults
// ({"cli": {"defaults": {"sweep": {"retention-days": 30}}}}). Programs that build their own CLI with CreateCli can
// supply configuration modules from Go code (CreateCliOptions.LoadModule): options, a ready instance, or a factory,
// project commands, and CLI settings, exactly as a JavaScript module exports them.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/adapters/libsql"
	"github.com/Better-IAM/better-iam/go/adapters/postgres"
	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/configfile"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// ConfigFileNames are the configuration file names the CLI looks for, in this order, in the working directory and
// then each parent up to the repository root or home directory.
var ConfigFileNames = []string{"better-iam.json", "better-iam.config.json"}

// ConfigContext is what a configuration factory receives, so one module can adapt to the command and environment
// it runs in: the CLI command being run (migrate, api, a custom command; "" outside the CLI), the environment and
// the working directory.
type ConfigContext = server.IamConfigContext

// ConfigFactory computes a deployment from the context: *server.BetterIamOptions or a ready *server.BetterIam.
type ConfigFactory func(ctx context.Context, config ConfigContext) (any, error)

// CliSettings are settings the CLI reads from a configuration module's `cli` member: defaults for the flags of
// commands that load the configuration or act as a token ("*" applies to every such command that has the flag),
// used when neither the flag nor its environment variable is set. Values are strings, numbers or booleans.
type CliSettings struct {
	// Defaults maps a command name (or "*") to flag names and values. Keys of one scope are applied in order.
	Defaults *core.Object
}

// ConfigModule is a configuration: Default configures the deployment (*server.BetterIamOptions, a ready
// *server.BetterIam, a server.IamConfigFactory, or a ConfigFactory), Commands adds project commands to the CLI
// (DefineCommand), and Cli sets flag defaults.
type ConfigModule struct {
	Default  any
	Commands []*CommandSpec
	Cli      *CliSettings
}

// ModuleLoader loads the configuration module at path (an absolute path that exists); env is the environment the
// command reads. CreateCliOptions.LoadModule lets a program supply modules from Go code; returning (nil, nil) falls
// back to the JSON reader.
type ModuleLoader func(ctx context.Context, path string, env map[string]string) (*ConfigModule, error)

// ResolvedConfigPath is where a configuration comes from.
type ResolvedConfigPath struct {
	Path string
	// Source is flag, env, discovered, or profile (the configuration a saved session was issued through).
	Source string
}

// FindConfigFile returns the nearest configuration file in cwd or one of its parents, like Prettier and ESLint find
// theirs, without leaving the repository: the search stops at the repository root (a directory holding .git) or the
// home directory, and skips files another user could have planted (see trustworthy). "" when there is none.
func FindConfigFile(cwd string) string {
	directory := resolvePath(cwd, ".")
	home, _ := os.UserHomeDir()
	if home != "" {
		home = resolvePath(home, ".")
	}
	for {
		for _, name := range ConfigFileNames {
			candidate := filepath.Join(directory, name)
			if fileExists(candidate) && trustworthy(candidate) {
				return candidate
			}
		}
		if directory == home || fileExists(filepath.Join(directory, ".git")) {
			return ""
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return ""
		}
		directory = parent
	}
}

// resolveConfigPath is --config, else BETTER_IAM_CONFIG, else the nearest configuration file; nil when there is
// none.
func resolveConfigPath(flag string, env map[string]string, cwd string) *ResolvedConfigPath {
	if flag != "" {
		return &ResolvedConfigPath{Path: resolvePath(cwd, flag), Source: "flag"}
	}
	if env["BETTER_IAM_CONFIG"] != "" {
		return &ResolvedConfigPath{Path: resolvePath(cwd, env["BETTER_IAM_CONFIG"]), Source: "env"}
	}
	if found := FindConfigFile(cwd); found != "" {
		return &ResolvedConfigPath{Path: found, Source: "discovered"}
	}
	return nil
}

var scriptConfig = regexp.MustCompile(`(?i)\.(mjs|js|cjs|ts|mts|cts)$`)

// importConfigModule loads a trusted configuration, with readable errors for the usual mistakes.
func importConfigModule(ctx context.Context, path string, env map[string]string, loader ModuleLoader) (*ConfigModule, error) {
	if !fileExists(path) {
		return nil, NewCliError("CONFIG_NOT_FOUND", "Configuration "+path+" does not exist",
			"Run better-iam init to create one, pass --config PATH, or set BETTER_IAM_CONFIG.")
	}
	if loader != nil {
		module, err := loader(ctx, path, env)
		if err != nil || module != nil {
			return module, err
		}
	}
	if scriptConfig.MatchString(path) {
		return nil, NewCliError("CONFIG_LOAD_FAILED", "The Go better-iam CLI cannot load the JavaScript configuration "+path,
			"Describe the deployment in better-iam.json (spec/conformance/CONFIG.md), or run the TypeScript CLI (npx better-iam).")
	}
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, systemError(err)
	}
	return LoadJSONConfigModule(text)
}

// LoadJSONConfigModule reads a better-iam.json document as a configuration module: its "cli" member (optional) is
// the CLI settings and everything else the standalone configuration (spec/conformance/CONFIG.md), opened by the
// module's factory when a command needs the instance.
func LoadJSONConfigModule(text []byte) (*ConfigModule, error) {
	parsed, err := core.ParseJSON(text)
	if err != nil {
		return nil, core.NewIamError("INVALID_CONFIG", "Invalid better-iam.json: "+err.Error())
	}
	module := &ConfigModule{}
	if object, ok := parsed.(*core.Object); ok && object != nil && object.Has("cli") {
		settings, err := cliSettingsOf(object.Get("cli"))
		if err != nil {
			return nil, err
		}
		module.Cli = settings
		object = object.Clone()
		object.Delete("cli")
		parsed = object
	}
	document := parsed
	module.Default = ConfigFactory(func(ctx context.Context, config ConfigContext) (any, error) {
		return server.OptionsFromConfig(core.CloneValue(document), server.ConfigRuntime{
			Adapters: storeAdapters(config.Cwd),
			Env:      config.Env,
			// `log` deliveries go to stderr: stdout carries the command's result.
			Log: func(line string) { _, _ = os.Stderr.WriteString(line + "\n") },
		})
	})
	return module, nil
}

func cliSettingsOf(value any) (*CliSettings, error) {
	invalid := func(message string) error {
		return core.NewIamError("INVALID_CONFIG", "Invalid better-iam.json: "+message)
	}
	object, ok := value.(*core.Object)
	if !ok || object == nil {
		return nil, invalid("cli must be an object")
	}
	settings := &CliSettings{}
	if !object.Has("defaults") || core.IsUndefined(object.Get("defaults")) {
		return settings, nil
	}
	defaults, ok := object.Get("defaults").(*core.Object)
	if !ok || defaults == nil {
		return nil, invalid("cli.defaults must be an object")
	}
	for _, scope := range defaults.Keys() {
		flags, ok := defaults.Get(scope).(*core.Object)
		if !ok || flags == nil {
			return nil, invalid("cli.defaults." + scope + " must be an object")
		}
		for _, name := range flags.Keys() {
			switch flags.Get(name).(type) {
			case string, float64, bool:
			default:
				return nil, invalid("cli.defaults." + scope + "." + name + " must be a string, number, or boolean")
			}
		}
	}
	settings.Defaults = defaults
	return settings, nil
}

// storeAdapters open the databases a JSON configuration names; relative SQLite paths resolve against cwd. They are
// the adapters configfile exports for applications that load the same file.
func storeAdapters(cwd string) server.ConfigAdapters { return configfile.Adapters(cwd) }

// storeOf keeps a failed constructor's typed nil out of the interface.
func storeOf[T core.IamStore](store T, err error) (core.IamStore, error) {
	if err != nil {
		return nil, err
	}
	return store, nil
}

// closeInstance stops the instance's background work and closes its store.
func closeInstance(ctx context.Context, iam *server.BetterIam) error {
	if iam == nil {
		return nil
	}
	iam.Close()
	if iam.Store != nil {
		return iam.Store.Close(ctx)
	}
	return nil
}

// newInstance creates the instance options describe, closing the options' database when creation fails.
func newInstance(ctx context.Context, options *server.BetterIamOptions) (*server.BetterIam, error) {
	iam, err := server.New(options)
	if err != nil {
		if options != nil && options.Database != nil {
			_ = options.Database.Close(ctx)
		}
		return nil, err
	}
	return iam, nil
}

// instantiate creates the IAM instance a module's default export describes (calling a factory with config).
func instantiate(ctx context.Context, module *ConfigModule, config ConfigContext) (*server.BetterIam, error) {
	var configuration any
	switch exported := module.Default.(type) {
	case ConfigFactory:
		value, err := exported(ctx, config)
		if err != nil {
			return nil, err
		}
		configuration = value
	case func(ctx context.Context, config ConfigContext) (any, error):
		value, err := exported(ctx, config)
		if err != nil {
			return nil, err
		}
		configuration = value
	case server.IamConfigFactory:
		value, err := exported(ctx, config)
		if err != nil {
			return nil, err
		}
		configuration = value
	case func(ctx context.Context, config server.IamConfigContext) (*server.BetterIamOptions, error):
		value, err := exported(ctx, config)
		if err != nil {
			return nil, err
		}
		configuration = value
	default:
		configuration = exported
	}
	switch value := configuration.(type) {
	case *server.BetterIam:
		if value != nil {
			return value, nil
		}
	case *server.BetterIamOptions:
		if value != nil {
			return newInstance(ctx, value)
		}
	}
	return nil, core.NewIamError("INVALID_CONFIG", "Configuration must export a default options object or factory")
}

// LoadConfigOptions are LoadConfig's options; empty fields default to the process's.
type LoadConfigOptions struct {
	Config  string
	Cwd     string
	Env     map[string]string
	Command string
	// LoadModule supplies configuration modules from Go code (see ModuleLoader).
	LoadModule ModuleLoader
}

// LoadConfig loads a configuration file and creates its instance: the same resolution the CLI uses, for programs,
// workers, and tests that want better-iam.json without the command line. Close the instance and its store when
// done. Applications that know the file's path can use configfile.Load instead, outside cmd/.
func LoadConfig(ctx context.Context, options LoadConfigOptions) (*server.BetterIam, error) {
	cwd := options.Cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	env := options.Env
	if env == nil {
		env = processEnv()
	}
	located := resolveConfigPath(options.Config, env, cwd)
	if located == nil {
		if env["BETTER_IAM_DATABASE_URL"] != "" {
			configuration, err := ConfigFromEnv(env)
			if err != nil {
				return nil, err
			}
			return newInstance(ctx, configuration)
		}
		return nil, NewCliError("CONFIG_NOT_FOUND", "No "+ConfigFileNames[0]+" (or "+ConfigFileNames[1]+") in "+cwd+" or its parents",
			"Run better-iam init, pass --config PATH, set BETTER_IAM_CONFIG, or set BETTER_IAM_DATABASE_URL and BETTER_IAM_SECRET.")
	}
	module, err := importConfigModule(ctx, located.Path, env, options.LoadModule)
	if err != nil {
		return nil, err
	}
	return instantiate(ctx, module, ConfigContext{Command: options.Command, Env: env, Cwd: cwd})
}

func list(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := core.JSTrim(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

var (
	postgresURL  = regexp.MustCompile(`(?i)^postgres(?:ql)?://`)
	sqliteURL    = regexp.MustCompile(`(?i)^sqlite:`)
	sqlitePrefix = regexp.MustCompile(`(?i)^sqlite:(//)?`)
	libsqlURL    = regexp.MustCompile(`(?i)^(libsql|wss?|https?)://`)
	fileURL      = regexp.MustCompile(`(?i)^file:`)
	sqliteFile   = regexp.MustCompile(`(?i)\.(db|sqlite3?)$`)
)

// ConfigFromEnv builds deployment options from environment variables alone (twelve-factor style), for containers
// and CI jobs that have no configuration file:
//
//   - BETTER_IAM_DATABASE_URL (required): postgres://…, sqlite:./iam.db (or a path ending in .db), or libsql://… /
//     file:… (BETTER_IAM_DATABASE_TOKEN authenticates)
//   - BETTER_IAM_SECRET (required), BETTER_IAM_PREVIOUS_SECRETS (comma-separated, during a rotation)
//   - BETTER_IAM_BASE_URL (default http://localhost:3000), BETTER_IAM_BASE_PATH, BETTER_IAM_TRUSTED_ORIGINS
//
// Everything else keeps its default; add callbacks (email, resolvers) to the result in code when you need them.
func ConfigFromEnv(env map[string]string) (*server.BetterIamOptions, error) {
	if env == nil {
		env = processEnv()
	}
	databaseURL := env["BETTER_IAM_DATABASE_URL"]
	if databaseURL == "" {
		return nil, core.NewIamError("MISSING_ENV", "Set BETTER_IAM_DATABASE_URL")
	}
	if env["BETTER_IAM_SECRET"] == "" {
		return nil, core.NewIamError("MISSING_ENV", "Set BETTER_IAM_SECRET")
	}
	var database core.IamStore
	var err error
	switch {
	case postgresURL.MatchString(databaseURL):
		database, err = storeOf(postgres.New(postgres.Options{ConnectionString: databaseURL}))
	case sqliteURL.MatchString(databaseURL):
		filename := sqlitePrefix.ReplaceAllString(databaseURL, "")
		if filename == "" {
			filename = ":memory:"
		}
		database, err = storeOf(sqlite.New(sqlite.Options{Filename: filename}))
	case libsqlURL.MatchString(databaseURL) || fileURL.MatchString(databaseURL):
		database, err = storeOf(libsql.New(libsql.Options{URL: databaseURL, AuthToken: env["BETTER_IAM_DATABASE_TOKEN"]}))
	case sqliteFile.MatchString(databaseURL) || databaseURL == ":memory:":
		database, err = storeOf(sqlite.New(sqlite.Options{Filename: databaseURL}))
	default:
		return nil, core.NewIamError("INVALID_CONFIG", "BETTER_IAM_DATABASE_URL must be postgres://…, sqlite:PATH, file:PATH, or libsql://…")
	}
	if err != nil {
		return nil, err
	}
	options := &server.BetterIamOptions{Database: database, Secret: env["BETTER_IAM_SECRET"], BaseURL: "http://localhost:3000"}
	if value, ok := env["BETTER_IAM_BASE_URL"]; ok {
		options.BaseURL = value
	}
	if basePath := env["BETTER_IAM_BASE_PATH"]; basePath != "" {
		options.BasePath = &basePath
	}
	if previous := list(env["BETTER_IAM_PREVIOUS_SECRETS"]); len(previous) > 0 {
		options.PreviousSecrets = previous
	}
	if origins := list(env["BETTER_IAM_TRUSTED_ORIGINS"]); len(origins) > 0 {
		options.TrustedOrigins = origins
	}
	return options, nil
}
