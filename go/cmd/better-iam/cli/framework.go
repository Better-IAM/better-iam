package cli

// Port of packages/cli/src/framework.ts: command declarations, flag parsing, help, the manifest, configuration
// loading and the per-command context.

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// CliIO is where the CLI writes, reads, and prompts. Everything is injectable so programs and tests can run
// commands.
type CliIO struct {
	// Out receives command results (stdout).
	Out func(message string)
	// Env is the environment the command reads (tokens, defaults, credentials file); never the process environment
	// implicitly.
	Env map[string]string
	// Err receives progress and warnings (stderr). Silent when nil.
	Err func(message string)
	// Prompt asks the person a question; hidden for passwords. Nil in non-interactive runs, which then fail instead.
	Prompt func(question string, hidden bool) (string, error)
	// Stdin reads all of standard input (--data -, login --with-token). Nil when there is none.
	Stdin func() (string, error)
	// Cwd is the directory relative paths and configuration discovery start from (default: the process's).
	Cwd string
	// Fetch sends remote (--url) requests (default: the HTTP client).
	Fetch func(request *http.Request) (*http.Response, error)
}

// FlagSpec is one flag of a command. Name is the flag name without the leading --.
type FlagSpec struct {
	Name string
	// Type is "string", "integer", or "boolean".
	Type string
	// Description is what one line of help says the flag does.
	Description string
	// Value is the placeholder in usage lines (PATH, TENANT_ID, N); defaults by type.
	Value    string
	Required bool
	// Env is an environment variable read when the flag is not given, for example BETTER_IAM_TENANT.
	Env string
	// Choices are the allowed values of a string flag.
	Choices []string
	// Min and Max bound an integer flag.
	Min *float64
	Max *float64
	// Default is the default the command applies, shown in help (the command applies it itself): a string, number,
	// or boolean; nil for none.
	Default any
	// Profile is, for token commands, the saved profile field used when neither the flag nor its variable is set
	// ("tenantId").
	Profile string
	// Hidden leaves the flag out of help and completion (still accepted).
	Hidden bool
	// NoWildcardDefault: a cli.defaults["*"] entry never fills this flag, only one for this very command. For flags
	// whose meaning differs between commands where a shared default could destroy data (how much audit history
	// audit-prune keeps). TypeScript: wildcardDefault: false.
	NoWildcardDefault bool
}

// ArgSpec is one positional argument of a command.
type ArgSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required,omitempty"`
	// Variadic collects every remaining positional argument. Only the last argument may be variadic.
	Variadic bool `json:"variadic,omitempty"`
}

// Flags are the parsed flags a command receives: booleans, numbers (float64; integers), and strings. A flag that
// is not set has no entry (booleans are always set).
type Flags map[string]any

// Has reports whether the flag has a value.
func (f Flags) Has(name string) bool {
	_, ok := f[name]
	return ok
}

// String is a string flag's value ("" when unset).
func (f Flags) String(name string) string {
	text, _ := f[name].(string)
	return text
}

// Int is an integer flag's value; ok is false when unset.
func (f Flags) Int(name string) (int64, bool) {
	number, ok := f[name].(float64)
	return int64(number), ok
}

// Bool is a boolean flag's value.
func (f Flags) Bool(name string) bool { return f[name] == true }

// CommandSpec declares a command.
type CommandSpec struct {
	Name string
	// Group is the section in help: Setup, Operations, Audit, Storage, Access, API, Session, Shell, or your own.
	Group string
	// Summary is one line, starting with a verb.
	Summary string
	// Description is paragraphs of detail for help <command> and the reference documentation.
	Description string
	// Usage replaces the generated usage line.
	Usage    string
	Flags    []FlagSpec
	Args     []ArgSpec
	Examples []string
	Aliases  []string
	// Target is "config" (a deployment operation; loads the configuration and runs with no credential), "token"
	// (acts as BETTER_IAM_TOKEN or the profile saved by login, in process through the configuration or remotely with
	// --url; authorized and audited like any client) or "none" (the default: needs neither).
	Target string
	// Output "text" commands print plain text and take no --format / --query; default "json".
	Output string
	// DefaultFormat is the format used when --format is not given (default json), for commands whose output scripts
	// read by line.
	DefaultFormat string
	// NoConfigDefaults: cli.defaults from the configuration never apply (TypeScript: configDefaults: false).
	NoConfigDefaults bool
	// Validate runs cross-flag checks after parsing, before the command runs; return UsageError(...). explicit names
	// the flags given on the command line, as opposed to filled from the environment, configuration defaults, or a
	// profile.
	Validate func(flags Flags, args []string, explicit map[string]bool) error
	// Run runs the command; a non-nil result is printed with --format / --query applied.
	Run func(ctx context.Context, c *CommandContext) (any, error)
}

// DefineCommand declares a CLI command (it returns its argument). Return them from a configuration module's
// Commands to add project commands (seeding, reports, migrations of your own) that get the same flag parsing,
// help, configuration loading, and output formatting as the built-in ones.
func DefineCommand(spec CommandSpec) *CommandSpec { return &spec }

func (spec *CommandSpec) target() string {
	if spec.Target == "" {
		return "none"
	}
	return spec.Target
}

func (spec *CommandSpec) output() string {
	if spec.Output == "" {
		return "json"
	}
	return spec.Output
}

func (spec *CommandSpec) group() string {
	if spec.Group == "" {
		return "Commands"
	}
	return spec.Group
}

// targetFlags choose the deployment and session; configuration defaults never set them.
var targetFlags = map[string]bool{"config": true, "url": true, "profile": true}

func configFlag() FlagSpec {
	return FlagSpec{Name: "config", Type: "string", Value: "PATH", Env: "BETTER_IAM_CONFIG",
		Description: "Configuration file; default: the nearest " + ConfigFileNames[0] + " or " + ConfigFileNames[1]}
}

var (
	urlFlag = FlagSpec{Name: "url", Type: "string", Value: "URL", Env: "BETTER_IAM_URL",
		Description: "Call a running IAM server (https://host or https://host/api/iam) instead of loading the configuration"}
	profileFlag = FlagSpec{Name: "profile", Type: "string", Value: "NAME", Env: "BETTER_IAM_PROFILE",
		Description: "Saved session to act as (see login); ignored while BETTER_IAM_TOKEN is set"}
	formatFlag = FlagSpec{Name: "format", Type: "string", Value: "FORMAT", Choices: outputFormats,
		Description: "Output as json (indented, default), compact (one line), or table"}
	queryFlag = FlagSpec{Name: "query", Type: "string", Value: "PATH",
		Description: "Print only part of the result, e.g. summary.create or findings[].kind (strings print raw)"}
)

func findFlag(flags []FlagSpec, name string) (FlagSpec, bool) {
	for _, flag := range flags {
		if flag.Name == name {
			return flag, true
		}
	}
	return FlagSpec{}, false
}

// CommandFlags is every flag a command accepts: its own, then the ones its target and output add.
func CommandFlags(spec *CommandSpec) []FlagSpec {
	flags := slices.Clone(spec.Flags)
	has := func(name string) bool {
		_, ok := findFlag(flags, name)
		return ok
	}
	target := spec.target()
	if (target == "config" || target == "token") && !has("config") {
		flags = append(flags, configFlag())
	}
	if target == "token" {
		if !has("url") {
			flags = append(flags, urlFlag)
		}
		if !has("profile") {
			flags = append(flags, profileFlag)
		}
	}
	if spec.output() == "json" {
		if !has("format") {
			flags = append(flags, formatFlag)
		}
		if !has("query") {
			flags = append(flags, queryFlag)
		}
	}
	return flags
}

func placeholder(flag FlagSpec) string {
	if flag.Value != "" {
		return flag.Value
	}
	if flag.Choices != nil {
		return strings.Join(flag.Choices, "|")
	}
	if flag.Type == "integer" {
		return "N"
	}
	return "VALUE"
}

// usageLine is the usage line: required flags as --flag VALUE, optional ones in brackets; common flags are left to
// help.
func usageLine(spec *CommandSpec) string {
	if spec.Usage != "" {
		return spec.Usage
	}
	parts := []string{"better-iam " + spec.Name}
	target := spec.target()
	if _, hasConfig := findFlag(spec.Flags, "config"); target == "config" || target == "token" || hasConfig {
		parts = append(parts, "--config "+ConfigFileNames[0])
	}
	for _, arg := range spec.Args {
		name := strings.ToUpper(arg.Name)
		if arg.Variadic {
			name += "..."
		}
		if arg.Required {
			parts = append(parts, name)
		} else {
			parts = append(parts, "["+name+"]")
		}
	}
	for _, flag := range spec.Flags {
		if flag.Name == "config" || flag.Hidden {
			continue
		}
		text := "--" + flag.Name
		if flag.Type != "boolean" {
			text += " " + placeholder(flag)
		}
		if flag.Required {
			parts = append(parts, text)
		} else {
			parts = append(parts, "["+text+"]")
		}
	}
	if target == "token" {
		parts = append(parts, "[--url URL]", "[--profile NAME]")
	}
	return strings.Join(parts, " ")
}

var (
	paragraphBreak = regexp.MustCompile(`\n\s*\n`)
	whitespace     = regexp.MustCompile(`\s+`)
)

func wrap(text string, indent, width int) []string {
	var lines []string
	for _, paragraph := range paragraphBreak.Split(text, -1) {
		line := ""
		for _, word := range whitespace.Split(paragraph, -1) {
			if word == "" {
				continue
			}
			if line != "" && indent+core.UTF16Len(line)+1+core.UTF16Len(word) > width {
				lines = append(lines, strings.Repeat(" ", indent)+line)
				line = word
			} else if line != "" {
				line += " " + word
			} else {
				line = word
			}
		}
		if line != "" {
			lines = append(lines, strings.Repeat(" ", indent)+line)
		}
		lines = append(lines, "")
	}
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func flagLabel(flag FlagSpec) string {
	if flag.Type == "boolean" {
		return "--" + flag.Name
	}
	return "--" + flag.Name + " " + placeholder(flag)
}

func flagLines(spec *CommandSpec) []string {
	var entries []FlagSpec
	for _, flag := range CommandFlags(spec) {
		if !flag.Hidden {
			entries = append(entries, flag)
		}
	}
	labels := make([]string, len(entries))
	width := 10
	for index, flag := range entries {
		labels[index] = flagLabel(flag)
		width = max(width, core.UTF16Len(labels[index]))
	}
	width = min(30, width)
	var lines []string
	for index, flag := range entries {
		var notes []string
		if flag.Required {
			notes = append(notes, "required")
		}
		if flag.Default != nil {
			notes = append(notes, "default "+jsString(flag.Default))
		}
		if flag.Env != "" {
			notes = append(notes, "env "+flag.Env)
		}
		if flag.Profile != "" {
			notes = append(notes, "or the saved profile")
		}
		description := flag.Description
		if len(notes) > 0 {
			description += " (" + strings.Join(notes, "; ") + ")"
		}
		label := labels[index]
		wrapped := wrap(description, width+6, 100)
		for i := range wrapped {
			wrapped[i] = strings.TrimLeft(wrapped[i], " \t\n\r\v\f")
		}
		pad := strings.Repeat(" ", width+6)
		if core.UTF16Len(label) > width {
			lines = append(lines, "  "+label)
			for _, line := range wrapped {
				lines = append(lines, pad+line)
			}
			continue
		}
		first := ""
		if len(wrapped) > 0 {
			first = wrapped[0]
		}
		lines = append(lines, "  "+padEnd(label, width)+"    "+first)
		if len(wrapped) > 1 {
			for _, line := range wrapped[1:] {
				lines = append(lines, pad+line)
			}
		}
	}
	return append(lines, "  "+padEnd("-h, --help", width)+"    Show this help")
}

// CommandHelp is `better-iam help <command>`: usage, description, arguments, flags, and examples.
func CommandHelp(spec *CommandSpec) string {
	lines := []string{"better-iam " + spec.Name + " - " + spec.Summary, "", "Usage", "  " + usageLine(spec)}
	if len(spec.Aliases) > 0 {
		lines = append(lines, "", "Aliases: "+strings.Join(spec.Aliases, ", "))
	}
	if spec.Description != "" {
		lines = append(lines, "")
		lines = append(lines, wrap(spec.Description, 2, 80)...)
	}
	if len(spec.Args) > 0 {
		lines = append(lines, "", "Arguments")
		width := 0
		for _, arg := range spec.Args {
			width = max(width, core.UTF16Len(arg.Name)+3)
		}
		for _, arg := range spec.Args {
			lines = append(lines, "  "+padEnd(strings.ToUpper(arg.Name), width)+"  "+arg.Description)
		}
	}
	lines = append(lines, "", "Flags")
	lines = append(lines, flagLines(spec)...)
	if len(spec.Examples) > 0 {
		lines = append(lines, "", "Examples")
		for _, example := range spec.Examples {
			lines = append(lines, "  $ "+example)
		}
	}
	return strings.Join(lines, "\n")
}

// EnvironmentVariable is one variable the CLI reads, for help and the manifest.
type EnvironmentVariable struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// environmentVariables are the variables the CLI reads.
var environmentVariables = []EnvironmentVariable{
	{"BETTER_IAM_CONFIG", "Configuration file, like --config"},
	{"BETTER_IAM_TOKEN", "Session or API key token commands act as"},
	{"BETTER_IAM_URL", "IAM server token commands call, like --url"},
	{"BETTER_IAM_PROFILE", "Saved session to use, like --profile"},
	{"BETTER_IAM_TENANT", "Default --tenant for token commands"},
	{"BETTER_IAM_CREDENTIALS", "File saved sessions live in (default ~/.config/better-iam/credentials.json, %APPDATA% on Windows)"},
	{"BETTER_IAM_ROOT_EMAIL", "bootstrap / recover-root: the root administrator (with BETTER_IAM_ROOT_NAME, BETTER_IAM_ROOT_PASSWORD)"},
	{"BETTER_IAM_ROOT_NAME", "bootstrap / recover-root: display name"},
	{"BETTER_IAM_ROOT_PASSWORD", "bootstrap / recover-root: password (never a flag)"},
	{"BETTER_IAM_PASSWORD", "login: the password, instead of the prompt"},
	{"BETTER_IAM_MFA_CODE", "login: the authenticator code, instead of the prompt"},
	{"BETTER_IAM_DATABASE_URL", "Without a configuration file: the database (postgres://, sqlite:PATH, libsql://), with BETTER_IAM_SECRET"},
	{"BETTER_IAM_SECRET", "Without a configuration file: the deployment secret"},
}

// ManifestFlag is one flag in the manifest.
type ManifestFlag struct {
	Flag        string   `json:"flag"`
	Value       string   `json:"value,omitempty"`
	Optional    bool     `json:"optional"`
	Description string   `json:"description"`
	Env         string   `json:"env,omitempty"`
	Default     any      `json:"default,omitempty"`
	Choices     []string `json:"choices,omitempty"`
}

// ManifestCommand is one command in the manifest.
type ManifestCommand struct {
	Name        string         `json:"name"`
	Aliases     []string       `json:"aliases"`
	Group       string         `json:"group"`
	Summary     string         `json:"summary"`
	Description string         `json:"description"`
	Usage       string         `json:"usage"`
	Target      string         `json:"target"`
	Args        []ArgSpec      `json:"args"`
	Flags       []ManifestFlag `json:"flags"`
	Examples    []string       `json:"examples"`
}

// CliManifest is a machine-readable description of every command: what `better-iam help --json` prints and the
// docs are built from.
type CliManifest struct {
	Name     string                `json:"name"`
	Version  string                `json:"version"`
	Commands []ManifestCommand     `json:"commands"`
	Env      []EnvironmentVariable `json:"env"`
}

func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func manifestOf(commands []*CommandSpec, version string) CliManifest {
	manifest := CliManifest{Name: "better-iam", Version: version, Commands: []ManifestCommand{}, Env: environmentVariables}
	for _, spec := range commands {
		description := spec.Description
		if description == "" {
			description = spec.Summary
		}
		flags := []ManifestFlag{}
		for _, flag := range CommandFlags(spec) {
			if flag.Hidden {
				continue
			}
			entry := ManifestFlag{Flag: "--" + flag.Name, Optional: !flag.Required, Description: flag.Description, Env: flag.Env,
				Default: flag.Default, Choices: flag.Choices}
			if flag.Type != "boolean" {
				entry.Value = placeholder(flag)
			}
			flags = append(flags, entry)
		}
		manifest.Commands = append(manifest.Commands, ManifestCommand{
			Name: spec.Name, Aliases: nonNil(slices.Clone(spec.Aliases)), Group: spec.group(), Summary: spec.Summary,
			Description: description, Usage: usageLine(spec), Target: spec.target(), Args: nonNil(slices.Clone(spec.Args)),
			Flags: flags, Examples: nonNil(slices.Clone(spec.Examples)),
		})
	}
	return manifest
}

var groupOrder = []string{"Setup", "Operations", "Audit", "Storage", "Access", "API", "Session", "Shell"}

func groupRank(group string) int {
	if index := slices.Index(groupOrder, group); index >= 0 {
		return index + 1
	}
	return 99
}

// overviewHelp is `better-iam help`: every command by section, every usage line, the details, and the environment.
func overviewHelp(commands []*CommandSpec, version string) string {
	var ordered []string
	groups := map[string][]*CommandSpec{}
	for _, spec := range commands {
		group := spec.group()
		if _, seen := groups[group]; !seen {
			ordered = append(ordered, group)
		}
		groups[group] = append(groups[group], spec)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if groupRank(a) != groupRank(b) {
			return groupRank(a) < groupRank(b)
		}
		return localeCompare(a, b) < 0
	})
	width := 0
	for _, spec := range commands {
		width = max(width, core.UTF16Len(spec.Name))
	}
	width += 2
	lines := []string{
		"Better IAM " + version,
		"",
		"Usage",
		"  better-iam <command> [flags]",
		"  better-iam help <command>      flags, details, and examples for one command",
		"  better-iam help --json         every command as JSON, for tools",
		"",
	}
	for _, group := range ordered {
		lines = append(lines, group)
		for _, spec := range groups[group] {
			lines = append(lines, "  "+padEnd(spec.Name, width)+spec.Summary)
		}
		lines = append(lines, "")
	}
	lines = append(lines, "Commands")
	for _, spec := range commands {
		lines = append(lines, "  "+usageLine(spec))
	}
	lines = append(lines, "")
	lines = append(lines, wrap("Configuration commands load "+ConfigFileNames[0]+" (or --config, BETTER_IAM_CONFIG, the nearest "+ConfigFileNames[0]+" or "+ConfigFileNames[1]+" in a parent directory, or BETTER_IAM_DATABASE_URL + BETTER_IAM_SECRET without a file). Token commands act as BETTER_IAM_TOKEN or the session saved by login, in process or against --url, and are authorized and audited like console operations. Secrets are never accepted in command-line arguments. Every flag also accepts --flag=value; results print as JSON unless --format says otherwise.", 2, 80)...)
	lines = append(lines, "")
	for _, spec := range commands {
		if spec.Description != "" {
			lines = append(lines, wrap(spec.Description, 2, 80)...)
			lines = append(lines, "")
		}
	}
	lines = append(lines, "Environment")
	envWidth := 0
	for _, entry := range environmentVariables {
		envWidth = max(envWidth, len(entry.Name))
	}
	envWidth += 2
	for _, entry := range environmentVariables {
		lines = append(lines, "  "+padEnd(entry.Name, envWidth)+entry.Description)
	}
	return strings.Join(lines, "\n")
}

type parsedArguments struct {
	values map[string]any
	order  []string
	args   []string
	help   bool
}

// parseArguments parses --flag value, --flag=value, boolean --flag, -- and positionals for one command.
func parseArguments(spec *CommandSpec, argv []string) (parsedArguments, error) {
	flags := CommandFlags(spec)
	parsed := parsedArguments{values: map[string]any{}}
	positionalOnly := false
	names := make([]string, len(flags))
	for index, flag := range flags {
		names[index] = flag.Name
	}
	for index := 0; index < len(argv); index++ {
		token := argv[index]
		if positionalOnly {
			parsed.args = append(parsed.args, token)
			continue
		}
		if token == "--" {
			positionalOnly = true
			continue
		}
		if token == "--help" || token == "-h" {
			parsed.help = true
			continue
		}
		if strings.HasPrefix(token, "--") {
			name, inline, hasInline := strings.Cut(token[2:], "=")
			flag, known := findFlag(flags, name)
			if !known {
				return parsed, UsageError(spec.Name+" does not take --"+name+"."+didYouMean(name, names, "--"),
					"Run better-iam help "+spec.Name+" for its flags.")
			}
			if _, seen := parsed.values[name]; seen {
				return parsed, UsageError("--" + name + " was given more than once")
			}
			if flag.Type == "boolean" {
				switch {
				case !hasInline:
					parsed.values[name] = true
				case inline == "true" || inline == "false":
					parsed.values[name] = inline == "true"
				default:
					return parsed, UsageError("--" + name + " is a switch; use --" + name + " or --" + name + "=false")
				}
				parsed.order = append(parsed.order, name)
				continue
			}
			value := inline
			present := hasInline
			if !hasInline {
				index++
				if index < len(argv) {
					value, present = argv[index], true
				}
			}
			if !present || value == "" || (!hasInline && strings.HasPrefix(value, "--")) {
				return parsed, UsageError("--" + name + " needs a value (" + placeholder(flag) + ")")
			}
			parsed.values[name] = value
			parsed.order = append(parsed.order, name)
			continue
		}
		if strings.HasPrefix(token, "-") && token != "-" && len(spec.Args) == 0 {
			return parsed, UsageError(spec.Name+" does not take "+token, "Run better-iam help "+spec.Name+".")
		}
		parsed.args = append(parsed.args, token)
	}
	specs := spec.Args
	if len(specs) == 0 && len(parsed.args) > 0 {
		return parsed, UsageError(spec.Name+" takes no arguments (got "+parsed.args[0]+")",
			"Flags start with --; run better-iam help "+spec.Name+".")
	}
	variadic := len(specs) > 0 && specs[len(specs)-1].Variadic
	if !variadic && len(parsed.args) > len(specs) {
		return parsed, UsageError(spec.Name + " takes at most " + strconv.Itoa(len(specs)) + " argument(s)")
	}
	return parsed, nil
}

var integerText = regexp.MustCompile(`^-?\d+$`)

const maxSafeInteger = 9007199254740991

// convert checks and converts one raw flag value (from argv, the environment, or configuration defaults).
func convert(name string, flag FlagSpec, raw any, source string) (any, error) {
	label := source + " (for --" + name + ")"
	if source == "flag" {
		label = "--" + name
	}
	if flag.Type == "boolean" {
		if value, ok := raw.(bool); ok {
			return value, nil
		}
		text := core.JSLower(jsString(raw))
		switch text {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no", "":
			return false, nil
		}
		return nil, UsageError(label + " must be true or false")
	}
	if flag.Type == "integer" {
		text := jsString(raw)
		low, high := float64(-maxSafeInteger), float64(maxSafeInteger)
		if flag.Min != nil {
			low = *flag.Min
		}
		if flag.Max != nil {
			high = *flag.Max
		}
		number, err := strconv.ParseFloat(text, 64)
		if !integerText.MatchString(text) || err != nil || number > maxSafeInteger || number < -maxSafeInteger || number < low || number > high {
			if flag.Min != nil || flag.Max != nil {
				return nil, UsageError(label + " must be an integer between " + core.NumberString(low) + " and " + core.NumberString(high))
			}
			return nil, UsageError(label + " must be an integer")
		}
		return number, nil
	}
	text := jsString(raw)
	if text == "" {
		return nil, UsageError(label + " needs a value")
	}
	if flag.Choices != nil && !slices.Contains(flag.Choices, text) {
		return nil, UsageError(label + " must be " + strings.Join(flag.Choices, ", "))
	}
	return text, nil
}

// CreateCliOptions configure CreateCli.
type CreateCliOptions struct {
	// Commands are added to (or, with NoBuiltins, replace) the built-in ones.
	Commands []*CommandSpec
	// NoBuiltins drops the built-in commands (TypeScript: builtins: false).
	NoBuiltins bool
	Version    string
	// LoadModule supplies configuration modules from Go code (see ModuleLoader); nil reads better-iam.json files.
	LoadModule ModuleLoader
}

// Cli is a command-line program: the built-in commands plus yours, runnable from code with any IO.
type Cli struct {
	Commands  []*CommandSpec
	version   string
	loader    ModuleLoader
	defaultIO func() *CliIO
}

// Program is what CommandContext.Program describes: the program's commands (with the configuration's project
// commands) and version.
type Program struct {
	Commands []*CommandSpec
	Version  string
}

func findCommand(list []*CommandSpec, name string) *CommandSpec {
	for _, spec := range list {
		if spec.Name == name || slices.Contains(spec.Aliases, name) {
			return spec
		}
	}
	return nil
}

func commandNames(list []*CommandSpec) []string {
	names := make([]string, len(list))
	for index, spec := range list {
		names[index] = spec.Name
	}
	return names
}

// Help is `better-iam help [command]`.
func (c *Cli) Help(name string) (string, error) {
	if name == "" {
		return overviewHelp(c.Commands, c.version), nil
	}
	spec := findCommand(c.Commands, name)
	if spec == nil {
		return "", NewCliError("INVALID_COMMAND", "Unknown command: "+name+"."+didYouMean(name, commandNames(c.Commands), ""))
	}
	return CommandHelp(spec), nil
}

// Manifest is the machine-readable description of the program's commands.
func (c *Cli) Manifest() CliManifest { return manifestOf(c.Commands, c.version) }

// configCommands are the commands a configuration module exports. A configuration is trusted code, so with
// discover false (help and shell completion, which shells run on their own at startup, possibly in a directory
// someone else controls) only a configuration named with --config or BETTER_IAM_CONFIG is loaded.
func (c *Cli) configCommands(ctx context.Context, argv []string, io *CliIO, cwd string, discover bool) ([]*CommandSpec, error) {
	flag := ""
	for index := 0; index < len(argv); index++ {
		token := argv[index]
		if token == "--config" {
			if index+1 < len(argv) {
				flag = argv[index+1]
			} else {
				flag = ""
			}
		} else if strings.HasPrefix(token, "--config=") {
			flag = strings.TrimPrefix(token, "--config=")
		}
	}
	if !discover && flag == "" && io.Env["BETTER_IAM_CONFIG"] == "" {
		return nil, nil
	}
	located := resolveConfigPath(flag, io.Env, cwd)
	if located == nil {
		return nil, nil
	}
	module, err := importConfigModule(ctx, located.Path, io.Env, c.loader)
	if err != nil {
		return nil, err
	}
	return slices.Clone(module.Commands), nil
}

func (c *Cli) cwdOf(io *CliIO) string {
	if io.Cwd != "" {
		return io.Cwd
	}
	cwd, _ := os.Getwd()
	return cwd
}

// Run runs one command line (without the program name); failures return an error whose code says what went wrong
// (an IamError, CliError, or the remote client's IamClientError). A nil io uses the process's.
func (c *Cli) Run(ctx context.Context, argv []string, io *CliIO) error {
	if io == nil {
		io = c.defaultIO()
	}
	if io.Env == nil {
		io.Env = map[string]string{}
	}
	if io.Out == nil {
		io.Out = func(string) {}
	}
	cwd := c.cwdOf(io)
	name := "help"
	if len(argv) > 0 {
		name = argv[0]
	}
	if name == "help" || name == "--help" || name == "-h" {
		rest := argv[min(1, len(argv)):]
		json := slices.Contains(rest, "--json")
		topic := ""
		for index, item := range rest {
			if !strings.HasPrefix(item, "-") && (index == 0 || rest[index-1] != "--config") {
				topic = item
				break
			}
		}
		all := c.Commands
		// Project commands appear in help for a configuration named with --config or BETTER_IAM_CONFIG; help never
		// loads a configuration it merely found in the directory.
		if extra, err := c.configCommands(ctx, rest, io, cwd, false); err == nil {
			all = slices.Clone(c.Commands)
			for _, spec := range extra {
				if findCommand(c.Commands, spec.Name) == nil {
					all = append(all, spec)
				}
			}
		}
		switch {
		case json:
			selected := all
			if topic != "" {
				selected = nil
				for _, spec := range all {
					if spec.Name == topic {
						selected = append(selected, spec)
					}
				}
			}
			io.Out(stringifyIndented(jsonValue(manifestOf(selected, c.version)), "  ", ""))
		case topic != "":
			spec := findCommand(all, topic)
			if spec == nil {
				return NewCliError("INVALID_COMMAND", "Unknown command: "+topic+"."+didYouMean(topic, commandNames(all), ""))
			}
			io.Out(CommandHelp(spec))
		default:
			io.Out(overviewHelp(all, c.version))
		}
		return nil
	}
	if name == "--version" || name == "version" || name == "-v" {
		io.Out(c.version)
		return nil
	}
	spec := findCommand(c.Commands, name)
	var extra []*CommandSpec
	loaded := false
	// An unknown name may be a project command: a configuration that fails to load reports its own error then,
	// instead of "unknown command"; completion scripts skip a broken configuration.
	projectCommands := func(strict, discover bool) ([]*CommandSpec, error) {
		if loaded {
			return extra, nil
		}
		commands, err := c.configCommands(ctx, argv[1:], io, cwd, discover)
		if err != nil {
			if strict {
				return nil, err
			}
			commands = nil
		}
		extra, loaded = commands, true
		return extra, nil
	}
	rest := slices.Clone(argv[1:])
	if spec == nil && !strings.HasPrefix(name, "-") {
		commands, err := projectCommands(true, true)
		if err != nil {
			return err
		}
		spec = findCommand(commands, name)
		// A project command found through --config accepts that flag even when it loads no configuration.
		if spec != nil {
			if _, hasConfig := findFlag(CommandFlags(spec), "config"); !hasConfig {
				var filtered []string
				for index, token := range rest {
					if token != "--config" && (index == 0 || rest[index-1] != "--config") && !strings.HasPrefix(token, "--config=") {
						filtered = append(filtered, token)
					}
				}
				rest = filtered
			}
		}
	}
	if spec == nil {
		var candidates []string
		for _, command := range append(slices.Clone(c.Commands), extra...) {
			candidates = append(candidates, command.Name)
			candidates = append(candidates, command.Aliases...)
		}
		return NewCliError("INVALID_COMMAND", "Unknown command: "+name+"."+didYouMean(name, candidates, ""),
			"Run better-iam help for the list of commands.")
	}
	// Completion scripts cover the project commands of a configuration named with --config or BETTER_IAM_CONFIG
	// (shells run completion at startup, so it never loads one it found); other commands never load the module just
	// for this.
	all := slices.Clone(c.Commands)
	var more []*CommandSpec
	if spec.Name == "completion" {
		more, _ = projectCommands(false, false)
	} else {
		more = extra
	}
	for _, item := range more {
		if findCommand(c.Commands, item.Name) == nil {
			all = append(all, item)
		}
	}
	return c.execute(ctx, spec, rest, io, cwd, Program{Commands: all, Version: c.version})
}

// DescribeProfileTarget is where a saved profile's session was issued: its server, its configuration, or the
// environment-only deployment.
func DescribeProfileTarget(profile *StoredProfile) string {
	switch {
	case profile.URL != "":
		return profile.URL
	case profile.Config != "":
		return profile.Config
	case profile.EnvConfig:
		return "BETTER_IAM_DATABASE_URL"
	}
	return "an unknown deployment"
}

// ProfileState is the saved profile a token command uses: Profile is nil when there is none, or when it belongs to
// another deployment than --url / --config name (then Mismatch holds it).
type ProfileState struct {
	Name     string
	Profile  *StoredProfile
	Mismatch *StoredProfile
}

// ApiOptions choose the credential of CommandContext.Api: Anonymous calls with no credential, Token with that token
// instead of the command's.
type ApiOptions struct {
	Anonymous bool
	Token     string
}

// CommandContext is what a command's Run receives.
type CommandContext struct {
	// Name is the command name as registered.
	Name string
	// Flags are the parsed flags (with the common ones: config, url, profile, format, query).
	Flags Flags
	// Args are the positional arguments.
	Args []string
	// Explicit names the flags given on the command line itself (not filled from the environment, defaults, or a
	// profile).
	Explicit map[string]bool
	IO       *CliIO
	Env      map[string]string
	Cwd      string
	// Profiles is the saved-session file.
	Profiles *ProfileStore
	// Program is the program running the command: its commands (with the configuration's project commands) and
	// version.
	Program Program

	spec   *CommandSpec
	runner *execution
}

// Path resolves a path against the working directory.
func (c *CommandContext) Path(value string) string { return resolvePath(c.Cwd, value) }

// Print prints a result with --format / --query applied. Returning a value from Run does the same.
func (c *CommandContext) Print(value any) error {
	if value == Null {
		value = nil
	}
	format := c.Flags.String("format")
	if format == "" {
		format = c.spec.DefaultFormat
	}
	text, err := FormatResult(value, format, c.Flags.String("query"), c.Flags.Has("query"))
	if err != nil {
		return err
	}
	c.IO.Out(text)
	return nil
}

// Note writes a line to stderr (progress, warnings); silent when the IO has no Err.
func (c *CommandContext) Note(message string) {
	if c.IO.Err != nil {
		c.IO.Err(message)
	}
}

// ConfigPath is where the configuration comes from, or nil when none was given or found.
func (c *CommandContext) ConfigPath(ctx context.Context) (*ResolvedConfigPath, error) {
	return c.runner.configPath(ctx)
}

// ConfigModule is the configuration module (loaded once); an empty module when there is no configuration.
func (c *CommandContext) ConfigModule(ctx context.Context) (*ConfigModule, error) {
	return c.runner.configModule(ctx)
}

// Iam is the IAM instance of the configuration, created once and closed after the command.
func (c *CommandContext) Iam(ctx context.Context) (*server.BetterIam, error) {
	return c.runner.iam(ctx)
}

// Open creates another configuration's instance (for example store-copy --target-config); also closed after the
// command.
func (c *CommandContext) Open(ctx context.Context, configPath string) (*server.BetterIam, error) {
	return c.runner.open(ctx, configPath, true)
}

// OpenEnv creates the instance of the deployment the environment describes (BETTER_IAM_DATABASE_URL); also closed
// after the command.
func (c *CommandContext) OpenEnv(ctx context.Context) (*server.BetterIam, error) {
	return c.runner.open(ctx, "", false)
}

// Token is the bearer token: BETTER_IAM_TOKEN, else the saved profile's.
func (c *CommandContext) Token(ctx context.Context) (string, error) { return c.runner.token(ctx) }

// Profile is the saved profile in use, when the command is not acting on BETTER_IAM_TOKEN (nil otherwise).
func (c *CommandContext) Profile(ctx context.Context) (*ProfileState, error) {
	return c.runner.profile(ctx)
}

// Api calls API routes as the token (or with no credential when options.Anonymous).
func (c *CommandContext) Api(ctx context.Context, options ApiOptions) (ApiTransport, error) {
	return c.runner.api(ctx, options)
}

// execution is the state of one command run (the closures of framework.ts execute).
type execution struct {
	cli      *Cli
	spec     *CommandSpec
	io       *CliIO
	cwd      string
	values   Flags
	profiles *ProfileStore

	usesProfile   bool
	profileDone   bool
	profileCached *ProfileState
	locatedDone   bool
	located       *ResolvedConfigPath
	module        *ConfigModule
	moduleErr     error
	moduleDone    bool
	instance      *server.BetterIam
	instanceErr   error
	instanceDone  bool
	opened        []*server.BetterIam
}

func (e *execution) has(name string) bool { return e.values.Has(name) }

func (e *execution) profile(ctx context.Context) (*ProfileState, error) {
	if e.profileDone {
		return e.profileCached, nil
	}
	if !e.usesProfile || e.profiles.Path == "" {
		e.profileDone = true
		e.profileCached = nil
		return nil, nil
	}
	name, err := e.profiles.CurrentName(e.values.String("profile"))
	if err != nil {
		return nil, err
	}
	saved, err := e.profiles.Get(name)
	if err != nil {
		return nil, err
	}
	matches := saved == nil
	if !matches {
		switch {
		case e.has("url"):
			matches = saved.URL != "" && sameEndpoint(saved.URL, e.values.String("url"))
		case e.has("config"):
			matches = saved.Config != "" && resolvePath(e.cwd, e.values.String("config")) == saved.Config
		default:
			matches = true
		}
	}
	state := &ProfileState{Name: name, Profile: saved}
	if !matches {
		state = &ProfileState{Name: name, Mismatch: saved}
	}
	e.profileDone, e.profileCached = true, state
	return state, nil
}

func (e *execution) remoteURL(ctx context.Context) (string, error) {
	if e.has("url") {
		return e.values.String("url"), nil
	}
	if e.has("config") {
		return "", nil
	}
	state, err := e.profile(ctx)
	if err != nil || state == nil || state.Profile == nil {
		return "", err
	}
	return state.Profile.URL, nil
}

func (e *execution) configPath(ctx context.Context) (*ResolvedConfigPath, error) {
	if e.locatedDone {
		return e.located, nil
	}
	if !e.has("config") && e.spec.target() == "token" {
		// Without --config, a token command uses the deployment its saved session came from.
		state, err := e.profile(ctx)
		if err != nil {
			return nil, err
		}
		if state != nil && state.Profile != nil {
			if state.Profile.Config != "" {
				e.locatedDone, e.located = true, &ResolvedConfigPath{Path: state.Profile.Config, Source: "profile"}
				return e.located, nil
			}
			if state.Profile.EnvConfig {
				e.locatedDone, e.located = true, nil
				return nil, nil
			}
		}
	}
	e.locatedDone, e.located = true, resolveConfigPath(e.values.String("config"), e.io.Env, e.cwd)
	return e.located, nil
}

func (e *execution) configModule(ctx context.Context) (*ConfigModule, error) {
	if e.moduleDone {
		return e.module, e.moduleErr
	}
	e.moduleDone = true
	where, err := e.configPath(ctx)
	if err != nil {
		e.moduleErr = err
		return nil, err
	}
	if where == nil {
		e.module = &ConfigModule{}
		return e.module, nil
	}
	e.module, e.moduleErr = importConfigModule(ctx, where.Path, e.io.Env, e.cli.loader)
	return e.module, e.moduleErr
}

func (e *execution) configContext() ConfigContext {
	return ConfigContext{Command: e.spec.Name, Env: e.io.Env, Cwd: e.cwd}
}

func (e *execution) iam(ctx context.Context) (*server.BetterIam, error) {
	if e.instanceDone {
		return e.instance, e.instanceErr
	}
	e.instanceDone = true
	e.instance, e.instanceErr = func() (*server.BetterIam, error) {
		where, err := e.configPath(ctx)
		if err != nil {
			return nil, err
		}
		var created *server.BetterIam
		switch {
		case where != nil:
			module, err := e.configModule(ctx)
			if err != nil {
				return nil, err
			}
			if created, err = instantiate(ctx, module, e.configContext()); err != nil {
				return nil, err
			}
		case e.io.Env["BETTER_IAM_DATABASE_URL"] != "":
			options, err := ConfigFromEnv(e.io.Env)
			if err != nil {
				return nil, err
			}
			if created, err = newInstance(ctx, options); err != nil {
				return nil, err
			}
		default:
			hint := "Run better-iam init, pass --config PATH, or set BETTER_IAM_DATABASE_URL and BETTER_IAM_SECRET."
			if e.spec.target() == "token" {
				hint = "Pass --config PATH or --url URL, run better-iam login, or run better-iam init."
			}
			return nil, NewCliError("CONFIG_NOT_FOUND", "No "+ConfigFileNames[0]+" (or "+ConfigFileNames[1]+") in "+e.cwd+" or its parents", hint)
		}
		e.opened = append(e.opened, created)
		return created, nil
	}()
	return e.instance, e.instanceErr
}

func (e *execution) open(ctx context.Context, path string, hasPath bool) (*server.BetterIam, error) {
	var created *server.BetterIam
	if !hasPath {
		options, err := ConfigFromEnv(e.io.Env)
		if err != nil {
			return nil, err
		}
		if created, err = newInstance(ctx, options); err != nil {
			return nil, err
		}
	} else {
		module, err := importConfigModule(ctx, resolvePath(e.cwd, path), e.io.Env, e.cli.loader)
		if err != nil {
			return nil, err
		}
		if created, err = instantiate(ctx, module, e.configContext()); err != nil {
			return nil, err
		}
	}
	e.opened = append(e.opened, created)
	return created, nil
}

func (e *execution) token(ctx context.Context) (string, error) {
	if fromEnv := e.io.Env["BETTER_IAM_TOKEN"]; fromEnv != "" {
		return fromEnv, nil
	}
	state, err := e.profile(ctx)
	if err != nil {
		return "", err
	}
	if state != nil && state.Profile != nil && state.Profile.Token != "" {
		if state.Profile.ExpiresAt != nil && *state.Profile.ExpiresAt <= nowMillis() {
			again := "Run better-iam login again."
			if state.Name != defaultProfile {
				again = "Run better-iam login --profile " + state.Name + " again."
			}
			return "", NewCliError("SESSION_EXPIRED", "The session saved as profile "+state.Name+" has expired", again)
		}
		return state.Profile.Token, nil
	}
	if state != nil && state.Mismatch != nil {
		return "", NewCliError("MISSING_ENV", "Set BETTER_IAM_TOKEN to a session or API key",
			`The saved session "`+state.Name+`" belongs to `+DescribeProfileTarget(state.Mismatch)+", not this deployment; run better-iam login against it with another --profile.")
	}
	return "", NewCliError("MISSING_ENV", "Set BETTER_IAM_TOKEN to a session or API key",
		"Or sign in once with better-iam login; later commands use the saved session.")
}

func (e *execution) api(ctx context.Context, options ApiOptions) (ApiTransport, error) {
	bearer := options.Token
	if bearer == "" && !options.Anonymous {
		token, err := e.token(ctx)
		if err != nil {
			return nil, err
		}
		bearer = token
	}
	remote, err := e.remoteURL(ctx)
	if err != nil {
		return nil, err
	}
	if remote != "" {
		return RemoteTransport(remote, bearer, e.io.Fetch)
	}
	where, err := e.configPath(ctx)
	if err != nil {
		return nil, err
	}
	instance, err := e.iam(ctx)
	if err != nil {
		return nil, err
	}
	target := "BETTER_IAM_DATABASE_URL"
	if where != nil {
		target = where.Path
	}
	return LocalTransport(instance, target, bearer), nil
}

func (c *Cli) execute(ctx context.Context, spec *CommandSpec, argv []string, io *CliIO, cwd string, program Program) (failure error) {
	parsed, err := parseArguments(spec, argv)
	if err != nil {
		return err
	}
	if parsed.help {
		io.Out(CommandHelp(spec))
		return nil
	}
	flags := CommandFlags(spec)
	target := spec.target()
	values := Flags{}
	explicit := map[string]bool{}
	for _, name := range parsed.order {
		explicit[name] = true
	}
	for _, name := range parsed.order {
		flag, _ := findFlag(flags, name)
		value, err := convert(name, flag, parsed.values[name], "flag")
		if err != nil {
			return err
		}
		values[name] = value
	}
	for _, flag := range flags {
		if !values.Has(flag.Name) && flag.Env != "" && io.Env[flag.Env] != "" {
			value, err := convert(flag.Name, flag, io.Env[flag.Env], flag.Env)
			if err != nil {
				return err
			}
			values[flag.Name] = value
		}
	}
	// One deployment per command: the command line beats the environment, and naming both at one level is
	// ambiguous.
	if target == "token" {
		switch {
		case explicit["url"] && explicit["config"]:
			return UsageError("Give --url or --config, not both")
		case explicit["config"]:
			delete(values, "url")
		case explicit["url"]:
			delete(values, "config")
		case values.Has("url") && values.Has("config"):
			return UsageError("BETTER_IAM_URL and BETTER_IAM_CONFIG are both set", "Pass --url or --config to choose one.")
		}
	}
	run := &execution{
		cli: c, spec: spec, io: io, cwd: cwd, values: values, profiles: CreateProfileStore(io.Env),
		// A token in the environment wins over saved profiles entirely: its target and tenant come from flags. A
		// saved session is only ever used with the deployment it was issued by, so its token never reaches another
		// server.
		usesProfile: target == "token" && io.Env["BETTER_IAM_TOKEN"] == "",
	}
	defer func() {
		for index := len(run.opened) - 1; index >= 0; index-- {
			if err := closeInstance(ctx, run.opened[index]); err != nil && failure == nil {
				failure = err
			}
		}
	}()
	// Configuration defaults (the module's cli.defaults) fill flags nobody set; they need the module loaded. The
	// flags that choose the deployment and session cannot come from that deployment's own configuration.
	if target != "none" && !spec.NoConfigDefaults {
		remote := ""
		if target == "token" {
			if remote, err = run.remoteURL(ctx); err != nil {
				return err
			}
		}
		if remote == "" {
			where, err := run.configPath(ctx)
			if err != nil {
				return err
			}
			missing := false
			for _, flag := range flags {
				if !values.Has(flag.Name) {
					missing = true
				}
			}
			// A missing file is reported by the command when it loads the configuration, after flag checks.
			if where != nil && fileExists(where.Path) && missing {
				module, err := run.configModule(ctx)
				if err != nil {
					return err
				}
				if module.Cli != nil && module.Cli.Defaults != nil {
					for _, scope := range []string{spec.Name, "*"} {
						entries, _ := module.Cli.Defaults.Get(scope).(*core.Object)
						if entries == nil {
							continue
						}
						for _, name := range entries.Keys() {
							flag, known := findFlag(flags, name)
							if !known || values.Has(name) || targetFlags[name] || (scope == "*" && flag.NoWildcardDefault) {
								continue
							}
							value, err := convert(name, flag, entries.Get(name), "cli.defaults['"+scope+"']")
							if err != nil {
								return err
							}
							values[name] = value
						}
					}
				}
			}
		}
	}
	// Last before the built-in default: the saved session's own values (its tenant).
	for _, flag := range flags {
		if !values.Has(flag.Name) && flag.Profile == "tenantId" {
			state, err := run.profile(ctx)
			if err != nil {
				return err
			}
			if state != nil && state.Profile != nil && state.Profile.TenantID != "" {
				values[flag.Name] = state.Profile.TenantID
			}
		}
	}
	for _, flag := range flags {
		if flag.Required && !values.Has(flag.Name) {
			if flag.Profile != "" {
				variable := flag.Env
				if variable == "" {
					variable = "it"
				}
				return UsageError("--"+flag.Name+" "+placeholder(flag)+" is required",
					"Pass --"+flag.Name+", set "+variable+", or log in with better-iam login --tenant ID.")
			}
			return UsageError("--" + flag.Name + " " + placeholder(flag) + " is required")
		}
	}
	for _, flag := range flags {
		if flag.Type == "boolean" && !values.Has(flag.Name) {
			values[flag.Name] = false
		}
	}
	args := parsed.args
	if args == nil {
		args = []string{}
	}
	for index, arg := range spec.Args {
		if arg.Required && index >= len(args) {
			return UsageError(spec.Name+" needs "+strings.ToUpper(arg.Name), "Run better-iam help "+spec.Name+".")
		}
	}
	if spec.Validate != nil {
		if err := spec.Validate(values, args, explicit); err != nil {
			return err
		}
	}
	commandContext := &CommandContext{
		Name: spec.Name, Flags: values, Args: args, Explicit: explicit, IO: io, Env: io.Env, Cwd: cwd,
		Profiles: run.profiles, Program: program, spec: spec, runner: run,
	}
	result, err := spec.Run(ctx, commandContext)
	if err != nil {
		return systemError(err)
	}
	if result != nil {
		if err := commandContext.Print(result); err != nil {
			return err
		}
	}
	return nil
}

// nullResult is the type of Null.
type nullResult struct{}

// Null is the result a command returns to print JSON null (a nil result prints nothing, like undefined).
var Null any = nullResult{}

// orNull turns a JSON null answer into Null, so it prints as the TypeScript CLI prints it.
func orNull(value any, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	if value == nil {
		return Null, nil
	}
	return value, nil
}
