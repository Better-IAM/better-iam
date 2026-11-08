package cli

// Port of packages/cli/src/commands/vault.ts: the secrets vault from the command line, values as BETTER_IAM_TOKEN,
// and the scheduler jobs.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

var (
	envVariable     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	nonAlphanumeric = regexp.MustCompile(`[^A-Za-z0-9]+`)
	edgeUnderscores = regexp.MustCompile(`^_+|_+$`)
	leadingDigit    = regexp.MustCompile(`^[0-9]`)
	trailingNewline = regexp.MustCompile(`\r?\n$`)
)

// SecretEnvName is the environment variable a secret under prefix becomes in `vault-run --prefix`: the rest of its
// name upper-cased, with every run of other characters turned into _ (prod/app/db-password under prod/app/ is
// DB_PASSWORD).
func SecretEnvName(name, prefix string) string {
	rest := name
	if strings.HasPrefix(name, prefix) {
		rest = name[len(prefix):]
	}
	variable := strings.ToUpper(edgeUnderscores.ReplaceAllString(nonAlphanumeric.ReplaceAllString(rest, "_"), ""))
	if leadingDigit.MatchString(variable) {
		return "_" + variable
	}
	return variable
}

type envMapping struct {
	variable string
	name     string
	field    string
	hasField bool
}

// mapping reads one VAR=name or VAR=name#field mapping of vault-run --env.
func mapping(entry string) (envMapping, error) {
	equals := strings.Index(entry, "=")
	if equals < 1 {
		return envMapping{}, UsageError("--env entries look like VAR=secret/name, not " + entry)
	}
	variable := core.JSTrim(entry[:equals])
	reference := core.JSTrim(entry[equals+1:])
	if !envVariable.MatchString(variable) {
		return envMapping{}, UsageError(variable + " is not an environment variable name")
	}
	name, field, hasField := strings.Cut(reference, "#")
	if name == "" {
		return envMapping{}, UsageError("--env " + variable + " names no secret")
	}
	return envMapping{variable: variable, name: name, field: field, hasField: hasField}, nil
}

// envValue is a revealed value as an environment string: the value, or one field of a json secret (non-strings as
// JSON).
func envValue(secret any, field string, hasField bool) (string, error) {
	if !hasField {
		value, _ := pathOf(secret, "value").(string)
		return value, nil
	}
	fields, _ := pathOf(secret, "fields").(*core.Object)
	var value any = core.Undefined
	if fields != nil && fields.Has(field) {
		value = fields.Get(field)
	}
	if core.IsUndefined(value) {
		return "", NewCliError("NOT_FOUND", "The secret "+jsString(pathOf(secret, "name"))+" has no field "+field)
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	return core.MustStringify(value), nil
}

// runChild runs the command with the environment, inheriting the terminal, and returns its exit status.
func runChild(command string, args []string, env map[string]string, cwd string) (int, error) {
	child := exec.Command(command, args...)
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	child.Env = make([]string, 0, len(names))
	for _, name := range names {
		child.Env = append(child.Env, name+"="+env[name])
	}
	child.Dir = cwd
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if code := exit.ExitCode(); code >= 0 {
				return code, nil
			}
			return 128, nil
		}
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return 0, NewCliError("COMMAND_NOT_FOUND", command+" was not found", "Check the command after --.")
		}
		return 0, err
	}
	return 0, nil
}

var vaultCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "vault-get",
		Group:       "Access",
		Summary:     "Print a secret from the vault",
		Description: "vault-get prints the value of a secret as BETTER_IAM_TOKEN (iam:vault:reveal): the current version, or --version / --stage, and with --field one field of a json secret. The value is printed on its own, so it can be captured with $(...); every reveal is audited as vault:reveal. Secrets handed out only through check-outs refuse with CHECKOUT_REQUIRED.",
		Target:      "token",
		Output:      "text",
		Args:        []ArgSpec{{Name: "name", Description: "The secret, such as prod/payments/db-password", Required: true}},
		Flags: []FlagSpec{
			tenantFlag,
			boundedInteger("version", "A version", 1, maxSafeInteger, nil),
			{Name: "stage", Type: "string", Value: "LABEL", Description: "A stage label such as previous"},
			{Name: "field", Type: "string", Value: "FIELD", Description: "One field of a json secret"},
		},
		Examples: []string{
			"better-iam vault-get prod/payments/db-password --tenant acme-id",
			"better-iam vault-get prod/smtp --field password",
		},
		Validate: func(flags Flags, args []string, explicit map[string]bool) error {
			if flags.Has("version") && flags.Has("stage") {
				return UsageError("Pass --version or --stage, not both")
			}
			return nil
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			input := core.NewObject("tenantId", c.Flags.String("tenant"), "name", c.Args[0])
			if version, ok := c.Flags.Int("version"); ok {
				input.Set("version", float64(version))
			}
			if stage := c.Flags.String("stage"); stage != "" {
				input.Set("stage", stage)
			}
			secret, err := call(ctx, c, "vault/reveal", input)
			if err != nil {
				return nil, err
			}
			return envValue(secret, c.Flags.String("field"), c.Flags.Has("field"))
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "vault-put",
		Group:       "Access",
		Summary:     "Store a new version of a secret",
		Description: "vault-put stores a new version of a secret as BETTER_IAM_TOKEN (iam:vault:write) from standard input (the default, or --value -), from --value-env (the name of an environment variable holding it), or --generate for a random value; secrets are never taken from the command line itself. The version becomes current unless --stage pending. Trailing newlines on standard input are removed.",
		Target:      "token",
		Args:        []ArgSpec{{Name: "name", Description: "The secret", Required: true}},
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "value-env", Type: "string", Value: "VARIABLE", Description: "Read the value from this environment variable"},
			{Name: "generate", Type: "boolean", Description: "Generate a random 32-character value"},
			{Name: "stage", Type: "string", Choices: []string{"current", "pending"}, Default: "current", Description: "Make it current now, or stage it for promotion"},
		},
		Examples: []string{
			`printf %s "$PASSWORD" | better-iam vault-put prod/payments/db-password`,
			"better-iam vault-put prod/signing-key --value-env SIGNING_KEY --stage pending",
			"better-iam vault-put staging/api-token --generate",
		},
		Validate: func(flags Flags, args []string, explicit map[string]bool) error {
			if flags.Bool("generate") && flags.String("value-env") != "" {
				return UsageError("Pass --generate or --value-env, not both")
			}
			return nil
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			value, hasValue := "", false
			if variable := c.Flags.String("value-env"); variable != "" {
				value, hasValue = c.Env[variable], true
				if value == "" {
					return nil, UsageError(variable + " is not set or empty")
				}
			} else if !c.Flags.Bool("generate") {
				if c.IO.Stdin == nil {
					return nil, UsageError("Pipe the value on standard input, or use --value-env")
				}
				text, err := c.IO.Stdin()
				if err != nil {
					return nil, err
				}
				value, hasValue = trailingNewline.ReplaceAllString(text, ""), true
				if value == "" {
					return nil, UsageError("Standard input was empty")
				}
			}
			stage := stringFlag(c.Flags, "stage", "current")
			input := core.NewObject("tenantId", c.Flags.String("tenant"), "name", c.Args[0])
			if hasValue {
				input.Set("value", value)
			} else {
				input.Set("generate", true)
			}
			input.Set("stage", stage)
			return orNull(call(ctx, c, "vault/put", input))
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "vault-run",
		Group:       "Access",
		Summary:     "Run a command with secrets in its environment",
		Description: "vault-run reveals secrets as BETTER_IAM_TOKEN (iam:vault:reveal on each) and runs the command after -- with them as environment variables, so they never touch disk or shell history. --env maps variables to secrets (VAR=name, or VAR=name#field for one field of a json secret; comma-separated). --prefix adds every static secret under a path you may reveal, named after the rest of its path (prod/app/db-password under prod/app/ becomes DB_PASSWORD; a json secret adds one variable per field, DB_PASSWORD_USERNAME). --env wins over --prefix. The command inherits the terminal and its exit status becomes vault-run's. BETTER_IAM_TOKEN is removed from the command's environment unless --keep-token.",
		Target:      "token",
		Output:      "text",
		Args:        []ArgSpec{{Name: "command", Description: "The command and its arguments, after --", Required: true, Variadic: true}},
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "env", Type: "string", Value: "VAR=NAME[#FIELD],...", Description: "Variables to set from secrets"},
			{Name: "prefix", Type: "string", Value: "PATH/", Description: "Add every secret under this path, named after the rest of its name"},
			{Name: "keep-token", Type: "boolean", Description: "Pass BETTER_IAM_TOKEN on to the command"},
		},
		Examples: []string{
			"better-iam vault-run --env DATABASE_PASSWORD=prod/payments/db-password -- node server.js",
			"better-iam vault-run --prefix prod/payments/ -- npm start",
		},
		Validate: func(flags Flags, args []string, explicit map[string]bool) error {
			if flags.String("env") == "" && flags.String("prefix") == "" {
				return UsageError("Pass --env, --prefix, or both")
			}
			return nil
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			tenantID := c.Flags.String("tenant")
			injected := map[string]string{}
			var order []string
			inject := func(variable, value string) {
				if _, seen := injected[variable]; !seen {
					order = append(order, variable)
				}
				injected[variable] = value
			}
			type revealed struct {
				value any
				err   error
			}
			cache := map[string]revealed{}
			reveal := func(name string) (any, error) {
				if cached, ok := cache[name]; ok {
					return cached.value, cached.err
				}
				value, err := transport.Call(ctx, "vault/reveal", core.NewObject("tenantId", tenantID, "name", name))
				cache[name] = revealed{value, err}
				return value, err
			}
			if prefix := c.Flags.String("prefix"); prefix != "" {
				listed, err := transport.Call(ctx, "vault/list", core.NewObject("tenantId", tenantID, "prefix", prefix, "limit", 500.0))
				if err != nil {
					return nil, err
				}
				secrets, _ := pathOf(listed, "secrets").([]any)
				for _, secret := range secrets {
					if pathOf(secret, "kind") != "static" || pathOf(secret, "status") != "active" {
						continue
					}
					name, _ := pathOf(secret, "name").(string)
					value, err := reveal(name)
					if err != nil {
						c.Note("Skipped " + name + ": " + err.Error())
						continue
					}
					base := SecretEnvName(name, prefix)
					fields, isObject := pathOf(value, "fields").(*core.Object)
					if pathOf(value, "format") == "json" && isObject && fields != nil {
						for _, field := range fields.Keys() {
							variable := base + "_" + SecretEnvName(field, "")
							if envVariable.MatchString(variable) {
								item := fields.Get(field)
								if text, ok := item.(string); ok {
									inject(variable, text)
								} else {
									inject(variable, core.MustStringify(item))
								}
							}
						}
					} else if envVariable.MatchString(base) {
						text, _ := pathOf(value, "value").(string)
						inject(base, text)
					}
				}
			}
			for _, entry := range strings.Split(c.Flags.String("env"), ",") {
				if core.JSTrim(entry) == "" {
					continue
				}
				mapped, err := mapping(entry)
				if err != nil {
					return nil, err
				}
				secret, err := reveal(mapped.name)
				if err != nil {
					return nil, err
				}
				value, err := envValue(secret, mapped.field, mapped.hasField)
				if err != nil {
					return nil, err
				}
				inject(mapped.variable, value)
			}
			childEnv := map[string]string{}
			for name, value := range c.Env {
				childEnv[name] = value
			}
			for _, variable := range order {
				childEnv[variable] = injected[variable]
			}
			if !c.Flags.Bool("keep-token") {
				delete(childEnv, "BETTER_IAM_TOKEN")
			}
			c.Note("Running " + c.Args[0] + " with " + strconv.Itoa(len(order)) + " secret(s) in its environment")
			status, err := runChild(c.Args[0], c.Args[1:], childEnv, c.Cwd)
			if err != nil {
				return nil, err
			}
			if status != 0 {
				failure := NewCliError("COMMAND_FAILED", c.Args[0]+" exited with status "+strconv.Itoa(status))
				failure.ExitStatus = status
				return nil, failure
			}
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "vault-rotate-due",
		Group:       "Operations",
		Summary:     "Rotate vault secrets whose scheduled rotation is due",
		Description: "vault-rotate-due rotates every static secret (or those of --tenant) whose rotation.intervalDays has passed and that has a generator or a rotator, acting as deployment-operator; due secrets with neither are recorded once per due date as vault:rotation-due. Failed rotations keep their pending version and retry with growing delays. Run it hourly.",
		Target:      "config",
		Flags:       []FlagSpec{{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this tenant"}},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Vault.RotateDue(ctx, tenantOnly(c.Flags)))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "vault-expire-leases",
		Group:       "Operations",
		Summary:     "End expired vault check-outs and leases",
		Description: "vault-expire-leases ends expired check-outs (rotating secrets that rotate on check-in), revokes expired dynamic leases and those of people who are no longer active at their engine, retries failed revocations, and deletes lease history past vault.accessRetentionDays. Run it every few minutes.",
		Target:      "config",
		Flags:       []FlagSpec{},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Vault.ExpireLeases(ctx, core.NewObject()))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "vault-purge-deleted",
		Group:       "Operations",
		Summary:     "Delete vault secrets whose recovery window has ended",
		Description: "vault-purge-deleted removes every secret scheduled for deletion whose recovery window has ended, with its versions, leases and access records (live dynamic leases are revoked at their engine first); each is audited as vault:purge. Run it daily.",
		Target:      "config",
		Flags:       []FlagSpec{},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Vault.PurgeDeleted(ctx, core.NewObject()))
		}),
	}),
}
