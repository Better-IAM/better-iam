package cli

// Port of packages/cli/src/commands/access.ts: token commands. They act as BETTER_IAM_TOKEN or a saved session, in
// process or against --url.

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var severities = []string{"high", "medium", "low"}

// tenantFlag is the tenant a token command acts in: the flag, BETTER_IAM_TENANT, or the saved profile's.
var tenantFlag = FlagSpec{Name: "tenant", Type: "string", Value: "TENANT_ID", Required: true, Env: "BETTER_IAM_TENANT",
	Profile: "tenantId", Description: "The tenant to act in"}

var inputFlag = FlagSpec{Name: "input", Type: "string", Value: "PATH", Required: true,
	Description: "Desired configuration: a .json file (JavaScript modules need the TypeScript CLI)"}

var resourcePattern = regexp.MustCompile(`^([^/:]+)[/:](.+)$`)

// parseResource reads project/p1, project:p1, or iam/roles/r1 (the first separator splits type and id).
func parseResource(value string) (*core.Object, error) {
	match := resourcePattern.FindStringSubmatch(value)
	if match == nil {
		return nil, UsageError(value + " is not a resource like project/p1 or project:p1")
	}
	return core.NewObject("type", match[1], "id", match[2]), nil
}

// identityID is an identity ID, or an email looked up in the tenant.
func identityID(ctx context.Context, api ApiTransport, tenantID, value string) (string, error) {
	if !strings.Contains(value, "@") {
		return value, nil
	}
	found, err := api.Call(ctx, "identities/list", core.NewObject("tenantId", tenantID, "query", value, "limit", 20.0))
	if err != nil {
		return "", err
	}
	list, _ := found.([]any)
	var matches []string
	for _, item := range list {
		identity, _ := item.(*core.Object)
		if identity == nil {
			continue
		}
		email, ok := identity.Get("email").(string)
		if ok && core.JSLower(email) == core.JSLower(value) {
			id, _ := identity.Get("id").(string)
			matches = append(matches, id)
		}
	}
	if len(matches) != 1 {
		return "", NewCliError("NOT_FOUND", "No single identity in "+tenantID+" has the email "+value)
	}
	return matches[0], nil
}

func desiredConfig(c *CommandContext, input, tenantID string) (any, error) {
	return LoadTenantConfig(c.Path(input), TenantConfigContext{TenantID: tenantID, Env: c.Env})
}

func numberAt(value any, keys ...string) float64 {
	number, _ := pathOf(value, keys...).(float64)
	return number
}

// call is a token command's single API call.
func call(ctx context.Context, c *CommandContext, path string, input *core.Object) (any, error) {
	transport, err := c.Api(ctx, ApiOptions{})
	if err != nil {
		return nil, err
	}
	return orNull(transport.Call(ctx, path, input))
}

var moduleOutput = regexp.MustCompile(`(?i)\.(m?[jt]s)$`)

func configSyncCommand(name string) *CommandSpec {
	plan := name == "config-plan"
	spec := CommandSpec{
		Name:        name,
		Group:       "Access",
		Summary:     "Apply a configuration to a tenant in one transaction",
		Description: "config-apply applies a configuration in one transaction (--prune also deletes items the file omits), authorized and audited like console operations.",
		Target:      "token",
		Flags:       []FlagSpec{tenantFlag, inputFlag, {Name: "prune", Type: "boolean", Description: "Also delete items the file omits"}},
		Examples:    []string{"better-iam config-apply --tenant ten_123 --input iam/tenant.json --prune"},
	}
	route := "config/apply"
	if plan {
		route = "config/plan"
		spec.Summary = "Show what applying a configuration would change"
		spec.Description = "config-plan shows what config-apply would change (--prune also plans deleting items the file omits); --fail-on-drift exits non-zero when anything would change, for CI. The input is the JSON tenant configuration config-export writes."
		spec.Flags = append(spec.Flags, FlagSpec{Name: "fail-on-drift", Type: "boolean", Description: "Exit non-zero when anything would change (CI)"})
		spec.Examples = []string{"better-iam config-plan --tenant ten_123 --input iam/tenant.json --fail-on-drift"}
	}
	spec.Run = func(ctx context.Context, c *CommandContext) (any, error) {
		tenantID := c.Flags.String("tenant")
		config, err := desiredConfig(c, c.Flags.String("input"), tenantID)
		if err != nil {
			return nil, err
		}
		planned, err := call(ctx, c, route, core.NewObject("tenantId", tenantID, "config", config, "prune", c.Flags.Bool("prune")))
		if err != nil {
			return nil, err
		}
		if err := c.Print(planned); err != nil {
			return nil, err
		}
		drift := numberAt(planned, "summary", "create") + numberAt(planned, "summary", "update") + numberAt(planned, "summary", "delete")
		if c.Flags.Bool("fail-on-drift") && drift > 0 {
			return nil, core.NewIamError("CONFIG_DRIFT", "The tenant differs from the configuration in "+core.NumberString(drift)+" item(s)")
		}
		return nil, nil
	}
	return DefineCommand(spec)
}

var accessCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "config-export",
		Group:       "Access",
		Summary:     "Print or save a tenant's configuration as code",
		Description: "config-export writes a tenant's roles, policies, groups, resource types, group bindings, packages, invariants, and agreements as JSON (or as a typed module when --output ends in .ts or .mjs). The config commands act as the session or API key in BETTER_IAM_TOKEN (or the session saved by login) and are authorized and audited like console operations.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "output", Type: "string", Value: "PATH", Description: "Write to this file instead (.json, or .ts/.mjs for a module); never overwrites"},
		},
		Examples: []string{"better-iam config-export --tenant ten_123 --output iam/tenant.json"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			tenantID := c.Flags.String("tenant")
			exported, err := call(ctx, c, "config/export", core.NewObject("tenantId", tenantID))
			if err != nil {
				return nil, err
			}
			if c.Flags.String("output") == "" {
				return exported, nil
			}
			output := c.Path(c.Flags.String("output"))
			body := stringifyIndented(jsonValue(exported), "  ", "") + "\n"
			if moduleOutput.MatchString(output) {
				body = tenantConfigModule(exported, output)
			}
			// Owner-only, like store-export: the document names every group member and binding.
			if err := writeNewFile(output, []byte(body), 0o600); err != nil {
				return nil, err
			}
			// The confirmation stays one line, as before; --format json indents it.
			format := c.Flags.String("format")
			if format == "" {
				format = "compact"
			}
			text, err := FormatResult(core.NewObject("tenantId", tenantID, "output", output), format, c.Flags.String("query"), c.Flags.Has("query"))
			if err != nil {
				return nil, err
			}
			c.IO.Out(text)
			return nil, nil
		},
	}),
	configSyncCommand("config-plan"),
	configSyncCommand("config-apply"),
	DefineCommand(CommandSpec{
		Name:        "config-validate",
		Group:       "Access",
		Summary:     "Check a configuration file offline, without a database or token",
		Description: "config-validate checks a configuration file offline: its shape, and names it refers to that the file does not define (those must already exist in the tenant, or planning fails). --strict exits non-zero on such warnings. It needs no configuration, database, or token, so it fits pre-commit hooks and CI.",
		Flags: []FlagSpec{
			inputFlag,
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Passed to a configuration factory as tenantId"},
			{Name: "strict", Type: "boolean", Description: "Exit non-zero when a reference is not defined in the file"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			config, err := desiredConfig(c, c.Flags.String("input"), c.Flags.String("tenant"))
			if err != nil {
				return nil, err
			}
			lint, err := LintTenantConfig(config)
			if err != nil {
				return nil, err
			}
			if err := c.Print(lint.Model()); err != nil {
				return nil, err
			}
			if c.Flags.Bool("strict") && len(lint.Warnings) > 0 {
				return nil, core.NewIamError("CONFIG_WARNINGS", strconv.Itoa(len(lint.Warnings))+" unresolved reference(s)")
			}
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "analyze",
		Group:       "Access",
		Summary:     "Print a tenant's access-analysis findings",
		Description: "analyze prints the tenant's access-analysis findings (as BETTER_IAM_TOKEN, which needs iam:analysis:read); with --fail-on it exits non-zero when an unsuppressed finding of that severity or higher exists, for CI and cron.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			boundedInteger("dormant-days", "Days without sign-in after which an identity counts as dormant", 1, 36500, nil),
			{Name: "fail-on", Type: "string", Choices: severities, Description: "Exit non-zero on a finding of this severity or higher"},
		},
		Examples: []string{"better-iam analyze --tenant ten_123 --fail-on high --format table"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			input := core.NewObject("tenantId", c.Flags.String("tenant"))
			if dormant, ok := c.Flags.Int("dormant-days"); ok {
				input.Set("dormantDays", float64(dormant))
			}
			report, err := call(ctx, c, "analysis/findings", input)
			if err != nil {
				return nil, err
			}
			if err := c.Print(report); err != nil {
				return nil, err
			}
			if failOn := c.Flags.String("fail-on"); failOn != "" {
				threshold := slices.Index(severities, failOn)
				failing := 0
				findings, _ := pathOf(report, "findings").([]any)
				for _, finding := range findings {
					severity, _ := pathOf(finding, "severity").(string)
					if slices.Index(severities, severity) <= threshold {
						failing++
					}
				}
				if failing > 0 {
					return nil, core.NewIamError("FINDINGS", strconv.Itoa(failing)+" finding(s) at or above "+failOn+" severity")
				}
			}
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "report",
		Group:       "Access",
		Summary:     "Print a tenant's access report",
		Description: "report prints the tenant's access report as BETTER_IAM_TOKEN: identities and bindings ending within --within-days (30), keys unused for --unused-days (30) or ending soon, live activations, and pending activation requests.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			boundedInteger("within-days", "Access ending within this many days", 0, 3650, 30.0),
			boundedInteger("unused-days", "Keys unused for this many days", 0, 3650, 30.0),
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			return call(ctx, c, "reports/access", core.NewObject("tenantId", c.Flags.String("tenant"),
				"withinMs", days(c.Flags, "within-days", 30), "unusedForMs", days(c.Flags, "unused-days", 30)))
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "mine-roles",
		Group:       "Access",
		Summary:     "Suggest roles from how access is actually held",
		Description: "mine-roles prints role-mining suggestions (role bundles, roles to bind to a group, redundant direct bindings, duplicate roles) and peer outliers grouped by --peer-by (default manager) as BETTER_IAM_TOKEN, which needs iam:analysis:read.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "peer-by", Type: "string", Value: "manager|attribute:NAME", Description: "How peers are grouped for outliers"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			tenantID := c.Flags.String("tenant")
			mining, err := transport.Call(ctx, "roleMining/suggest", core.NewObject("tenantId", tenantID))
			if err != nil {
				return nil, err
			}
			input := core.NewObject("tenantId", tenantID)
			if c.Flags.Has("peer-by") {
				input.Set("peerBy", c.Flags.String("peer-by"))
			}
			peers, err := transport.Call(ctx, "roleMining/outliers", input)
			if err != nil {
				return nil, err
			}
			out := core.NewObject()
			if object, ok := mining.(*core.Object); ok && object != nil {
				out.Assign(object)
			}
			out.Set("peers", peers)
			return out, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "check-invariants",
		Group:       "Access",
		Summary:     "Evaluate a tenant's access invariants",
		Description: "check-invariants evaluates the tenant's access invariants as BETTER_IAM_TOKEN (iam:invariants:read); --fail-on-broken exits non-zero when one is broken or cannot be evaluated, for CI after config-apply.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "fail-on-broken", Type: "boolean", Description: "Exit non-zero when an invariant is broken or unevaluable"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			run, err := call(ctx, c, "invariants/run", core.NewObject("tenantId", c.Flags.String("tenant")))
			if err != nil {
				return nil, err
			}
			if err := c.Print(run); err != nil {
				return nil, err
			}
			failed, errorsCount := numberAt(run, "summary", "failed"), numberAt(run, "summary", "errors")
			if c.Flags.Bool("fail-on-broken") && failed+errorsCount > 0 {
				return nil, core.NewIamError("INVARIANTS_BROKEN", core.NumberString(failed)+" broken and "+core.NumberString(errorsCount)+" unevaluable invariant(s)")
			}
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "whoami",
		Group:       "Access",
		Summary:     "Print who the current token acts as",
		Description: "whoami prints who BETTER_IAM_TOKEN acts as (sts.getCallerIdentity): identity, tenant, session kind and id, format, MFA, expiry, and any role, trust, session name, or web identity; it needs no permission and records nothing, so it also checks that a session, API key, role session, or session token (opaque or JWT) is still valid. Without BETTER_IAM_TOKEN it reports the session saved by login.",
		Target:      "token",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			// sts.getCallerIdentity: no permission, no audit event; an unusable credential fails with UNAUTHENTICATED.
			return call(ctx, c, "sts/getCallerIdentity", nil)
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "can",
		Group:       "Access",
		Summary:     "Check whether the current token may perform an action",
		Description: "can asks whether the token may perform ACTION on RESOURCE (type/id) in the tenant and prints the decision with its reason; it exits non-zero (ACCESS_DENIED) when the answer is no, so scripts can branch on it. The decision is recorded like any authorization check.",
		Target:      "token",
		Args: []ArgSpec{
			{Name: "action", Description: "The action, for example projects:read", Required: true},
			{Name: "resource", Description: "type/id or type:id, for example project/p1", Required: true},
		},
		Flags:    []FlagSpec{tenantFlag},
		Examples: []string{"better-iam can projects:read project/p1 --tenant ten_123"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			resource, err := parseResource(c.Args[1])
			if err != nil {
				return nil, err
			}
			decision, err := transport.Call(ctx, "authorize", core.NewObject("tenantId", c.Flags.String("tenant"), "action", c.Args[0], "resource", resource))
			if err != nil {
				return nil, err
			}
			if err := c.Print(decision); err != nil {
				return nil, err
			}
			if pathOf(decision, "allowed") != true {
				message := "Not allowed"
				if reason, ok := pathOf(decision, "reason").(string); ok && reason != "" {
					message += ": " + reason
				}
				return nil, core.NewIamError("ACCESS_DENIED", message, 403)
			}
			return nil, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "explain",
		Group:       "Access",
		Summary:     "Explain why an identity is or is not allowed an action",
		Description: "explain simulates the decision for another identity (by ID or email) without signing in as them: the matching statements, boundaries, and reason (policies.simulate, which needs iam:policies:simulate). --assume-mfa evaluates as if they had used MFA.",
		Target:      "token",
		Args: []ArgSpec{
			{Name: "action", Description: "The action, for example projects:write", Required: true},
			{Name: "resource", Description: "type/id or type:id", Required: true},
		},
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "identity", Type: "string", Value: "ID|EMAIL", Required: true, Description: "Whose decision to explain"},
			{Name: "assume-mfa", Type: "boolean", Description: "Evaluate as an MFA session"},
		},
		Examples: []string{"better-iam explain projects:write project/p1 --identity alice@acme.test"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			tenantID := c.Flags.String("tenant")
			identity, err := identityID(ctx, transport, tenantID, c.Flags.String("identity"))
			if err != nil {
				return nil, err
			}
			resource, err := parseResource(c.Args[1])
			if err != nil {
				return nil, err
			}
			return orNull(transport.Call(ctx, "policies/simulate", core.NewObject("tenantId", tenantID, "identityId", identity,
				"action", c.Args[0], "resource", resource, "assumeMfa", c.Flags.Bool("assume-mfa"))))
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "who-can",
		Group:       "Access",
		Summary:     "List every identity that may perform an action on a resource",
		Description: "who-can lists every active identity of the tenant that could perform ACTION on RESOURCE, with the reason (policies.whoCan, which needs iam:policies:simulate); root administrators are not listed because their override applies everywhere.",
		Target:      "token",
		Args: []ArgSpec{
			{Name: "action", Description: "The action", Required: true},
			{Name: "resource", Description: "type/id or type:id", Required: true},
		},
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "kind", Type: "string", Choices: []string{"user", "service"}, Description: "Only people or only service accounts"},
			{Name: "assume-mfa", Type: "boolean", Description: "Evaluate as MFA sessions"},
			boundedInteger("limit", "Most identities listed", 1, 1000, 100.0),
		},
		Examples: []string{"better-iam who-can projects:delete project/p1 --format table"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			resource, err := parseResource(c.Args[1])
			if err != nil {
				return nil, err
			}
			input := core.NewObject("tenantId", c.Flags.String("tenant"), "action", c.Args[0], "resource", resource)
			if kind := c.Flags.String("kind"); kind != "" {
				input.Set("kind", kind)
			}
			input.Set("assumeMfa", c.Flags.Bool("assume-mfa"))
			if limit, ok := c.Flags.Int("limit"); ok {
				input.Set("limit", float64(limit))
			}
			return orNull(transport.Call(ctx, "policies/whoCan", input))
		},
	}),
}
