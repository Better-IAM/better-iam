package cli

// Port of packages/cli/src/commands/operations.ts: deployment operations for schedulers. They take no credential
// and act on the whole deployment (or one --tenant).

import (
	"context"
	"strconv"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const day = 86_400_000.0

var tenantFilter = FlagSpec{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this organization (default: every active one)"}

// days is an integer flag in milliseconds, or fallback days when unset.
func days(flags Flags, name string, fallback float64) float64 {
	if value, ok := flags.Int(name); ok {
		return float64(value) * day
	}
	return fallback * day
}

// tenantOnly is { tenantId } when --tenant is set, else {}.
func tenantOnly(flags Flags) *core.Object {
	input := core.NewObject()
	if tenant := flags.String("tenant"); tenant != "" {
		input.Set("tenantId", tenant)
	}
	return input
}

// withIam runs fn with the configuration's instance.
func withIam(fn func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error)) func(ctx context.Context, c *CommandContext) (any, error) {
	return func(ctx context.Context, c *CommandContext) (any, error) {
		iam, err := c.Iam(ctx)
		if err != nil {
			return nil, err
		}
		return fn(ctx, c, iam)
	}
}

// result returns a server result as a command result (nil objects print nothing).
func result(value *core.Object, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	return value, nil
}

func lengthOf(value any) int {
	list, _ := value.([]any)
	return len(list)
}

func pathOf(value any, keys ...string) any {
	for _, key := range keys {
		object, ok := value.(*core.Object)
		if !ok || object == nil {
			return core.Undefined
		}
		value = object.Get(key)
	}
	return value
}

var operationCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name: "outbox",
		// One line, as scripts that read this output by line have always received it.
		DefaultFormat: "compact",
		Group:         "Operations",
		Summary:       "Deliver pending emails, SMS, and webhooks from the outbox",
		Description:   "outbox delivers pending transactional messages from the encrypted delivery outbox and then dispatches audit hooks (webhooks); a deployment operation for a scheduler.",
		Target:        "config",
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			dispatched, err := iam.Auth.DispatchOutbox(ctx, 0)
			if err != nil {
				return nil, err
			}
			if err := c.Print(dispatched); err != nil {
				return nil, err
			}
			_, err = iam.DispatchAuditHooks(ctx)
			return nil, err
		}),
	}),
	DefineCommand(CommandSpec{
		Name: "purge",
		// One line, as scripts that read this output by line have always received it.
		DefaultFormat: "compact",
		Group:         "Operations",
		Summary:       "Remove deleted tenants past retention and expired grants",
		Description:   "Purge removes tenants deleted more than N days ago (default 30) including their data, and records the action in the audit log. Audit records remain.",
		Target:        "config",
		Flags: []FlagSpec{func() FlagSpec {
			flag := boundedInteger("retention-days", "Keep deleted tenants this many days", 0, 3650, 30.0)
			// Deletes tenant data: only cli.defaults.purge may change it, never a shared '*' default.
			flag.NoWildcardDefault = true
			return flag
		}()},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.PurgeDeleted(ctx, core.NewObject("retentionMs", days(c.Flags, "retention-days", 30))))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "sweep",
		Group:       "Operations",
		Summary:     "Delete expired sessions, protocol artifacts, and old deliveries",
		Description: "sweep deletes expired sessions, devices, relationship tuples, OAuth and SAML artifacts, and deliveries older than --retention-days (30) in short batches, at most --limit (10000) records per run; schedule it beside purge.",
		Target:      "config",
		Flags: []FlagSpec{
			boundedInteger("limit", "Most records deleted per run", 1, 1_000_000, 10000.0),
			boundedInteger("retention-days", "Keep delivered and failed deliveries this many days", 0, 3650, 30.0),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := core.NewObject()
			if limit, ok := c.Flags.Int("limit"); ok {
				input.Set("limit", float64(limit))
			}
			if c.Flags.Has("retention-days") {
				input.Set("deliveryRetentionMs", days(c.Flags, "retention-days", 30))
			}
			return result(iam.SweepExpired(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "digest",
		Group:       "Operations",
		Summary:     "Email each organization owner its access report",
		Description: "digest emails the access report to the owners of every active organization (or one --tenant) that has something to report, at most once a day per organization; a deployment operation for cron, like purge.",
		Target:      "config",
		Flags: []FlagSpec{
			tenantFilter,
			boundedInteger("within-days", "Report access ending within this many days", 0, 3650, 30.0),
			boundedInteger("unused-days", "Report keys unused for this many days", 0, 3650, 30.0),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := tenantOnly(c.Flags)
			input.Set("withinMs", days(c.Flags, "within-days", 30))
			input.Set("unusedForMs", days(c.Flags, "unused-days", 30))
			return result(iam.SendAccessDigest(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "remind",
		Group:       "Operations",
		Summary:     "Email people whose access ends soon",
		Description: "remind emails each person whose account, role bindings, group memberships, or packages end within --within-days (7), once per item and end date; a deployment operation like digest.",
		Target:      "config",
		Flags: []FlagSpec{
			tenantFilter,
			// Reminders look at most a year ahead (the server's own bound).
			boundedInteger("within-days", "Remind about access ending within this many days", 1, 365, 7.0),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := tenantOnly(c.Flags)
			input.Set("withinMs", days(c.Flags, "within-days", 7))
			return result(iam.SendExpiryReminders(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "reconcile",
		Group:       "Operations",
		Summary:     "Apply access-package rules (birthright access)",
		Description: "reconcile applies access-package rules (birthright access): identities that match a package's autoAssign rule receive it and automatic holders that stopped matching lose it, at most --limit (1000) changes per organization and run, under each rule owner's grant authority; a deployment operation for cron (run it after purge). Unusually large changes are held back until confirmed with --tenant ID --package ID --confirm; --fail-on-attention exits non-zero when a change failed, was held back, or a rule is suspended.",
		Usage:       "better-iam reconcile --config better-iam.json [--tenant TENANT_ID [--package PACKAGE_ID [--confirm]]] [--limit N] [--fail-on-attention]",
		Target:      "config",
		Flags: []FlagSpec{
			tenantFilter,
			{Name: "package", Type: "string", Value: "PACKAGE_ID", Description: "Only this package (needs --tenant)"},
			{Name: "confirm", Type: "boolean", Description: "Apply a held-back large change (needs --package)"},
			boundedInteger("limit", "Most changes per organization and run", 1, 10000, 1000.0),
			{Name: "fail-on-attention", Type: "boolean", Description: "Exit non-zero when a change failed, was held back, or a rule is suspended"},
		},
		Validate: func(flags Flags, args []string, explicit map[string]bool) error {
			if flags.String("package") != "" && flags.String("tenant") == "" {
				return UsageError("--package needs --tenant")
			}
			if flags.Bool("confirm") && flags.String("package") == "" {
				return UsageError("--confirm needs --package")
			}
			return nil
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			// Applies package rules under their owners' authority; no credential.
			input := tenantOnly(c.Flags)
			if pkg := c.Flags.String("package"); pkg != "" {
				input.Set("packageId", pkg)
			}
			if limit, ok := c.Flags.Int("limit"); ok {
				input.Set("limit", float64(limit))
			}
			if c.Flags.Bool("confirm") {
				input.Set("confirm", true)
			}
			reconciled, err := iam.ReconcilePackages(ctx, input)
			if err != nil {
				return nil, err
			}
			if err := c.Print(reconciled); err != nil {
				return nil, err
			}
			attention := lengthOf(pathOf(reconciled, "failed")) + lengthOf(pathOf(reconciled, "suspended")) +
				lengthOf(pathOf(reconciled, "braked")) + lengthOf(pathOf(reconciled, "skipped", "failedTenants"))
			if c.Flags.Bool("fail-on-attention") && attention > 0 {
				return nil, core.NewIamError("RECONCILE_ATTENTION", strconv.Itoa(attention)+" package rule problem(s) need attention")
			}
			return nil, nil
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "close-certifications",
		Group:       "Operations",
		Summary:     "Close and apply overdue auto-closing certification campaigns",
		Description: "close-certifications closes every access-certification campaign created with autoClose whose due date has passed (or only one --tenant's), applying its decisions under the creator's authority; a deployment operation for cron.",
		Target:      "config",
		Flags:       []FlagSpec{tenantFilter},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.CloseOverdueCertifications(ctx, tenantOnly(c.Flags)))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "monitor-invariants",
		Group:       "Operations",
		Summary:     "Evaluate every organization's invariants and audit status changes",
		Description: "monitor-invariants evaluates every organization's invariants (or one --tenant's) and records invariant:broken / invariant:restored audit events when their status changes, so webhooks can alert; a deployment operation for cron.",
		Target:      "config",
		Flags:       []FlagSpec{tenantFilter},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.CheckInvariants(ctx, tenantOnly(c.Flags)))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "detect-threats",
		Group:       "Operations",
		Summary:     "Read each organization's new audit events and raise threat detections",
		Description: "detect-threats runs identity threat detection for every active organization (or one --tenant): it reads up to --max-events (2000) unread audit events from the organization's cursor, verifies their hash chain (a break is reported as audit-tampering), evaluates the detection rules, records detections and incidents, updates identity risk, and runs the organization's response playbooks. It prints what the run did; pending counts organizations with more unread events than one run reads, which the next run continues. A deployment operation for cron, every minute.",
		Target:      "config",
		Flags: []FlagSpec{
			tenantFilter,
			// The server's own bounds (threat-engine.ts).
			boundedInteger("max-events", "Most unread audit events read per organization and run", 1, 20_000, 2000.0),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := tenantOnly(c.Flags)
			if maxEvents, ok := c.Flags.Int("max-events"); ok {
				input.Set("maxEvents", float64(maxEvents))
			}
			return result(iam.DetectThreats(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "rotate-secrets",
		Group:       "Operations",
		Summary:     "Re-seal stored secrets with the current deployment secret",
		Description: "rotate-secrets re-seals authenticator secrets, webhook secrets, and pending deliveries sealed with previousSecrets using the current secret; --dry-run only counts them.",
		Target:      "config",
		Flags:       []FlagSpec{{Name: "dry-run", Type: "boolean", Description: "Only count what would be re-sealed"}},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			rotated, err := iam.RotateSecrets(ctx, server.SecretRotationOptions{DryRun: c.Flags.Bool("dry-run")})
			if err != nil {
				return nil, err
			}
			if err := c.Print(rotated); err != nil {
				return nil, err
			}
			unreadable := 0.0
			if rotated.Unreadable != nil {
				for _, key := range rotated.Unreadable.Keys() {
					count, _ := rotated.Unreadable.Get(key).(float64)
					unreadable += count
				}
			}
			if unreadable > 0 {
				return nil, core.NewIamError("UNREADABLE_SECRETS", core.NumberString(unreadable)+" stored value(s) open with no configured secret; add the secret that sealed them to previousSecrets")
			}
			return nil, nil
		}),
	}),
}
