package cli

// Port of packages/cli/src/commands/billing.ts, compliance.ts and vc.ts: the scheduler jobs (no credential) and the
// spend report (as BETTER_IAM_TOKEN).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

var periodFlag = FlagSpec{Name: "period", Type: "string", Value: "YYYY-MM", Description: "The billing month"}

var groupings = []string{"meter", "identity", "agent", "team", "department", "tenant", "day"}

func optionalString(input *core.Object, flags Flags, flag, key string) {
	if value := flags.String(flag); value != "" {
		input.Set(key, value)
	}
}

var billingCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "billing-close",
		Group:       "Operations",
		Summary:     "Issue billing statements for a month that has ended",
		Description: "billing-close invoices every billing account with something to bill in --period (default: last month): usage, subscription fees and seats, and pending invoice items. It skips accounts already invoiced, applies coupons and credit, emails the invoices, and deletes raw usage events past their retention; a deployment operation for a daily scheduler. With --draft (or billing.autoFinalize: false) invoices stay drafts, refreshed on each run, until finalized.",
		Target:      "config",
		Flags: []FlagSpec{
			periodFlag,
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only the billing account that pays for this tenant"},
			{Name: "draft", Type: "boolean", Description: "Keep the invoices as drafts to review and finalize"},
		},
		Examples: []string{"better-iam billing-close", "better-iam billing-close --period 2026-08", "better-iam billing-close --draft"},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := core.NewObject()
			optionalString(input, c.Flags, "period", "period")
			optionalString(input, c.Flags, "tenant", "tenantId")
			if c.Flags.Bool("draft") {
				input.Set("draft", true)
			}
			return result(iam.Billing.ClosePeriod(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "billing-reminders",
		Group:       "Operations",
		Summary:     "Remind billing contacts of unpaid invoices",
		Description: "billing-reminders emails the billing contacts of every finalized invoice with an amount due as payment-reminder at the steps of billing.paymentReminderDays (default 3 days before the due date, on it, and 7 and 14 days after), once per step; each is audited as billing:payment-reminder. Run it daily.",
		Target:      "config",
		Flags:       []FlagSpec{},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Billing.SendPaymentReminders(ctx))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "billing-alerts",
		Group:       "Operations",
		Summary:     "Send spend-budget alerts",
		Description: "billing-alerts checks every spend budget (or those one --tenant owns) and alerts, once per threshold and window, on thresholds reached and projections past the budget: audited as billing:budget-alert and emailed as spend-alert when mail is configured. Run it hourly.",
		Target:      "config",
		Flags: []FlagSpec{
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only budgets this tenant owns (default: every budget)"},
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Billing.CheckBudgets(ctx, tenantOnly(c.Flags)))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "billing-anomalies",
		Group:       "Operations",
		Summary:     "Alert on spend spikes from yesterday",
		Description: "billing-anomalies checks every billing account (or the one paying for --tenant) for people, teams and meters whose spend on --day (default yesterday) is --factor (3) times their average over the 14 days before and --minimum (10) currency units more; each is audited as billing:anomaly once and emailed as spend-anomaly when mail is configured. Run it daily.",
		Target:      "config",
		Flags: []FlagSpec{
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only the billing account that pays for this tenant"},
			{Name: "day", Type: "string", Value: "YYYY-MM-DD", Description: "The day to check"},
			boundedInteger("factor", "Times the usual daily spend that counts as a spike", 2, 1000, 3.0),
			boundedInteger("minimum", "Smallest spend and increase worth reporting, in currency units", 0, 1_000_000, 10.0),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := tenantOnly(c.Flags)
			optionalString(input, c.Flags, "day", "day")
			if factor, ok := c.Flags.Int("factor"); ok {
				input.Set("factor", float64(factor))
			}
			if minimum, ok := c.Flags.Int("minimum"); ok {
				input.Set("minimum", float64(minimum))
			}
			return result(iam.Billing.DetectAnomalies(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "billing-seats",
		Group:       "Operations",
		Summary:     "Record one seat per active person for today",
		Description: "billing-seats records one unit of --meter (default seats) for every active person of every tenant the meter reaches, once per day; a sum meter then counts seat-days and a unique meter active seats per month. Run it daily.",
		Target:      "config",
		Flags: []FlagSpec{
			{Name: "meter", Type: "string", Value: "KEY", Default: "seats", Description: "The meter seats are recorded on"},
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this tenant and the tenants below it"},
			{Name: "include-service-accounts", Type: "boolean", Description: "Count service accounts and agents as seats too"},
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := core.NewObject()
			optionalString(input, c.Flags, "meter", "meter")
			optionalString(input, c.Flags, "tenant", "tenantId")
			if c.Flags.Bool("include-service-accounts") {
				input.Set("kinds", []any{"user", "service", "agent"})
			}
			return result(iam.Billing.RecordSeats(ctx, input))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "spend",
		Group:       "Access",
		Summary:     "Print a tenant's spend for a month",
		Description: "spend prints the spend of the tenant and the tenants below it as BETTER_IAM_TOKEN (iam:billing:read), grouped by --group-by (default meter) and optionally narrowed to a --team, --department, --identity or --meter; the current month also carries a linear forecast.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			periodFlag,
			{Name: "group-by", Type: "string", Choices: groupings, Default: "meter", Description: "How rows are grouped"},
			{Name: "team", Type: "string", Value: "TEAM_ID", Description: "Only this team (with its sub-teams)"},
			{Name: "department", Type: "string", Value: "DEPARTMENT_ID", Description: "Only this department (with those below it)"},
			{Name: "identity", Type: "string", Value: "IDENTITY_ID", Description: "Only this person or account"},
			{Name: "meter", Type: "string", Value: "KEY", Description: "Only this meter"},
		},
		Examples: []string{"better-iam spend --tenant acme-id --group-by team", "better-iam spend --period 2026-08"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			groupBy := c.Flags.String("group-by")
			if groupBy == "" {
				groupBy = "meter"
			}
			input := core.NewObject("tenantId", c.Flags.String("tenant"), "groupBy", groupBy)
			optionalString(input, c.Flags, "period", "period")
			optionalString(input, c.Flags, "team", "teamId")
			optionalString(input, c.Flags, "department", "departmentId")
			optionalString(input, c.Flags, "identity", "identityId")
			optionalString(input, c.Flags, "meter", "meter")
			return orNull(transport.Call(ctx, "billing/spend", input))
		},
	}),
}

var complianceCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "compliance-evaluate",
		Group:       "Operations",
		Summary:     "Evaluate compliance controls",
		Description: "compliance-evaluate runs the enabled compliance controls of every active tenant (or one --tenant's), records the results and a run, and audits it as compliance:evaluate. Tenants whose evaluation failed are listed under failed; their controls show as stale after three days. A deployment operation; run it daily.",
		Target:      "config",
		Flags:       []FlagSpec{{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this tenant"}},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Compliance.EvaluateAll(ctx, tenantOnly(c.Flags)))
		}),
	}),
}

var vcCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "vc-sweep",
		Group:       "Operations",
		Summary:     "Revoke verifiable credentials of people who left",
		Description: "vc-sweep revokes every valid verifiable credential (or one --tenant's) whose holder is no longer an active member, in the Token Status List verifiers read, and audits each as vc:credential:revoke. A deployment operation; run it hourly.",
		Target:      "config",
		Flags:       []FlagSpec{{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this tenant"}},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.VerifiableCredentials.Sweep(ctx, tenantOnly(c.Flags)))
		}),
	}),
}
