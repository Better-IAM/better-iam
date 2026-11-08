//! Billing (`commands/billing.ts`): the scheduler jobs (no credential) and the spend report (as BETTER_IAM_TOKEN).

use serde_json::{Value, json};

use super::{members, object, tenant_flag, tenant_input, to_json};
use crate::framework::{ApiOptions, CommandSpec, CommandTarget, FlagSpec, define_command};

fn period_flag() -> FlagSpec {
    FlagSpec::string("The billing month").value("YYYY-MM")
}

const GROUPINGS: [&str; 7] = [
    "meter",
    "identity",
    "agent",
    "team",
    "department",
    "tenant",
    "day",
];

pub fn billing_commands() -> Vec<CommandSpec> {
    vec![
        define_command("billing-close", "Issue billing statements for a month that has ended", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("period", flags.string("period").map(Value::from)),
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("draft", flags.boolean("draft").then_some(Value::Bool(true))),
            ]);
            let result = context.iam()?.billing.close_period(Some(&input)).await?;
            Ok(Some(to_json(&result)?))
        })
        .group("Operations")
        .description(
            "billing-close invoices every billing account with something to bill in --period (default: last month): usage, subscription fees and seats, and pending invoice items. It skips accounts already invoiced, applies coupons and credit, emails the invoices, and deletes raw usage events past their retention; a deployment operation for a daily scheduler. With --draft (or billing.autoFinalize: false) invoices stay drafts, refreshed on each run, until finalized.",
        )
        .target(CommandTarget::Config)
        .flag("period", period_flag())
        .flag(
            "tenant",
            FlagSpec::string("Only the billing account that pays for this tenant").value("TENANT_ID"),
        )
        .flag("draft", FlagSpec::boolean("Keep the invoices as drafts to review and finalize"))
        .examples(&[
            "better-iam billing-close",
            "better-iam billing-close --period 2026-08",
            "better-iam billing-close --draft",
        ]),
        define_command("billing-reminders", "Remind billing contacts of unpaid invoices", |context| async move {
            Ok(Some(context.iam()?.billing.send_payment_reminders().await?))
        })
        .group("Operations")
        .description(
            "billing-reminders emails the billing contacts of every finalized invoice with an amount due as payment-reminder at the steps of billing.paymentReminderDays (default 3 days before the due date, on it, and 7 and 14 days after), once per step; each is audited as billing:payment-reminder. Run it daily.",
        )
        .target(CommandTarget::Config),
        define_command("billing-alerts", "Send spend-budget alerts", |context| async move {
            let input = tenant_input(&context.flags);
            Ok(Some(context.iam()?.billing.check_budgets(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "billing-alerts checks every spend budget (or those one --tenant owns) and alerts, once per threshold and window, on thresholds reached and projections past the budget: audited as billing:budget-alert and emailed as spend-alert when mail is configured. Run it hourly.",
        )
        .target(CommandTarget::Config)
        .flag(
            "tenant",
            FlagSpec::string("Only budgets this tenant owns (default: every budget)").value("TENANT_ID"),
        ),
        define_command("billing-anomalies", "Alert on spend spikes from yesterday", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("day", flags.string("day").map(Value::from)),
                ("factor", flags.integer("factor").map(Value::from)),
                ("minimum", flags.integer("minimum").map(Value::from)),
            ]);
            Ok(Some(context.iam()?.billing.detect_anomalies(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "billing-anomalies checks every billing account (or the one paying for --tenant) for people, teams and meters whose spend on --day (default yesterday) is --factor (3) times their average over the 14 days before and --minimum (10) currency units more; each is audited as billing:anomaly once and emailed as spend-anomaly when mail is configured. Run it daily.",
        )
        .target(CommandTarget::Config)
        .flag(
            "tenant",
            FlagSpec::string("Only the billing account that pays for this tenant").value("TENANT_ID"),
        )
        .flag("day", FlagSpec::string("The day to check").value("YYYY-MM-DD"))
        .flag(
            "factor",
            FlagSpec::integer("Times the usual daily spend that counts as a spike")
                .min(2)
                .max(1000)
                .default_number(3),
        )
        .flag(
            "minimum",
            FlagSpec::integer("Smallest spend and increase worth reporting, in currency units")
                .min(0)
                .max(1_000_000)
                .default_number(10),
        ),
        define_command("billing-seats", "Record one seat per active person for today", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("meter", flags.string("meter").map(Value::from)),
                ("tenantId", flags.string("tenant").map(Value::from)),
                (
                    "kinds",
                    flags
                        .boolean("include-service-accounts")
                        .then(|| json!(["user", "service", "agent"])),
                ),
            ]);
            Ok(Some(context.iam()?.billing.record_seats(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "billing-seats records one unit of --meter (default seats) for every active person of every tenant the meter reaches, once per day; a sum meter then counts seat-days and a unique meter active seats per month. Run it daily.",
        )
        .target(CommandTarget::Config)
        .flag(
            "meter",
            FlagSpec::string("The meter seats are recorded on").value("KEY").default_text("seats"),
        )
        .flag(
            "tenant",
            FlagSpec::string("Only this tenant and the tenants below it").value("TENANT_ID"),
        )
        .flag(
            "include-service-accounts",
            FlagSpec::boolean("Count service accounts and agents as seats too"),
        ),
        define_command("spend", "Print a tenant's spend for a month", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("groupBy", Some(Value::from(flags.string("group-by").unwrap_or("meter")))),
                ("period", flags.string("period").map(Value::from)),
                ("teamId", flags.string("team").map(Value::from)),
                ("departmentId", flags.string("department").map(Value::from)),
                ("identityId", flags.string("identity").map(Value::from)),
                ("meter", flags.string("meter").map(Value::from)),
            ]);
            Ok(Some(
                context
                    .api(ApiOptions::default())?
                    .call("billing/spend", members(input))
                    .await?,
            ))
        })
        .group("Access")
        .description(
            "spend prints the spend of the tenant and the tenants below it as BETTER_IAM_TOKEN (iam:billing:read), grouped by --group-by (default meter) and optionally narrowed to a --team, --department, --identity or --meter; the current month also carries a linear forecast.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag("period", period_flag())
        .flag(
            "group-by",
            FlagSpec::string("How rows are grouped").choices(&GROUPINGS).default_text("meter"),
        )
        .flag("team", FlagSpec::string("Only this team (with its sub-teams)").value("TEAM_ID"))
        .flag(
            "department",
            FlagSpec::string("Only this department (with those below it)").value("DEPARTMENT_ID"),
        )
        .flag("identity", FlagSpec::string("Only this person or account").value("IDENTITY_ID"))
        .flag("meter", FlagSpec::string("Only this meter").value("KEY"))
        .examples(&[
            "better-iam spend --tenant acme-id --group-by team",
            "better-iam spend --period 2026-08",
        ]),
    ]
}
