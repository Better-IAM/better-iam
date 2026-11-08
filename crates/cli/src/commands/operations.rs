//! Deployment operations for schedulers (`commands/operations.ts`): no credential, they act on the whole deployment
//! (or one --tenant).

use better_iam_core::IamError;
use better_iam_server::secrets::SecretRotationOptions;
use serde_json::{Value, json};

use super::{array_len, object, tenant_input};
use crate::errors::usage_error;
use crate::framework::{CommandSpec, CommandTarget, FlagSpec, define_command};
use crate::output::OutputFormat;

const DAY: i64 = 86_400_000;

fn tenant_filter() -> FlagSpec {
    FlagSpec::string("Only this organization (default: every active one)").value("TENANT_ID")
}

pub fn operation_commands() -> Vec<CommandSpec> {
    vec![
        define_command("outbox", "Deliver pending emails, SMS, and webhooks from the outbox", |context| async move {
            let instance = context.iam()?;
            let result = instance.auth.dispatch_outbox(None).await?;
            context.print(&json!({
                "delivered": result.delivered,
                "failed": result.failed,
                "abandoned": result.abandoned,
            }))?;
            instance.dispatch_audit_hooks().await?;
            Ok(None)
        })
        // One line, as scripts that read this output by line have always received it.
        .default_format(OutputFormat::Compact)
        .group("Operations")
        .description(
            "outbox delivers pending transactional messages from the encrypted delivery outbox and then dispatches audit hooks (webhooks); a deployment operation for a scheduler.",
        )
        .target(CommandTarget::Config),
        define_command("purge", "Remove deleted tenants past retention and expired grants", |context| async move {
            let days = context.flags.integer("retention-days").unwrap_or(30);
            Ok(Some(context.iam()?.purge_deleted(Some(&json!({ "retentionMs": days * DAY }))).await?))
        })
        // One line, as scripts that read this output by line have always received it.
        .default_format(OutputFormat::Compact)
        .group("Operations")
        .description(
            "Purge removes tenants deleted more than N days ago (default 30) including their data, and records the action in the audit log. Audit records remain.",
        )
        .target(CommandTarget::Config)
        .flag(
            "retention-days",
            FlagSpec::integer("Keep deleted tenants this many days")
                .min(0)
                .max(3650)
                .default_number(30)
                // Deletes tenant data: only `cli.defaults.purge` may change it, never a shared '*' default.
                .no_wildcard_default(),
        ),
        define_command("sweep", "Delete expired sessions, protocol artifacts, and old deliveries", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("limit", flags.integer("limit").map(Value::from)),
                (
                    "deliveryRetentionMs",
                    flags.integer("retention-days").map(|days| Value::from(days * DAY)),
                ),
            ]);
            Ok(Some(context.iam()?.sweep_expired(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "sweep deletes expired sessions, devices, relationship tuples, OAuth and SAML artifacts, and deliveries older than --retention-days (30) in short batches, at most --limit (10000) records per run; schedule it beside purge.",
        )
        .target(CommandTarget::Config)
        .flag(
            "limit",
            FlagSpec::integer("Most records deleted per run").min(1).max(1_000_000).default_number(10000),
        )
        .flag(
            "retention-days",
            FlagSpec::integer("Keep delivered and failed deliveries this many days")
                .min(0)
                .max(3650)
                .default_number(30),
        ),
        define_command("digest", "Email each organization owner its access report", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("withinMs", Some(Value::from(flags.integer("within-days").unwrap_or(30) * DAY))),
                ("unusedForMs", Some(Value::from(flags.integer("unused-days").unwrap_or(30) * DAY))),
            ]);
            Ok(Some(context.iam()?.send_access_digest(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "digest emails the access report to the owners of every active organization (or one --tenant) that has something to report, at most once a day per organization; a deployment operation for cron, like purge.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant_filter())
        .flag(
            "within-days",
            FlagSpec::integer("Report access ending within this many days").min(0).max(3650).default_number(30),
        )
        .flag(
            "unused-days",
            FlagSpec::integer("Report keys unused for this many days").min(0).max(3650).default_number(30),
        ),
        define_command("remind", "Email people whose access ends soon", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("withinMs", Some(Value::from(flags.integer("within-days").unwrap_or(7) * DAY))),
            ]);
            Ok(Some(context.iam()?.send_expiry_reminders(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "remind emails each person whose account, role bindings, group memberships, or packages end within --within-days (7), once per item and end date; a deployment operation like digest.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant_filter())
        // Reminders look at most a year ahead (the server's own bound).
        .flag(
            "within-days",
            FlagSpec::integer("Remind about access ending within this many days").min(1).max(365).default_number(7),
        ),
        define_command("reconcile", "Apply access-package rules (birthright access)", |context| async move {
            let flags = &context.flags;
            // Applies package rules under their owners' authority; no credential.
            let input = object(vec![
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("packageId", flags.string("package").map(Value::from)),
                ("limit", flags.integer("limit").map(Value::from)),
                ("confirm", flags.boolean("confirm").then_some(Value::Bool(true))),
            ]);
            let result = context.iam()?.reconcile_packages(Some(&input)).await?;
            context.print(&result)?;
            let attention = array_len(result.get("failed"))
                + array_len(result.get("suspended"))
                + array_len(result.get("braked"))
                + array_len(result.get("skipped").and_then(|skipped| skipped.get("failedTenants")));
            if flags.boolean("fail-on-attention") && attention > 0 {
                return Err(IamError::new(
                    "RECONCILE_ATTENTION",
                    format!("{attention} package rule problem(s) need attention"),
                )
                .into());
            }
            Ok(None)
        })
        .group("Operations")
        .description(
            "reconcile applies access-package rules (birthright access): identities that match a package's autoAssign rule receive it and automatic holders that stopped matching lose it, at most --limit (1000) changes per organization and run, under each rule owner's grant authority; a deployment operation for cron (run it after purge). Unusually large changes are held back until confirmed with --tenant ID --package ID --confirm; --fail-on-attention exits non-zero when a change failed, was held back, or a rule is suspended.",
        )
        .usage(
            "better-iam reconcile --config better-iam.json [--tenant TENANT_ID [--package PACKAGE_ID [--confirm]]] [--limit N] [--fail-on-attention]",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant_filter())
        .flag("package", FlagSpec::string("Only this package (needs --tenant)").value("PACKAGE_ID"))
        .flag("confirm", FlagSpec::boolean("Apply a held-back large change (needs --package)"))
        .flag(
            "limit",
            FlagSpec::integer("Most changes per organization and run").min(1).max(10000).default_number(1000),
        )
        .flag(
            "fail-on-attention",
            FlagSpec::boolean("Exit non-zero when a change failed, was held back, or a rule is suspended"),
        )
        .validate(|flags, _, _| {
            if flags.string("package").is_some() && flags.string("tenant").is_none() {
                return Err(usage_error("--package needs --tenant", None));
            }
            if flags.boolean("confirm") && flags.string("package").is_none() {
                return Err(usage_error("--confirm needs --package", None));
            }
            Ok(())
        }),
        define_command(
            "close-certifications",
            "Close and apply overdue auto-closing certification campaigns",
            |context| async move {
                let input = tenant_input(&context.flags);
                Ok(Some(context.iam()?.close_overdue_certifications(Some(&input)).await?))
            },
        )
        .group("Operations")
        .description(
            "close-certifications closes every access-certification campaign created with autoClose whose due date has passed (or only one --tenant's), applying its decisions under the creator's authority; a deployment operation for cron.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant_filter()),
        define_command(
            "monitor-invariants",
            "Evaluate every organization's invariants and audit status changes",
            |context| async move {
                let input = tenant_input(&context.flags);
                Ok(Some(context.iam()?.check_invariants(Some(&input)).await?))
            },
        )
        .group("Operations")
        .description(
            "monitor-invariants evaluates every organization's invariants (or one --tenant's) and records invariant:broken / invariant:restored audit events when their status changes, so webhooks can alert; a deployment operation for cron.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant_filter()),
        define_command(
            "detect-threats",
            "Read each organization's new audit events and raise threat detections",
            |context| async move {
                let flags = &context.flags;
                let input = object(vec![
                    ("tenantId", flags.string("tenant").map(Value::from)),
                    ("maxEvents", flags.integer("max-events").map(Value::from)),
                ]);
                Ok(Some(context.iam()?.detect_threats(Some(&input)).await?))
            },
        )
        .group("Operations")
        .description(
            "detect-threats runs identity threat detection for every active organization (or one --tenant): it reads up to --max-events (2000) unread audit events from the organization's cursor, verifies their hash chain (a break is reported as audit-tampering), evaluates the detection rules, records detections and incidents, updates identity risk, and runs the organization's response playbooks. It prints what the run did; pending counts organizations with more unread events than one run reads, which the next run continues. A deployment operation for cron, every minute.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant_filter())
        // The server's own bounds (threat-engine.ts).
        .flag(
            "max-events",
            FlagSpec::integer("Most unread audit events read per organization and run")
                .min(1)
                .max(20_000)
                .default_number(2000),
        ),
        define_command("rotate-secrets", "Re-seal stored secrets with the current deployment secret", |context| async move {
            let result = context
                .iam()?
                .rotate_secrets(&SecretRotationOptions {
                    dry_run: context.flags.boolean("dry-run"),
                    batch_size: None,
                    limit: None,
                })
                .await?;
            let value = serde_json::to_value(&result).map_err(|_| better_iam_server::js::internal_error())?;
            context.print(&value)?;
            let unreadable: f64 = result.unreadable.values().sum();
            if unreadable > 0.0 {
                return Err(IamError::new(
                    "UNREADABLE_SECRETS",
                    format!(
                        "{} stored value(s) open with no configured secret; add the secret that sealed them to previousSecrets",
                        better_iam_core::js::number_to_string(unreadable)
                    ),
                )
                .into());
            }
            Ok(None)
        })
        .group("Operations")
        .description(
            "rotate-secrets re-seals authenticator secrets, webhook secrets, and pending deliveries sealed with previousSecrets using the current secret; --dry-run only counts them.",
        )
        .target(CommandTarget::Config)
        .flag("dry-run", FlagSpec::boolean("Only count what would be re-sealed")),
    ]
}
