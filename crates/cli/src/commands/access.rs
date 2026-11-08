//! Token commands (`commands/access.ts`): they act as BETTER_IAM_TOKEN or a saved session, in process or against
//! --url.

use std::sync::{Arc, LazyLock};

use better_iam_core::{IamError, js};
use regex::Regex;
use serde_json::{Map, Value, json};

use super::{members, object, tenant_flag};
use crate::commands::audit::write_new_file;
use crate::errors::{CliError, CliResult, usage_error};
use crate::framework::{
    ApiOptions, ArgSpec, CommandContext, CommandSpec, CommandTarget, FlagSpec, define_command,
};
use crate::output::{OutputFormat, format_result, stringify};
use crate::paths::display;
use crate::tenant_config::{
    TenantConfigContext, lint_tenant_config, load_tenant_config, tenant_config_module,
};
use crate::transport::ApiTransport;

const DAY: i64 = 86_400_000;
const SEVERITIES: [&str; 3] = ["high", "medium", "low"];

fn input_flag() -> FlagSpec {
    FlagSpec::string(
        "Desired configuration: a .json file (JavaScript/TypeScript modules need the Node.js CLI)",
    )
    .value("PATH")
    .required()
}

static RESOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^/:]+)[/:](.+)$").expect("regex"));

/// `project/p1`, `project:p1`, or `iam/roles/r1` (the first separator splits type and id) (`parseResource`).
pub fn parse_resource(value: &str) -> CliResult<Value> {
    let Some(captures) = RESOURCE.captures(value) else {
        return Err(usage_error(
            format!("{value} is not a resource like project/p1 or project:p1"),
            None,
        ));
    };
    Ok(json!({ "type": &captures[1], "id": &captures[2] }))
}

/// An identity ID, or an email looked up in the tenant.
async fn identity_id(api: &ApiTransport, tenant_id: &str, value: &str) -> CliResult<String> {
    if !value.contains('@') {
        return Ok(value.to_owned());
    }
    let found = api
        .call(
            "identities/list",
            members(json!({ "tenantId": tenant_id, "query": value, "limit": 20 })),
        )
        .await?;
    let wanted = value.to_lowercase();
    let matches: Vec<&Value> = found
        .as_array()
        .into_iter()
        .flatten()
        .filter(|identity| {
            identity
                .get("email")
                .and_then(Value::as_str)
                .is_some_and(|email| email.to_lowercase() == wanted)
        })
        .collect();
    if matches.len() != 1 {
        return Err(CliError::new(
            "NOT_FOUND",
            format!("No single identity in {tenant_id} has the email {value}"),
            None,
        ));
    }
    Ok(better_iam_server::js::js_string(matches[0].get("id")))
}

fn desired_config(
    context: &CommandContext,
    input: &str,
    tenant_id: Option<&str>,
) -> CliResult<Value> {
    load_tenant_config(
        &context.path(input),
        &TenantConfigContext {
            tenant_id: tenant_id.map(str::to_owned),
            env: context.env.clone(),
        },
    )
}

fn number(value: Option<&Value>) -> f64 {
    value.and_then(js::as_number).unwrap_or(0.0)
}

static MODULE_OUTPUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(m?[jt]s)$").expect("regex"));

fn plan_or_apply(name: &'static str) -> CommandSpec {
    let plan = name == "config-plan";
    let mut spec = define_command(
        name,
        if plan {
            "Show what applying a configuration would change"
        } else {
            "Apply a configuration to a tenant in one transaction"
        },
        move |context: Arc<CommandContext>| async move {
            let flags = &context.flags;
            let tenant_id = flags.string("tenant").unwrap_or_default().to_owned();
            let config = desired_config(&context, flags.string("input").unwrap_or_default(), Some(&tenant_id))?;
            let result = context
                .api(ApiOptions::default())?
                .call(
                    if plan { "config/plan" } else { "config/apply" },
                    members(json!({ "tenantId": tenant_id, "config": config, "prune": flags.boolean("prune") })),
                )
                .await?;
            context.print(&result)?;
            let summary = result.get("summary");
            let drift = number(summary.and_then(|summary| summary.get("create")))
                + number(summary.and_then(|summary| summary.get("update")))
                + number(summary.and_then(|summary| summary.get("delete")));
            if flags.boolean("fail-on-drift") && drift > 0.0 {
                return Err(IamError::new(
                    "CONFIG_DRIFT",
                    format!(
                        "The tenant differs from the configuration in {} item(s)",
                        js::number_to_string(drift)
                    ),
                )
                .into());
            }
            Ok(None)
        },
    )
    .group("Access")
    .description(if plan {
        "config-plan shows what config-apply would change (--prune also plans deleting items the file omits); --fail-on-drift exits non-zero when anything would change, for CI. The input is a JSON tenant configuration."
    } else {
        "config-apply applies a configuration in one transaction (--prune also deletes items the file omits), authorized and audited like console operations."
    })
    .target(CommandTarget::Token)
    .flag("tenant", tenant_flag())
    .flag("input", input_flag())
    .flag("prune", FlagSpec::boolean("Also delete items the file omits"));
    if plan {
        spec = spec
            .flag(
                "fail-on-drift",
                FlagSpec::boolean("Exit non-zero when anything would change (CI)"),
            )
            .examples(&[
                "better-iam config-plan --tenant ten_123 --input iam/tenant.json --fail-on-drift",
            ]);
    } else {
        spec = spec.examples(&[
            "better-iam config-apply --tenant ten_123 --input iam/tenant.json --prune",
        ]);
    }
    spec
}

pub fn access_commands() -> Vec<CommandSpec> {
    vec![
        define_command("config-export", "Print or save a tenant's configuration as code", |context| async move {
            let flags = &context.flags;
            let tenant_id = flags.string("tenant").unwrap_or_default().to_owned();
            let exported = context
                .api(ApiOptions::default())?
                .call("config/export", members(json!({ "tenantId": tenant_id })))
                .await?;
            let Some(output) = flags.string("output") else {
                return Ok(Some(exported));
            };
            let output = context.path(output);
            let shown = display(&output);
            let body = if MODULE_OUTPUT.is_match(&shown) {
                tenant_config_module(&exported, &shown)
            } else {
                format!("{}\n", stringify(&exported, Some(2)))
            };
            // Owner-only, like store-export: the document names every group member and binding.
            write_new_file(&output, body.as_bytes(), 0o600)?;
            // The confirmation stays one line, as before; --format json indents it.
            (context.io.out)(&format_result(
                &json!({ "tenantId": tenant_id, "output": shown }),
                Some(flags.format().unwrap_or(OutputFormat::Compact)),
                flags.query(),
            )?);
            Ok(None)
        })
        .group("Access")
        .description(
            "config-export writes a tenant's roles, policies, groups, resource types, group bindings, packages, invariants, and agreements as JSON (or as a typed module when --output ends in .ts or .mjs). The config commands act as the session or API key in BETTER_IAM_TOKEN (or the session saved by login) and are authorized and audited like console operations.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag(
            "output",
            FlagSpec::string("Write to this file instead (.json, or .ts/.mjs for a module); never overwrites")
                .value("PATH"),
        )
        .examples(&["better-iam config-export --tenant ten_123 --output iam/tenant.json"]),
        plan_or_apply("config-plan"),
        plan_or_apply("config-apply"),
        define_command(
            "config-validate",
            "Check a configuration file offline, without a database or token",
            |context| async move {
                let flags = &context.flags;
                let config = desired_config(&context, flags.string("input").unwrap_or_default(), flags.string("tenant"))?;
                let lint = lint_tenant_config(&config)?;
                context.print(&lint)?;
                let warnings = lint.get("warnings").and_then(Value::as_array).map_or(0, Vec::len);
                if flags.boolean("strict") && warnings > 0 {
                    return Err(IamError::new("CONFIG_WARNINGS", format!("{warnings} unresolved reference(s)")).into());
                }
                Ok(None)
            },
        )
        .group("Access")
        .description(
            "config-validate checks a configuration file offline: its shape, and names it refers to that the file does not define (those must already exist in the tenant, or planning fails). --strict exits non-zero on such warnings. It needs no configuration, database, or token, so it fits pre-commit hooks and CI.",
        )
        .flag("input", input_flag())
        .flag(
            "tenant",
            FlagSpec::string("Passed to a configuration factory as tenantId").value("TENANT_ID"),
        )
        .flag(
            "strict",
            FlagSpec::boolean("Exit non-zero when a reference is not defined in the file"),
        ),
        define_command("analyze", "Print a tenant's access-analysis findings", |context| async move {
            let flags = &context.flags;
            let report = context
                .api(ApiOptions::default())?
                .call(
                    "analysis/findings",
                    members(object(vec![
                        ("tenantId", flags.string("tenant").map(Value::from)),
                        ("dormantDays", flags.integer("dormant-days").map(Value::from)),
                    ])),
                )
                .await?;
            context.print(&report)?;
            if let Some(fail_on) = flags.string("fail-on") {
                let threshold = SEVERITIES.iter().position(|item| *item == fail_on).unwrap_or(0);
                let failing = report
                    .get("findings")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|finding| {
                        let severity = finding.get("severity").and_then(Value::as_str).unwrap_or("");
                        // `severities.indexOf(severity) <= threshold`: an unknown severity is -1.
                        SEVERITIES.iter().position(|item| *item == severity).is_none_or(|index| index <= threshold)
                    })
                    .count();
                if failing > 0 {
                    return Err(IamError::new(
                        "FINDINGS",
                        format!("{failing} finding(s) at or above {fail_on} severity"),
                    )
                    .into());
                }
            }
            Ok(None)
        })
        .group("Access")
        .description(
            "analyze prints the tenant's access-analysis findings (as BETTER_IAM_TOKEN, which needs iam:analysis:read); with --fail-on it exits non-zero when an unsuppressed finding of that severity or higher exists, for CI and cron.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag(
            "dormant-days",
            FlagSpec::integer("Days without sign-in after which an identity counts as dormant")
                .min(1)
                .max(36500),
        )
        .flag(
            "fail-on",
            FlagSpec::string("Exit non-zero on a finding of this severity or higher").choices(&SEVERITIES),
        )
        .examples(&["better-iam analyze --tenant ten_123 --fail-on high --format table"]),
        define_command("report", "Print a tenant's access report", |context| async move {
            let flags = &context.flags;
            Ok(Some(
                context
                    .api(ApiOptions::default())?
                    .call(
                        "reports/access",
                        members(json!({
                            "tenantId": flags.string("tenant").unwrap_or_default(),
                            "withinMs": flags.integer("within-days").unwrap_or(30) * DAY,
                            "unusedForMs": flags.integer("unused-days").unwrap_or(30) * DAY,
                        })),
                    )
                    .await?,
            ))
        })
        .group("Access")
        .description(
            "report prints the tenant's access report as BETTER_IAM_TOKEN: identities and bindings ending within --within-days (30), keys unused for --unused-days (30) or ending soon, live activations, and pending activation requests.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag(
            "within-days",
            FlagSpec::integer("Access ending within this many days").min(0).max(3650).default_number(30),
        )
        .flag(
            "unused-days",
            FlagSpec::integer("Keys unused for this many days").min(0).max(3650).default_number(30),
        ),
        define_command("mine-roles", "Suggest roles from how access is actually held", |context| async move {
            let flags = &context.flags;
            let transport = context.api(ApiOptions::default())?;
            let tenant_id = flags.string("tenant").unwrap_or_default();
            let mining = transport
                .call("roleMining/suggest", members(json!({ "tenantId": tenant_id })))
                .await?;
            let peers = transport
                .call(
                    "roleMining/outliers",
                    members(object(vec![
                        ("tenantId", Some(Value::from(tenant_id))),
                        ("peerBy", flags.string("peer-by").map(Value::from)),
                    ])),
                )
                .await?;
            let mut result = match mining {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            result.insert("peers".into(), peers);
            Ok(Some(Value::Object(result)))
        })
        .group("Access")
        .description(
            "mine-roles prints role-mining suggestions (role bundles, roles to bind to a group, redundant direct bindings, duplicate roles) and peer outliers grouped by --peer-by (default manager) as BETTER_IAM_TOKEN, which needs iam:analysis:read.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag(
            "peer-by",
            FlagSpec::string("How peers are grouped for outliers").value("manager|attribute:NAME"),
        ),
        define_command("check-invariants", "Evaluate a tenant's access invariants", |context| async move {
            let flags = &context.flags;
            let run = context
                .api(ApiOptions::default())?
                .call(
                    "invariants/run",
                    members(json!({ "tenantId": flags.string("tenant").unwrap_or_default() })),
                )
                .await?;
            context.print(&run)?;
            let summary = run.get("summary");
            let failed = number(summary.and_then(|summary| summary.get("failed")));
            let errors = number(summary.and_then(|summary| summary.get("errors")));
            if flags.boolean("fail-on-broken") && failed + errors > 0.0 {
                return Err(IamError::new(
                    "INVARIANTS_BROKEN",
                    format!(
                        "{} broken and {} unevaluable invariant(s)",
                        js::number_to_string(failed),
                        js::number_to_string(errors)
                    ),
                )
                .into());
            }
            Ok(None)
        })
        .group("Access")
        .description(
            "check-invariants evaluates the tenant's access invariants as BETTER_IAM_TOKEN (iam:invariants:read); --fail-on-broken exits non-zero when one is broken or cannot be evaluated, for CI after config-apply.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag(
            "fail-on-broken",
            FlagSpec::boolean("Exit non-zero when an invariant is broken or unevaluable"),
        ),
        define_command("whoami", "Print who the current token acts as", |context| async move {
            // sts.getCallerIdentity: no permission, no audit event; an unusable credential fails with UNAUTHENTICATED.
            Ok(Some(context.api(ApiOptions::default())?.call("sts/getCallerIdentity", None).await?))
        })
        .group("Access")
        .description(
            "whoami prints who BETTER_IAM_TOKEN acts as (sts.getCallerIdentity): identity, tenant, session kind and id, format, MFA, expiry, and any role, trust, session name, or web identity; it needs no permission and records nothing, so it also checks that a session, API key, role session, or session token (opaque or JWT) is still valid. Without BETTER_IAM_TOKEN it reports the session saved by login.",
        )
        .target(CommandTarget::Token),
        define_command("can", "Check whether the current token may perform an action", |context| async move {
            let flags = &context.flags;
            let decision = context
                .api(ApiOptions::default())?
                .call(
                    "authorize",
                    members(json!({
                        "tenantId": flags.string("tenant").unwrap_or_default(),
                        "action": context.args[0],
                        "resource": parse_resource(&context.args[1])?,
                    })),
                )
                .await?;
            context.print(&decision)?;
            if decision.get("allowed") != Some(&Value::Bool(true)) {
                let reason = decision
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|reason| !reason.is_empty())
                    .map(|reason| format!(": {reason}"))
                    .unwrap_or_default();
                return Err(IamError::with_status("ACCESS_DENIED", format!("Not allowed{reason}"), 403).into());
            }
            Ok(None)
        })
        .group("Access")
        .description(
            "can asks whether the token may perform ACTION on RESOURCE (type/id) in the tenant and prints the decision with its reason; it exits non-zero (ACCESS_DENIED) when the answer is no, so scripts can branch on it. The decision is recorded like any authorization check.",
        )
        .target(CommandTarget::Token)
        .arg(ArgSpec::new("action", "The action, for example projects:read").required())
        .arg(ArgSpec::new("resource", "type/id or type:id, for example project/p1").required())
        .flag("tenant", tenant_flag())
        .examples(&["better-iam can projects:read project/p1 --tenant ten_123"]),
        define_command("explain", "Explain why an identity is or is not allowed an action", |context| async move {
            let flags = &context.flags;
            let transport = context.api(ApiOptions::default())?;
            let tenant_id = flags.string("tenant").unwrap_or_default();
            let identity = identity_id(&transport, tenant_id, flags.string("identity").unwrap_or_default()).await?;
            Ok(Some(
                transport
                    .call(
                        "policies/simulate",
                        members(json!({
                            "tenantId": tenant_id,
                            "identityId": identity,
                            "action": context.args[0],
                            "resource": parse_resource(&context.args[1])?,
                            "assumeMfa": flags.boolean("assume-mfa"),
                        })),
                    )
                    .await?,
            ))
        })
        .group("Access")
        .description(
            "explain simulates the decision for another identity (by ID or email) without signing in as them: the matching statements, boundaries, and reason (policies.simulate, which needs iam:policies:simulate). --assume-mfa evaluates as if they had used MFA.",
        )
        .target(CommandTarget::Token)
        .arg(ArgSpec::new("action", "The action, for example projects:write").required())
        .arg(ArgSpec::new("resource", "type/id or type:id").required())
        .flag("tenant", tenant_flag())
        .flag(
            "identity",
            FlagSpec::string("Whose decision to explain").value("ID|EMAIL").required(),
        )
        .flag("assume-mfa", FlagSpec::boolean("Evaluate as an MFA session"))
        .examples(&["better-iam explain projects:write project/p1 --identity alice@acme.test"]),
        define_command("who-can", "List every identity that may perform an action on a resource", |context| async move {
            let flags = &context.flags;
            Ok(Some(
                context
                    .api(ApiOptions::default())?
                    .call(
                        "policies/whoCan",
                        members(object(vec![
                            ("tenantId", Some(Value::from(flags.string("tenant").unwrap_or_default()))),
                            ("action", Some(Value::from(context.args[0].clone()))),
                            ("resource", Some(parse_resource(&context.args[1])?)),
                            ("kind", flags.string("kind").map(Value::from)),
                            ("assumeMfa", Some(Value::Bool(flags.boolean("assume-mfa")))),
                            ("limit", flags.integer("limit").map(Value::from)),
                        ])),
                    )
                    .await?,
            ))
        })
        .group("Access")
        .description(
            "who-can lists every active identity of the tenant that could perform ACTION on RESOURCE, with the reason (policies.whoCan, which needs iam:policies:simulate); root administrators are not listed because their override applies everywhere.",
        )
        .target(CommandTarget::Token)
        .arg(ArgSpec::new("action", "The action").required())
        .arg(ArgSpec::new("resource", "type/id or type:id").required())
        .flag("tenant", tenant_flag())
        .flag(
            "kind",
            FlagSpec::string("Only people or only service accounts").choices(&["user", "service"]),
        )
        .flag("assume-mfa", FlagSpec::boolean("Evaluate as MFA sessions"))
        .flag(
            "limit",
            FlagSpec::integer("Most identities listed").min(1).max(1000).default_number(100),
        )
        .examples(&["better-iam who-can projects:delete project/p1 --format table"]),
    ]
}
