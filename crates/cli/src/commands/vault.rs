//! The secrets vault from the command line (`commands/vault.ts`): values as BETTER_IAM_TOKEN, and the scheduler
//! jobs.

use std::collections::HashMap;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Value, json};

use super::{members, object, only_tenant, tenant_flag, tenant_input};
use crate::errors::{CliError, CliResult, usage_error};
use crate::framework::{
    ApiOptions, ArgSpec, CommandOutput, CommandSpec, CommandTarget, FlagSpec, define_command,
};
use crate::output::stringify;
use crate::transport::ApiTransport;

static ENV_VARIABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("regex"));
static NON_ALNUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^A-Za-z0-9]+").expect("regex"));

/// The environment variable a secret under `prefix` becomes in `vault-run --prefix`: the rest of its name upper-cased,
/// with every run of other characters turned into `_` (`prod/app/db-password` under `prod/app/` is `DB_PASSWORD`)
/// (`secretEnvName`).
pub fn secret_env_name(name: &str, prefix: &str) -> String {
    let rest = name.strip_prefix(prefix).unwrap_or(name);
    let variable = NON_ALNUM.replace_all(rest, "_");
    let variable = variable.trim_matches('_').to_uppercase();
    if variable.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{variable}")
    } else {
        variable
    }
}

/// One `VAR=name` or `VAR=name#field` mapping of `vault-run --env`.
fn mapping(entry: &str) -> CliResult<(String, String, Option<String>)> {
    let equals = entry.find('=');
    let Some(equals) = equals.filter(|index| *index >= 1) else {
        return Err(usage_error(
            format!("--env entries look like VAR=secret/name, not {entry}"),
            None,
        ));
    };
    let variable = entry[..equals].trim().to_owned();
    let reference = entry[equals + 1..].trim();
    if !ENV_VARIABLE.is_match(&variable) {
        return Err(usage_error(
            format!("{variable} is not an environment variable name"),
            None,
        ));
    }
    let (name, field) = match reference.find('#') {
        None => (reference.to_owned(), None),
        Some(hash) => (
            reference[..hash].to_owned(),
            Some(reference[hash + 1..].to_owned()),
        ),
    };
    if name.is_empty() {
        return Err(usage_error(
            format!("--env {variable} names no secret"),
            None,
        ));
    }
    Ok((variable, name, field))
}

/// A field value as an environment string: strings as they are, anything else as JSON.
fn field_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => stringify(other, None),
    }
}

/// A revealed value as an environment string: the value, or one field of a json secret (non-strings as JSON).
fn env_value(secret: &Value, field: Option<&str>) -> CliResult<String> {
    let Some(field) = field else {
        return Ok(better_iam_server::js::js_string(secret.get("value")));
    };
    match secret.get("fields").and_then(|fields| fields.get(field)) {
        Some(value) => Ok(field_text(value)),
        None => Err(CliError::new(
            "NOT_FOUND",
            format!(
                "The secret {} has no field {field}",
                better_iam_server::js::js_string(secret.get("name"))
            ),
            None,
        )),
    }
}

/// Runs the command with the environment and resolves with its exit status.
async fn run_child(
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    cwd: std::path::PathBuf,
) -> CliResult<i32> {
    let shown = command.clone();
    tokio::task::spawn_blocking(move || {
        let status = std::process::Command::new(&command)
            .args(&args)
            .env_clear()
            .envs(&env)
            .current_dir(&cwd)
            .status();
        match status {
            Ok(status) => {
                Ok(status
                    .code()
                    .unwrap_or(if exit_by_signal(&status) { 128 } else { 1 }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(CliError::hinted(
                "COMMAND_NOT_FOUND",
                format!("{shown} was not found"),
                "Check the command after --.",
            )),
            Err(error) => Err(CliError::unknown(
                format!("spawn {shown}: {error}"),
                error.to_string(),
            )),
        }
    })
    .await
    .map_err(|error| CliError::unknown("The command could not be run", error.to_string()))?
}

#[cfg(unix)]
fn exit_by_signal(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    status.signal().is_some()
}

#[cfg(not(unix))]
fn exit_by_signal(_status: &std::process::ExitStatus) -> bool {
    false
}

async fn reveal(
    transport: &ApiTransport,
    cache: &mut IndexMap<String, CliResult<Value>>,
    tenant_id: &str,
    name: &str,
) -> CliResult<Value> {
    if let Some(cached) = cache.get(name) {
        return cached.clone();
    }
    let result = transport
        .call(
            "vault/reveal",
            members(json!({ "tenantId": tenant_id, "name": name })),
        )
        .await;
    cache.insert(name.to_owned(), result.clone());
    result
}

pub fn vault_commands() -> Vec<CommandSpec> {
    vec![
        define_command("vault-get", "Print a secret from the vault", |context| async move {
            let flags = &context.flags;
            let secret = context
                .api(ApiOptions::default())?
                .call(
                    "vault/reveal",
                    members(object(vec![
                        ("tenantId", Some(Value::from(flags.string("tenant").unwrap_or_default()))),
                        ("name", Some(Value::from(context.args[0].clone()))),
                        ("version", flags.integer("version").map(Value::from)),
                        ("stage", flags.string("stage").map(Value::from)),
                    ])),
                )
                .await?;
            Ok(Some(Value::String(env_value(&secret, flags.string("field"))?)))
        })
        .group("Access")
        .description(
            "vault-get prints the value of a secret as BETTER_IAM_TOKEN (iam:vault:reveal): the current version, or --version / --stage, and with --field one field of a json secret. The value is printed on its own, so it can be captured with $(...); every reveal is audited as vault:reveal. Secrets handed out only through check-outs refuse with CHECKOUT_REQUIRED.",
        )
        .target(CommandTarget::Token)
        .output(CommandOutput::Text)
        .arg(ArgSpec::new("name", "The secret, such as prod/payments/db-password").required())
        .flag("tenant", tenant_flag())
        .flag("version", FlagSpec::integer("A version").min(1).max(9_007_199_254_740_991))
        .flag("stage", FlagSpec::string("A stage label such as previous").value("LABEL"))
        .flag("field", FlagSpec::string("One field of a json secret").value("FIELD"))
        .examples(&[
            "better-iam vault-get prod/payments/db-password --tenant acme-id",
            "better-iam vault-get prod/smtp --field password",
        ])
        .validate(|flags, _, _| {
            if flags.integer("version").is_some() && flags.string("stage").is_some() {
                return Err(usage_error("Pass --version or --stage, not both", None));
            }
            Ok(())
        }),
        define_command("vault-put", "Store a new version of a secret", |context| async move {
            let flags = &context.flags;
            let mut value: Option<String> = None;
            if let Some(variable) = flags.string("value-env") {
                match context.env.get(variable).filter(|value| !value.is_empty()) {
                    Some(found) => value = Some(found.clone()),
                    None => return Err(usage_error(format!("{variable} is not set or empty"), None)),
                }
            } else if !flags.boolean("generate") {
                let Some(stdin) = &context.io.stdin else {
                    return Err(usage_error("Pipe the value on standard input, or use --value-env", None));
                };
                let mut text = stdin().await?;
                if text.ends_with('\n') {
                    text.pop();
                    if text.ends_with('\r') {
                        text.pop();
                    }
                }
                if text.is_empty() {
                    return Err(usage_error("Standard input was empty", None));
                }
                value = Some(text);
            }
            let input = object(vec![
                ("tenantId", Some(Value::from(flags.string("tenant").unwrap_or_default()))),
                ("name", Some(Value::from(context.args[0].clone()))),
                ("value", value.clone().map(Value::from)),
                ("generate", value.is_none().then_some(Value::Bool(true))),
                ("stage", Some(Value::from(flags.string("stage").unwrap_or("current")))),
            ]);
            Ok(Some(context.api(ApiOptions::default())?.call("vault/put", members(input)).await?))
        })
        .group("Access")
        .description(
            "vault-put stores a new version of a secret as BETTER_IAM_TOKEN (iam:vault:write) from standard input (the default, or --value -), from --value-env (the name of an environment variable holding it), or --generate for a random value; secrets are never taken from the command line itself. The version becomes current unless --stage pending. Trailing newlines on standard input are removed.",
        )
        .target(CommandTarget::Token)
        .arg(ArgSpec::new("name", "The secret").required())
        .flag("tenant", tenant_flag())
        .flag(
            "value-env",
            FlagSpec::string("Read the value from this environment variable").value("VARIABLE"),
        )
        .flag("generate", FlagSpec::boolean("Generate a random 32-character value"))
        .flag(
            "stage",
            FlagSpec::string("Make it current now, or stage it for promotion")
                .choices(&["current", "pending"])
                .default_text("current"),
        )
        .examples(&[
            "printf %s \"$PASSWORD\" | better-iam vault-put prod/payments/db-password",
            "better-iam vault-put prod/signing-key --value-env SIGNING_KEY --stage pending",
            "better-iam vault-put staging/api-token --generate",
        ])
        .validate(|flags, _, _| {
            if flags.boolean("generate") && flags.string("value-env").is_some() {
                return Err(usage_error("Pass --generate or --value-env, not both", None));
            }
            Ok(())
        }),
        define_command("vault-run", "Run a command with secrets in its environment", |context| async move {
            let flags = &context.flags;
            let transport = context.api(ApiOptions::default())?;
            let tenant_id = flags.string("tenant").unwrap_or_default().to_owned();
            let mut injected: IndexMap<String, String> = IndexMap::new();
            let mut cache: IndexMap<String, CliResult<Value>> = IndexMap::new();
            if let Some(prefix) = flags.string("prefix") {
                let listed = transport
                    .call(
                        "vault/list",
                        members(json!({ "tenantId": tenant_id, "prefix": prefix, "limit": 500 })),
                    )
                    .await?;
                let secrets = listed.get("secrets").and_then(Value::as_array).cloned().unwrap_or_default();
                for secret in secrets {
                    if secret.get("kind").and_then(Value::as_str) != Some("static")
                        || secret.get("status").and_then(Value::as_str) != Some("active")
                    {
                        continue;
                    }
                    let name = better_iam_server::js::js_string(secret.get("name"));
                    let revealed = match reveal(&transport, &mut cache, &tenant_id, &name).await {
                        Ok(revealed) => revealed,
                        Err(error) => {
                            context.note(&format!("Skipped {name}: {}", error.message()));
                            continue;
                        }
                    };
                    let base = secret_env_name(&name, prefix);
                    match revealed.get("fields") {
                        Some(Value::Object(fields)) if revealed.get("format").and_then(Value::as_str) == Some("json") => {
                            for (field, value) in better_iam_core::js::entries(fields) {
                                let variable = format!("{base}_{}", secret_env_name(field, ""));
                                if ENV_VARIABLE.is_match(&variable) {
                                    injected.insert(variable, field_text(value));
                                }
                            }
                        }
                        _ => {
                            if ENV_VARIABLE.is_match(&base) {
                                injected.insert(base, better_iam_server::js::js_string(revealed.get("value")));
                            }
                        }
                    }
                }
            }
            for entry in flags.string("env").unwrap_or("").split(',').filter(|item| !item.trim().is_empty()) {
                let (variable, name, field) = mapping(entry)?;
                let revealed = reveal(&transport, &mut cache, &tenant_id, &name).await?;
                injected.insert(variable, env_value(&revealed, field.as_deref())?);
            }
            let mut child_env: HashMap<String, String> = context.env.clone();
            for (key, value) in &injected {
                child_env.insert(key.clone(), value.clone());
            }
            if !flags.boolean("keep-token") {
                child_env.remove("BETTER_IAM_TOKEN");
            }
            let command = context.args[0].clone();
            context.note(&format!("Running {command} with {} secret(s) in its environment", injected.len()));
            let status = run_child(command.clone(), context.args[1..].to_vec(), child_env, context.cwd.clone()).await?;
            if status != 0 {
                let mut failure = CliError::new("COMMAND_FAILED", format!("{command} exited with status {status}"), None);
                failure.exit_status = Some(status);
                return Err(failure);
            }
            Ok(None)
        })
        .group("Access")
        .description(
            "vault-run reveals secrets as BETTER_IAM_TOKEN (iam:vault:reveal on each) and runs the command after -- with them as environment variables, so they never touch disk or shell history. --env maps variables to secrets (VAR=name, or VAR=name#field for one field of a json secret; comma-separated). --prefix adds every static secret under a path you may reveal, named after the rest of its path (prod/app/db-password under prod/app/ becomes DB_PASSWORD; a json secret adds one variable per field, DB_PASSWORD_USERNAME). --env wins over --prefix. The command inherits the terminal and its exit status becomes vault-run's. BETTER_IAM_TOKEN is removed from the command's environment unless --keep-token.",
        )
        .target(CommandTarget::Token)
        .output(CommandOutput::Text)
        .arg(
            ArgSpec::new("command", "The command and its arguments, after --")
                .required()
                .variadic(),
        )
        .flag("tenant", tenant_flag())
        .flag("env", FlagSpec::string("Variables to set from secrets").value("VAR=NAME[#FIELD],..."))
        .flag(
            "prefix",
            FlagSpec::string("Add every secret under this path, named after the rest of its name").value("PATH/"),
        )
        .flag("keep-token", FlagSpec::boolean("Pass BETTER_IAM_TOKEN on to the command"))
        .examples(&[
            "better-iam vault-run --env DATABASE_PASSWORD=prod/payments/db-password -- node server.js",
            "better-iam vault-run --prefix prod/payments/ -- npm start",
        ])
        .validate(|flags, _, _| {
            if flags.string("env").is_none() && flags.string("prefix").is_none() {
                return Err(usage_error("Pass --env, --prefix, or both", None));
            }
            Ok(())
        }),
        define_command("vault-rotate-due", "Rotate vault secrets whose scheduled rotation is due", |context| async move {
            let input = tenant_input(&context.flags);
            Ok(Some(context.iam()?.vault.rotate_due(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "vault-rotate-due rotates every static secret (or those of --tenant) whose rotation.intervalDays has passed and that has a generator or a rotator, acting as deployment-operator; due secrets with neither are recorded once per due date as vault:rotation-due. Failed rotations keep their pending version and retry with growing delays. Run it hourly.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", only_tenant()),
        define_command("vault-expire-leases", "End expired vault check-outs and leases", |context| async move {
            Ok(Some(context.iam()?.vault.expire_leases(None).await?))
        })
        .group("Operations")
        .description(
            "vault-expire-leases ends expired check-outs (rotating secrets that rotate on check-in), revokes expired dynamic leases and those of people who are no longer active at their engine, retries failed revocations, and deletes lease history past vault.accessRetentionDays. Run it every few minutes.",
        )
        .target(CommandTarget::Config),
        define_command("vault-purge-deleted", "Delete vault secrets whose recovery window has ended", |context| async move {
            Ok(Some(context.iam()?.vault.purge_deleted(None).await?))
        })
        .group("Operations")
        .description(
            "vault-purge-deleted removes every secret scheduled for deletion whose recovery window has ended, with its versions, leases and access records (live dynamic leases are revoked at their engine first); each is audited as vault:purge. Run it daily.",
        )
        .target(CommandTarget::Config),
    ]
}
