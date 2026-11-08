//! Setup commands (`commands/setup.ts`): init, migrate, bootstrap, recover-root, doctor, secret.

use std::io::Write as _;

use base64::Engine as _;
use better_iam_core::{Filter, FindOptions, IamError, js};
use serde_json::{Map, Value, json};

use crate::config::CONFIG_FILE_NAMES;
use crate::errors::{CliError, CliResult, io_error, usage_error};
use crate::framework::{CommandOutput, CommandSpec, CommandTarget, Env, FlagSpec, define_command};
use crate::output::stringify;

/// The database a starter configuration uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    Sqlite,
    Postgres,
    Libsql,
}

/// The starter configuration `init` writes (`configTemplate`): the store for the chosen database, the secret from
/// the environment, sign-up off, a permission catalog to edit, and CLI flag defaults.
pub fn config_template(database: Database) -> String {
    let store = match database {
        Database::Sqlite => json!({ "kind": "sqlite", "path": "./better-iam.db" }),
        Database::Libsql => {
            json!({ "kind": "libsql", "url": { "env": "BETTER_IAM_DATABASE_URL" } })
        }
        Database::Postgres => json!({ "kind": "postgres", "url": { "env": "DATABASE_URL" } }),
    };
    let config = json!({
        "store": store,
        "baseURL": "http://localhost:3000",
        // At least 32 random characters; generate one with: better-iam secret
        "secret": { "env": "BETTER_IAM_SECRET" },
        "authentication": { "signUpEnabled": false },
        "permissions": {
            "mode": "catalog",
            "actions": ["projects:read", "projects:write"],
            "resourceTypes": {
                "workspace": {
                    "managed": true,
                    "actions": ["workspaces:read", "workspaces:manage"],
                    "attributes": { "archived": "boolean" }
                }
            }
        },
        // Defaults for CLI flags when neither the flag nor its environment variable is set: per command, or '*' for
        // every command that has the flag (better-iam help <command> lists them).
        "cli": { "defaults": { "sweep": { "retention-days": 30 } } }
    });
    format!("{}\n", stringify(&config, Some(2)))
}

fn root_input(env: &Env) -> CliResult<Value> {
    let email = env
        .get("BETTER_IAM_ROOT_EMAIL")
        .filter(|value| !value.is_empty());
    let name = env
        .get("BETTER_IAM_ROOT_NAME")
        .cloned()
        .unwrap_or_else(|| "Root administrator".to_owned());
    let password = env
        .get("BETTER_IAM_ROOT_PASSWORD")
        .filter(|value| !value.is_empty());
    let (Some(email), Some(password)) = (email, password) else {
        return Err(CliError::hinted(
            "MISSING_ENV",
            "Set BETTER_IAM_ROOT_EMAIL and BETTER_IAM_ROOT_PASSWORD",
            "The password is read from the environment only, never from a flag.",
        ));
    };
    Ok(json!({ "email": email, "name": name, "password": password }))
}

pub fn setup_commands() -> Vec<CommandSpec> {
    vec![
        define_command(
            "init",
            "Write a starter configuration file for SQLite, PostgreSQL, or libSQL",
            |context| async move {
                let flags = &context.flags;
                if flags.boolean("typescript") {
                    return Err(usage_error(
                        "--typescript writes a TypeScript module, which only the Node.js CLI loads",
                        Some("The Rust CLI writes better-iam.json; run better-iam init without --typescript."),
                    ));
                }
                let target = context.path(flags.string("config").unwrap_or(CONFIG_FILE_NAMES[0]));
                if target.exists() {
                    return Err(IamError::new(
                        "CONFIG_EXISTS",
                        "Configuration already exists; it was not overwritten",
                    )
                    .into());
                }
                let database = match flags.string("database").unwrap_or("sqlite") {
                    "postgres" => Database::Postgres,
                    "libsql" => Database::Libsql,
                    _ => Database::Sqlite,
                };
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .map_err(|error| io_error(&error, "open", &target))?;
                file.write_all(config_template(database).as_bytes())
                    .map_err(|error| io_error(&error, "write", &target))?;
                (context.io.out)(&format!(
                    "Created {}. Set BETTER_IAM_SECRET to a stable high-entropy secret (at least 32 characters; better-iam secret prints one), then run migrate.",
                    target.display()
                ));
                Ok(None)
            },
        )
        .group("Setup")
        .description(
            "init writes a starter better-iam.json: the store for the chosen database, the secret read from BETTER_IAM_SECRET, CLI flag defaults (the cli member), and a permission catalog to edit (spec/conformance/CONFIG.md describes every member). It never overwrites an existing file.",
        )
        .usage("better-iam init [--config better-iam.json] [--database sqlite|postgres|libsql]")
        .output(CommandOutput::Text)
        .flag("config", FlagSpec::string("Where to write the configuration").value("PATH"))
        .flag(
            "database",
            FlagSpec::string("Database adapter to configure")
                .choices(&["sqlite", "postgres", "libsql"])
                .default_text("sqlite"),
        )
        .flag(
            "typescript",
            FlagSpec::boolean("Write a typed better-iam.config.ts (Node.js CLI only)").hidden(),
        )
        .examples(&["better-iam init", "better-iam init --database postgres"]),
        define_command(
            "migrate",
            "Create or upgrade the database schema and apply plugin migrations",
            |context| async move {
                context.iam()?.initialize().await?;
                Ok(Some(Value::String("Database and plugin migrations applied.".into())))
            },
        )
        .group("Setup")
        .description(
            "migrate creates or upgrades the database schema and applies plugin migrations. Run it on every deploy before the application starts.",
        )
        .target(CommandTarget::Config)
        .output(CommandOutput::Text),
        define_command(
            "bootstrap",
            "Create the root administrator from environment variables",
            |context| async move {
                let input = root_input(&context.env)?;
                Ok(Some(context.iam()?.bootstrap(&input).await?))
            },
        )
        .group("Setup")
        .description(
            "bootstrap creates the root administrator from BETTER_IAM_ROOT_EMAIL, BETTER_IAM_ROOT_NAME, and BETTER_IAM_ROOT_PASSWORD (secrets are never accepted in command-line arguments). The root must enroll MFA before use.",
        )
        .target(CommandTarget::Config),
        define_command(
            "recover-root",
            "Create a new root administrator when every root credential is lost",
            |context| async move {
                let input = root_input(&context.env)?;
                Ok(Some(context.iam()?.recover_root(&input).await?))
            },
        )
        .group("Setup")
        .description(
            "recover-root creates a new root administrator from the same environment variables as bootstrap, for when every root credential is lost; the action is audited as root:recover.",
        )
        .target(CommandTarget::Config),
        define_command(
            "doctor",
            "Check the database, schema, secrets, transports, and scheduled jobs",
            |context| async move {
                let flags = &context.flags;
                let instance = context.iam()?;
                // Schema, durability, secrets, transports, and scheduled jobs (`iam.selfCheck()`); first, so a database
                // without the IAM schema is reported instead of failing the reads below.
                let options = match flags.integer("retention-days") {
                    Some(days) => json!({ "deliveryRetentionMs": days * 86_400_000 }),
                    None => json!({}),
                };
                let check = instance.self_check(Some(&options)).await?;
                let storage = check.get("storage").cloned().unwrap_or(Value::Null);
                let schema = storage.is_null() || !storage.get("schemaVersion").is_none_or(Value::is_null);
                let roots = if schema {
                    instance
                        .store
                        .find("tenants", &Filter::new().eq("parentId", Value::Null), &FindOptions::default())
                        .await?
                } else {
                    Vec::new()
                };
                let chains = if schema {
                    instance.store.find("auditChains", &Filter::new(), &FindOptions::default()).await?
                } else {
                    Vec::new()
                };
                let events: f64 = chains
                    .iter()
                    .map(|chain| chain.get("sequence").and_then(js::as_number).unwrap_or(0.0))
                    .sum();
                let findings = check.get("findings").cloned().unwrap_or_else(|| json!([]));
                let mut report = Map::new();
                report.insert("runtime".into(), json!(format!("rust better-iam-cli {}", env!("CARGO_PKG_VERSION"))));
                report.insert("database".into(), json!("connected"));
                report.insert("rootInitialized".into(), json!(roots.len() == 1));
                report.insert("rootCount".into(), json!(roots.len()));
                report.insert("auditChains".into(), json!(chains.len()));
                report.insert("auditEvents".into(), js::number(events).unwrap_or(Value::Null));
                // Adapter, schema version, applied migrations, record counts, and durability settings.
                report.insert("storage".into(), storage);
                report.insert("ok".into(), check.get("ok").cloned().unwrap_or(Value::Null));
                report.insert("findings".into(), findings.clone());
                context.print(&Value::Object(report))?;
                let serious: Vec<String> = findings
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|finding| finding.get("severity").and_then(Value::as_str) != Some("info"))
                    .map(|finding| better_iam_server::js::js_string(finding.get("check")))
                    .collect();
                if flags.boolean("strict") && !serious.is_empty() {
                    return Err(IamError::new(
                        "DOCTOR_FINDINGS",
                        format!("{} finding(s): {}", serious.len(), serious.join(", ")),
                    )
                    .into());
                }
                Ok(None)
            },
        )
        .group("Setup")
        .description(
            "doctor connects to the database and lists findings (schema behind, not bootstrapped, weak secret, risky durability, missing email transport, jobs that are not running); --strict exits non-zero when any error or warning is found; pass the --retention-days your sweep uses so its backlog is judged the same way.",
        )
        .target(CommandTarget::Config)
        .flag("strict", FlagSpec::boolean("Exit non-zero when any error or warning is found"))
        .flag(
            "retention-days",
            FlagSpec::integer("Delivery retention your sweep uses, to judge its backlog the same way")
                .min(0)
                .max(3650),
        ),
        define_command("secret", "Print a new random secret for BETTER_IAM_SECRET", |context| async move {
            let flags = &context.flags;
            let count = usize::try_from(flags.integer("bytes").unwrap_or(48)).unwrap_or(48);
            let mut bytes = vec![0u8; count];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            Ok(Some(Value::String(if flags.boolean("env") {
                format!("BETTER_IAM_SECRET={value}")
            } else {
                value
            })))
        })
        .group("Setup")
        .description(
            "secret prints a new random value for BETTER_IAM_SECRET (64 URL-safe characters by default) from the operating system random generator; --env prints it as a BETTER_IAM_SECRET= line for a .env file. It reads no configuration and stores nothing.",
        )
        .output(CommandOutput::Text)
        .flag(
            "bytes",
            FlagSpec::integer("Random bytes (the secret is their base64url form)")
                .min(24)
                .max(256)
                .default_number(48),
        )
        .flag("env", FlagSpec::boolean("Print BETTER_IAM_SECRET=value"))
        .examples(&["better-iam secret --env >> .env"]),
    ]
}
