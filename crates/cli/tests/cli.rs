//! Ports of the CLI tests (tests/cli.test.ts, cli-dx.test.ts, cli-remote.test.ts, security-cli.test.ts and the CLI
//! parts of store-snapshot.test.ts). Configuration modules (`better-iam.config.mjs`) become `better-iam.json` files;
//! project commands are added with `create_cli`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use better_iam_auth::totp;
use better_iam_cli::framework::{CliIo, Env};
use better_iam_cli::transport::{FetchFn, HttpCall, HttpReply};
use better_iam_cli::{
    ArgSpec, CliError, CommandOutput, CommandTarget, CreateCliOptions, FlagSpec, LoadConfigOptions,
    OutputFormat, cli_manifest, config_from_env, create_cli, define_command, format_result,
    load_config, run_cli,
};
use better_iam_core::{Filter, FindOptions, IamStoreExt, js};
use better_iam_server::index::BetterIam;
use bytes::Bytes;
use serde_json::{Value, json};

const SECRET: &str = "cli-dx-testing-secret-with-32-characters!";
const ROOT_EMAIL: &str = "root@example.test";
const ROOT_PASSWORD: &str = "a strong cli root password";

fn root_env() -> Vec<(&'static str, String)> {
    vec![
        ("BETTER_IAM_ROOT_EMAIL", ROOT_EMAIL.to_owned()),
        ("BETTER_IAM_ROOT_NAME", "Root".to_owned()),
        ("BETTER_IAM_ROOT_PASSWORD", ROOT_PASSWORD.to_owned()),
    ]
}

/// Debug-build futures are large: every test runs on a thread with a 64 MiB stack.
fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test thread");
}

#[derive(Clone, Default)]
struct Recorder {
    output: Arc<Mutex<Vec<String>>>,
    notes: Arc<Mutex<Vec<String>>>,
    cwd: Option<PathBuf>,
}

impl Recorder {
    fn new(cwd: Option<&Path>) -> Self {
        Self {
            cwd: cwd.map(Path::to_path_buf),
            ..Self::default()
        }
    }

    fn io(&self, env: &[(&str, String)]) -> CliIo {
        let output = self.output.clone();
        let notes = self.notes.clone();
        let mut io = CliIo::new(
            Arc::new(move |line: &str| output.lock().unwrap().push(line.to_owned())),
            env.iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect::<Env>(),
        );
        io.err = Some(Arc::new(move |line: &str| {
            notes.lock().unwrap().push(line.to_owned())
        }));
        io.cwd = self.cwd.clone();
        io
    }

    fn with_stdin(&self, env: &[(&str, String)], text: &str) -> CliIo {
        let mut io = self.io(env);
        let text = text.to_owned();
        io.stdin = Some(Arc::new(move || {
            let text = text.clone();
            Box::pin(async move { Ok(text) })
        }));
        io
    }

    fn lines(&self) -> Vec<String> {
        self.output.lock().unwrap().clone()
    }

    fn raw(&self) -> String {
        self.lines().last().cloned().unwrap_or_default()
    }

    fn last(&self) -> Value {
        serde_json::from_str(&self.raw()).unwrap_or_else(|_| panic!("not JSON: {}", self.raw()))
    }
}

fn argv(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

async fn cli(args: &[&str], io: CliIo) -> Result<(), CliError> {
    run_cli(&argv(args), Some(io)).await
}

async fn fails(args: &[&str], io: CliIo) -> CliError {
    match cli(args, io).await {
        Ok(()) => panic!("{} should fail", args.join(" ")),
        Err(error) => error,
    }
}

fn s(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A standalone configuration on its own SQLite file, with CLI defaults.
fn write_config(folder: &Path, extra: Value) -> PathBuf {
    let path = folder.join("better-iam.json");
    let mut config = json!({
        "store": { "kind": "sqlite", "path": s(&folder.join("iam.db")) },
        "secret": SECRET,
        "baseURL": "http://localhost:3000",
        "permissions": { "actions": ["documents:read"] },
        "resolveResource": { "kind": "echo" },
    });
    if let (Value::Object(config), Value::Object(extra)) = (&mut config, extra) {
        config.extend(extra);
    }
    std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
    path
}

/// Migrates and bootstraps a configuration, then signs root in with MFA through `api` calls; returns the tenant, the
/// session token, and the authenticator secret.
async fn root_session(config: &Path) -> (String, String, String) {
    let r = Recorder::new(None);
    let config = s(config);
    cli(&["migrate", "--config", &config], r.io(&root_env()))
        .await
        .unwrap();
    cli(&["bootstrap", "--config", &config], r.io(&root_env()))
        .await
        .unwrap();
    let tenant_id = r.last()["tenant"]["id"].as_str().unwrap().to_owned();
    cli(
        &[
            "api",
            "auth.signIn",
            "--config",
            &config,
            &format!("tenantId={tenant_id}"),
            &format!("email={ROOT_EMAIL}"),
            &format!("password={ROOT_PASSWORD}"),
        ],
        r.io(&[]),
    )
    .await
    .unwrap();
    let challenge = r.last()["challenge"]
        .as_str()
        .expect("root must require MFA")
        .to_owned();
    cli(
        &[
            "api",
            "auth.beginMfa",
            "--config",
            &config,
            &format!("tenantId={tenant_id}"),
            &format!("challenge={challenge}"),
        ],
        r.io(&[]),
    )
    .await
    .unwrap();
    let mfa_secret = r.last()["secret"].as_str().unwrap().to_owned();
    // The previous step's code, so a later sign-in can use the current one.
    let code = totp::generate(&mfa_secret, js::system_now_ms() - 30_000.0).unwrap();
    cli(
        &[
            "api",
            "auth.confirmMfa",
            "--config",
            &config,
            &format!("credential.tenantId={tenant_id}"),
            &format!("credential.challenge={challenge}"),
            &format!("code={code}"),
        ],
        r.io(&[]),
    )
    .await
    .unwrap();
    let token = r.last()["token"].as_str().unwrap().to_owned();
    (tenant_id, token, mfa_secret)
}

fn temp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

// --- deployment CLI (cli.test.ts) ------------------------------------------------------------------------------------

#[test]
fn scaffolds_configuration_without_overwriting_an_existing_file() {
    run(|| async {
        let folder = temp();
        let config = s(&folder.path().join("better-iam.json"));
        let r = Recorder::new(None);
        cli(&["init", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert!(
            std::fs::read_to_string(&config)
                .unwrap()
                .contains("BETTER_IAM_SECRET")
        );
        assert_eq!(
            fails(&["init", "--config", &config], r.io(&[]))
                .await
                .code(),
            "CONFIG_EXISTS"
        );
        assert_eq!(r.lines().len(), 1);
        assert_eq!(
            fails(&["init", "--database", "mysql"], r.io(&[]))
                .await
                .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(&["init", "--typescript"], r.io(&[])).await.code(),
            "INVALID_ARGUMENT"
        );
    });
}

#[test]
fn migrates_bootstraps_diagnoses_and_recovers_through_trusted_configuration() {
    run(|| async {
        let folder = temp();
        let config = s(&write_config(folder.path(), json!({})));
        let r = Recorder::new(None);
        let env = root_env();
        cli(&["migrate", "--config", &config], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.raw(), "Database and plugin migrations applied.");
        cli(&["bootstrap", "--config", &config], r.io(&env))
            .await
            .unwrap();
        let bootstrap = r.last();
        assert_eq!(bootstrap["mfaEnrollmentRequired"], json!(true));
        assert!(!r.lines().join("\n").contains(ROOT_PASSWORD));
        cli(&["doctor", "--config", &config], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.last()["rootInitialized"], json!(true));
        assert_eq!(r.last()["database"], json!("connected"));
        assert_eq!(
            fails(&["bootstrap", "--config", &config], r.io(&env))
                .await
                .code(),
            "ALREADY_INITIALIZED"
        );
        let mut recovery = env.clone();
        recovery[0].1 = "recovery@example.test".into();
        cli(&["recover-root", "--config", &config], r.io(&recovery))
            .await
            .unwrap();
        assert_eq!(r.last()["identity"]["rootAdmin"], json!(true));
        cli(&["outbox", "--config", &config], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.raw(), r#"{"delivered":0,"failed":0,"abandoned":0}"#);
        let empty = json!({
            "purgedTenants": [],
            "deletedRecords": 0,
            "expiredBindings": 0,
            "expiredRequests": 0,
            "expiredIdentities": 0,
            "expiredActivations": 0,
            "expiredMemberships": 0,
            "expiredAssignments": 0,
        });
        cli(&["purge", "--config", &config], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.last(), empty);
        assert!(!r.raw().contains('\n'));
        cli(
            &["purge", "--config", &config, "--retention-days", "0"],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last(), empty);

        // Audit chain operations read storage directly and never record events themselves.
        let tenant_id = bootstrap["tenant"]["id"].as_str().unwrap().to_owned();
        cli(
            &["audit-verify", "--config", &config, "--tenant", &tenant_id],
            r.io(&env),
        )
        .await
        .unwrap();
        let verification = r.last();
        assert_eq!(verification["tenantId"], json!(tenant_id));
        assert_eq!(verification["valid"], json!(true));
        assert_eq!(verification["first"], json!(1));
        assert_eq!(verification["unchained"], json!(0));
        let checked = verification["checked"].as_u64().unwrap();
        assert!(checked >= 3);
        let export_path = s(&folder.path().join("audit.jsonl"));
        cli(
            &[
                "audit-export",
                "--config",
                &config,
                "--tenant",
                &tenant_id,
                "--output",
                &export_path,
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        let exported = r.last();
        assert_eq!(exported["count"], json!(checked));
        assert_eq!(exported["firstSequence"], json!(1));
        let lines: Vec<String> = std::fs::read_to_string(&export_path)
            .unwrap()
            .trim()
            .split('\n')
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len() as u64, checked);
        assert_eq!(
            serde_json::from_str::<Value>(&lines[0]).unwrap()["sequence"],
            json!(1)
        );
        cli(&["doctor", "--config", &config], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.last()["auditChains"], json!(1));

        // Pruning after archiving keeps the chain verifiable from the checkpoint.
        cli(
            &["audit-prune", "--config", &config, "--tenant", &tenant_id],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last(), json!({ "deleted": 0 }));
        cli(
            &[
                "audit-prune",
                "--config",
                &config,
                "--tenant",
                &tenant_id,
                "--retention-days",
                "0",
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["deleted"], json!(checked));
        cli(
            &["audit-verify", "--config", &config, "--tenant", &tenant_id],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["valid"], json!(true));
        assert_eq!(r.last()["checked"], json!(1));
        assert_eq!(r.last()["first"], json!(checked + 1));
        assert!(
            cli(
                &[
                    "audit-export",
                    "--config",
                    &config,
                    "--tenant",
                    &tenant_id,
                    "--output",
                    &export_path
                ],
                r.io(&env),
            )
            .await
            .is_err()
        );
        assert_eq!(
            fails(&["audit-verify", "--config", &config], r.io(&env))
                .await
                .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(
                &["purge", "--config", &config, "--tenant", &tenant_id],
                r.io(&env)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
    });
}

// --- developer experience (cli-dx.test.ts) ---------------------------------------------------------------------------

/// `better-iam help` lays out its sections as the TypeScript `overviewHelp` does: every built-in command belongs to a
/// named section, so the only `Commands` heading is the one over the usage lines. (A project command without a
/// `group` is listed under a `Commands` section of its own, before that heading, in both implementations.)
#[test]
fn overview_help_has_one_commands_heading_like_the_typescript_cli() {
    run(|| async {
        let r = Recorder::new(None);
        cli(&["help"], r.io(&[])).await.unwrap();
        let help = r.raw();
        let headings: Vec<&str> = help
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with(' '))
            .collect();
        assert_eq!(
            headings,
            [
                headings[0],
                "Usage",
                "Setup",
                "Operations",
                "Audit",
                "Storage",
                "Access",
                "API",
                "Session",
                "Shell",
                "Commands",
                "Environment",
            ]
        );
        assert!(headings[0].starts_with("Better IAM "), "{}", headings[0]);
    });
}

#[test]
fn describes_every_command_in_help_per_command_help_and_a_json_manifest() {
    run(|| async {
        let r = Recorder::new(None);
        cli(&["help", "--json"], r.io(&[])).await.unwrap();
        let manifest = r.last();
        assert_eq!(manifest, cli_manifest());
        let names: Vec<&str> = manifest["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["name"].as_str().unwrap())
            .collect();
        for name in [
            "init",
            "migrate",
            "whoami",
            "store-copy",
            "api",
            "login",
            "can",
            "completion",
        ] {
            assert!(names.contains(&name), "{name}");
        }
        for command in manifest["commands"].as_array().unwrap() {
            let name = command["name"].as_str().unwrap();
            let usage = command["usage"].as_str().unwrap();
            assert!(
                usage == format!("better-iam {name}")
                    || usage.starts_with(&format!("better-iam {name} ")),
                "{usage}"
            );
            assert!(command["summary"].as_str().unwrap().len() > 10);
        }
        let analyze = manifest["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|command| command["name"] == json!("analyze"))
            .unwrap();
        let flags = analyze["flags"].as_array().unwrap();
        assert!(flags.iter().any(|flag| flag["flag"] == json!("--tenant")
            && flag["value"] == json!("TENANT_ID")
            && flag["optional"] == json!(false)
            && flag["env"] == json!("BETTER_IAM_TENANT")));
        assert!(flags.iter().any(|flag| flag["flag"] == json!("--fail-on")
            && flag["choices"] == json!(["high", "medium", "low"])));

        cli(&["help", "can"], r.io(&[])).await.unwrap();
        let help = r.raw();
        assert!(help.contains("better-iam can - Check whether"));
        assert!(help.contains("Examples"));
        cli(&["can", "--help"], r.io(&[])).await.unwrap();
        assert_eq!(r.raw(), help);
        cli(&["--version"], r.io(&[])).await.unwrap();
        assert_eq!(r.raw(), better_iam_cli::VERSION);
        cli(&["help"], r.io(&[])).await.unwrap();
        assert!(
            r.raw()
                .starts_with(&format!("Better IAM {}\n", better_iam_cli::VERSION))
        );

        let error = fails(&["analyse"], r.io(&[])).await;
        assert_eq!(error.code(), "INVALID_COMMAND");
        assert!(error.message().contains("Did you mean analyze?"));
        assert_eq!(
            fails(&["help", "analyse"], r.io(&[])).await.code(),
            "INVALID_COMMAND"
        );
        let error = fails(&["analyze", "--tenat", "x"], r.io(&[])).await;
        assert_eq!(error.code(), "INVALID_ARGUMENT");
        assert!(error.message().contains("Did you mean --tenant?"));
        assert_eq!(
            error.hint.as_deref(),
            Some("Run better-iam help analyze for its flags.")
        );
    });
}

#[test]
fn parses_flags_switches_and_numbers_the_same_way_for_every_command() {
    run(|| async {
        let r = Recorder::new(None);
        cli(&["secret", "--bytes=24"], r.io(&[])).await.unwrap();
        let value = r.raw();
        assert_eq!(value.len(), 32);
        assert!(
            value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        );
        cli(&["secret", "--env"], r.io(&[])).await.unwrap();
        let line = r.raw();
        assert!(
            line.starts_with("BETTER_IAM_SECRET=") && line.len() == "BETTER_IAM_SECRET=".len() + 64
        );
        for args in [
            vec!["secret", "--bytes=10"],
            vec!["secret", "--bytes", "many"],
            vec!["secret", "--env=maybe"],
            vec!["secret", "extra"],
            vec!["secret", "--bytes", "30", "--bytes", "40"],
            vec!["secret", "-x"],
            vec!["sweep", "--limit"],
        ] {
            assert_eq!(
                fails(&args, r.io(&[])).await.code(),
                "INVALID_ARGUMENT",
                "{}",
                args.join(" ")
            );
        }
        let error = fails(&["secret", "--bytes=10"], r.io(&[])).await;
        assert_eq!(
            error.message(),
            "--bytes must be an integer between 24 and 256"
        );
    });
}

#[test]
fn prints_completion_scripts_for_bash_zsh_fish_and_powershell() {
    run(|| async {
        let r = Recorder::new(None);
        for shell in ["bash", "zsh", "fish", "powershell"] {
            cli(&["completion", shell], r.io(&[])).await.unwrap();
            let script = r.raw();
            assert!(script.contains("analyze"), "{shell}");
            assert!(
                script.contains(if shell == "fish" {
                    "-l fail-on"
                } else {
                    "--fail-on"
                }),
                "{shell}"
            );
            assert!(script.contains("high"), "{shell}");
        }
        let lines = r.lines();
        assert!(lines[0].contains("complete -o default -F _better_iam better-iam"));
        assert!(lines[1].contains("bashcompinit"));
        assert!(lines[3].contains("Register-ArgumentCompleter"));
        assert_eq!(
            fails(&["completion", "tcsh"], r.io(&[])).await.code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(&["completion"], r.io(&[])).await.code(),
            "INVALID_ARGUMENT"
        );

        // Flag values first in bash, then flag names.
        cli(&["completion", "bash"], r.io(&[])).await.unwrap();
        let script = r.raw();
        let analyze = &script[script.find("    analyze)").unwrap()..];
        let values = analyze
            .find("--fail-on) COMPREPLY=( $(compgen -W 'high medium low'")
            .unwrap();
        assert!(values > 0);
        assert!(values < analyze.find("-*) COMPREPLY").unwrap());
        assert!(!script.contains("*) return ;;"));
    });
}

#[test]
fn scaffolds_a_configuration_that_the_cli_loads_by_discovery() {
    run(|| async {
        let folder = temp();
        let r = Recorder::new(Some(folder.path()));
        cli(&["init"], r.io(&[])).await.unwrap();
        let written = std::fs::read_to_string(folder.path().join("better-iam.json")).unwrap();
        let parsed: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["secret"], json!({ "env": "BETTER_IAM_SECRET" }));
        assert_eq!(
            parsed["cli"]["defaults"]["sweep"]["retention-days"],
            json!(30)
        );
        assert_eq!(fails(&["init"], r.io(&[])).await.code(), "CONFIG_EXISTS");
        let postgres = folder.path().join("postgres.json");
        cli(
            &["init", "--database", "postgres", "--config", &s(&postgres)],
            r.io(&[]),
        )
        .await
        .unwrap();
        assert!(
            std::fs::read_to_string(&postgres)
                .unwrap()
                .contains("\"postgres\"")
        );

        // The generated file runs as written (the store path pointed at this folder), found without --config.
        let project = folder.path().join("app");
        std::fs::create_dir_all(project.join("src").join("deep")).unwrap();
        let mut config = parsed.clone();
        config["store"]["path"] = json!(s(&project.join("iam.db")));
        std::fs::write(
            project.join("better-iam.json"),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let nested = Recorder::new(Some(&project.join("src").join("deep")));
        let env = [("BETTER_IAM_SECRET", SECRET.to_owned())];
        cli(&["migrate"], nested.io(&env)).await.unwrap();
        assert_eq!(nested.raw(), "Database and plugin migrations applied.");
        cli(&["doctor"], nested.io(&env)).await.unwrap();
        assert_eq!(nested.last()["database"], json!("connected"));
        assert_eq!(nested.last()["rootInitialized"], json!(false));
        // The secret comes from the environment the command receives.
        let error = fails(&["migrate"], nested.io(&[])).await;
        assert_eq!(error.code(), "INVALID_CONFIG");
    });
}

#[test]
fn runs_project_commands_with_configuration_defaults_environment_variables_and_output_flags() {
    run(|| async {
        let folder = temp();
        let config = write_config(
            folder.path(),
            json!({ "cli": { "defaults": { "echo-flags": { "level": 5 }, "*": { "format": "compact" } } } }),
        );
        let echo = define_command(
            "echo-flags",
            "Print the flags a project command received",
            |context| async move {
                let instance = context.iam()?;
                Ok(Some(json!({
                    "name": context.name,
                    "level": context.flags.integer("level"),
                    "who": context.flags.string("who"),
                    "basePath": instance.endpoint.base_path,
                })))
            },
        )
        .target(CommandTarget::Config)
        .flag(
            "level",
            FlagSpec::integer("A level")
                .env("ECHO_LEVEL")
                .min(0)
                .max(10),
        )
        .flag("who", FlagSpec::string("A name").required());
        let rows = define_command("rows", "Print two rows", |_| async move {
            Ok(Some(
                json!({ "rows": [{ "name": "a", "size": 1 }, { "name": "b", "size": 2 }] }),
            ))
        });
        let program = create_cli(CreateCliOptions {
            commands: vec![echo, rows],
            ..CreateCliOptions::default()
        });
        let r = Recorder::new(Some(folder.path()));
        let go = |args: &[&str], io: CliIo| {
            let program = program.clone();
            let args = argv(args);
            async move { program.run(&args, Some(io)).await }
        };

        go(&["echo-flags", "--who", "ada"], r.io(&[]))
            .await
            .unwrap();
        assert!(!r.raw().contains('\n'));
        assert_eq!(
            r.last(),
            json!({ "name": "echo-flags", "level": 5, "who": "ada", "basePath": "/api/iam" })
        );
        go(
            &["echo-flags", "--who", "ada"],
            r.io(&[("ECHO_LEVEL", "7".into())]),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["level"], json!(7));
        go(
            &["echo-flags", "--who=ada", "--level=9", "--format", "json"],
            r.io(&[("ECHO_LEVEL", "7".into())]),
        )
        .await
        .unwrap();
        assert!(r.raw().contains("\n  \"level\": 9"));
        go(&["echo-flags", "--who", "ada", "--query", "who"], r.io(&[]))
            .await
            .unwrap();
        assert_eq!(r.raw(), "ada");
        assert_eq!(
            go(&["echo-flags"], r.io(&[])).await.unwrap_err().code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            go(&["echo-flags", "--who", "a", "--level", "11"], r.io(&[]))
                .await
                .unwrap_err()
                .code(),
            "INVALID_ARGUMENT"
        );
        let error = go(
            &["echo-flags", "--who", "a"],
            r.io(&[("ECHO_LEVEL", "high".into())]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "INVALID_ARGUMENT");
        assert!(error.message().contains("ECHO_LEVEL"));

        // Found through --config from elsewhere, BETTER_IAM_CONFIG, or discovery from a subdirectory.
        let other = temp();
        let elsewhere = Recorder::new(Some(other.path()));
        go(&["rows", "--format", "table"], elsewhere.io(&[]))
            .await
            .unwrap();
        assert_eq!(elsewhere.raw(), "NAME  SIZE\na     1\nb     2");
        go(
            &["rows", "--query", "rows[].name"],
            elsewhere.io(&[("BETTER_IAM_CONFIG", s(&config))]),
        )
        .await
        .unwrap();
        assert_eq!(elsewhere.last(), json!(["a", "b"]));
        std::fs::create_dir(folder.path().join("sub")).unwrap();
        let sub = Recorder::new(Some(&folder.path().join("sub")));
        go(&["echo-flags", "--who", "x"], sub.io(&[]))
            .await
            .unwrap();
        assert_eq!(sub.last()["level"], json!(5));

        go(&["help"], r.io(&[])).await.unwrap();
        assert!(r.raw().contains("echo-flags"));
        go(&["help", "echo-flags"], r.io(&[])).await.unwrap();
        assert!(r.raw().contains("--level N"));
        go(&["completion", "fish"], r.io(&[])).await.unwrap();
        assert!(r.raw().contains("-a echo-flags"));
        let error = go(&["echo-flag", "--who", "x"], r.io(&[]))
            .await
            .unwrap_err();
        assert!(error.message().contains("Did you mean echo-flags?"));
        // The built-in program has no project commands.
        assert_eq!(fails(&["rows"], r.io(&[])).await.code(), "INVALID_COMMAND");
    });
}

#[test]
fn configures_a_deployment_from_environment_variables_alone() {
    run(|| async {
        let folder = temp();
        let r = Recorder::new(Some(folder.path()));
        let mut env = vec![
            (
                "BETTER_IAM_DATABASE_URL",
                format!("sqlite:{}", s(&folder.path().join("env.db"))),
            ),
            ("BETTER_IAM_SECRET", SECRET.to_owned()),
        ];
        env.extend(root_env());
        cli(&["migrate"], r.io(&env)).await.unwrap();
        cli(&["bootstrap"], r.io(&env)).await.unwrap();
        assert_eq!(r.last()["identity"]["rootAdmin"], json!(true));
        cli(&["doctor"], r.io(&env)).await.unwrap();
        assert_eq!(r.last()["rootInitialized"], json!(true));
        assert_eq!(
            fails(&["migrate"], r.io(&[])).await.code(),
            "CONFIG_NOT_FOUND"
        );
        assert_eq!(
            fails(
                &["migrate"],
                r.io(&[
                    ("BETTER_IAM_DATABASE_URL", "mysql://db".into()),
                    ("BETTER_IAM_SECRET", SECRET.into())
                ])
            )
            .await
            .code(),
            "INVALID_CONFIG"
        );
        assert_eq!(
            fails(
                &["migrate"],
                r.io(&[(
                    "BETTER_IAM_DATABASE_URL",
                    format!("sqlite:{}", s(&folder.path().join("x.db")))
                )])
            )
            .await
            .code(),
            "MISSING_ENV"
        );

        let options = config_from_env(
            &[
                (
                    "BETTER_IAM_DATABASE_URL".to_owned(),
                    format!("sqlite:{}", s(&folder.path().join("env.db"))),
                ),
                ("BETTER_IAM_SECRET".to_owned(), SECRET.to_owned()),
                (
                    "BETTER_IAM_TRUSTED_ORIGINS".to_owned(),
                    "https://a.test, https://b.test".to_owned(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        assert_eq!(options["baseURL"], json!("http://localhost:3000"));
        assert_eq!(
            options["trustedOrigins"],
            json!(["https://a.test", "https://b.test"])
        );

        let iam = load_config(LoadConfigOptions {
            cwd: Some(folder.path().to_path_buf()),
            env: Some(
                env.iter()
                    .map(|(key, value)| ((*key).to_owned(), value.clone()))
                    .collect(),
            ),
            ..LoadConfigOptions::default()
        })
        .unwrap();
        let roots = iam
            .store
            .find(
                "tenants",
                &Filter::new().eq("parentId", Value::Null),
                &FindOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(roots.len(), 1);
        iam.store.close().await.unwrap();
    });
}

#[test]
fn calls_api_routes_in_process_and_plans_configuration_files() {
    run(|| async {
        let folder = temp();
        let config = write_config(folder.path(), json!({}));
        let (tenant_id, token, _) = root_session(&config).await;
        let r = Recorder::new(Some(folder.path()));
        let as_root = [("BETTER_IAM_TOKEN", token.clone())];

        cli(
            &["api", "auth.getSession", "--format", "json"],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["identity"]["rootAdmin"], json!(true));
        cli(
            &[
                "api",
                "roles.create",
                "name=Auditor",
                "permissions[]=documents:read",
                "--tenant",
                &tenant_id,
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["name"], json!("Auditor"));
        assert_eq!(r.last()["tenantId"], json!(tenant_id));
        let mut with_tenant = as_root.to_vec();
        with_tenant.push(("BETTER_IAM_TENANT", tenant_id.clone()));
        cli(
            &["api", "roles.list", "--query", "[].name"],
            r.io(&with_tenant),
        )
        .await
        .unwrap();
        assert!(r.last().as_array().unwrap().contains(&json!("Auditor")));
        cli(&["api", "--list", "config"], r.io(&as_root))
            .await
            .unwrap();
        assert!(r.raw().contains("config.apply"));
        assert!(r.raw().contains("POST /api/iam/config/apply"));
        assert_eq!(
            fails(&["api", "--list", "nothing"], r.io(&as_root))
                .await
                .code(),
            "NOT_FOUND"
        );

        // A tenant configuration file.
        let file = folder.path().join("tenant.json");
        std::fs::write(
            &file,
            json!({
                "version": 1,
                "roles": [{ "name": "Viewer", "description": "Readers", "permissions": ["documents:read"] }],
                "groups": [{ "name": "Readers" }],
                "bindings": [{ "group": "Readers", "role": "Viewer" }],
            })
            .to_string(),
        )
        .unwrap();
        let file = s(&file);
        cli(
            &["config-validate", "--input", &file, "--tenant", &tenant_id],
            r.io(&[]),
        )
        .await
        .unwrap();
        assert_eq!(
            r.last(),
            json!({ "valid": true, "items": { "roles": 1, "groups": 1, "bindings": 1 }, "warnings": [] })
        );
        cli(
            &["config-plan", "--tenant", &tenant_id, "--input", &file],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(
            r.last()["summary"],
            json!({ "create": 3, "update": 0, "delete": 0, "unchanged": 0 })
        );
        assert_eq!(
            fails(
                &[
                    "config-plan",
                    "--tenant",
                    &tenant_id,
                    "--input",
                    &file,
                    "--fail-on-drift"
                ],
                r.io(&as_root)
            )
            .await
            .code(),
            "CONFIG_DRIFT"
        );
        cli(
            &["config-apply", "--tenant", &tenant_id, "--input", &file],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["applied"], json!(true));

        // Exported back, as JSON and as typed modules; the JSON plans as unchanged.
        let exported = s(&folder.path().join("exported.json"));
        cli(
            &[
                "config-export",
                "--tenant",
                &tenant_id,
                "--output",
                &exported,
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(
            r.last(),
            json!({ "tenantId": tenant_id, "output": exported })
        );
        cli(
            &[
                "config-plan",
                "--tenant",
                &tenant_id,
                "--input",
                &exported,
                "--fail-on-drift",
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["summary"]["create"], json!(0));
        assert_eq!(r.last()["summary"]["update"], json!(0));
        assert_eq!(r.last()["summary"]["delete"], json!(0));
        for (name, marker) in [
            ("exported.config.ts", "defineTenantConfig("),
            (
                "exported.config.mjs",
                "@type {import('better-iam/server').TenantConfig}",
            ),
        ] {
            let output = s(&folder.path().join(name));
            cli(
                &["config-export", "--tenant", &tenant_id, "--output", &output],
                r.io(&as_root),
            )
            .await
            .unwrap();
            assert!(std::fs::read_to_string(&output).unwrap().contains(marker));
            // Modules run under Node.js only.
            assert_eq!(
                fails(
                    &["config-plan", "--tenant", &tenant_id, "--input", &output],
                    r.io(&as_root)
                )
                .await
                .code(),
                "INVALID_INPUT"
            );
        }
        // Never overwrites.
        assert_eq!(
            fails(
                &[
                    "config-export",
                    "--tenant",
                    &tenant_id,
                    "--output",
                    &exported
                ],
                r.io(&as_root)
            )
            .await
            .code(),
            "EEXIST"
        );

        // Offline validation: shape errors fail, unresolved names warn (and fail with --strict).
        let loose = folder.path().join("loose.json");
        std::fs::write(
            &loose,
            json!({
                "version": 1,
                "roles": [{ "name": "A", "policies": ["Missing"], "permissions": ["documents:read"] }],
                "bindings": [{ "group": "Nobody", "role": "A" }],
            })
            .to_string(),
        )
        .unwrap();
        let loose_path = s(&loose);
        cli(&["config-validate", "--input", &loose_path], r.io(&[]))
            .await
            .unwrap();
        assert_eq!(
            r.last()["warnings"],
            json!([
                "Role \"A\" names policy \"Missing\", which this file does not define",
                "Binding Nobody -> A names group \"Nobody\", which this file does not define",
            ])
        );
        assert_eq!(
            fails(
                &["config-validate", "--input", &loose_path, "--strict"],
                r.io(&[])
            )
            .await
            .code(),
            "CONFIG_WARNINGS"
        );
        std::fs::write(&loose, json!({ "version": 2 }).to_string()).unwrap();
        assert_eq!(
            fails(&["config-validate", "--input", &loose_path], r.io(&[]))
                .await
                .code(),
            "INVALID_INPUT"
        );

        // Access questions as the token.
        cli(
            &[
                "can",
                "documents:read",
                "documents/a",
                "--tenant",
                &tenant_id,
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["allowed"], json!(true));
        cli(&["whoami"], r.io(&as_root)).await.unwrap();
        assert_eq!(r.last()["tenantId"], json!(tenant_id));
        assert_eq!(
            fails(&["can", "documents:read", "nothing"], r.io(&with_tenant))
                .await
                .code(),
            "INVALID_ARGUMENT"
        );
    });
}

#[test]
fn keeps_local_saved_sessions_with_their_configuration_and_orders_flag_sources() {
    run(|| async {
        let folder = temp();
        let config = write_config(
            folder.path(),
            json!({ "cli": { "defaults": { "show-tenant": { "tenant": "from-defaults" } } } }),
        );
        let (tenant_id, token, _) = root_session(&config).await;
        let credentials = (
            "BETTER_IAM_CREDENTIALS",
            s(&folder.path().join("credentials.json")),
        );
        let other_folder = temp();
        let elsewhere = Recorder::new(Some(other_folder.path()));
        let config_text = s(&config);

        // Saved through the configuration: later commands use it from anywhere, without --config.
        cli(
            &["login", "--with-token", "--config", &config_text],
            elsewhere.with_stdin(std::slice::from_ref(&credentials), &token),
        )
        .await
        .unwrap();
        assert_eq!(elsewhere.last()["profile"], json!("default"));
        assert_eq!(elsewhere.last()["config"], json!(config_text));
        assert_eq!(elsewhere.last()["tenantId"], json!(tenant_id));
        cli(
            &["whoami", "--format", "json"],
            elsewhere.io(std::slice::from_ref(&credentials)),
        )
        .await
        .unwrap();
        assert_eq!(elsewhere.last()["tenantId"], json!(tenant_id));
        // Another configuration is another deployment.
        let another = temp();
        let other_config = s(&write_config(another.path(), json!({})));
        assert_eq!(
            fails(
                &["whoami", "--config", &other_config],
                elsewhere.io(std::slice::from_ref(&credentials))
            )
            .await
            .code(),
            "MISSING_ENV"
        );
        // An explicit --config beats BETTER_IAM_URL; both from the environment is ambiguous.
        cli(
            &["whoami", "--config", &config_text],
            elsewhere.io(&[
                credentials.clone(),
                ("BETTER_IAM_URL", "http://localhost:9".into()),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(
            fails(
                &["whoami"],
                elsewhere.io(&[
                    credentials.clone(),
                    ("BETTER_IAM_URL", "http://localhost:9".into()),
                    ("BETTER_IAM_CONFIG", config_text.clone()),
                ])
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );

        // Flag sources: command line, then environment, then configuration defaults, then the saved session.
        let probe = define_command(
            "show-tenant",
            "Print the tenant a token command resolved",
            |context| async move { Ok(Some(json!({ "tenant": context.flags.string("tenant") }))) },
        )
        .target(CommandTarget::Token)
        .flag(
            "tenant",
            FlagSpec::string("Tenant")
                .env("BETTER_IAM_TENANT")
                .profile("tenantId"),
        );
        let program = create_cli(CreateCliOptions {
            commands: vec![probe],
            ..CreateCliOptions::default()
        });
        let r = Recorder::new(Some(folder.path()));
        program
            .run(
                &argv(&["show-tenant"]),
                Some(r.io(std::slice::from_ref(&credentials))),
            )
            .await
            .unwrap();
        assert_eq!(r.last(), json!({ "tenant": "from-defaults" }));
        program
            .run(
                &argv(&["show-tenant"]),
                Some(r.io(&[
                    credentials.clone(),
                    ("BETTER_IAM_TENANT", "from-env".into()),
                ])),
            )
            .await
            .unwrap();
        assert_eq!(r.last(), json!({ "tenant": "from-env" }));
        program
            .run(
                &argv(&["show-tenant", "--tenant", "from-flag"]),
                Some(r.io(&[
                    credentials.clone(),
                    ("BETTER_IAM_TENANT", "from-env".into()),
                ])),
            )
            .await
            .unwrap();
        assert_eq!(r.last(), json!({ "tenant": "from-flag" }));
        // Without defaults for it, --tenant falls back to the saved session's tenant.
        cli(
            &["api", "roles.create", "name=Probe", "--query", "tenantId"],
            r.io(std::slice::from_ref(&credentials)),
        )
        .await
        .unwrap();
        assert_eq!(r.raw(), tenant_id);
        cli(&["token"], r.io(std::slice::from_ref(&credentials)))
            .await
            .unwrap();
        assert_eq!(r.raw(), token);

        cli(
            &["logout"],
            elsewhere.io(std::slice::from_ref(&credentials)),
        )
        .await
        .unwrap();
        assert_eq!(
            elsewhere.last(),
            json!({ "profile": "default", "revoked": true, "forgotten": true })
        );
        assert_eq!(
            fails(
                &["whoami", "--config", &config_text],
                elsewhere.io(&[("BETTER_IAM_TOKEN", token.clone())])
            )
            .await
            .code(),
            "UNAUTHENTICATED"
        );
    });
}

#[test]
fn signs_sessions_of_environment_only_deployments_out_through_the_same_environment() {
    run(|| async {
        let folder = temp();
        // Root signs in through a configuration naming the same database as the environment.
        let config = write_config(folder.path(), json!({}));
        let (tenant_id, token, _) = root_session(&config).await;
        let mut env = vec![
            (
                "BETTER_IAM_DATABASE_URL",
                format!("sqlite:{}", s(&folder.path().join("iam.db"))),
            ),
            ("BETTER_IAM_SECRET", SECRET.to_owned()),
            (
                "BETTER_IAM_CREDENTIALS",
                s(&folder.path().join("credentials.json")),
            ),
        ];
        env.extend(root_env());
        let other = temp();
        let r = Recorder::new(Some(other.path()));
        cli(&["login", "--with-token"], r.with_stdin(&env, &token))
            .await
            .unwrap();
        let file: Value = serde_json::from_str(
            &std::fs::read_to_string(folder.path().join("credentials.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(file["profiles"]["default"]["envConfig"], json!(true));
        cli(&["whoami", "--format", "json"], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.last()["tenantId"], json!(tenant_id));
        cli(&["logout"], r.io(&env)).await.unwrap();
        assert_eq!(r.last()["revoked"], json!(true));
    });
}

#[test]
fn builds_project_clis_from_code_and_reports_failures_with_exit_codes() {
    run(|| async {
        let hello = define_command("hello", "Greet someone by name", |context| async move {
            let who = context.args[0].clone();
            Ok(Some(Value::String(if context.flags.boolean("shout") {
                format!("HELLO {}", who.to_uppercase())
            } else {
                format!("hello {who}")
            })))
        })
        .arg(ArgSpec::new("who", "Who to greet").required())
        .flag("shout", FlagSpec::boolean("Upper case"))
        .output(CommandOutput::Text);
        let only = create_cli(CreateCliOptions {
            builtins: Some(false),
            commands: vec![hello.clone()],
            version: Some("9.9.9".into()),
        });
        let r = Recorder::new(None);
        only.run(&argv(&["hello", "world", "--shout"]), Some(r.io(&[])))
            .await
            .unwrap();
        assert_eq!(r.raw(), "HELLO WORLD");
        let names: Vec<Value> = only.manifest()["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["name"].clone())
            .collect();
        assert_eq!(names, vec![json!("hello")]);
        assert!(!only.help(None).unwrap().contains("migrate"));
        assert!(
            only.help(Some("hello"))
                .unwrap()
                .contains("better-iam hello WHO [--shout]")
        );
        assert_eq!(
            only.run(&argv(&["migrate"]), Some(r.io(&[])))
                .await
                .unwrap_err()
                .code(),
            "INVALID_COMMAND"
        );
        assert_eq!(
            create_cli(CreateCliOptions {
                commands: vec![hello],
                ..CreateCliOptions::default()
            })
            .commands
            .len(),
            cli_manifest()["commands"].as_array().unwrap().len() + 1
        );

        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let report = |error: &CliError| {
            let lines = lines.clone();
            better_iam_cli::report_failure(error, &Env::new(), &move |line| {
                lines.lock().unwrap().push(line.to_owned())
            })
        };
        let error = fails(&["analyse"], r.io(&[])).await;
        assert_eq!(report(&error), 2);
        assert!(
            lines
                .lock()
                .unwrap()
                .join("\n")
                .contains("INVALID_COMMAND: Unknown command: analyse")
        );
        let missing = temp();
        let error = fails(
            &[
                "migrate",
                "--config",
                &s(&missing.path().join("missing.json")),
            ],
            r.io(&[]),
        )
        .await;
        assert_eq!(report(&error), 1);
        assert!(
            lines
                .lock()
                .unwrap()
                .join("\n")
                .contains("Hint: Run better-iam init")
        );
        // Unknown failures stay generic; control characters never reach the terminal.
        let error = CliError::unknown("fetch failed", "connect ECONNREFUSED");
        assert_eq!(report(&error), 1);
        assert!(
            lines
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .starts_with("Better IAM command failed.")
        );
        let error: CliError = better_iam_core::IamError::new("X", "a\u{1b}[2Kb").into();
        report(&error);
        assert_eq!(lines.lock().unwrap().last().unwrap(), "X: a [2Kb");
        let mut exited = CliError::new("COMMAND_FAILED", "node exited with status 3", None);
        exited.exit_status = Some(3);
        assert_eq!(report(&exited), 3);
    });
}

// --- security (security-cli.test.ts) ---------------------------------------------------------------------------------

#[test]
fn discovery_stops_at_the_repository_root() {
    run(|| async {
        let top = temp();
        write_config(top.path(), json!({}));
        let repository = top.path().join("repo");
        std::fs::create_dir_all(repository.join(".git")).unwrap();
        let r = Recorder::new(Some(&repository));
        assert_eq!(
            fails(&["migrate"], r.io(&[])).await.code(),
            "CONFIG_NOT_FOUND"
        );
        assert!(!top.path().join("iam.db").exists());
    });
}

#[test]
fn audit_gates_fail_on_an_unknown_tenant_a_wiped_chain_and_an_empty_archive() {
    run(|| async {
        let directory = temp();
        let database = directory.path().join("iam.db");
        let mut env = vec![
            (
                "BETTER_IAM_DATABASE_URL",
                format!("sqlite:{}", s(&database)),
            ),
            ("BETTER_IAM_SECRET", SECRET.to_owned()),
        ];
        env.extend(root_env());
        let r = Recorder::new(Some(directory.path()));
        cli(&["migrate"], r.io(&env)).await.unwrap();
        cli(&["bootstrap"], r.io(&env)).await.unwrap();
        let tenant_id = r.last()["tenant"]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            fails(&["audit-verify", "--tenant", "no-such-tenant"], r.io(&env))
                .await
                .code(),
            "NOT_FOUND"
        );
        cli(&["audit-verify", "--tenant", &tenant_id], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.last()["valid"], json!(true));
        let iam = load_config(LoadConfigOptions {
            env: Some(
                env.iter()
                    .map(|(key, value)| ((*key).to_owned(), value.clone()))
                    .collect(),
            ),
            cwd: Some(directory.path().to_path_buf()),
            ..LoadConfigOptions::default()
        })
        .unwrap();
        let wipe = tenant_id.clone();
        iam.store
            .transaction(move |tx| async move {
                for event in tx
                    .find(
                        "audit",
                        &Filter::new().eq("tenantId", wipe.as_str()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    tx.delete("audit", event["id"].as_str().unwrap()).await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        iam.store.close().await.unwrap();
        assert_eq!(
            fails(&["audit-verify", "--tenant", &tenant_id], r.io(&env))
                .await
                .code(),
            "AUDIT_CHAIN_BROKEN"
        );
        let archive = temp();
        std::fs::create_dir(archive.path().join("ten_1")).unwrap();
        assert_eq!(
            fails(
                &[
                    "audit-verify-archive",
                    "--directory",
                    &s(archive.path()),
                    "--tenant",
                    "ten_1"
                ],
                r.io(&env)
            )
            .await
            .code(),
            "AUDIT_ARCHIVE_INVALID"
        );
        assert_eq!(
            fails(
                &[
                    "audit-verify-archive",
                    "--directory",
                    &s(archive.path()),
                    "--tenant",
                    "../x"
                ],
                r.io(&env)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
    });
}

#[test]
fn never_lets_a_shared_default_shorten_audit_prune_retention() {
    run(|| async {
        let directory = temp();
        write_config(
            directory.path(),
            json!({ "cli": { "defaults": { "*": { "retention-days": 7 } } } }),
        );
        let probe = define_command("audit-prune", "Print the retention audit-prune would use", |context| async move {
            Ok(Some(json!({ "retentionMs": context.flags.integer("retention-days").unwrap_or(365) * 86_400_000 })))
        })
        .target(CommandTarget::Config)
        .flag("tenant", FlagSpec::string("Tenant").required())
        .flag(
            "retention-days",
            FlagSpec::integer("Keep events newer than this many days")
                .min(0)
                .max(36500)
                .default_number(365)
                .no_wildcard_default(),
        )
        .flag("limit", FlagSpec::integer("Any flag a shared default may fill"));
        let program = create_cli(CreateCliOptions {
            builtins: Some(false),
            commands: vec![probe],
            version: None,
        });
        let r = Recorder::new(Some(directory.path()));
        program
            .run(&argv(&["audit-prune", "--tenant", "t1"]), Some(r.io(&[])))
            .await
            .unwrap();
        assert_eq!(r.last()["retentionMs"], json!(365 * 86_400_000_i64));
        // The built-in command declares the same flag.
        let manifest = cli_manifest();
        let prune = manifest["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|command| command["name"] == json!("audit-prune"))
            .unwrap()
            .clone();
        assert!(
            prune["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag["flag"] == json!("--retention-days"))
        );
    });
}

#[test]
fn shows_terminal_control_sequences_from_server_data_as_replacement_characters() {
    let evil = "Mallory\u{1b}]52;c;cHduZWQ=\u{7}\u{1b}[2K";
    assert!(
        !format_result(
            &json!({ "rows": [{ "name": evil }] }),
            Some(OutputFormat::Table),
            None
        )
        .unwrap()
        .contains('\u{1b}')
    );
    assert!(
        !format_result(
            &json!({ "name": evil }),
            Some(OutputFormat::Json),
            Some("name")
        )
        .unwrap()
        .contains('\u{1b}')
    );
    // JSON output escapes them already.
    let json_text =
        format_result(&json!({ "name": evil }), Some(OutputFormat::Json), None).unwrap();
    assert!(!json_text.contains('\u{1b}'));
    assert!(json_text.contains("\\u001b"));
}

#[test]
fn sends_a_literal_at_value_when_it_is_escaped() {
    run(|| async {
        let directory = temp();
        std::fs::write(directory.path().join("secret.txt"), "TOP-SECRET").unwrap();
        let r = Recorder::new(None);
        let io = r.io(&[]);
        let body = better_iam_cli::commands::api::request_body(
            &io,
            directory.path(),
            None,
            &argv(&["displayName=\\@secret.txt"]),
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::Value::Object(body),
            json!({ "displayName": "@secret.txt" })
        );
        let body = better_iam_cli::commands::api::request_body(
            &io,
            directory.path(),
            Some(r#"{"a":{"__proto__":{"x":1},"b":2}}"#),
            &argv(&[
                "content=@secret.txt",
                "limit:=10",
                "resource.type=project",
                "tags[]=a",
                "tags[]=b",
            ]),
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::Value::Object(body),
            json!({
                "a": { "b": 2 },
                "content": "TOP-SECRET",
                "limit": 10,
                "resource": { "type": "project" },
                "tags": ["a", "b"],
            })
        );
        for items in [
            vec!["novalue"],
            vec!["__proto__.x=1"],
            vec!["a[].b=1"],
            vec!["n:=nope"],
        ] {
            let error = better_iam_cli::commands::api::request_body(
                &io,
                directory.path(),
                None,
                &argv(&items),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), "INVALID_ARGUMENT", "{items:?}");
        }
    });
}

#[test]
fn selects_query_paths_and_renders_tables() {
    use better_iam_cli::select_path;
    let value = json!({ "summary": { "create": 2 }, "findings": [{ "kind": "a" }, { "kind": "b" }], "roles": [{ "name": "r" }] });
    assert_eq!(select_path(&value, "summary.create").unwrap(), json!(2));
    assert_eq!(
        select_path(&value, "findings[].kind").unwrap(),
        json!(["a", "b"])
    );
    assert_eq!(select_path(&value, "roles.0.name").unwrap(), json!("r"));
    assert_eq!(select_path(&value, "roles[0].name").unwrap(), json!("r"));
    assert_eq!(select_path(&value, "roles.length").unwrap(), json!(1));
    assert_eq!(select_path(&value, "missing.key").unwrap(), Value::Null);
    assert_eq!(
        select_path(&value, "__proto__").unwrap_err().code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        select_path(&value, "a[x]").unwrap_err().code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        format_result(&json!([]), Some(OutputFormat::Table), None).unwrap(),
        "(no rows)"
    );
    assert_eq!(
        format_result(
            &json!({ "a": 1, "long": "x" }),
            Some(OutputFormat::Table),
            None
        )
        .unwrap(),
        "a     1\nlong  x"
    );
    let wide: Value =
        json!([{ "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7, "h": 8, "i": 9 }]);
    let table = format_result(&wide, Some(OutputFormat::Table), None).unwrap();
    assert!(table.ends_with("(1 more column(s); use --format json to see them)"));
    assert_eq!(
        format_result(&json!(1.0), Some(OutputFormat::Json), None).unwrap(),
        "1"
    );
    assert_eq!(
        format_result(&json!({ "a": [1, { "b": null }] }), None, None).unwrap(),
        "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ]\n}"
    );
}

// --- storage snapshots (store-snapshot.test.ts, the CLI part) ---------------------------------------------------------

#[test]
fn moves_a_deployment_to_another_database_through_snapshots() {
    run(|| async {
        let folder = temp();
        let source = folder.path().join("source");
        let target = folder.path().join("target");
        let copy = folder.path().join("copy");
        for path in [&source, &target, &copy] {
            std::fs::create_dir(path).unwrap();
        }
        let source_config = s(&write_config(&source, json!({})));
        let target_config = s(&write_config(&target, json!({})));
        let copy_config = s(&write_config(&copy, json!({})));
        let r = Recorder::new(Some(folder.path()));
        let env = root_env();
        cli(&["migrate", "--config", &source_config], r.io(&env))
            .await
            .unwrap();
        cli(&["bootstrap", "--config", &source_config], r.io(&env))
            .await
            .unwrap();
        let tenant_id = r.last()["tenant"]["id"].as_str().unwrap().to_owned();

        // Arguments and files are checked before a database is touched.
        assert_eq!(
            fails(&["store-export", "--config", &source_config], r.io(&env))
                .await
                .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(
                &[
                    "store-import",
                    "--config",
                    &target_config,
                    "--input",
                    "missing.jsonl"
                ],
                r.io(&env)
            )
            .await
            .code(),
            "ENOENT"
        );
        assert!(!target.join("iam.db").exists());
        assert_eq!(
            fails(
                &[
                    "store-copy",
                    "--config",
                    &source_config,
                    "--target-config",
                    &source_config
                ],
                r.io(&env)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );

        let snapshot = s(&folder.path().join("snapshot.jsonl"));
        cli(
            &[
                "store-export",
                "--config",
                &source_config,
                "--output",
                &snapshot,
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        let exported = r.last();
        assert_eq!(exported["output"], json!(snapshot));
        assert!(exported["records"].as_u64().unwrap() > 0);
        assert_eq!(
            fails(
                &[
                    "store-export",
                    "--config",
                    &source_config,
                    "--output",
                    &snapshot
                ],
                r.io(&env)
            )
            .await
            .code(),
            "EEXIST"
        );
        cli(
            &[
                "store-import",
                "--config",
                &target_config,
                "--input",
                &snapshot,
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["records"], exported["records"]);
        assert_eq!(
            r.last()["next"],
            json!("Run migrate to apply plugin migrations.")
        );
        cli(
            &[
                "audit-verify",
                "--config",
                &target_config,
                "--tenant",
                &tenant_id,
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["valid"], json!(true));
        // A second import into the now populated database changes nothing.
        assert!(
            cli(
                &[
                    "store-import",
                    "--config",
                    &target_config,
                    "--input",
                    &snapshot
                ],
                r.io(&env)
            )
            .await
            .is_err()
        );

        cli(
            &[
                "store-copy",
                "--config",
                &source_config,
                "--target-config",
                &copy_config,
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["records"], exported["records"]);
        assert_eq!(r.last()["target"], json!(copy_config));
        cli(&["doctor", "--config", &copy_config], r.io(&env))
            .await
            .unwrap();
        assert_eq!(r.last()["rootInitialized"], json!(true));
    });
}

// --- remote CLI (cli-remote.test.ts) ---------------------------------------------------------------------------------

/// `fetch` that answers through the instance's HTTP handler, as a running server would over the network.
fn handler_fetch(iam: Arc<BetterIam>) -> FetchFn {
    Arc::new(move |call: HttpCall| {
        let iam = iam.clone();
        Box::pin(async move {
            let mut builder = http::Request::builder()
                .method("POST")
                .uri(call.url.as_str());
            for (name, value) in &call.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let request = builder.body(Bytes::from(call.body)).unwrap();
            let response = iam.handler(request).await;
            Ok(HttpReply {
                status: response.status().as_u16(),
                headers: response
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            value.to_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect(),
                body: response.body().to_vec(),
            })
        })
    })
}

const URL: &str = "http://localhost:3000";

#[test]
fn logs_in_once_against_a_server_and_later_commands_act_as_the_saved_session() {
    run(|| async {
        let folder = temp();
        let config = write_config(folder.path(), json!({}));
        let (tenant_id, root_token, mfa_secret) = root_session(&config).await;
        let iam = load_config(LoadConfigOptions {
            config: Some(s(&config)),
            env: Some(Env::new()),
            ..LoadConfigOptions::default()
        })
        .unwrap();
        let credentials = s(&folder.path().join("credentials.json"));
        let r = Recorder::new(Some(folder.path()));
        let remote = |env: &[(&str, String)]| {
            let mut all = vec![("BETTER_IAM_CREDENTIALS", credentials.clone())];
            all.extend(env.iter().cloned());
            let mut io = r.io(&all);
            io.fetch = Some(handler_fetch(iam.clone()));
            io
        };

        // Any route with key=value input, against the server.
        cli(
            &["api", "auth.getSession", "--url", URL],
            remote(&[("BETTER_IAM_TOKEN", root_token.clone())]),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["identity"]["rootAdmin"], json!(true));
        cli(
            &[
                "api",
                "roles.create",
                "--url",
                URL,
                "name=Remote",
                "--tenant",
                &tenant_id,
            ],
            remote(&[("BETTER_IAM_TOKEN", root_token.clone())]),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["name"], json!("Remote"));
        let error = fails(
            &["api", "roles.list", "--url", URL, "--tenant", &tenant_id],
            remote(&[("BETTER_IAM_TOKEN", "not a token".into())]),
        )
        .await;
        assert_eq!(error.code(), "INVALID_TOKEN");
        assert_eq!(
            fails(
                &[
                    "api",
                    "roles.list",
                    "--url",
                    "http://example.com",
                    "--tenant",
                    &tenant_id
                ],
                remote(&[("BETTER_IAM_TOKEN", root_token.clone())])
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
        cli(
            &[
                "api",
                "--list",
                "roles",
                "--url",
                "https://iam.example.com/custom/iam",
            ],
            remote(&[]),
        )
        .await
        .unwrap();
        assert!(r.raw().contains("POST /custom/iam/roles/create"));

        // Password sign-in needs the password from the environment (no prompt without a terminal).
        let sign_in = [
            "login", "--url", URL, "--tenant", &tenant_id, "--email", ROOT_EMAIL,
        ];
        assert_eq!(fails(&sign_in, remote(&[])).await.code(), "MISSING_ENV");
        assert_eq!(
            fails(
                &sign_in,
                remote(&[("BETTER_IAM_PASSWORD", "not the password at all".into())])
            )
            .await
            .code(),
            "INVALID_CREDENTIALS"
        );
        // Root requires MFA: the code comes from BETTER_IAM_MFA_CODE.
        assert_eq!(
            fails(
                &sign_in,
                remote(&[("BETTER_IAM_PASSWORD", ROOT_PASSWORD.into())])
            )
            .await
            .code(),
            "MISSING_ENV"
        );
        let code = totp::generate(&mfa_secret, js::system_now_ms()).unwrap();
        cli(
            &sign_in,
            remote(&[
                ("BETTER_IAM_PASSWORD", ROOT_PASSWORD.into()),
                ("BETTER_IAM_MFA_CODE", code),
            ]),
        )
        .await
        .unwrap();
        let login = r.last();
        assert_eq!(login["profile"], json!("default"));
        assert_eq!(login["url"], json!(format!("{URL}/api/iam")));
        assert_eq!(login["tenantId"], json!(tenant_id));
        let file: Value =
            serde_json::from_str(&std::fs::read_to_string(&credentials).unwrap()).unwrap();
        assert_eq!(file["version"], json!(1));
        assert_eq!(file["current"], json!("default"));
        assert_eq!(file["profiles"]["default"]["email"], json!(ROOT_EMAIL));
        assert_eq!(file["profiles"]["default"]["kind"], json!("user"));
        assert!(!file.to_string().contains(ROOT_PASSWORD));
        let saved_token = file["profiles"]["default"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(!r.lines().join("\n").contains(&saved_token));

        // No token, URL, or tenant: the profile supplies all three.
        cli(&["whoami"], remote(&[])).await.unwrap();
        assert_eq!(r.last()["tenantId"], json!(tenant_id));
        cli(&["can", "documents:read", "documents/a"], remote(&[]))
            .await
            .unwrap();
        assert_eq!(r.last()["allowed"], json!(true));
        cli(&["token"], remote(&[])).await.unwrap();
        assert_eq!(r.raw(), saved_token);

        // A second profile from a token on standard input.
        let mut io = remote(&[]);
        io.stdin = Some(Arc::new({
            let root_token = root_token.clone();
            move || {
                let text = format!("{root_token}\n");
                Box::pin(async move { Ok(text) })
            }
        }));
        cli(
            &["login", "--with-token", "--url", URL, "--profile", "ops"],
            io,
        )
        .await
        .unwrap();
        assert_eq!(r.last()["profile"], json!("ops"));
        cli(&["profiles", "--format", "json"], remote(&[]))
            .await
            .unwrap();
        let listed = r.last();
        assert_eq!(listed[0]["name"], json!("default"));
        assert_eq!(listed[0]["current"], json!(false));
        assert_eq!(listed[1]["name"], json!("ops"));
        assert_eq!(listed[1]["current"], json!(true));
        assert!(!r.raw().contains("token"));
        cli(&["profiles"], remote(&[])).await.unwrap();
        assert!(r.raw().starts_with("NAME"));
        assert!(r.raw().contains("CURRENT"));
        cli(&["whoami", "--profile", "default"], remote(&[]))
            .await
            .unwrap();
        assert_eq!(r.last()["tenantId"], json!(tenant_id));

        // A saved session is never sent to another deployment.
        assert_eq!(
            fails(
                &["whoami", "--url", "https://other.example.com"],
                remote(&[])
            )
            .await
            .code(),
            "MISSING_ENV"
        );
        // Logging in to another deployment never silently replaces the current profile.
        let mut io = remote(&[]);
        io.stdin = Some(Arc::new(|| {
            Box::pin(async { Ok("biam_abcdefghijklmnopqrstuvwxyz".to_owned()) })
        }));
        assert_eq!(
            cli(
                &[
                    "login",
                    "--with-token",
                    "--url",
                    "https://other.example.com"
                ],
                io
            )
            .await
            .unwrap_err()
            .code(),
            "PROFILE_IN_USE"
        );

        cli(&["profiles", "use", "default"], remote(&[]))
            .await
            .unwrap();
        cli(&["logout"], remote(&[])).await.unwrap();
        assert_eq!(
            r.last(),
            json!({ "profile": "default", "revoked": true, "forgotten": true })
        );
        assert_eq!(
            fails(
                &["whoami", "--url", URL],
                remote(&[("BETTER_IAM_TOKEN", saved_token.clone())])
            )
            .await
            .code(),
            "UNAUTHENTICATED"
        );
        assert_eq!(fails(&["whoami"], remote(&[])).await.code(), "MISSING_ENV");
        cli(&["profiles", "use", "ops"], remote(&[])).await.unwrap();
        cli(&["whoami"], remote(&[])).await.unwrap();
        assert_eq!(r.last()["tenantId"], json!(tenant_id));
        assert_eq!(
            fails(&["profiles", "use", "missing"], remote(&[]))
                .await
                .code(),
            "NOT_FOUND"
        );
        assert_eq!(
            fails(&["profiles", "use", "../escape"], remote(&[]))
                .await
                .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(&["logout", "--profile", "missing"], remote(&[]))
                .await
                .code(),
            "NOT_FOUND"
        );

        // A saved session past its end is refused before any request.
        let mut saved: Value =
            serde_json::from_str(&std::fs::read_to_string(&credentials).unwrap()).unwrap();
        saved["profiles"]["ops"]["expiresAt"] = json!(1);
        std::fs::write(&credentials, saved.to_string()).unwrap();
        assert_eq!(
            fails(&["whoami"], remote(&[])).await.code(),
            "SESSION_EXPIRED"
        );
        cli(&["profiles", "remove", "ops"], remote(&[]))
            .await
            .unwrap();
        assert_eq!(r.last(), json!({ "removed": "ops" }));
        iam.store.close().await.unwrap();
    });
}

// --- vault (vault-cli.test.ts) ----------------------------------------------------------------------------------------

#[test]
fn names_environment_variables_after_secret_paths() {
    use better_iam_cli::commands::vault::secret_env_name;
    assert_eq!(
        secret_env_name("prod/app/db-password", "prod/app/"),
        "DB_PASSWORD"
    );
    assert_eq!(
        secret_env_name("prod/app/v2.api-key", "prod/"),
        "APP_V2_API_KEY"
    );
    assert_eq!(secret_env_name("prod/app/1st", "prod/app/"), "_1ST");
}

/// A shell command line for `vault-run`: the platform shell running `script`.
fn shell(script: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), script.into()]
    } else {
        vec!["sh".into(), "-c".into(), script.into()]
    }
}

#[test]
fn puts_gets_and_runs_a_command_with_secrets_in_its_environment() {
    run(|| async {
        let folder = temp();
        let config = s(&write_config(folder.path(), json!({})));
        let (tenant_id, token, _) = root_session(Path::new(&config)).await;
        let r = Recorder::new(Some(folder.path()));
        let env = [
            ("BETTER_IAM_TOKEN", token.clone()),
            ("BETTER_IAM_TENANT", tenant_id.clone()),
            ("KEEP_ME", "yes".to_owned()),
        ];
        let create = |name: &str, extra: Value| {
            let mut body = json!({ "tenantId": tenant_id, "name": name });
            if let (Value::Object(body), Value::Object(extra)) = (&mut body, extra) {
                body.extend(extra);
            }
            body.to_string()
        };
        for body in [
            create(
                "app/db-password",
                json!({ "value": "the-database-password" }),
            ),
            create(
                "app/smtp",
                json!({ "format": "json", "fields": { "host": "smtp.acme.test", "password": "mail-password" } }),
            ),
            create(
                "app/signing-key",
                json!({ "value": "k1", "rotation": { "intervalDays": 1, "generator": { "length": 16 } } }),
            ),
        ] {
            cli(
                &["api", "vault.create", "--config", &config, "--data", &body],
                r.io(&env),
            )
            .await
            .unwrap();
        }

        cli(
            &["vault-put", "app/db-password", "--config", &config],
            r.with_stdin(&env, "rotated-by-cli\n"),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["version"], json!(2));
        assert_eq!(r.last()["stages"], json!(["current"]));
        cli(
            &["vault-get", "app/db-password", "--config", &config],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.raw(), "rotated-by-cli");
        cli(
            &[
                "vault-get",
                "app/smtp",
                "--field",
                "host",
                "--config",
                &config,
            ],
            r.io(&env),
        )
        .await
        .unwrap();
        assert_eq!(r.raw(), "smtp.acme.test");
        assert_eq!(
            fails(
                &[
                    "vault-get",
                    "app/smtp",
                    "--field",
                    "port",
                    "--config",
                    &config
                ],
                r.io(&env)
            )
            .await
            .code(),
            "NOT_FOUND"
        );
        assert_eq!(
            fails(
                &[
                    "vault-get",
                    "app/smtp",
                    "--version",
                    "1",
                    "--stage",
                    "previous",
                    "--config",
                    &config
                ],
                r.io(&env)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );

        let dump = folder.path().join("env.txt");
        let script = if cfg!(windows) {
            format!("set > {}", s(&dump))
        } else {
            format!("env > \"{}\"", s(&dump))
        };
        let mut args = argv(&[
            "vault-run",
            "--config",
            &config,
            "--env",
            "DATABASE_PASSWORD=app/db-password,MAIL_HOST=app/smtp#host",
            "--prefix",
            "app/",
            "--",
        ]);
        args.extend(shell(&script));
        run_cli(&args, Some(r.io(&env))).await.unwrap();
        let dumped = std::fs::read_to_string(&dump).unwrap();
        let vars: std::collections::HashMap<String, String> = dumped
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_uppercase(), value.trim_end_matches('\r').to_owned()))
            .collect();
        for (key, value) in [
            ("DATABASE_PASSWORD", "rotated-by-cli"),
            ("MAIL_HOST", "smtp.acme.test"),
            ("DB_PASSWORD", "rotated-by-cli"),
            ("SMTP_HOST", "smtp.acme.test"),
            ("SMTP_PASSWORD", "mail-password"),
            ("SIGNING_KEY", "k1"),
            ("KEEP_ME", "yes"),
        ] {
            assert_eq!(vars.get(key).map(String::as_str), Some(value), "{key}");
        }
        // The IAM token does not travel to the child.
        assert!(!vars.contains_key("BETTER_IAM_TOKEN"));

        // The command's exit status comes back.
        let mut args = argv(&[
            "vault-run",
            "--config",
            &config,
            "--env",
            "X=app/db-password",
            "--",
        ]);
        args.extend(shell("exit 3"));
        let error = run_cli(&args, Some(r.io(&env))).await.unwrap_err();
        assert_eq!(error.code(), "COMMAND_FAILED");
        assert_eq!(error.exit_status, Some(3));
        assert_eq!(
            better_iam_cli::report_failure(&error, &Env::new(), &|_| {}),
            3
        );
        assert_eq!(
            fails(
                &["vault-run", "--config", &config, "--", "anything"],
                r.io(&env)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(
                &[
                    "vault-run",
                    "--config",
                    &config,
                    "--env",
                    "1BAD=app/x",
                    "--",
                    "anything"
                ],
                r.io(&env)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(
                &[
                    "vault-run",
                    "--config",
                    &config,
                    "--env",
                    "X=app/db-password",
                    "--",
                    "no-such-command-anywhere"
                ],
                r.io(&env)
            )
            .await
            .code(),
            "COMMAND_NOT_FOUND"
        );

        // The scheduler jobs.
        cli(&["vault-rotate-due", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert_eq!(
            r.last(),
            json!({ "rotated": [], "failed": [], "reminded": [] })
        );
        cli(&["vault-expire-leases", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert_eq!(r.last()["expired"], json!(0));
        cli(&["vault-purge-deleted", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert_eq!(r.last(), json!({ "purged": 0 }));
    });
}

// --- operations (cli-detect-threats.test.ts, cli-analyze.test.ts, the scheduler jobs) ---------------------------------

#[test]
fn runs_deployment_operations_and_access_reports() {
    run(|| async {
        let folder = temp();
        let config = s(&write_config(folder.path(), json!({})));
        let (tenant_id, token, _) = root_session(Path::new(&config)).await;
        let r = Recorder::new(Some(folder.path()));
        cli(
            &[
                "detect-threats",
                "--config",
                &config,
                "--tenant",
                &tenant_id,
                "--max-events",
                "5",
            ],
            r.io(&[]),
        )
        .await
        .unwrap();
        assert!(r.last().is_object());
        assert_eq!(
            fails(
                &["detect-threats", "--config", &config, "--max-events", "0"],
                r.io(&[])
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
        cli(&["sweep", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert!(r.last().is_object());
        cli(&["monitor-invariants", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert!(r.last().is_object());
        cli(
            &["rotate-secrets", "--config", &config, "--dry-run"],
            r.io(&[]),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["done"], json!(true));
        cli(&["reconcile", "--config", &config], r.io(&[]))
            .await
            .unwrap();
        assert!(r.last().is_object());
        assert_eq!(
            fails(
                &["reconcile", "--config", &config, "--package", "p1"],
                r.io(&[])
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(
                &[
                    "reconcile",
                    "--config",
                    &config,
                    "--tenant",
                    "t",
                    "--confirm"
                ],
                r.io(&[])
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );

        let as_root = [
            ("BETTER_IAM_TOKEN", token),
            ("BETTER_IAM_TENANT", tenant_id.clone()),
        ];
        cli(&["analyze", "--config", &config], r.io(&as_root))
            .await
            .unwrap();
        assert!(r.last()["findings"].is_array());
        cli(&["report", "--config", &config], r.io(&as_root))
            .await
            .unwrap();
        assert!(r.last().is_object());
        cli(
            &["check-invariants", "--config", &config, "--fail-on-broken"],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert!(r.last()["summary"].is_object());
        cli(
            &[
                "who-can",
                "documents:read",
                "documents/a",
                "--config",
                &config,
                "--format",
                "compact",
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert!(r.last().is_object());
        cli(
            &[
                "explain",
                "documents:read",
                "documents/a",
                "--config",
                &config,
                "--identity",
                ROOT_EMAIL,
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        assert!(r.last()["allowed"].is_boolean());
        assert_eq!(
            fails(
                &[
                    "explain",
                    "documents:read",
                    "documents/a",
                    "--config",
                    &config,
                    "--identity",
                    "nobody@x.test"
                ],
                r.io(&as_root)
            )
            .await
            .code(),
            "NOT_FOUND"
        );
    });
}

// --- SSH (ssh-cli.test.ts) ---------------------------------------------------------------------------------------------

/// An OpenSSH `ssh-ed25519` public key line for a raw 32-byte key (hex).
fn ssh_public_key(hex_key: &str, comment: &str) -> String {
    use base64::Engine as _;
    let key = hex::decode(hex_key).unwrap();
    let mut blob = Vec::new();
    for part in [b"ssh-ed25519".as_slice(), key.as_slice()] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    format!(
        "ssh-ed25519 {} {comment}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

#[test]
fn enrolls_and_syncs_a_host_and_gets_a_person_a_certificate() {
    run(|| async {
        let folder = temp();
        let config = write_config(folder.path(), json!({ "ssh": true }));
        let (tenant_id, token, _) = root_session(&config).await;
        let config_text = s(&config);
        let iam = load_config(LoadConfigOptions {
            config: Some(config_text.clone()),
            env: Some(Env::new()),
            ..LoadConfigOptions::default()
        })
        .unwrap();
        let r = Recorder::new(Some(folder.path()));
        let remote = |env: &[(&str, String)]| {
            let mut io = r.io(env);
            io.fetch = Some(handler_fetch(iam.clone()));
            io
        };
        let as_root = [("BETTER_IAM_TOKEN", token.clone())];
        cli(
            &[
                "api",
                "ssh.setup",
                "--config",
                &config_text,
                &format!("tenantId={tenant_id}"),
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        cli(
            &[
                "api",
                "ssh.createHost",
                "--config",
                &config_text,
                &format!("tenantId={tenant_id}"),
                "name=web-01",
                "logins[]=deploy",
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        let created = r.last();
        let join_token = created["joinToken"].as_str().unwrap().to_owned();
        let host_id = created["host"]["id"].as_str().unwrap().to_owned();
        std::fs::write(
            folder.path().join("host_key.pub"),
            format!(
                "{}\n",
                ssh_public_key(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                    "root@web-01"
                )
            ),
        )
        .unwrap();
        cli(
            &[
                "ssh-host-enroll",
                "--url",
                URL,
                "--host-key",
                "host_key.pub",
                "--root",
                "root",
                "--dry-run",
            ],
            remote(&[("BETTER_IAM_SSH_JOIN_TOKEN", join_token.clone())]),
        )
        .await
        .unwrap();
        // A dry run lists the files (and spends the join token) without writing anything.
        assert!(
            r.last()["files"]
                .as_array()
                .unwrap()
                .contains(&json!("/etc/ssh/better-iam/renewal-token"))
        );
        assert!(!folder.path().join("root").exists());
        cli(
            &[
                "api",
                "ssh.resetJoinToken",
                "--config",
                &config_text,
                &format!("tenantId={tenant_id}"),
                &format!("hostId={host_id}"),
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        let join_token = r.last()["joinToken"].as_str().unwrap().to_owned();
        cli(
            &[
                "ssh-host-enroll",
                "--url",
                URL,
                "--host-key",
                "host_key.pub",
                "--root",
                "root",
            ],
            remote(&[("BETTER_IAM_SSH_JOIN_TOKEN", join_token)]),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["host"], json!("web-01"));
        assert_eq!(r.last()["hostId"], json!(host_id));
        assert!(
            r.notes
                .lock()
                .unwrap()
                .iter()
                .any(|note| note.contains("reload sshd"))
        );
        let etc = folder.path().join("root").join("etc").join("ssh");
        assert_eq!(
            std::fs::read_to_string(etc.join("better-iam").join("principals").join("deploy"))
                .unwrap(),
            "deploy@web-01\n"
        );
        assert_eq!(
            &std::fs::read(etc.join("better-iam").join("revoked.krl")).unwrap()[..6],
            b"SSHKRL"
        );
        assert!(
            std::fs::read_to_string(etc.join("sshd_config.d").join("00-better-iam.conf"))
                .unwrap()
                .contains("TrustedUserCAKeys")
        );
        assert!(
            std::fs::read_to_string(etc.join("better-iam").join("renewal-token"))
                .unwrap()
                .starts_with("biam_sshr.")
        );

        cli(
            &["ssh-host-sync", "--url", URL, "--root", "root"],
            remote(&[]),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["host"], json!("web-01"));
        assert_eq!(r.last()["certificateRenewed"], json!(false));

        // A person gets a certificate next to their key and the known_hosts lines for the host authority.
        std::fs::write(
            folder.path().join("id_ed25519.pub"),
            format!(
                "{}\n",
                ssh_public_key(
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                    "root@laptop"
                )
            ),
        )
        .unwrap();
        cli(
            &[
                "ssh-cert",
                "--url",
                URL,
                "--tenant",
                &tenant_id,
                "--key",
                "id_ed25519.pub",
                "--known-hosts",
                "known_hosts",
                "--ttl-minutes",
                "30",
            ],
            remote(&as_root),
        )
        .await
        .unwrap();
        assert_eq!(r.last()["principals"], json!(["deploy@web-01"]));
        assert_eq!(r.last()["hosts"][0]["name"], json!("web-01"));
        assert!(
            std::fs::read_to_string(folder.path().join("id_ed25519-cert.pub"))
                .unwrap()
                .starts_with("ssh-ed25519-cert-v01@openssh.com ")
        );
        assert!(
            std::fs::read_to_string(folder.path().join("known_hosts"))
                .unwrap()
                .starts_with("@cert-authority web-01 ssh-ed25519 ")
        );
        assert_eq!(
            &std::fs::read(folder.path().join("known_hosts_revoked_hosts")).unwrap()[..6],
            b"SSHKRL"
        );
        assert_eq!(
            fails(
                &[
                    "ssh-cert",
                    "--url",
                    URL,
                    "--tenant",
                    &tenant_id,
                    "--key",
                    "id_ed25519"
                ],
                remote(&as_root)
            )
            .await
            .code(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            fails(
                &[
                    "ssh-cert",
                    "--url",
                    URL,
                    "--tenant",
                    &tenant_id,
                    "--key",
                    "missing.pub"
                ],
                remote(&as_root)
            )
            .await
            .code(),
            "NOT_FOUND"
        );

        // The sweep job runs from the configuration.
        cli(&["ssh-sweep", "--config", &config_text], r.io(&[]))
            .await
            .unwrap();
        assert_eq!(r.last()["examined"], json!(1));
        assert_eq!(r.last()["revoked"], json!(0));

        // A login removed from the host: the next sync deletes its principals file.
        cli(
            &[
                "api",
                "ssh.updateHost",
                "--config",
                &config_text,
                &format!("tenantId={tenant_id}"),
                &format!("hostId={host_id}"),
                "logins[]=ops",
            ],
            r.io(&as_root),
        )
        .await
        .unwrap();
        cli(
            &["ssh-host-sync", "--url", URL, "--root", "root"],
            remote(&[]),
        )
        .await
        .unwrap();
        assert!(
            r.last()["files"]
                .as_array()
                .unwrap()
                .contains(&json!("-/etc/ssh/better-iam/principals/deploy"))
        );
        let principals: Vec<String> = std::fs::read_dir(etc.join("better-iam").join("principals"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(principals, vec!["ops".to_owned()]);
        assert_eq!(
            fails(
                &["ssh-host-sync", "--url", URL, "--root", "elsewhere"],
                remote(&[])
            )
            .await
            .code(),
            "NOT_FOUND"
        );
        iam.store.close().await.unwrap();
    });
}
