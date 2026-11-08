//! Configuration loading (`config.ts`).
//!
//! The npm CLI imports a JavaScript configuration module (`better-iam.config.mjs`); this CLI reads the language-neutral
//! standalone configuration every implementation shares, `better-iam.json` (spec/conformance/CONFIG.md), with one
//! extra member the CLI removes before building the instance: `cli` (`{ "defaults": { command: { flag: value } } }`),
//! the counterpart of the module's named `cli` export. Project commands, which a JSON file cannot hold, are added in
//! code with [`crate::create_cli`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use better_iam_core::{IamError, js};
use better_iam_server::index::{BetterIam, better_iam};
use better_iam_server::standalone_config::{ConfigRuntime, options_from_config};
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::errors::{CliError, CliResult};
use crate::framework::Env;
use crate::paths::{home_dir, resolve_path};

/// Configuration file names the CLI looks for, in this order, in the working directory and then each parent up to the
/// repository root or home directory (`configFileNames`).
pub const CONFIG_FILE_NAMES: [&str; 1] = ["better-iam.json"];

/// What a configuration is instantiated for (`ConfigContext`): the command and the environment `{"env": "NAME"}`
/// values read.
#[derive(Debug, Clone, Default)]
pub struct ConfigContext {
    /// The CLI command being run (`migrate`, `api`, a custom command), or None outside the CLI.
    pub command: Option<String>,
    pub env: Env,
    pub cwd: PathBuf,
}

/// Settings the CLI reads from the configuration's `cli` member: defaults for the flags of commands that load the
/// configuration or act as a token (`'*'` applies to every such command that has the flag), used when neither the flag
/// nor its environment variable is set (`CliSettings`).
#[derive(Debug, Clone, Default)]
pub struct CliSettings {
    pub defaults: Map<String, Value>,
}

/// A loaded configuration file (`ConfigModule`): the deployment options (the file without `cli`) and the CLI
/// settings. `None` options: no configuration was found (`{}` in TypeScript).
#[derive(Debug, Clone, Default)]
pub struct ConfigModule {
    pub path: Option<PathBuf>,
    pub options: Option<Value>,
    pub cli: CliSettings,
}

/// Where a configuration was found (`ResolvedConfigPath`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfigPath {
    pub path: PathBuf,
    pub source: ConfigSource,
}

/// `flag`, `env`, `discovered`, or `profile` (the configuration a saved session was issued through).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Flag,
    Env,
    Discovered,
    Profile,
}

/// Whether a found configuration may be read without being named: on POSIX systems, a file another user owns, or one
/// in a directory anyone may write to (such as /tmp), could have been planted there.
fn trustworthy(candidate: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let Ok(file) = std::fs::metadata(candidate) else {
            return false;
        };
        let Some(parent) = candidate.parent() else {
            return false;
        };
        let Ok(directory) = std::fs::metadata(parent) else {
            return false;
        };
        (file.uid() == uid || file.uid() == 0) && (directory.mode() & 0o002) == 0
    }
    #[cfg(not(unix))]
    {
        let _ = candidate;
        true
    }
}

/// The nearest configuration file in `cwd` or one of its parents, without leaving the repository: the search stops at
/// the repository root (a directory holding `.git`) or the home directory, and skips files another user could have
/// planted (`findConfigFile`).
pub fn find_config_file(cwd: &Path) -> Option<PathBuf> {
    let mut directory = resolve_path(cwd, Path::new("."));
    let home = home_dir().map(|home| resolve_path(&home, Path::new(".")));
    loop {
        for name in CONFIG_FILE_NAMES {
            let candidate = directory.join(name);
            if candidate.exists() && trustworthy(&candidate) {
                return Some(candidate);
            }
        }
        if home.as_ref() == Some(&directory) || directory.join(".git").exists() {
            return None;
        }
        let parent = directory.parent()?.to_path_buf();
        if parent == directory {
            return None;
        }
        directory = parent;
    }
}

/// `--config`, else `BETTER_IAM_CONFIG`, else the nearest configuration file; None when there is none
/// (`resolveConfigPath`).
pub fn resolve_config_path(
    flag: Option<&str>,
    env: &Env,
    cwd: &Path,
) -> Option<ResolvedConfigPath> {
    if let Some(flag) = flag.filter(|flag| !flag.is_empty()) {
        return Some(ResolvedConfigPath {
            path: resolve_path(cwd, Path::new(flag)),
            source: ConfigSource::Flag,
        });
    }
    if let Some(named) = env
        .get("BETTER_IAM_CONFIG")
        .filter(|value| !value.is_empty())
    {
        return Some(ResolvedConfigPath {
            path: resolve_path(cwd, Path::new(named)),
            source: ConfigSource::Env,
        });
    }
    find_config_file(cwd).map(|path| ResolvedConfigPath {
        path,
        source: ConfigSource::Discovered,
    })
}

/// Reads a configuration file, with readable errors for the usual mistakes (`importConfigModule`).
pub fn import_config_module(path: &Path) -> CliResult<ConfigModule> {
    if !path.exists() {
        return Err(CliError::hinted(
            "CONFIG_NOT_FOUND",
            format!("Configuration {} does not exist", path.display()),
            "Run better-iam init to create one, pass --config PATH, or set BETTER_IAM_CONFIG.",
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| crate::errors::io_error(&error, "open", path))?;
    let mut parsed = js::parse(&text).map_err(|error| {
        CliError::hinted(
            "CONFIG_LOAD_FAILED",
            format!("Configuration {} is not valid JSON: {error}", path.display()),
            "The Rust CLI reads better-iam.json (spec/conformance/CONFIG.md); JavaScript configuration modules need the Node.js CLI.",
        )
    })?;
    let mut cli = CliSettings::default();
    if let Value::Object(map) = &mut parsed
        && let Some(settings) = map.shift_remove("cli")
    {
        match settings {
            Value::Object(settings) => match settings.get("defaults") {
                None => {}
                Some(Value::Object(defaults)) => cli.defaults = defaults.clone(),
                Some(_) => {
                    return Err(IamError::new(
                        "INVALID_CONFIG",
                        "Invalid better-iam.json: cli.defaults must be an object",
                    )
                    .into());
                }
            },
            _ => {
                return Err(IamError::new(
                    "INVALID_CONFIG",
                    "Invalid better-iam.json: cli must be an object",
                )
                .into());
            }
        }
    }
    Ok(ConfigModule {
        path: Some(path.to_path_buf()),
        options: Some(parsed),
        cli,
    })
}

/// The runtime a configuration is read with: `{"env": "NAME"}` values come from the command's environment.
fn runtime(env: &Env) -> ConfigRuntime {
    ConfigRuntime {
        env: Some(
            env.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>(),
        ),
        ..ConfigRuntime::default()
    }
}

/// Creates the IAM instance a configuration describes (`instantiate`).
pub fn instantiate(module: &ConfigModule, context: &ConfigContext) -> CliResult<Arc<BetterIam>> {
    let Some(options) = &module.options else {
        return Err(IamError::new(
            "INVALID_CONFIG",
            "Configuration must export a default options object or factory",
        )
        .into());
    };
    from_config(options, &context.env)
}

/// An instance from a standalone configuration value.
pub fn from_config(config: &Value, env: &Env) -> CliResult<Arc<BetterIam>> {
    let options = options_from_config(config, &runtime(env))?;
    Ok(Arc::new(better_iam(options)?))
}

/// What [`load_config`] takes (`loadConfig(options)`).
#[derive(Debug, Clone, Default)]
pub struct LoadConfigOptions {
    pub config: Option<String>,
    pub cwd: Option<PathBuf>,
    pub env: Option<Env>,
    pub command: Option<String>,
}

/// Loads a configuration file and creates its instance: the same resolution the CLI uses, for programs, workers, and
/// tests that want `better-iam.json` without the command line. Close `instance.store` when done (`loadConfig`).
pub fn load_config(options: LoadConfigOptions) -> CliResult<Arc<BetterIam>> {
    let cwd = options
        .cwd
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let env = options
        .env
        .clone()
        .unwrap_or_else(crate::framework::process_env);
    let Some(located) = resolve_config_path(options.config.as_deref(), &env, &cwd) else {
        if env
            .get("BETTER_IAM_DATABASE_URL")
            .is_some_and(|url| !url.is_empty())
        {
            return from_config(&config_from_env(&env)?, &env);
        }
        return Err(CliError::hinted(
            "CONFIG_NOT_FOUND",
            format!(
                "No {} in {} or its parents",
                CONFIG_FILE_NAMES[0],
                cwd.display()
            ),
            "Run better-iam init, pass --config PATH, set BETTER_IAM_CONFIG, or set BETTER_IAM_DATABASE_URL and BETTER_IAM_SECRET.",
        ));
    };
    instantiate(
        &import_config_module(&located.path)?,
        &ConfigContext {
            command: options.command,
            env,
            cwd,
        },
    )
}

fn list(value: Option<&String>) -> Option<Vec<String>> {
    value.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

static POSTGRES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^postgres(?:ql)?://").expect("regex"));
static SQLITE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^sqlite:").expect("regex"));
static SQLITE_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^sqlite:(//)?").expect("regex"));
static LIBSQL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(libsql|wss?|https?)://").expect("regex"));
static FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^file:").expect("regex"));
static SQLITE_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(db|sqlite3?)$").expect("regex"));

/// Deployment options from environment variables alone (twelve-factor style), for containers and CI jobs that have no
/// configuration file, as the standalone configuration they describe (`configFromEnv`):
///
/// - `BETTER_IAM_DATABASE_URL` (required): `postgres://…`, `sqlite:./iam.db` (or a path ending in `.db`), or
///   `libsql://…` / `file:…` (needs the `libsql` feature; `BETTER_IAM_DATABASE_TOKEN` authenticates)
/// - `BETTER_IAM_SECRET` (required), `BETTER_IAM_PREVIOUS_SECRETS` (comma-separated, during a rotation)
/// - `BETTER_IAM_BASE_URL` (default `http://localhost:3000`), `BETTER_IAM_BASE_PATH`, `BETTER_IAM_TRUSTED_ORIGINS`
pub fn config_from_env(env: &Env) -> CliResult<Value> {
    let Some(url) = env
        .get("BETTER_IAM_DATABASE_URL")
        .filter(|url| !url.is_empty())
    else {
        return Err(IamError::new("MISSING_ENV", "Set BETTER_IAM_DATABASE_URL").into());
    };
    let Some(secret) = env
        .get("BETTER_IAM_SECRET")
        .filter(|secret| !secret.is_empty())
    else {
        return Err(IamError::new("MISSING_ENV", "Set BETTER_IAM_SECRET").into());
    };
    let store = if POSTGRES.is_match(url) {
        json!({ "kind": "postgres", "url": url })
    } else if SQLITE.is_match(url) {
        let filename = SQLITE_PREFIX.replace(url, "").into_owned();
        json!({ "kind": "sqlite", "path": if filename.is_empty() { ":memory:".to_owned() } else { filename } })
    } else if LIBSQL.is_match(url) || FILE.is_match(url) {
        if !cfg!(feature = "libsql") {
            return Err(CliError::hinted(
                "MISSING_DEPENDENCY",
                "A libSQL database URL needs the libsql feature of better-iam-cli",
                "Install it with that feature (cargo install better-iam-cli --features libsql).",
            ));
        }
        let mut store = Map::new();
        store.insert("kind".into(), json!("libsql"));
        store.insert("url".into(), json!(url));
        if let Some(token) = env
            .get("BETTER_IAM_DATABASE_TOKEN")
            .filter(|token| !token.is_empty())
        {
            store.insert("authToken".into(), json!(token));
        }
        Value::Object(store)
    } else if SQLITE_FILE.is_match(url) || url == ":memory:" {
        json!({ "kind": "sqlite", "path": url })
    } else {
        return Err(IamError::new(
            "INVALID_CONFIG",
            "BETTER_IAM_DATABASE_URL must be postgres://…, sqlite:PATH, file:PATH, or libsql://…",
        )
        .into());
    };
    let previous_secrets = list(env.get("BETTER_IAM_PREVIOUS_SECRETS"));
    let trusted_origins = list(env.get("BETTER_IAM_TRUSTED_ORIGINS"));
    let mut config = Map::new();
    config.insert("store".into(), store);
    config.insert("secret".into(), json!(secret));
    config.insert(
        "baseURL".into(),
        json!(
            env.get("BETTER_IAM_BASE_URL")
                .cloned()
                .unwrap_or_else(|| "http://localhost:3000".to_owned())
        ),
    );
    if let Some(base_path) = env
        .get("BETTER_IAM_BASE_PATH")
        .filter(|path| !path.is_empty())
    {
        config.insert("basePath".into(), json!(base_path));
    }
    if let Some(previous) = previous_secrets.filter(|items| !items.is_empty()) {
        config.insert("previousSecrets".into(), json!(previous));
    }
    if let Some(origins) = trusted_origins.filter(|items| !items.is_empty()) {
        config.insert("trustedOrigins".into(), json!(origins));
    }
    Ok(Value::Object(config))
}
