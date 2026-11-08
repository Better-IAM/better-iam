//! Saved sessions (`profiles.ts`): the credentials file `login`, `logout`, `profiles`, and token commands share.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use better_iam_core::js;
use better_iam_server::metrics::locale_compare;
use regex::Regex;
use serde_json::{Map, Value};

use crate::errors::{CliError, CliResult, io_error, usage_error};
use crate::framework::Env;
use crate::output::stringify;
use crate::paths::resolve_path;

/// A signed-in session saved by `better-iam login`, so later commands act as it without `BETTER_IAM_TOKEN`. It belongs
/// to one deployment: a remote endpoint (`url`) or the configuration it was created with (`config`) (`StoredProfile`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoredProfile {
    /// The IAM endpoint (`https://host/api/iam`) the session was issued by, for remote commands.
    pub url: Option<String>,
    /// The configuration file the session was issued through, for in-process commands.
    pub config: Option<String>,
    /// The session was issued through the environment-only deployment (`BETTER_IAM_DATABASE_URL`, no file).
    pub env_config: Option<bool>,
    pub tenant_id: Option<String>,
    pub identity_id: Option<String>,
    pub email: Option<String>,
    /// Session kind: `user`, `api-key`, `role`, or `session-token`.
    pub kind: Option<String>,
    /// The bearer token. The file is written with owner-only permissions; treat it like a password.
    pub token: String,
    /// When the session ends (epoch ms), when known.
    pub expires_at: Option<f64>,
    pub saved_at: f64,
}

impl StoredProfile {
    /// The profile as the file stores it, in the TypeScript member order.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        if let Some(url) = &self.url {
            map.insert("url".into(), Value::String(url.clone()));
        }
        if let Some(config) = &self.config {
            map.insert("config".into(), Value::String(config.clone()));
        }
        if let Some(env_config) = self.env_config {
            map.insert("envConfig".into(), Value::Bool(env_config));
        }
        map.insert("token".into(), Value::String(self.token.clone()));
        if let Some(tenant_id) = &self.tenant_id {
            map.insert("tenantId".into(), Value::String(tenant_id.clone()));
        }
        if let Some(identity_id) = &self.identity_id {
            map.insert("identityId".into(), Value::String(identity_id.clone()));
        }
        if let Some(email) = &self.email {
            map.insert("email".into(), Value::String(email.clone()));
        }
        if let Some(kind) = &self.kind {
            map.insert("kind".into(), Value::String(kind.clone()));
        }
        if let Some(expires_at) = self.expires_at {
            map.insert(
                "expiresAt".into(),
                js::number(expires_at).unwrap_or(Value::Null),
            );
        }
        map.insert(
            "savedAt".into(),
            js::number(self.saved_at).unwrap_or(Value::Null),
        );
        Value::Object(map)
    }

    /// Reads a stored profile (members of the wrong type count as absent).
    pub fn from_value(value: &Value) -> Self {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
        let number = |key: &str| value.get(key).and_then(js::as_number);
        Self {
            url: text("url"),
            config: text("config"),
            env_config: value.get("envConfig").and_then(Value::as_bool),
            tenant_id: text("tenantId"),
            identity_id: text("identityId"),
            email: text("email"),
            kind: text("kind"),
            token: text("token").unwrap_or_default(),
            expires_at: number("expiresAt"),
            saved_at: number("savedAt").unwrap_or(0.0),
        }
    }

    /// `profile[field]` for flags filled from the saved session (`FlagSpec.profile`).
    pub fn field(&self, name: &str) -> Option<&str> {
        match name {
            "tenantId" => self.tenant_id.as_deref(),
            _ => None,
        }
    }
}

/// A profile as listed by `better-iam profiles`: everything except the token (`ProfileSummary`), as JSON in the
/// member order of `{ name, current, ...rest }`.
pub type ProfileSummary = Value;

#[derive(Debug, Clone, Default)]
struct CredentialsFile {
    current: Option<String>,
    profiles: Map<String, Value>,
}

impl CredentialsFile {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("version".into(), Value::from(1));
        if let Some(current) = &self.current {
            map.insert("current".into(), Value::String(current.clone()));
        }
        map.insert("profiles".into(), Value::Object(self.profiles.clone()));
        Value::Object(map)
    }
}

static PROFILE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,64}$").expect("regex"));

/// `defaultProfile`.
pub const DEFAULT_PROFILE: &str = "default";

fn non_empty<'a>(env: &'a Env, key: &str) -> Option<&'a String> {
    env.get(key).filter(|value| !value.is_empty())
}

/// Where saved sessions live: `BETTER_IAM_CREDENTIALS`, else `%APPDATA%\better-iam\credentials.json` on Windows, else
/// `$XDG_CONFIG_HOME/better-iam/credentials.json` or `~/.config/better-iam/credentials.json`. Read only from the given
/// environment, so an embedding program (and every test) decides whether a profile can be found at all
/// (`credentialsPath`).
pub fn credentials_path(env: &Env) -> Option<PathBuf> {
    if let Some(path) = non_empty(env, "BETTER_IAM_CREDENTIALS") {
        let cwd = std::env::current_dir().unwrap_or_default();
        return Some(resolve_path(&cwd, Path::new(path)));
    }
    if cfg!(windows)
        && let Some(appdata) = non_empty(env, "APPDATA")
    {
        return Some(
            Path::new(appdata)
                .join("better-iam")
                .join("credentials.json"),
        );
    }
    let home = non_empty(env, "HOME").or_else(|| non_empty(env, "USERPROFILE"));
    let base = non_empty(env, "XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.map(|home| Path::new(home).join(".config")));
    base.map(|base| base.join("better-iam").join("credentials.json"))
}

/// `assertProfileName(name)`.
pub fn assert_profile_name(name: &str) -> CliResult<String> {
    if !PROFILE_NAME.is_match(name) {
        return Err(usage_error(
            "Profile names use letters, digits, dot, dash, and underscore (at most 64)",
            None,
        ));
    }
    Ok(name.to_owned())
}

/// Reads and writes the saved-session file. Every write replaces the file atomically with mode 0600 (`ProfileStore`).
#[derive(Debug, Clone)]
pub struct ProfileStore {
    /// The file in use, or None when the environment names no home or config directory.
    pub path: Option<PathBuf>,
    env: Env,
}

/// Opens the saved-session file that `login`, `logout`, `profiles`, and token commands use, located from `env` (see
/// [`credentials_path`]) (`createProfileStore`).
pub fn create_profile_store(env: &Env) -> ProfileStore {
    ProfileStore {
        path: credentials_path(env),
        env: env.clone(),
    }
}

impl ProfileStore {
    fn read(&self) -> CliResult<CredentialsFile> {
        let Some(path) = &self.path else {
            return Ok(CredentialsFile::default());
        };
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CredentialsFile::default());
            }
            Err(error) => return Err(io_error(&error, "open", path)),
        };
        let invalid = || {
            CliError::hinted(
                "INVALID_CREDENTIALS_FILE",
                format!("{} is not a Better IAM credentials file", path.display()),
                "Delete it or point BETTER_IAM_CREDENTIALS at another file, then run better-iam login.",
            )
        };
        let parsed = js::parse(&raw).map_err(|_| invalid())?;
        let version_ok = parsed.get("version").and_then(js::as_number) == Some(1.0);
        let Some(Value::Object(profiles)) = parsed.get("profiles").filter(|_| version_ok) else {
            return Err(invalid());
        };
        Ok(CredentialsFile {
            current: parsed
                .get("current")
                .and_then(Value::as_str)
                .map(str::to_owned),
            profiles: profiles.clone(),
        })
    }

    fn write(&self, file: &CredentialsFile) -> CliResult<()> {
        let Some(path) = &self.path else {
            return Err(CliError::hinted(
                "NO_CREDENTIALS_FILE",
                "No place to save sessions: HOME, APPDATA, and XDG_CONFIG_HOME are all unset",
                "Set BETTER_IAM_CREDENTIALS to a file path.",
            ));
        };
        if let Some(parent) = path.parent() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(parent)
                .map_err(|error| io_error(&error, "mkdir", parent))?;
        }
        let suffix = hex::encode(rand::random::<[u8; 6]>());
        let temporary = PathBuf::from(format!("{}.{suffix}.tmp", path.display()));
        let body = format!("{}\n", stringify(&file.to_value(), Some(2)));
        let result = (|| -> CliResult<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut handle = options
                .open(&temporary)
                .map_err(|error| io_error(&error, "open", &temporary))?;
            handle
                .write_all(body.as_bytes())
                .map_err(|error| io_error(&error, "write", &temporary))?;
            drop(handle);
            std::fs::rename(&temporary, path).map_err(|error| io_error(&error, "rename", path))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// `--profile`, else `BETTER_IAM_PROFILE`, else the file's current profile, else `default` (`currentName`).
    pub fn current_name(&self, explicit: Option<&str>) -> CliResult<String> {
        if let Some(explicit) = explicit.filter(|name| !name.is_empty()) {
            return assert_profile_name(explicit);
        }
        if let Some(named) = non_empty(&self.env, "BETTER_IAM_PROFILE") {
            return assert_profile_name(named);
        }
        let file = self.read()?;
        assert_profile_name(
            file.current
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or(DEFAULT_PROFILE),
        )
    }

    pub fn get(&self, name: &str) -> CliResult<Option<StoredProfile>> {
        let file = self.read()?;
        Ok(file.profiles.get(name).map(StoredProfile::from_value))
    }

    /// Every saved profile without its token, sorted by name, the current one marked (`list`).
    pub fn list(&self, explicit: Option<&str>) -> CliResult<Vec<ProfileSummary>> {
        let file = self.read()?;
        let current = self.current_name(explicit)?;
        let mut entries: Vec<(&String, &Value)> = file.profiles.iter().collect();
        entries.sort_by(|a, b| locale_compare(a.0, b.0));
        Ok(entries
            .into_iter()
            .map(|(name, profile)| {
                let mut summary = Map::new();
                summary.insert("name".into(), Value::String(name.clone()));
                summary.insert("current".into(), Value::Bool(*name == current));
                if let Value::Object(members) = profile {
                    for (key, value) in js::entries(members) {
                        if key != "token" {
                            summary.insert(key.clone(), value.clone());
                        }
                    }
                }
                Value::Object(summary)
            })
            .collect())
    }

    pub fn save(&self, name: &str, profile: &StoredProfile, make_current: bool) -> CliResult<()> {
        assert_profile_name(name)?;
        let mut file = self.read()?;
        file.profiles.insert(name.to_owned(), profile.to_value());
        if make_current {
            file.current = Some(name.to_owned());
        }
        self.write(&file)
    }

    pub fn remove(&self, name: &str) -> CliResult<bool> {
        let mut file = self.read()?;
        if file.profiles.shift_remove(name).is_none() {
            return Ok(false);
        }
        if file.current.as_deref() == Some(name) {
            file.current = None;
        }
        self.write(&file)?;
        Ok(true)
    }

    pub fn use_profile(&self, name: &str) -> CliResult<()> {
        let mut file = self.read()?;
        assert_profile_name(name)?;
        if !file.profiles.contains_key(name) {
            return Err(CliError::hinted(
                "NOT_FOUND",
                format!("No saved profile named {name}"),
                "Run better-iam profiles to list them.",
            ));
        }
        file.current = Some(name.to_owned());
        self.write(&file)
    }
}
