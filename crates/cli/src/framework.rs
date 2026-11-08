//! The command framework (`framework.ts`): command and flag specifications, help, the manifest, argument parsing,
//! flag sources (command line, environment, configuration defaults, saved session), and the command context.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use better_iam_server::index::BetterIam;
use better_iam_server::metrics::locale_compare;
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::config::{
    CONFIG_FILE_NAMES, ConfigContext, ConfigModule, ConfigSource, ResolvedConfigPath,
    config_from_env, from_config, import_config_module, instantiate, resolve_config_path,
};
use crate::errors::{CliError, CliResult, did_you_mean, usage_error};
use crate::output::{OUTPUT_FORMATS, OutputFormat, format_result, stringify};
use crate::paths::{display, resolve_path};
use crate::profiles::{ProfileStore, StoredProfile, create_profile_store};
use crate::transport::{ApiTransport, FetchFn, local_transport, remote_transport, same_endpoint};

/// The environment a command reads (tokens, defaults, credentials file); never the process environment implicitly.
pub type Env = HashMap<String, String>;

/// The process environment (`process.env`).
pub fn process_env() -> Env {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

/// A line writer (stdout or stderr).
pub type LineFn = Arc<dyn Fn(&str) + Send + Sync>;
/// Asks the person a question; the flag is `hidden` (passwords).
pub type PromptFn =
    Arc<dyn Fn(String, bool) -> BoxFuture<'static, CliResult<String>> + Send + Sync>;
/// Reads all of standard input.
pub type StdinFn = Arc<dyn Fn() -> BoxFuture<'static, CliResult<String>> + Send + Sync>;

/// Where the CLI writes, reads, and prompts. Everything is injectable so programs and tests can run commands
/// (`CliIO`).
#[derive(Clone)]
pub struct CliIo {
    /// Command results (stdout).
    pub out: LineFn,
    /// The environment the command reads (tokens, defaults, credentials file).
    pub env: Env,
    /// Progress and warnings (stderr). Silent when absent.
    pub err: Option<LineFn>,
    /// Asks the person a question. Absent in non-interactive runs, which then fail instead.
    pub prompt: Option<PromptFn>,
    /// Reads all of standard input (`--data -`, `login --with-token`).
    pub stdin: Option<StdinFn>,
    /// The directory relative paths and configuration discovery start from (default: the working directory).
    pub cwd: Option<PathBuf>,
    /// The Fetch implementation remote (`--url`) calls use (default: HTTP(S) over the network).
    pub fetch: Option<FetchFn>,
}

impl CliIo {
    /// An IO that writes results to `out` and reads `env`, with nothing else.
    pub fn new(out: LineFn, env: Env) -> Self {
        Self {
            out,
            env,
            err: None,
            prompt: None,
            stdin: None,
            cwd: None,
            fetch: None,
        }
    }
}

/// `string`, `integer`, or `boolean`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagType {
    String,
    Integer,
    Boolean,
}

/// A parsed flag value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl FlagValue {
    fn to_json(&self) -> Value {
        match self {
            Self::String(text) => Value::String(text.clone()),
            Self::Integer(number) => Value::from(*number),
            Self::Boolean(flag) => Value::Bool(*flag),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::String(text) => text.clone(),
            Self::Integer(number) => number.to_string(),
            Self::Boolean(flag) => flag.to_string(),
        }
    }
}

/// One flag of a command (`FlagSpec`).
#[derive(Debug, Clone)]
pub struct FlagSpec {
    pub kind: FlagType,
    /// What one line of help says the flag does.
    pub description: String,
    /// Placeholder in usage lines (`PATH`, `TENANT_ID`, `N`); defaults by type.
    pub value: Option<String>,
    pub required: bool,
    /// An environment variable read when the flag is not given, for example `BETTER_IAM_TENANT`.
    pub env: Option<String>,
    /// Allowed values of a string flag.
    pub choices: Option<Vec<String>>,
    /// Bounds of an integer flag.
    pub min: Option<i64>,
    pub max: Option<i64>,
    /// The default the command applies, shown in help (the command applies it itself).
    pub default: Option<FlagValue>,
    /// Token commands: the saved profile field used when neither the flag nor its variable is set.
    pub profile: Option<String>,
    /// Left out of help and completion (still accepted).
    pub hidden: bool,
    /// `false`: a `cli.defaults['*']` entry never fills this flag, only one for this very command.
    pub wildcard_default: bool,
}

impl FlagSpec {
    fn of(kind: FlagType, description: &str) -> Self {
        Self {
            kind,
            description: description.to_owned(),
            value: None,
            required: false,
            env: None,
            choices: None,
            min: None,
            max: None,
            default: None,
            profile: None,
            hidden: false,
            wildcard_default: true,
        }
    }

    pub fn string(description: &str) -> Self {
        Self::of(FlagType::String, description)
    }

    pub fn integer(description: &str) -> Self {
        Self::of(FlagType::Integer, description)
    }

    pub fn boolean(description: &str) -> Self {
        Self::of(FlagType::Boolean, description)
    }

    pub fn value(mut self, placeholder: &str) -> Self {
        self.value = Some(placeholder.to_owned());
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn env(mut self, name: &str) -> Self {
        self.env = Some(name.to_owned());
        self
    }

    pub fn choices(mut self, choices: &[&str]) -> Self {
        self.choices = Some(choices.iter().map(|choice| (*choice).to_owned()).collect());
        self
    }

    pub fn min(mut self, min: i64) -> Self {
        self.min = Some(min);
        self
    }

    pub fn max(mut self, max: i64) -> Self {
        self.max = Some(max);
        self
    }

    pub fn default_text(mut self, value: &str) -> Self {
        self.default = Some(FlagValue::String(value.to_owned()));
        self
    }

    pub fn default_number(mut self, value: i64) -> Self {
        self.default = Some(FlagValue::Integer(value));
        self
    }

    pub fn profile(mut self, field: &str) -> Self {
        self.profile = Some(field.to_owned());
        self
    }

    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    pub fn no_wildcard_default(mut self) -> Self {
        self.wildcard_default = false;
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = description.to_owned();
        self
    }
}

/// The flags of a command, in declaration order (keys are flag names without `--`).
pub type FlagSpecs = Vec<(String, FlagSpec)>;

/// A positional argument (`ArgSpec`).
#[derive(Debug, Clone)]
pub struct ArgSpec {
    pub name: String,
    pub description: String,
    pub required: bool,
    /// Collects every remaining positional argument. Only the last argument may be variadic.
    pub variadic: bool,
}

impl ArgSpec {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            required: false,
            variadic: false,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn variadic(mut self) -> Self {
        self.variadic = true;
        self
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert(
            "description".into(),
            Value::String(self.description.clone()),
        );
        if self.required {
            map.insert("required".into(), Value::Bool(true));
        }
        if self.variadic {
            map.insert("variadic".into(), Value::Bool(true));
        }
        Value::Object(map)
    }
}

/// - `Config`: a deployment operation; loads the configuration (`--config`, `BETTER_IAM_CONFIG`, or the nearest
///   `better-iam.json`) and runs with no credential.
/// - `Token`: acts as a session or API key (`BETTER_IAM_TOKEN` or the profile saved by `login`), in process through
///   the configuration or remotely with `--url`; authorized and audited like any client.
/// - `None`: needs neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandTarget {
    Config,
    Token,
    None,
}

impl CommandTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Token => "token",
            Self::None => "none",
        }
    }
}

/// `json` commands take `--format` / `--query`; `text` commands print plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutput {
    Json,
    Text,
}

/// The parsed flags a command receives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags(pub IndexMap<String, FlagValue>);

impl Flags {
    /// A string flag's value (`flags.name`), when set.
    pub fn string(&self, name: &str) -> Option<&str> {
        match self.0.get(name) {
            Some(FlagValue::String(text)) => Some(text.as_str()),
            _ => None,
        }
    }

    /// An integer flag's value, when set.
    pub fn integer(&self, name: &str) -> Option<i64> {
        match self.0.get(name) {
            Some(FlagValue::Integer(number)) => Some(*number),
            _ => None,
        }
    }

    /// A boolean flag (false when absent).
    pub fn boolean(&self, name: &str) -> bool {
        matches!(self.0.get(name), Some(FlagValue::Boolean(true)))
    }

    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// The output format (`flags.format`).
    pub fn format(&self) -> Option<OutputFormat> {
        self.string("format").and_then(OutputFormat::parse)
    }

    /// `--query`.
    pub fn query(&self) -> Option<&str> {
        self.string("query")
    }
}

/// Cross-flag checks after parsing, before the command runs (`validate`). `explicit` names the flags given on the
/// command line.
pub type ValidateFn =
    Arc<dyn Fn(&Flags, &[String], &HashSet<String>) -> CliResult<()> + Send + Sync>;
/// A command's body: its result is printed with `--format` / `--query` (None prints nothing).
pub type RunFn =
    Arc<dyn Fn(Arc<CommandContext>) -> BoxFuture<'static, CliResult<Option<Value>>> + Send + Sync>;

/// A command (`CommandSpec`).
#[derive(Clone)]
pub struct CommandSpec {
    pub name: String,
    /// Section in `help`: Setup, Operations, Audit, Storage, Access, API, Session, Shell, or your own.
    pub group: Option<String>,
    /// One line, starting with a verb.
    pub summary: String,
    /// Paragraphs of detail for `help <command>` and the reference documentation.
    pub description: Option<String>,
    /// Replaces the generated usage line.
    pub usage: Option<String>,
    pub flags: FlagSpecs,
    pub args: Vec<ArgSpec>,
    pub examples: Vec<String>,
    pub aliases: Vec<String>,
    pub target: CommandTarget,
    pub output: CommandOutput,
    /// The format used when `--format` is not given (default `json`).
    pub default_format: Option<OutputFormat>,
    /// Whether `cli.defaults` from the configuration apply (reads the configuration before the command runs).
    pub config_defaults: bool,
    pub validate: Option<ValidateFn>,
    pub run: RunFn,
}

impl std::fmt::Debug for CommandSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSpec")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Declares a command with flags (`defineCommand`): add project commands (seeding, reports, migrations of your own)
/// with [`crate::create_cli`]; they get the same flag parsing, help, configuration loading, and output formatting as
/// the built-in ones.
pub fn define_command<F, Fut>(name: &str, summary: &str, run: F) -> CommandSpec
where
    F: Fn(Arc<CommandContext>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = CliResult<Option<Value>>> + Send + 'static,
{
    CommandSpec {
        name: name.to_owned(),
        group: None,
        summary: summary.to_owned(),
        description: None,
        usage: None,
        flags: Vec::new(),
        args: Vec::new(),
        examples: Vec::new(),
        aliases: Vec::new(),
        target: CommandTarget::None,
        output: CommandOutput::Json,
        default_format: None,
        config_defaults: true,
        validate: None,
        run: Arc::new(move |context| Box::pin(run(context))),
    }
}

impl CommandSpec {
    pub fn group(mut self, group: &str) -> Self {
        self.group = Some(group.to_owned());
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }

    pub fn usage(mut self, usage: &str) -> Self {
        self.usage = Some(usage.to_owned());
        self
    }

    pub fn flag(mut self, name: &str, flag: FlagSpec) -> Self {
        self.flags.push((name.to_owned(), flag));
        self
    }

    pub fn arg(mut self, arg: ArgSpec) -> Self {
        self.args.push(arg);
        self
    }

    pub fn examples(mut self, examples: &[&str]) -> Self {
        self.examples = examples
            .iter()
            .map(|example| (*example).to_owned())
            .collect();
        self
    }

    pub fn aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(|alias| (*alias).to_owned()).collect();
        self
    }

    pub fn target(mut self, target: CommandTarget) -> Self {
        self.target = target;
        self
    }

    pub fn output(mut self, output: CommandOutput) -> Self {
        self.output = output;
        self
    }

    pub fn default_format(mut self, format: OutputFormat) -> Self {
        self.default_format = Some(format);
        self
    }

    pub fn config_defaults(mut self, enabled: bool) -> Self {
        self.config_defaults = enabled;
        self
    }

    pub fn validate(
        mut self,
        validate: impl Fn(&Flags, &[String], &HashSet<String>) -> CliResult<()> + Send + Sync + 'static,
    ) -> Self {
        self.validate = Some(Arc::new(validate));
        self
    }

    fn own_flag(&self, name: &str) -> Option<&FlagSpec> {
        self.flags
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, flag)| flag)
    }

    fn names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.aliases.iter().map(String::as_str))
    }
}

/// Flags that choose the deployment and session; configuration defaults never set them.
const TARGET_FLAGS: [&str; 3] = ["config", "url", "profile"];

fn config_flag() -> FlagSpec {
    FlagSpec::string(&format!(
        "Configuration file; default: the nearest {}",
        CONFIG_FILE_NAMES[0]
    ))
    .value("PATH")
    .env("BETTER_IAM_CONFIG")
}

fn url_flag() -> FlagSpec {
    FlagSpec::string(
        "Call a running IAM server (https://host or https://host/api/iam) instead of loading the configuration",
    )
    .value("URL")
    .env("BETTER_IAM_URL")
}

fn profile_flag() -> FlagSpec {
    FlagSpec::string("Saved session to act as (see login); ignored while BETTER_IAM_TOKEN is set")
        .value("NAME")
        .env("BETTER_IAM_PROFILE")
}

fn format_flag() -> FlagSpec {
    FlagSpec::string("Output as json (indented, default), compact (one line), or table")
        .value("FORMAT")
        .choices(&OUTPUT_FORMATS)
}

fn query_flag() -> FlagSpec {
    FlagSpec::string(
        "Print only part of the result, e.g. summary.create or findings[].kind (strings print raw)",
    )
    .value("PATH")
}

/// Every flag a command accepts: its own, then the ones its target and output add (`commandFlags`).
pub fn command_flags(spec: &CommandSpec) -> FlagSpecs {
    let mut flags = spec.flags.clone();
    let has = |flags: &FlagSpecs, name: &str| flags.iter().any(|(key, _)| key == name);
    if matches!(spec.target, CommandTarget::Config | CommandTarget::Token) && !has(&flags, "config")
    {
        flags.push(("config".into(), config_flag()));
    }
    if spec.target == CommandTarget::Token {
        if !has(&flags, "url") {
            flags.push(("url".into(), url_flag()));
        }
        if !has(&flags, "profile") {
            flags.push(("profile".into(), profile_flag()));
        }
    }
    if spec.output == CommandOutput::Json {
        if !has(&flags, "format") {
            flags.push(("format".into(), format_flag()));
        }
        if !has(&flags, "query") {
            flags.push(("query".into(), query_flag()));
        }
    }
    flags
}

fn placeholder(flag: &FlagSpec) -> String {
    if let Some(value) = &flag.value {
        return value.clone();
    }
    if let Some(choices) = &flag.choices {
        return choices.join("|");
    }
    if flag.kind == FlagType::Integer {
        "N".to_owned()
    } else {
        "VALUE".to_owned()
    }
}

/// The usage line: required flags as `--flag VALUE`, optional ones in brackets; common flags are left to help
/// (`usageLine`).
pub fn usage_line(spec: &CommandSpec) -> String {
    if let Some(usage) = &spec.usage {
        return usage.clone();
    }
    let mut parts = vec![format!("better-iam {}", spec.name)];
    if matches!(spec.target, CommandTarget::Config | CommandTarget::Token)
        || spec.own_flag("config").is_some()
    {
        parts.push(format!("--config {}", CONFIG_FILE_NAMES[0]));
    }
    for arg in &spec.args {
        let name = format!(
            "{}{}",
            arg.name.to_uppercase(),
            if arg.variadic { "..." } else { "" }
        );
        parts.push(if arg.required {
            name
        } else {
            format!("[{name}]")
        });
    }
    for (name, flag) in &spec.flags {
        if name == "config" || flag.hidden {
            continue;
        }
        let text = if flag.kind == FlagType::Boolean {
            format!("--{name}")
        } else {
            format!("--{name} {}", placeholder(flag))
        };
        parts.push(if flag.required {
            text
        } else {
            format!("[{text}]")
        });
    }
    if spec.target == CommandTarget::Token {
        parts.push("[--url URL]".into());
        parts.push("[--profile NAME]".into());
    }
    parts.join(" ")
}

fn len16(text: &str) -> usize {
    better_iam_core::js::utf16_len(text)
}

fn pad_end(text: &str, width: usize) -> String {
    let length = len16(text);
    if length >= width {
        text.to_owned()
    } else {
        format!("{text}{}", " ".repeat(width - length))
    }
}

static PARAGRAPH: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\n\s*\n").expect("regex"));

/// Splits on blank lines (`/\n\s*\n/`).
fn paragraphs(text: &str) -> Vec<&str> {
    PARAGRAPH.split(text).collect()
}

fn wrap(text: &str, indent: usize, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for paragraph in paragraphs(text) {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && indent + len16(&line) + 1 + len16(word) > width {
                lines.push(format!("{}{line}", " ".repeat(indent)));
                line = word.to_owned();
            } else if line.is_empty() {
                line = word.to_owned();
            } else {
                line = format!("{line} {word}");
            }
        }
        if !line.is_empty() {
            lines.push(format!("{}{line}", " ".repeat(indent)));
        }
        lines.push(String::new());
    }
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

fn flag_label(name: &str, flag: &FlagSpec) -> String {
    if flag.kind == FlagType::Boolean {
        format!("--{name}")
    } else {
        format!("--{name} {}", placeholder(flag))
    }
}

fn flag_lines(spec: &CommandSpec) -> Vec<String> {
    let entries: Vec<(String, FlagSpec)> = command_flags(spec)
        .into_iter()
        .filter(|(_, flag)| !flag.hidden)
        .collect();
    let labels: Vec<String> = entries
        .iter()
        .map(|(name, flag)| flag_label(name, flag))
        .collect();
    let width = 30.min(
        labels
            .iter()
            .map(|label| len16(label))
            .max()
            .unwrap_or(0)
            .max(10),
    );
    let mut lines: Vec<String> = Vec::new();
    for ((_, flag), label) in entries.iter().zip(&labels) {
        let mut notes: Vec<String> = Vec::new();
        if flag.required {
            notes.push("required".into());
        }
        if let Some(default) = &flag.default {
            notes.push(format!("default {}", default.text()));
        }
        if let Some(env) = &flag.env {
            notes.push(format!("env {env}"));
        }
        if flag.profile.is_some() {
            notes.push("or the saved profile".into());
        }
        let description = if notes.is_empty() {
            flag.description.clone()
        } else {
            format!("{} ({})", flag.description, notes.join("; "))
        };
        let wrapped: Vec<String> = wrap(&description, width + 6, 100)
            .into_iter()
            .map(|line| line.trim_start().to_owned())
            .collect();
        let pad = " ".repeat(width + 6);
        if len16(label) > width {
            lines.push(format!("  {label}"));
            lines.extend(wrapped.iter().map(|line| format!("{pad}{line}")));
        } else {
            lines.push(format!(
                "  {}    {}",
                pad_end(label, width),
                wrapped.first().cloned().unwrap_or_default()
            ));
            lines.extend(wrapped.iter().skip(1).map(|line| format!("{pad}{line}")));
        }
    }
    lines.push(format!(
        "  {}    Show this help",
        pad_end("-h, --help", width)
    ));
    lines
}

/// `better-iam help <command>`: usage, description, arguments, flags, and examples (`commandHelp`).
pub fn command_help(spec: &CommandSpec) -> String {
    let mut lines = vec![
        format!("better-iam {} - {}", spec.name, spec.summary),
        String::new(),
        "Usage".to_owned(),
        format!("  {}", usage_line(spec)),
    ];
    if !spec.aliases.is_empty() {
        lines.push(String::new());
        lines.push(format!("Aliases: {}", spec.aliases.join(", ")));
    }
    if let Some(description) = &spec.description {
        lines.push(String::new());
        lines.extend(wrap(description, 2, 80));
    }
    if !spec.args.is_empty() {
        lines.push(String::new());
        lines.push("Arguments".into());
        let width = spec
            .args
            .iter()
            .map(|arg| len16(&arg.name) + 3)
            .max()
            .unwrap_or(0);
        for arg in &spec.args {
            lines.push(format!(
                "  {}  {}",
                pad_end(&arg.name.to_uppercase(), width),
                arg.description
            ));
        }
    }
    lines.push(String::new());
    lines.push("Flags".into());
    lines.extend(flag_lines(spec));
    if !spec.examples.is_empty() {
        lines.push(String::new());
        lines.push("Examples".into());
        lines.extend(spec.examples.iter().map(|example| format!("  $ {example}")));
    }
    lines.join("\n")
}

/// Environment variables the CLI reads, for help and the manifest (`environmentVariables`).
pub const ENVIRONMENT_VARIABLES: [(&str, &str); 13] = [
    ("BETTER_IAM_CONFIG", "Configuration file, like --config"),
    (
        "BETTER_IAM_TOKEN",
        "Session or API key token commands act as",
    ),
    (
        "BETTER_IAM_URL",
        "IAM server token commands call, like --url",
    ),
    ("BETTER_IAM_PROFILE", "Saved session to use, like --profile"),
    ("BETTER_IAM_TENANT", "Default --tenant for token commands"),
    (
        "BETTER_IAM_CREDENTIALS",
        "File saved sessions live in (default ~/.config/better-iam/credentials.json, %APPDATA% on Windows)",
    ),
    (
        "BETTER_IAM_ROOT_EMAIL",
        "bootstrap / recover-root: the root administrator (with BETTER_IAM_ROOT_NAME, BETTER_IAM_ROOT_PASSWORD)",
    ),
    (
        "BETTER_IAM_ROOT_NAME",
        "bootstrap / recover-root: display name",
    ),
    (
        "BETTER_IAM_ROOT_PASSWORD",
        "bootstrap / recover-root: password (never a flag)",
    ),
    (
        "BETTER_IAM_PASSWORD",
        "login: the password, instead of the prompt",
    ),
    (
        "BETTER_IAM_MFA_CODE",
        "login: the authenticator code, instead of the prompt",
    ),
    (
        "BETTER_IAM_DATABASE_URL",
        "Without a configuration file: the database (postgres://, sqlite:PATH, libsql://), with BETTER_IAM_SECRET",
    ),
    (
        "BETTER_IAM_SECRET",
        "Without a configuration file: the deployment secret",
    ),
];

/// A machine-readable description of every command: what `better-iam help --json` prints and the docs are built from
/// (`manifestOf`).
pub fn manifest_of(commands: &[Arc<CommandSpec>], version: &str) -> Value {
    let commands: Vec<Value> = commands
        .iter()
        .map(|spec| {
            let flags: Vec<Value> = command_flags(spec)
                .into_iter()
                .filter(|(_, flag)| !flag.hidden)
                .map(|(name, flag)| {
                    let mut entry = Map::new();
                    entry.insert("flag".into(), Value::String(format!("--{name}")));
                    if flag.kind != FlagType::Boolean {
                        entry.insert("value".into(), Value::String(placeholder(&flag)));
                    }
                    entry.insert("optional".into(), Value::Bool(!flag.required));
                    entry.insert(
                        "description".into(),
                        Value::String(flag.description.clone()),
                    );
                    if let Some(env) = &flag.env {
                        entry.insert("env".into(), Value::String(env.clone()));
                    }
                    if let Some(default) = &flag.default {
                        entry.insert("default".into(), default.to_json());
                    }
                    if let Some(choices) = &flag.choices {
                        entry.insert("choices".into(), json!(choices));
                    }
                    Value::Object(entry)
                })
                .collect();
            let mut entry = Map::new();
            entry.insert("name".into(), Value::String(spec.name.clone()));
            entry.insert("aliases".into(), json!(spec.aliases));
            entry.insert(
                "group".into(),
                Value::String(spec.group.clone().unwrap_or_else(|| "Commands".into())),
            );
            entry.insert("summary".into(), Value::String(spec.summary.clone()));
            entry.insert(
                "description".into(),
                Value::String(
                    spec.description
                        .clone()
                        .unwrap_or_else(|| spec.summary.clone()),
                ),
            );
            entry.insert("usage".into(), Value::String(usage_line(spec)));
            entry.insert("target".into(), Value::String(spec.target.as_str().into()));
            entry.insert(
                "args".into(),
                Value::Array(spec.args.iter().map(ArgSpec::to_json).collect()),
            );
            entry.insert("flags".into(), Value::Array(flags));
            entry.insert("examples".into(), json!(spec.examples));
            Value::Object(entry)
        })
        .collect();
    json!({
        "name": "better-iam",
        "version": version,
        "commands": commands,
        "env": ENVIRONMENT_VARIABLES
            .iter()
            .map(|(name, description)| json!({ "name": name, "description": description }))
            .collect::<Vec<_>>(),
    })
}

const GROUP_ORDER: [&str; 8] = [
    "Setup",
    "Operations",
    "Audit",
    "Storage",
    "Access",
    "API",
    "Session",
    "Shell",
];

/// `better-iam help`: every command by section, every usage line, the details, and the environment
/// (`overviewHelp`).
pub fn overview_help(commands: &[Arc<CommandSpec>], version: &str) -> String {
    let mut groups: IndexMap<String, Vec<&CommandSpec>> = IndexMap::new();
    for spec in commands {
        groups
            .entry(spec.group.clone().unwrap_or_else(|| "Commands".into()))
            .or_default()
            .push(spec);
    }
    let rank = |group: &str| {
        GROUP_ORDER
            .iter()
            .position(|item| *item == group)
            .map_or(99, |index| index + 1)
    };
    let mut ordered: Vec<&String> = groups.keys().collect();
    ordered.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| locale_compare(a, b)));
    let width = commands
        .iter()
        .map(|spec| len16(&spec.name))
        .max()
        .unwrap_or(0)
        + 2;
    let mut lines: Vec<String> = vec![
        format!("Better IAM {version}"),
        String::new(),
        "Usage".into(),
        "  better-iam <command> [flags]".into(),
        "  better-iam help <command>      flags, details, and examples for one command".into(),
        "  better-iam help --json         every command as JSON, for tools".into(),
        String::new(),
    ];
    for group in ordered {
        lines.push(group.clone());
        for spec in &groups[group] {
            lines.push(format!("  {}{}", pad_end(&spec.name, width), spec.summary));
        }
        lines.push(String::new());
    }
    lines.push("Commands".into());
    lines.extend(
        commands
            .iter()
            .map(|spec| format!("  {}", usage_line(spec))),
    );
    lines.push(String::new());
    lines.extend(wrap(
        &format!(
            "Configuration commands load {name} (or --config, BETTER_IAM_CONFIG, the nearest {name} in a parent directory, or BETTER_IAM_DATABASE_URL + BETTER_IAM_SECRET without a file). Token commands act as BETTER_IAM_TOKEN or the session saved by login, in process or against --url, and are authorized and audited like console operations. Secrets are never accepted in command-line arguments. Every flag also accepts --flag=value; results print as JSON unless --format says otherwise.",
            name = CONFIG_FILE_NAMES[0]
        ),
        2,
        80,
    ));
    lines.push(String::new());
    for spec in commands {
        if let Some(description) = &spec.description {
            lines.extend(wrap(description, 2, 80));
            lines.push(String::new());
        }
    }
    lines.push("Environment".into());
    let env_width = ENVIRONMENT_VARIABLES
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0)
        + 2;
    for (name, description) in ENVIRONMENT_VARIABLES {
        lines.push(format!("  {}{description}", pad_end(name, env_width)));
    }
    lines.join("\n")
}

/// A raw flag value before conversion.
#[derive(Debug, Clone, PartialEq)]
enum Raw {
    Text(String),
    Switch(bool),
    Json(Value),
}

/// What [`parse_arguments`] returns.
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    values: IndexMap<String, Raw>,
    pub args: Vec<String>,
    pub help: bool,
}

/// Parses `--flag value`, `--flag=value`, boolean `--flag`, `--` and positionals for one command
/// (`parseArguments`).
pub fn parse_arguments(spec: &CommandSpec, argv: &[String]) -> CliResult<Parsed> {
    let flags = command_flags(spec);
    let mut parsed = Parsed::default();
    let mut positional_only = false;
    let mut index = 0;
    while index < argv.len() {
        let token = &argv[index];
        if positional_only {
            parsed.args.push(token.clone());
            index += 1;
            continue;
        }
        if token == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if token == "--help" || token == "-h" {
            parsed.help = true;
            index += 1;
            continue;
        }
        if let Some(rest) = token.strip_prefix("--") {
            let (name, inline) = match rest.find('=') {
                Some(equals) => (&rest[..equals], Some(&rest[equals + 1..])),
                None => (rest, None),
            };
            let Some((_, flag)) = flags.iter().find(|(key, _)| key == name) else {
                return Err(usage_error(
                    format!(
                        "{} does not take --{name}.{}",
                        spec.name,
                        did_you_mean(name, flags.iter().map(|(key, _)| key.as_str()), "--")
                    ),
                    Some(&format!("Run better-iam help {} for its flags.", spec.name)),
                ));
            };
            if parsed.values.contains_key(name) {
                return Err(usage_error(
                    format!("--{name} was given more than once"),
                    None,
                ));
            }
            if flag.kind == FlagType::Boolean {
                match inline {
                    None => parsed.values.insert(name.to_owned(), Raw::Switch(true)),
                    Some("true") => parsed.values.insert(name.to_owned(), Raw::Switch(true)),
                    Some("false") => parsed.values.insert(name.to_owned(), Raw::Switch(false)),
                    Some(_) => {
                        return Err(usage_error(
                            format!("--{name} is a switch; use --{name} or --{name}=false"),
                            None,
                        ));
                    }
                };
                index += 1;
                continue;
            }
            let value = match inline {
                Some(inline) => Some(inline.to_owned()),
                None => {
                    index += 1;
                    argv.get(index).cloned()
                }
            };
            let value = match value {
                Some(value)
                    if !value.is_empty() && !(inline.is_none() && value.starts_with("--")) =>
                {
                    value
                }
                _ => {
                    return Err(usage_error(
                        format!("--{name} needs a value ({})", placeholder(flag)),
                        None,
                    ));
                }
            };
            parsed.values.insert(name.to_owned(), Raw::Text(value));
            index += 1;
            continue;
        }
        if token.starts_with('-') && token != "-" && spec.args.is_empty() {
            return Err(usage_error(
                format!("{} does not take {token}", spec.name),
                Some(&format!("Run better-iam help {}.", spec.name)),
            ));
        }
        parsed.args.push(token.clone());
        index += 1;
    }
    if spec.args.is_empty() && !parsed.args.is_empty() {
        return Err(usage_error(
            format!("{} takes no arguments (got {})", spec.name, parsed.args[0]),
            Some(&format!(
                "Flags start with --; run better-iam help {}.",
                spec.name
            )),
        ));
    }
    if !spec.args.last().is_some_and(|arg| arg.variadic) && parsed.args.len() > spec.args.len() {
        return Err(usage_error(
            format!(
                "{} takes at most {} argument(s)",
                spec.name,
                spec.args.len()
            ),
            None,
        ));
    }
    Ok(parsed)
}

/// `String(raw)` for a configuration default.
fn raw_text(raw: &Raw) -> String {
    match raw {
        Raw::Text(text) => text.clone(),
        Raw::Switch(flag) => flag.to_string(),
        Raw::Json(value) => better_iam_server::js::js_string(Some(value)),
    }
}

/// Checks and converts one raw flag value (from argv, the environment, or configuration defaults) (`convert`).
fn convert(name: &str, flag: &FlagSpec, raw: &Raw, source: &str) -> CliResult<FlagValue> {
    let label = if source == "flag" {
        format!("--{name}")
    } else {
        format!("{source} (for --{name})")
    };
    match flag.kind {
        FlagType::Boolean => {
            if let Raw::Switch(flag) | Raw::Json(Value::Bool(flag)) = raw {
                return Ok(FlagValue::Boolean(*flag));
            }
            let text = raw_text(raw).to_lowercase();
            if ["true", "1", "yes"].contains(&text.as_str()) {
                return Ok(FlagValue::Boolean(true));
            }
            if ["false", "0", "no", ""].contains(&text.as_str()) {
                return Ok(FlagValue::Boolean(false));
            }
            Err(usage_error(format!("{label} must be true or false"), None))
        }
        FlagType::Integer => {
            let text = raw_text(raw);
            let min = flag.min.unwrap_or(-9_007_199_254_740_991);
            let max = flag.max.unwrap_or(9_007_199_254_740_991);
            let digits = {
                let body = text.strip_prefix('-').unwrap_or(&text);
                !body.is_empty() && body.bytes().all(|byte| byte.is_ascii_digit())
            };
            let number = better_iam_core::js::string_to_number(&text);
            if !digits
                || !better_iam_core::js::is_safe_integer(number)
                || (number as i64) < min
                || (number as i64) > max
            {
                return Err(usage_error(
                    if flag.min.is_some() || flag.max.is_some() {
                        format!("{label} must be an integer between {min} and {max}")
                    } else {
                        format!("{label} must be an integer")
                    },
                    None,
                ));
            }
            Ok(FlagValue::Integer(number as i64))
        }
        FlagType::String => {
            let text = raw_text(raw);
            if text.is_empty() {
                return Err(usage_error(format!("{label} needs a value"), None));
            }
            if let Some(choices) = &flag.choices
                && !choices.contains(&text)
            {
                return Err(usage_error(
                    format!("{label} must be {}", choices.join(", ")),
                    None,
                ));
            }
            Ok(FlagValue::String(text))
        }
    }
}

/// What [`create_cli`] takes (`CreateCliOptions`).
#[derive(Clone, Default)]
pub struct CreateCliOptions {
    /// Commands in addition to (or, with `builtins: false`, instead of) the built-in ones.
    pub commands: Vec<CommandSpec>,
    /// Keep the built-in commands (default true).
    pub builtins: Option<bool>,
    pub version: Option<String>,
}

/// The program running a command: its commands and version.
#[derive(Clone, Debug)]
pub struct Program {
    pub commands: Vec<Arc<CommandSpec>>,
    pub version: String,
}

/// A command-line program: the built-in commands plus yours, runnable from code with any IO (`Cli`).
#[derive(Clone)]
pub struct Cli {
    pub commands: Vec<Arc<CommandSpec>>,
    version: String,
    default_io: fn() -> CliIo,
}

fn find<'a>(list: &'a [Arc<CommandSpec>], name: &str) -> Option<&'a Arc<CommandSpec>> {
    list.iter()
        .find(|spec| spec.name == name || spec.aliases.iter().any(|alias| alias == name))
}

fn unknown_command(name: &str, commands: &[Arc<CommandSpec>]) -> CliError {
    CliError::new(
        "INVALID_COMMAND",
        format!(
            "Unknown command: {name}.{}",
            did_you_mean(
                name,
                commands.iter().map(|command| command.name.as_str()),
                ""
            )
        ),
        None,
    )
}

/// `createCliProgram(builtins, version, defaultIO)`.
pub fn create_cli_program(
    builtins: Vec<CommandSpec>,
    version: &str,
    default_io: fn() -> CliIo,
    options: CreateCliOptions,
) -> Cli {
    let mut commands: Vec<Arc<CommandSpec>> = if options.builtins == Some(false) {
        Vec::new()
    } else {
        builtins.into_iter().map(Arc::new).collect()
    };
    commands.extend(options.commands.into_iter().map(Arc::new));
    Cli {
        commands,
        version: options.version.unwrap_or_else(|| version.to_owned()),
        default_io,
    }
}

impl Cli {
    /// The version the program reports.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// `help(command?)`.
    pub fn help(&self, name: Option<&str>) -> CliResult<String> {
        let Some(name) = name else {
            return Ok(overview_help(&self.commands, &self.version));
        };
        match find(&self.commands, name) {
            Some(spec) => Ok(command_help(spec)),
            None => Err(unknown_command(name, &self.commands)),
        }
    }

    /// `manifest()`.
    pub fn manifest(&self) -> Value {
        manifest_of(&self.commands, &self.version)
    }

    /// Runs one command line (without the program name) (`run`).
    pub async fn run(&self, argv: &[String], io: Option<CliIo>) -> CliResult<()> {
        let io = io.unwrap_or_else(self.default_io);
        let cwd = io
            .cwd
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        let name = argv.first().map_or("help", String::as_str);
        if ["help", "--help", "-h"].contains(&name) {
            let rest = &argv[1.min(argv.len())..];
            let json = rest.iter().any(|item| item == "--json");
            let topic = rest
                .iter()
                .enumerate()
                .find(|(index, item)| {
                    !item.starts_with('-') && (*index == 0 || rest[index - 1] != "--config")
                })
                .map(|(_, item)| item.as_str());
            if json {
                let listed: Vec<Arc<CommandSpec>> = match topic {
                    Some(topic) => self
                        .commands
                        .iter()
                        .filter(|spec| spec.name == topic)
                        .cloned()
                        .collect(),
                    None => self.commands.clone(),
                };
                (io.out)(&stringify(&manifest_of(&listed, &self.version), Some(2)));
            } else if let Some(topic) = topic {
                let Some(spec) = find(&self.commands, topic) else {
                    return Err(unknown_command(topic, &self.commands));
                };
                (io.out)(&command_help(spec));
            } else {
                (io.out)(&overview_help(&self.commands, &self.version));
            }
            return Ok(());
        }
        if ["--version", "version", "-v"].contains(&name) {
            (io.out)(&self.version);
            return Ok(());
        }
        let Some(spec) = find(&self.commands, name).cloned() else {
            return Err(CliError::hinted(
                "INVALID_COMMAND",
                format!(
                    "Unknown command: {name}.{}",
                    did_you_mean(
                        name,
                        self.commands.iter().flat_map(|command| command.names()),
                        ""
                    )
                ),
                "Run better-iam help for the list of commands.",
            ));
        };
        let program = Program {
            commands: self.commands.clone(),
            version: self.version.clone(),
        };
        execute(spec, &argv[1..], io, cwd, program).await
    }
}

/// Where a saved profile's session was issued: its server, its configuration, or the environment-only deployment
/// (`describeProfileTarget`).
pub fn describe_profile_target(profile: &StoredProfile) -> String {
    profile
        .url
        .clone()
        .or_else(|| profile.config.clone())
        .unwrap_or_else(|| {
            if profile.env_config == Some(true) {
                "BETTER_IAM_DATABASE_URL".to_owned()
            } else {
                "an unknown deployment".to_owned()
            }
        })
}

/// The saved profile in use (`profile()`): `profile` is None when there is none, or when it belongs to another
/// deployment than `--url` / `--config` name (then `mismatch` holds it).
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileMatch {
    pub name: String,
    pub profile: Option<StoredProfile>,
    pub mismatch: Option<StoredProfile>,
}

/// What [`CommandContext::api`] takes.
#[derive(Debug, Clone, Default)]
pub struct ApiOptions {
    /// Call with no credential (false), or as the token (default).
    pub anonymous: bool,
    pub token: Option<String>,
}

#[derive(Default)]
struct Caches {
    profile: Option<Option<ProfileMatch>>,
    located: Option<Option<ResolvedConfigPath>>,
    module: Option<Arc<ConfigModule>>,
    instance: Option<Arc<BetterIam>>,
    opened: Vec<Arc<BetterIam>>,
}

/// The context a command runs with (`CommandContext`).
pub struct CommandContext {
    /// The command name as registered.
    pub name: String,
    pub flags: Flags,
    /// Positional arguments.
    pub args: Vec<String>,
    /// The flags given on the command line itself (not filled from the environment, defaults, or a profile).
    pub explicit: HashSet<String>,
    pub io: CliIo,
    pub env: Env,
    pub cwd: PathBuf,
    pub profiles: ProfileStore,
    /// The program running the command: its commands and version.
    pub program: Program,
    target: CommandTarget,
    default_format: Option<OutputFormat>,
    uses_profile: bool,
    caches: Mutex<Caches>,
}

impl CommandContext {
    fn lock(&self) -> std::sync::MutexGuard<'_, Caches> {
        self.caches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Resolves a path against the working directory.
    pub fn path(&self, value: &str) -> PathBuf {
        resolve_path(&self.cwd, Path::new(value))
    }

    /// Prints a result with `--format` / `--query` applied. Returning a value from `run` does the same.
    pub fn print(&self, value: &Value) -> CliResult<()> {
        let text = format_result(
            value,
            self.flags.format().or(self.default_format),
            self.flags.query(),
        )?;
        (self.io.out)(&text);
        Ok(())
    }

    /// Writes a line to stderr (progress, warnings); silent when the IO has no `err`.
    pub fn note(&self, message: &str) {
        if let Some(err) = &self.io.err {
            err(message);
        }
    }

    fn has(&self, name: &str) -> bool {
        self.flags.has(name)
    }

    /// The saved profile in use, when the command is not acting on `BETTER_IAM_TOKEN` (`profile()`).
    pub fn profile(&self) -> CliResult<Option<ProfileMatch>> {
        if let Some(cached) = &self.lock().profile {
            return Ok(cached.clone());
        }
        let resolved = if !self.uses_profile || self.profiles.path.is_none() {
            None
        } else {
            let name = self.profiles.current_name(self.flags.string("profile"))?;
            let saved = self.profiles.get(&name)?;
            let matches = match &saved {
                None => true,
                Some(saved) => {
                    if self.has("url") {
                        saved.url.as_deref().is_some_and(|url| {
                            same_endpoint(url, self.flags.string("url").unwrap_or(""))
                        })
                    } else if self.has("config") {
                        saved.config.as_deref().is_some_and(|config| {
                            display(&self.path(self.flags.string("config").unwrap_or(""))) == config
                        })
                    } else {
                        true
                    }
                }
            };
            Some(if matches {
                ProfileMatch {
                    name,
                    profile: saved,
                    mismatch: None,
                }
            } else {
                ProfileMatch {
                    name,
                    profile: None,
                    mismatch: saved,
                }
            })
        };
        self.lock().profile = Some(resolved.clone());
        Ok(resolved)
    }

    fn remote_url(&self) -> CliResult<Option<String>> {
        if self.has("url") {
            return Ok(self.flags.string("url").map(str::to_owned));
        }
        if self.has("config") {
            return Ok(None);
        }
        Ok(self
            .profile()?
            .and_then(|matched| matched.profile)
            .and_then(|profile| profile.url))
    }

    /// Where the configuration comes from, or None when none was given or found (`configPath`).
    pub fn config_path(&self) -> CliResult<Option<ResolvedConfigPath>> {
        if let Some(located) = &self.lock().located {
            return Ok(located.clone());
        }
        let mut located: Option<Option<ResolvedConfigPath>> = None;
        if !self.has("config") && self.target == CommandTarget::Token {
            // Without --config, a token command uses the deployment its saved session came from.
            let saved = self.profile()?.and_then(|matched| matched.profile);
            if let Some(config) = saved.as_ref().and_then(|saved| saved.config.clone()) {
                located = Some(Some(ResolvedConfigPath {
                    path: PathBuf::from(config),
                    source: ConfigSource::Profile,
                }));
            } else if saved.as_ref().and_then(|saved| saved.env_config) == Some(true) {
                located = Some(None);
            }
        }
        let located = match located {
            Some(located) => located,
            None => resolve_config_path(self.flags.string("config"), &self.env, &self.cwd),
        };
        self.lock().located = Some(located.clone());
        Ok(located)
    }

    /// The configuration (read once) (`configModule`).
    pub fn config_module(&self) -> CliResult<Arc<ConfigModule>> {
        if let Some(module) = &self.lock().module {
            return Ok(module.clone());
        }
        let module = Arc::new(match self.config_path()? {
            None => ConfigModule::default(),
            Some(where_) => import_config_module(&where_.path)?,
        });
        self.lock().module = Some(module.clone());
        Ok(module)
    }

    fn config_context(&self) -> ConfigContext {
        ConfigContext {
            command: Some(self.name.clone()),
            env: self.env.clone(),
            cwd: self.cwd.clone(),
        }
    }

    /// The IAM instance of the configuration, created once and closed after the command (`iam()`).
    pub fn iam(&self) -> CliResult<Arc<BetterIam>> {
        if let Some(instance) = &self.lock().instance {
            return Ok(instance.clone());
        }
        let created = if self.config_path()?.is_some() {
            instantiate(self.config_module()?.as_ref(), &self.config_context())?
        } else if self
            .env
            .get("BETTER_IAM_DATABASE_URL")
            .is_some_and(|url| !url.is_empty())
        {
            from_config(&config_from_env(&self.env)?, &self.env)?
        } else {
            return Err(CliError::hinted(
                "CONFIG_NOT_FOUND",
                format!(
                    "No {} in {} or its parents",
                    CONFIG_FILE_NAMES[0],
                    display(&self.cwd)
                ),
                if self.target == CommandTarget::Token {
                    "Pass --config PATH or --url URL, run better-iam login, or run better-iam init."
                } else {
                    "Run better-iam init, pass --config PATH, or set BETTER_IAM_DATABASE_URL and BETTER_IAM_SECRET."
                },
            ));
        };
        let mut caches = self.lock();
        caches.opened.push(created.clone());
        caches.instance = Some(created.clone());
        Ok(created)
    }

    /// Another configuration's instance (for example `store-copy --target-config`), or with no path the deployment the
    /// environment describes (`BETTER_IAM_DATABASE_URL`); also closed after the command (`open`).
    pub fn open(&self, config_path: Option<&str>) -> CliResult<Arc<BetterIam>> {
        let created = match config_path {
            None => from_config(&config_from_env(&self.env)?, &self.env)?,
            Some(path) => instantiate(
                &import_config_module(&self.path(path))?,
                &self.config_context(),
            )?,
        };
        self.lock().opened.push(created.clone());
        Ok(created)
    }

    /// The bearer token: `BETTER_IAM_TOKEN`, else the saved profile's (`token()`).
    pub fn token(&self) -> CliResult<String> {
        if let Some(token) = self
            .env
            .get("BETTER_IAM_TOKEN")
            .filter(|token| !token.is_empty())
        {
            return Ok(token.clone());
        }
        let saved = self.profile()?;
        if let Some(matched) = &saved
            && let Some(profile) = matched
                .profile
                .as_ref()
                .filter(|profile| !profile.token.is_empty())
        {
            if let Some(expires_at) = profile.expires_at
                && expires_at <= better_iam_core::js::system_now_ms()
            {
                return Err(CliError::hinted(
                    "SESSION_EXPIRED",
                    format!("The session saved as profile {} has expired", matched.name),
                    format!(
                        "Run better-iam login{} again.",
                        if matched.name == "default" {
                            String::new()
                        } else {
                            format!(" --profile {}", matched.name)
                        }
                    ),
                ));
            }
            return Ok(profile.token.clone());
        }
        if let Some(matched) = &saved
            && let Some(mismatch) = &matched.mismatch
        {
            return Err(CliError::hinted(
                "MISSING_ENV",
                "Set BETTER_IAM_TOKEN to a session or API key",
                format!(
                    "The saved session \"{}\" belongs to {}, not this deployment; run better-iam login against it with another --profile.",
                    matched.name,
                    describe_profile_target(mismatch)
                ),
            ));
        }
        Err(CliError::hinted(
            "MISSING_ENV",
            "Set BETTER_IAM_TOKEN to a session or API key",
            "Or sign in once with better-iam login; later commands use the saved session.",
        ))
    }

    /// Calls API routes as the token (or with no credential) (`api()`).
    pub fn api(&self, options: ApiOptions) -> CliResult<ApiTransport> {
        let bearer = match options.token {
            Some(token) => Some(token),
            None if options.anonymous => None,
            None => Some(self.token()?),
        };
        if let Some(url) = self.remote_url()? {
            return remote_transport(&url, bearer.as_deref(), self.io.fetch.clone());
        }
        let where_ = self.config_path()?;
        let iam = self.iam()?;
        let target = where_.map_or_else(
            || "BETTER_IAM_DATABASE_URL".to_owned(),
            |where_| display(&where_.path),
        );
        Ok(local_transport(iam, &target, bearer.as_deref()))
    }

    fn opened(&self) -> Vec<Arc<BetterIam>> {
        std::mem::take(&mut self.lock().opened)
    }
}

/// A flag value for `values[name]` in error messages and conversions.
fn defaults_scope(defaults: &Map<String, Value>, scope: &str) -> Vec<(String, Value)> {
    match defaults.get(scope) {
        Some(Value::Object(map)) => better_iam_core::js::entries(map)
            .into_iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

async fn execute(
    spec: Arc<CommandSpec>,
    argv: &[String],
    io: CliIo,
    cwd: PathBuf,
    program: Program,
) -> CliResult<()> {
    let parsed = parse_arguments(&spec, argv)?;
    if parsed.help {
        (io.out)(&command_help(&spec));
        return Ok(());
    }
    let flags = command_flags(&spec);
    let flag = |name: &str| {
        flags
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, flag)| flag)
    };
    let target = spec.target;
    let mut values: IndexMap<String, FlagValue> = IndexMap::new();
    let explicit: HashSet<String> = parsed.values.keys().cloned().collect();
    for (name, raw) in &parsed.values {
        if let Some(spec_flag) = flag(name) {
            values.insert(name.clone(), convert(name, spec_flag, raw, "flag")?);
        }
    }
    for (name, spec_flag) in &flags {
        if values.contains_key(name) {
            continue;
        }
        if let Some(env_name) = &spec_flag.env
            && let Some(raw) = io.env.get(env_name).filter(|value| !value.is_empty())
        {
            values.insert(
                name.clone(),
                convert(name, spec_flag, &Raw::Text(raw.clone()), env_name)?,
            );
        }
    }
    // One deployment per command: the command line beats the environment, and naming both at one level is ambiguous.
    if target == CommandTarget::Token {
        if explicit.contains("url") && explicit.contains("config") {
            return Err(usage_error("Give --url or --config, not both", None));
        }
        if explicit.contains("config") {
            values.shift_remove("url");
        } else if explicit.contains("url") {
            values.shift_remove("config");
        } else if values.contains_key("url") && values.contains_key("config") {
            return Err(usage_error(
                "BETTER_IAM_URL and BETTER_IAM_CONFIG are both set",
                Some("Pass --url or --config to choose one."),
            ));
        }
    }
    let profiles = create_profile_store(&io.env);
    // A token in the environment wins over saved profiles entirely: its target and tenant come from flags. A saved
    // session is only ever used with the deployment it was issued by, so its token never reaches another server.
    let uses_profile = target == CommandTarget::Token
        && !io
            .env
            .get("BETTER_IAM_TOKEN")
            .is_some_and(|token| !token.is_empty());
    let mut context = CommandContext {
        name: spec.name.clone(),
        flags: Flags(values),
        args: parsed.args.clone(),
        explicit: explicit.clone(),
        env: io.env.clone(),
        io,
        cwd,
        profiles,
        program,
        target,
        default_format: spec.default_format,
        uses_profile,
        caches: Mutex::new(Caches::default()),
    };
    // Configuration defaults fill flags nobody set; they need the configuration read. The flags that choose the
    // deployment and session cannot come from that deployment's own configuration.
    if target != CommandTarget::None
        && spec.config_defaults
        && !(target == CommandTarget::Token && context.remote_url()?.is_some())
    {
        let where_ = context.config_path()?;
        let missing = flags.iter().any(|(name, _)| !context.flags.has(name));
        // A missing file is reported by the command when it loads the configuration, after flag checks.
        let present = where_.as_ref().is_some_and(|where_| where_.path.exists());
        if present && missing {
            let module = context.config_module()?;
            for scope in [spec.name.as_str(), "*"] {
                for (name, raw) in defaults_scope(&module.cli.defaults, scope) {
                    let Some(spec_flag) = flag(&name) else {
                        continue;
                    };
                    if context.flags.has(&name)
                        || TARGET_FLAGS.contains(&name.as_str())
                        || (scope == "*" && !spec_flag.wildcard_default)
                    {
                        continue;
                    }
                    let converted = convert(
                        &name,
                        spec_flag,
                        &Raw::Json(raw),
                        &format!("cli.defaults['{scope}']"),
                    )?;
                    context.flags.0.insert(name, converted);
                }
            }
        }
    }
    // Last before the built-in default: the saved session's own values (its tenant).
    for (name, spec_flag) in &flags {
        if context.flags.has(name) {
            continue;
        }
        if let Some(field) = &spec_flag.profile
            && let Some(saved) = context
                .profile()?
                .and_then(|matched| matched.profile)
                .and_then(|profile| profile.field(field).map(str::to_owned))
                .filter(|value| !value.is_empty())
        {
            context
                .flags
                .0
                .insert(name.clone(), FlagValue::String(saved));
        }
    }
    for (name, spec_flag) in &flags {
        if spec_flag.required && !context.flags.has(name) {
            return Err(usage_error(
                format!("--{name} {} is required", placeholder(spec_flag)),
                spec_flag
                    .profile
                    .as_ref()
                    .map(|_| {
                        format!(
                            "Pass --{name}, set {}, or log in with better-iam login --tenant ID.",
                            spec_flag.env.as_deref().unwrap_or("it")
                        )
                    })
                    .as_deref(),
            ));
        }
    }
    for (name, spec_flag) in &flags {
        if spec_flag.kind == FlagType::Boolean && !context.flags.has(name) {
            context
                .flags
                .0
                .insert(name.clone(), FlagValue::Boolean(false));
        }
    }
    for (index, arg) in spec.args.iter().enumerate() {
        if arg.required && context.args.get(index).is_none() {
            return Err(usage_error(
                format!("{} needs {}", spec.name, arg.name.to_uppercase()),
                Some(&format!("Run better-iam help {}.", spec.name)),
            ));
        }
    }
    if let Some(validate) = &spec.validate {
        validate(&context.flags, &context.args, &explicit)?;
    }
    let context = Arc::new(context);
    let result = (spec.run)(context.clone()).await;
    let printed = match result {
        Ok(Some(value)) => context.print(&value),
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    let mut closed: CliResult<()> = Ok(());
    for created in context.opened().into_iter().rev() {
        if let Err(error) = created.store.close().await
            && closed.is_ok()
        {
            closed = Err(error.into());
        }
    }
    printed?;
    closed
}
