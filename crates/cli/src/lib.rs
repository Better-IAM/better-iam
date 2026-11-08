//! The `better-iam` command line for Rust, the counterpart of the `@better-iam/cli` npm package: migrations,
//! bootstrap, scheduled jobs, audit and storage operations, diagnostics, configuration as code, saved sessions, and
//! calls to any API route, with the same commands, flags, output, and exit codes.
//!
//! Every module mirrors the TypeScript module of the same name in `packages/cli/src` (`framework.ts` →
//! [`framework`], `commands/access.ts` → [`commands::access`], ...). One difference is the configuration: the npm CLI
//! imports `better-iam.config.mjs`, a JavaScript module; this CLI reads the standalone configuration every
//! implementation shares, `better-iam.json` (spec/conformance/CONFIG.md), whose `cli` member holds flag defaults.
//! Project commands are added in code with [`create_cli`] and [`define_command`].

pub mod commands;
pub mod config;
pub mod errors;
pub mod framework;
pub mod output;
pub mod paths;
pub mod profiles;
pub mod tenant_config;
pub mod terminal;
pub mod transport;

pub use commands::builtin_commands;
pub use config::{
    CONFIG_FILE_NAMES, CliSettings, ConfigContext, ConfigModule, LoadConfigOptions,
    config_from_env, find_config_file, load_config,
};
pub use errors::{CliError, CliFailure, CliResult, usage_error};
pub use framework::{
    ApiOptions, ArgSpec, Cli, CliIo, CommandContext, CommandOutput, CommandSpec, CommandTarget,
    CreateCliOptions, Env, FlagSpec, FlagSpecs, FlagType, FlagValue, Flags, command_help,
    define_command,
};
pub use output::{OutputFormat, format_result, select_path};
pub use profiles::{
    ProfileStore, ProfileSummary, StoredProfile, create_profile_store, credentials_path,
};
pub use tenant_config::{
    TenantConfigContext, TenantConfigLint, lint_tenant_config, load_tenant_config,
};
pub use terminal::process_io;
pub use transport::{ApiTransport, list_routes, local_transport, remote_transport};

use framework::{create_cli_program, manifest_of};
use std::sync::Arc;

/// The version of this CLI (the workspace version, in lockstep with the npm packages).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Creates a `better-iam`-style program from code: the built-in commands plus your own ([`define_command`]), with the
/// same parsing, help, configuration loading, and output. Use it to ship a project CLI, or to run commands in tests
/// (`createCli`).
pub fn create_cli(options: CreateCliOptions) -> Cli {
    create_cli_program(builtin_commands(), VERSION, process_io, options)
}

/// Runs one `better-iam` command line (without the program name) and resolves when it finishes; failures return a
/// [`CliError`] whose `code` says what went wrong (`runCli`). With no IO, the process's own.
pub async fn run_cli(argv: &[String], io: Option<CliIo>) -> CliResult<()> {
    create_cli(CreateCliOptions::default()).run(argv, io).await
}

/// The machine-readable description of every built-in command (what `better-iam help --json` prints), for docs and
/// tools (`cliManifest`).
pub fn cli_manifest() -> serde_json::Value {
    let commands: Vec<Arc<CommandSpec>> = builtin_commands().into_iter().map(Arc::new).collect();
    manifest_of(&commands, VERSION)
}

/// Messages can come from a remote server: control characters (terminal escapes) are dropped before printing.
fn printable(text: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in text.chars() {
        let code = c as u32;
        if code <= 0x1f || (0x7f..=0x9f).contains(&code) {
            if !in_run {
                out.push(' ');
                in_run = true;
            }
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out
}

/// Prints a failure as the binary does (`CODE: message` and a hint) through `err`, and returns the exit status: 2 for
/// a usage mistake, the command's own status for `vault-run`, 1 otherwise.
pub fn report_failure(error: &CliError, env: &Env, err: &dyn Fn(&str)) -> i32 {
    let code = error.error_code();
    let message = printable(error.message());
    // IAM errors (local or remote) and system errors (ENOENT, EEXIST) say what went wrong; anything else may carry
    // driver details such as connection strings, so it stays generic unless BETTER_IAM_DEBUG is set.
    match code {
        Some(code) if error.known => err(&format!("{}: {message}", printable(code))),
        _ => err(
            "Better IAM command failed. Check configuration and database connectivity (set BETTER_IAM_DEBUG=1 for details).",
        ),
    }
    if let Some(hint) = &error.hint {
        err(&format!("Hint: {hint}"));
    }
    if env
        .get("BETTER_IAM_DEBUG")
        .is_some_and(|value| !value.is_empty())
    {
        err(&format!("{error:?}"));
    }
    // A command run by `vault-run` failed: exit with its status, as the command itself would have.
    if let Some(status) = error.exit_status
        && status > 0
        && status < 256
    {
        return status;
    }
    match code {
        Some(code) if errors::USAGE_CODES.contains(&code) => 2,
        _ => 1,
    }
}

/// Runs the CLI like the `better-iam` binary: prints `CODE: message` (and a hint) on stderr on failure and resolves
/// with the exit status, 0 on success, 2 for a usage mistake, 1 otherwise (`main`). For wrappers that ship their own
/// binary.
pub async fn main(argv: &[String], cli: Option<&Cli>) -> i32 {
    let default = create_cli(CreateCliOptions::default());
    let cli = cli.unwrap_or(&default);
    match cli.run(argv, None).await {
        Ok(()) => 0,
        Err(error) => report_failure(&error, &framework::process_env(), &|line| {
            eprintln!("{line}")
        }),
    }
}

/// What the `better-iam` binary does: runs [`main`] on the process arguments on a runtime with large stacks (debug
/// builds of the server's futures are large) and returns the exit status (`runBinary`).
pub fn run_binary(argv: Vec<String>, cli: Option<Cli>) -> i32 {
    let worker = std::thread::Builder::new()
        .name("better-iam".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(64 * 1024 * 1024)
                .build();
            match runtime {
                Ok(runtime) => runtime.block_on(async move { main(&argv, cli.as_ref()).await }),
                Err(error) => {
                    eprintln!(
                        "INCOMPLETE: the command could not start ({error}); nothing was reported."
                    );
                    1
                }
            }
        });
    match worker.map(std::thread::JoinHandle::join) {
        Ok(Ok(status)) => status,
        _ => {
            eprintln!("INCOMPLETE: the command stopped before it finished; nothing was reported.");
            1
        }
    }
}
