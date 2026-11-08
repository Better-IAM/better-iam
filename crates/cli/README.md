# better-iam-cli

The `better-iam` command line for Rust, the counterpart of the `@better-iam/cli` npm package. It has the same
commands, flags, help, output formats (`--format json|compact|table`, `--query`), and exit codes (0 on success, 2
for a usage mistake, 1 otherwise; `vault-run` exits with its command's status), and it shares its database with the
TypeScript implementation.

```sh
cargo install better-iam-cli            # add --features libsql for libsql:// databases
better-iam init                         # writes better-iam.json
BETTER_IAM_SECRET=$(better-iam secret) better-iam migrate
better-iam help                         # every command; better-iam help <command> for one
```

## Configuration

The npm CLI imports `better-iam.config.mjs`, a JavaScript module. This CLI reads the standalone configuration every
implementation shares, `better-iam.json` (see `spec/conformance/CONFIG.md` in the repository): `--config PATH`, else
`BETTER_IAM_CONFIG`, else the nearest `better-iam.json` in the working directory or a parent (up to the repository
root or the home directory), else `BETTER_IAM_DATABASE_URL` and `BETTER_IAM_SECRET` alone.

One extra member holds CLI flag defaults, the counterpart of the module's `cli` export:

```json
{
  "store": { "kind": "sqlite", "path": "./better-iam.db" },
  "secret": { "env": "BETTER_IAM_SECRET" },
  "baseURL": "https://iam.example.com",
  "cli": { "defaults": { "sweep": { "retention-days": 30 }, "*": { "format": "compact" } } }
}
```

Tenant configurations (`config-plan`, `config-apply`, `config-validate`) are JSON files; `config-export` still writes
`.ts` / `.mjs` modules for Node.js projects when `--output` names one.

## Project commands

Programs add their own commands with the same parsing, help, configuration loading, and output:

```rust
use better_iam_cli::{create_cli, define_command, CommandTarget, CreateCliOptions, FlagSpec};
use serde_json::json;

let seed = define_command("seed", "Create the demo organization", |context| async move {
    let iam = context.iam()?;
    let _ = iam;
    Ok(Some(json!({ "created": true })))
})
.target(CommandTarget::Config)
.flag("slug", FlagSpec::string("Organization slug").default_text("demo"));
let cli = create_cli(CreateCliOptions { commands: vec![seed], ..Default::default() });
std::process::exit(better_iam_cli::run_binary(std::env::args().skip(1).collect(), Some(cli)));
```
