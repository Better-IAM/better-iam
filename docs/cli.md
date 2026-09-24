# The `better-iam` CLI

The CLI runs deployment jobs (migrations, bootstrap, scheduled sweeps), manages tenants as code, and calls any API
method as a signed-in person or API key. Every command also has a programmatic equivalent, so anything you script in a
shell you can also do from a worker, a test, or a seed script (see [Everything from code](#everything-from-code)).

```sh
npx better-iam help              # every command, grouped, with usage lines
npx better-iam help config-plan  # one command: flags, defaults, environment variables, examples
npx better-iam config-plan --help
```

The binary ships with both `better-iam` (the umbrella package) and `@better-iam/cli`.

## Configuration

Commands that touch the deployment load a configuration module. The CLI looks for it in this order:

1. `--config PATH`
2. `BETTER_IAM_CONFIG`
3. the nearest `better-iam.config.mjs`, `.js`, `.ts`, `.mts`, or `.cjs` in the working directory or any parent (like
   Prettier and ESLint), so commands work from any subdirectory of a project. The search stops at the repository root
   (a directory with `.git`) or your home directory, and on Linux and macOS skips files owned by another user or kept
   in a directory anyone may write to (such as `/tmp`): a configuration is code, and importing it runs it
4. no file at all: `BETTER_IAM_DATABASE_URL` + `BETTER_IAM_SECRET` (see [environment-only](#environment-only-deployments))

`better-iam init` writes a starter (`--typescript` for `better-iam.config.ts`, `--database sqlite|postgres|libsql`).
TypeScript configurations need Node.js 22.18 or later, where type stripping is on by default.

```ts
// better-iam.config.ts
import type { CliSettings, CommandSpec } from 'better-iam/cli';
import { defineConfig } from 'better-iam/server';
import { postgresAdapter } from 'better-iam/adapter-postgres';

// A factory keeps importing the module free of side effects; the CLI calls it with { command, env, cwd }.
export default defineConfig(({ env = process.env, command } = {}) => ({
  database: postgresAdapter({ connectionString: env.DATABASE_URL! }),
  secret: env.BETTER_IAM_SECRET ?? '',
  baseURL: env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
  // Settings can depend on the command: no email transport needed for a migration.
  authentication: command === 'migrate' ? {} : { sendEmail },
}));

// Defaults for any command's flags, used when neither the flag nor its environment variable is set.
export const cli: CliSettings = {
  defaults: {
    sweep: { 'retention-days': 90 },
    'audit-prune': { 'retention-days': 730 },
    '*': { format: 'table' }, // every configuration or token command that has the flag
  },
};

// Project commands (see "Project commands" below).
export const commands: CommandSpec<any>[] = [];
```

Your server uses the same module: `const iam = betterIam(await configOptions(config))` (`configOptions` calls a
factory, or returns plain options unchanged). Scripts and tests that want the CLI's resolution without the command line
call `loadConfig({ config?, cwd?, env? })` from `better-iam/cli`, which returns the instance (close `iam.store` when
done).

A flag's value comes from, in order: the command line (`--flag value` or `--flag=value`), its environment variable (for
example `BETTER_IAM_TENANT` for `--tenant`), `cli.defaults`, the saved profile (for `--tenant` on token commands), and
finally the command's built-in default. `better-iam help <command>` lists each flag's variable and default. A `'*'`
default never fills a flag whose meaning differs between commands where it deletes data (`--retention-days` of
`audit-prune` and `purge`): set those under the command's own name.

### Environment-only deployments

Containers and CI jobs can skip the file entirely:

| Variable                      | Meaning                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------ |
| `BETTER_IAM_DATABASE_URL`     | `postgres://…`, `sqlite:./iam.db` (or a path ending in `.db`), `libsql://…` or `file:…` (libSQL) |
| `BETTER_IAM_SECRET`           | the deployment secret (`better-iam secret` prints a new one)                                     |
| `BETTER_IAM_PREVIOUS_SECRETS` | comma-separated, during a [secret rotation](deployment.md)                                       |
| `BETTER_IAM_BASE_URL`         | default `http://localhost:3000`                                                                  |
| `BETTER_IAM_BASE_PATH`        | default `/api/iam`                                                                               |
| `BETTER_IAM_TRUSTED_ORIGINS`  | comma-separated                                                                                  |
| `BETTER_IAM_DATABASE_TOKEN`   | libSQL auth token                                                                                |

`configFromEnv(env)` from `better-iam/cli` returns the same options for code: spread them and add callbacks,
`betterIam({ ...(await configFromEnv()), authentication: { sendEmail } })`.

## Two kinds of commands

**Configuration commands** (`migrate`, `bootstrap`, `doctor`, `purge`, `sweep`, `outbox`, `digest`, `audit-*`,
`store-*`, …) are deployment operations: they load the configuration and act on the whole deployment with no
credential. Run them from deploy hooks and schedulers.

**Token commands** (`api`, `config-*`, `analyze`, `report`, `can`, `explain`, `who-can`, `whoami`, …) act as a person
or API key and are authorized and audited exactly like the console or the HTTP API. They run either in process through
the configuration, or against a running server with `--url https://iam.example.com` (or `https://host/custom/base`;
also `BETTER_IAM_URL`). The token is `BETTER_IAM_TOKEN`, else the session saved by `login`.

## Signing in

```sh
better-iam login --url https://iam.example.com --org acme --email me@acme.test
# Password: ••••••••          (or BETTER_IAM_PASSWORD; never a flag)
# Authenticator code: 123456  (or BETTER_IAM_MFA_CODE; --email-code for an emailed code)
better-iam whoami             # no token, URL, or tenant needed from now on
better-iam can projects:read project/p1
```

`login` saves the session as a profile (`--profile NAME`, default `default`) in
`~/.config/better-iam/credentials.json` (`%APPDATA%\better-iam\credentials.json` on Windows, or
`BETTER_IAM_CREDENTIALS`), written with owner-only permissions. The profile remembers the server or configuration and
the tenant, so later commands need neither. For CI, pipe an API key in: `echo "$KEY" | better-iam login --with-token
--url https://iam.example.com --profile ci` (the token is checked with `whoami` before it is saved).

| Command                   | Does                                                                             |
| ------------------------- | -------------------------------------------------------------------------------- |
| `profiles`                | lists saved sessions (never their tokens), marking the current one               |
| `profiles use NAME`       | makes a profile current (`--profile NAME` / `BETTER_IAM_PROFILE` per call)       |
| `profiles remove NAME`    | forgets one without signing it out                                               |
| `logout [--profile NAME]` | signs a user session out on the server, then forgets it; keys are only forgotten |
| `token`                   | prints the token in use: `export BETTER_IAM_TOKEN=$(better-iam token)`           |

`BETTER_IAM_TOKEN` always wins: while it is set, profiles are ignored entirely (target and tenant come from flags).

A saved session only ever goes to the deployment that issued it. With `--url` (or `BETTER_IAM_URL`) naming another
server, or `--config` another configuration, the profile is not used and the command fails with `MISSING_ENV`
explaining which deployment the session belongs to; log in there under another `--profile`. Likewise `login` refuses
(`PROFILE_IN_USE`) to overwrite a profile saved for another deployment unless you name it with `--profile`. `--url`
must use `https://` except for `localhost`, and `--url` with `--config` is refused (on the command line either one
overrides the other's environment variable).

## Calling any API method

`better-iam api` calls any route of the HTTP API (`POST {basePath}/{group}/{method}`), with the same permission checks:

```sh
better-iam api --list                 # every route, with whether it needs a credential
better-iam api --list roles
better-iam api roles.create name=Reader permissions:='["documents:read"]'
better-iam api policies.create name=Deny-deletes document:=@deny.json
better-iam api authorize action=documents:read resource.type=document resource.id=d1
better-iam api identities.list limit:=100 --query '[].email' --format compact
echo '{"slug":"acme"}' | better-iam api tenants.lookup --data -
```

| Item                | Sets                                                               |
| ------------------- | ------------------------------------------------------------------ |
| `name=Admin`        | a string                                                           |
| `limit:=10`         | JSON (`:=true`, `:='["a","b"]'`, `:=null`)                         |
| `document:=@p.json` | JSON read from a file                                              |
| `content=@terms.md` | a file's text                                                      |
| `resource.type=doc` | a nested field                                                     |
| `actions[]=read`    | appends to a list                                                  |
| `--data JSON`       | the whole body (`@file.json`, `-` for stdin); items then add to it |

`--tenant` (or `BETTER_IAM_TENANT`, or the saved profile) fills `tenantId` when the input has none. Public routes
(`tenants.lookup`, `auth.signIn`, invitation acceptance) need no token.

## Asking authorization questions

```sh
better-iam can documents:write document/d1             # exits 1 (ACCESS_DENIED) when the answer is no
better-iam explain documents:write document/d1 --identity alice@acme.test [--assume-mfa]
better-iam who-can documents:delete document/d1 --format table
```

`can` answers for the token itself (recorded like any authorization check). `explain` and `who-can` simulate other
identities without signing in as them (`policies.simulate` / `policies.whoCan`, which need `iam:policies:simulate`).

## Configuration as code

A tenant's roles, policies, groups, group bindings, packages, invariants, and agreements can live in your repository as
JSON or as a module. Modules can compute values per environment and share constants with the application:

```ts
// iam/tenant.config.ts
import { defineTenantConfig } from 'better-iam/server';

export default defineTenantConfig(({ env }) => ({
  version: 1,
  roles: [{ name: 'Reader', permissions: ['documents:read'] }],
  groups: [{ name: 'Readers', members: env.STAGE === 'prod' ? [] : ['dev@acme.test'] }],
  bindings: [{ group: 'Readers', role: 'Reader' }],
}));
```

```sh
better-iam config-export --tenant ten_123 --output iam/tenant.config.ts   # start from what exists (.json, .ts, .mjs)
better-iam config-validate --input iam/tenant.config.ts --strict         # offline: no database, no token
better-iam config-plan --input iam/tenant.config.ts --fail-on-drift       # CI: exits non-zero when anything differs
better-iam config-apply --input iam/tenant.config.ts --prune              # one transaction, audited
```

`config-validate` checks the shape and warns about names the file uses but does not define (they must already exist in
the tenant); `--strict` turns those warnings into a failure, which fits pre-commit hooks. A CI job:

```yaml
- run: npx better-iam config-validate --input iam/tenant.config.ts --strict
- run: npx better-iam config-plan --input iam/tenant.config.ts --fail-on-drift
  env:
    BETTER_IAM_URL: https://iam.example.com
    BETTER_IAM_TOKEN: ${{ secrets.IAM_API_KEY }}
    BETTER_IAM_TENANT: ten_123
```

The same value applies from code with `iam.api.config.apply(credential, { tenantId, config, prune })`.

## Output and exit codes

Results print as indented JSON (the job commands `purge`, `outbox`, `audit-prune`, and `audit-export` print one line,
as they always have, for logs read line by line). `--format compact` prints one line, `--format json` indents, `--format table` prints aligned columns (for
lists, or the one list inside a result such as `findings`), and `--query PATH` prints part of a result: `summary.create`,
`roles.0.name`, `findings[].kind` (`[]` maps over a list). A string selected by `--query` prints without quotes, so
`id=$(better-iam api roles.create name=X --query id)` works.

Failures print `CODE: message` on stderr, often followed by `Hint: …` with the next step. Exit status is 0 on success,
2 for a command-line mistake (`INVALID_ARGUMENT`, `INVALID_COMMAND`, with "did you mean" suggestions), and 1 otherwise
(including CI gates such as `CONFIG_DRIFT`, `FINDINGS`, `ACCESS_DENIED`). `BETTER_IAM_DEBUG=1` prints stack traces.

## Project commands

Export commands from the configuration module and they become `better-iam <name>`, with the same flag parsing, help,
configuration loading, environment variables, `cli.defaults`, output flags, and completion as the built-in ones:

```ts
import { defineCommand } from 'better-iam/cli';

export const commands = [
  defineCommand({
    name: 'seed',
    summary: 'Create the demo organization',
    target: 'config', // loads the configuration; 'token' acts as a session; 'none' needs neither
    flags: {
      slug: { type: 'string', description: 'Organization slug', default: 'demo', env: 'SEED_SLUG' },
      members: { type: 'integer', min: 0, max: 100, description: 'People to invite' },
    },
    async run({ iam, flags, note }) {
      const instance = await iam();
      note(`Seeding ${flags.slug ?? 'demo'}…`); // stderr
      return { created: true }; // printed with --format / --query applied
    },
  }),
];
```

A `token` command gets `api()` (a transport whose `call('roles/list', { tenantId })` works in process and with
`--url`) and `token()`. To ship your own binary, `createCli({ commands, builtins })` returns a program with
`run(argv, io)`, `help()`, and `manifest()`; `runBinary()` runs it with the binary's exit-status handling.

`better-iam help --json` prints every command as JSON (usage, flags, variables, defaults, examples) for tools and
documentation. `better-iam completion bash|zsh|fish|powershell` prints a completion script. Shells run it at startup,
possibly in a directory someone else controls, so completion and `help` list project commands only for a
configuration named with `--config` or `BETTER_IAM_CONFIG`, never one they merely found:

```sh
eval "$(better-iam completion bash)"                                  # ~/.bashrc
better-iam completion fish > ~/.config/fish/completions/better-iam.fish
better-iam completion powershell | Out-String | Invoke-Expression     # $PROFILE
```

## Everything from code

Every command is a thin layer over a public function. The CLI adds argument parsing and output, nothing else:

| Command                         | Code                                                                                                |
| ------------------------------- | --------------------------------------------------------------------------------------------------- |
| `migrate`                       | `await iam.initialize()`                                                                            |
| `bootstrap` / `recover-root`    | `iam.bootstrap({ email, name, password })` / `iam.recoverRoot(...)`                                 |
| `doctor`                        | `iam.selfCheck({ deliveryRetentionMs })`                                                            |
| `outbox`                        | `iam.auth.dispatchOutbox()` then `iam.dispatchAuditHooks()`                                         |
| `purge` / `sweep`               | `iam.purgeDeleted({ retentionMs })` / `iam.sweepExpired({ limit, deliveryRetentionMs })`            |
| `digest` / `remind`             | `iam.sendAccessDigest(...)` / `iam.sendExpiryReminders(...)`                                        |
| `reconcile`                     | `iam.reconcilePackages({ tenantId, packageId, limit, confirm })`                                    |
| `close-certifications`          | `iam.closeOverdueCertifications({ tenantId })`                                                      |
| `monitor-invariants`            | `iam.checkInvariants({ tenantId })`                                                                 |
| `detect-threats`                | `iam.detectThreats({ tenantId, maxEvents })`                                                        |
| `rotate-secrets`                | `iam.rotateSecrets({ dryRun })`                                                                     |
| `audit-archive` / `audit-prune` | `iam.archiveAudit(...)` / `iam.pruneAudit({ tenantId, retentionMs })`                               |
| `audit-verify`                  | `verifyAuditChain(events, { head })` from `better-iam/core` (or `iam.api.audit.verify`)             |
| `store-export/import/copy`      | `exportStore` / `importStore` / `copyStore` from `better-iam/core`                                  |
| `config-export/plan/apply`      | `iam.api.config.export/plan/apply(credential, { tenantId, config, prune })`                         |
| `config-validate`               | `lintTenantConfig(config)` from `better-iam/cli`, `validateTenantConfig` from `better-iam/server`   |
| `analyze` / `report`            | `iam.api.analysis.findings(...)` / `iam.api.reports.access(...)`                                    |
| `mine-roles`                    | `iam.api.roleMining.suggest(...)` and `.outliers(...)`                                              |
| `check-invariants`              | `iam.api.invariants.run(credential, { tenantId })`                                                  |
| `whoami`                        | `iam.api.sts.getCallerIdentity(credential)`                                                         |
| `can` / `explain` / `who-can`   | `iam.authorize(...)` / `iam.api.policies.simulate(...)` / `iam.api.policies.whoCan(...)`            |
| `api group.method`              | `iam.api.group.method(credential, input)`, or `client.group.method(input)` from `better-iam/client` |
| `login`                         | `client.auth.signIn(...)` then `client.auth.verifyMfa(...)`                                         |
| any command line                | `runCli(['config-plan', '--input', 'x.ts'], { out, env })` from `better-iam/cli`                    |

`runCli(argv, io)` takes an `io` with `out`, `env` (the CLI never reads `process.env` implicitly), and optional `err`,
`prompt`, `stdin`, `cwd`, and `fetch`, so tests and programs run commands without touching the real terminal.
