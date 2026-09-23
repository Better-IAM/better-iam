# CLI

The `better-iam` command: deployment jobs (migrate, bootstrap, doctor, scheduled sweeps, audit and storage operations),
configuration as code (`config-export`, `config-validate`, `config-plan`, `config-apply`, in JSON or TypeScript), any
API method as a signed-in person or API key (`api`, `login`, `can`, `explain`, `who-can`), and your own project
commands.

```sh
better-iam help                     # every command
better-iam help config-plan         # one command's flags, defaults, and environment variables
better-iam init --typescript        # better-iam.config.ts
better-iam migrate                  # finds the nearest better-iam.config.* (or --config PATH)
better-iam login --url https://iam.example.com --org acme --email me@acme.test
better-iam api roles.create name=Reader permissions:='["documents:read"]'
eval "$(better-iam completion bash)"
```

Everything is also callable from code: `runCli(argv, io)`, `createCli({ commands })`, `defineCommand`, `loadConfig`,
and `configFromEnv`. Secrets (root and sign-in passwords) are read from the environment or a hidden prompt, never from
arguments. The configuration module is trusted, executable code.

Node.js 22.12+ server runtime (TypeScript configurations need 22.18+); PostgreSQL, SQLite, and libSQL adapters. All
packages are ESM with TypeScript declarations. Version 0.1.0 packages are synchronized. See `docs/cli.md` in the Better
IAM source repository. No AWS wire compatibility is claimed. Publication does not grant rights; see LICENSE.
Dependencies retain their own licenses.
