# better-iam

[Better IAM](https://github.com/Better-IAM/better-iam) for Rust in one dependency, the port of the `better-iam`
umbrella package: the server, core, authentication, the storage adapters, the typed HTTP client and the projects
plugin, each re-exported as a module behind a feature (`server`, `auth`, `sqlite`, `client` and `projects` by
default; `postgres`, `libsql` and `types` on request). The crate root re-exports what the TypeScript umbrella's
index exports.

```rust,ignore
use better_iam::{better_iam, define_policy, BetterIamOptions};
use better_iam::adapter_sqlite::{sqlite_adapter, SqliteAdapterOptions};
use better_iam::client::{create_iam_client, ClientOptions};
```

The database is shared with the TypeScript implementation, so Rust and Node replicas can run side by side.
