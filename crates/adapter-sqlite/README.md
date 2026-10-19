# better-iam-adapter-sqlite

SQLite storage for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of
`@better-iam/adapter-sqlite`. It runs the same schema migrations and SQL as the TypeScript adapter, so TypeScript
and Rust servers can share one database file.

```rust,ignore
use better_iam_adapter_sqlite::{sqlite_adapter, SqliteAdapterOptions};

let store = sqlite_adapter(SqliteAdapterOptions::new("iam.db"))?;
store.migrate().await?;
```

Operations serialize per canonical filename in this process; SQLite's `BEGIN IMMEDIATE` lock coordinates other
processes (including TypeScript ones) with a bounded wait (`busy_timeout_ms`, default 5000).
