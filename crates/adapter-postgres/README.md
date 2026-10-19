# better-iam-adapter-postgres

PostgreSQL storage for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of
`@better-iam/adapter-postgres`: the same schema, migrations, SQL, value encoding and advisory-lock transactions, so
TypeScript and Rust servers can share one database.

```rust,ignore
use better_iam_adapter_postgres::{postgres_adapter, PostgresAdapterOptions};

let store = postgres_adapter(PostgresAdapterOptions::new("postgres://iam@localhost/iam"))?;
store.migrate().await?;
```

Transactions serialize through a database advisory lock, including other adapter instances and TypeScript servers.
TLS (rustls, no OpenSSL) is used when the connection string sets `sslmode=prefer` or `sslmode=require`.
