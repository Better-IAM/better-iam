# @better-iam/adapter-postgres

PostgreSQL persistence for Better IAM, using Kysely and node-postgres. Requires Node.js 22.12 or later. Install `better-iam` to receive this adapter with the complete distribution, or install this package directly.

```ts
import { postgresAdapter } from '@better-iam/adapter-postgres';

const database = postgresAdapter({ connectionString: process.env.DATABASE_URL! });
await database.migrate();
// Pass database to betterIam({ database, ... }).
```

`poolSize` defaults to 10 (allowed range: 1–100). `lockTimeoutMs` defaults to 5000 (allowed range: 1–60000). Configure transport encryption in the PostgreSQL connection string for your deployment. Keep connection strings and credentials on the server.

Every write must execute inside `database.transaction(async tx => ...)`. Application transactions acquire a database-wide transaction advisory lock before reading data. This serializes write decisions across pools and processes. PostgreSQL READ COMMITTED is intentional: each data read obtains its snapshot after the advisory lock is acquired. An early SERIALIZABLE snapshot could become stale while waiting for the lock. This implementation provides serialized application transactions while favoring clear revocation semantics over concurrent write throughput.

All clients writing Better IAM records must honor the adapter's advisory lock. Never write directly to its tables in application code. Do not perform network requests or long-running work inside transactions. Nested transactions on one adapter join the outer callback; a failed nested operation forces rollback. Do not nest a second adapter's transaction inside the first on the same database. A completed transaction handle rejects later use.

Records use the same schema and strict JSON filter semantics as SQLite. Natural keys are unique within collection and tenant. `put` updates existing rows and forbids changing tenant ownership. ID sorting and pagination are independent of database locale. Tenant and ID predicates use indexes; remaining JSON filters execute in application code. Large collections with complex JSON filters may require a future indexed adapter implementation.

`migrate()` checks the schema version and is idempotent. Back up production data before upgrades. `close()` drains and closes the pool. Database uniqueness conflicts expose `IamError` code `CONFLICT`; lock timeouts expose `STORAGE_BUSY`. Retry the complete operation after a busy response.

The shared generic record schema has no application foreign keys. Better IAM services validate references, tenant boundaries, and hierarchy within transactions. A raw adapter is privileged persistence access, not an authorization boundary.

Integration tests use a dedicated database configured through `BETTER_IAM_POSTGRES_URL`. They skip explicitly when this environment variable is absent and clean only their randomly named test collection.

License: Apache-2.0.
