# Server

The betterIam factory, tenant provisioning, authenticated management services, authorization, events and webhooks, Node/Fetch handlers, root bootstrap, and audit dispatch.

```ts
import { betterIam } from '@better-iam/server';
```

Node.js 22.12+ server runtime; PostgreSQL and SQLite adapters. All packages are ESM with TypeScript declarations. Version 0.1.0 packages are synchronized. The browser client and core do not import server drivers.

## Layout

`betterIam()` in `src/index.ts` composes small modules that share one `ServerContext`:

- `options.ts` validates configuration; `catalog.ts` owns the permission catalog; `plugins.ts` validates plugins.
- `context.ts` provides storage helpers (tenants, ancestry, authorities, scoping, owner setup).
- `decisions.ts` evaluates policies (including relationships and simulated principals), `principals.ts` resolves credentials, `operations.ts` wraps every call in the transactional authorization envelope, `events.ts` records chained audit events and drives webhooks and subscribers, `observe.ts` times spans, and `assertions.ts` issues and verifies stateless assertions.
- `api/` holds one file per API group; `flows.ts` holds invitation, linking, and role-assumption flows; `lifecycle.ts` holds bootstrap, audit-chain backfill, and the retention worker; `federation.ts` exposes protocol callbacks; `http.ts` holds the transports.

Configuration, threat-model documentation, and runnable SQLite/PostgreSQL examples are included in the Better IAM source repository. No AWS wire compatibility is claimed. Publication does not grant rights; see LICENSE. Dependencies retain their own licenses.
