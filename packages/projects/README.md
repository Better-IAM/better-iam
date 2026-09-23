# @better-iam/projects

Reference Projects plugin for Better IAM. Requires Node.js 22.12 or later. Install `better-iam` to receive this plugin with the complete distribution, or install this package directly.

```ts
import { betterIam } from '@better-iam/server';
import { createProjectsPlugin } from '@better-iam/projects';

const iam = betterIam({
  /* ... */
  plugins: [createProjectsPlugin()],
});
```

Registering the plugin adds the `projects:read` and `projects:write` actions to the action catalog and mounts the plugin endpoints. Every call runs through the server's transactional authorization service: tenant scope, ancestry boundaries, policies, audit records, and root override apply unchanged. Project records live in the `projects` collection, are scoped to one tenant, and never cross tenants.

## Endpoints

All endpoints are `POST /api/iam/plugins/projects/{path}` (or `iam.callPlugin`) and take `{ tenantId, ... }`:

| Path      | Action           | Input                                          | Result                       |
| --------- | ---------------- | ---------------------------------------------- | ---------------------------- |
| `create`  | `projects:write` | `{ tenantId, name, description? }`             | Created project              |
| `list`    | `projects:read`  | `{ tenantId, status? }`                        | Projects ordered by creation |
| `get`     | `projects:read`  | `{ tenantId, projectId }`                      | Project                      |
| `update`  | `projects:write` | `{ tenantId, projectId, name?, description? }` | Updated project              |
| `archive` | `projects:write` | `{ tenantId, projectId }`                      | Archived project             |
| `restore` | `projects:write` | `{ tenantId, projectId }`                      | Restored project             |

Names are unique within a tenant (1-100 characters); descriptions are at most 500 characters. Archiving is reversible; invalid transitions and duplicate names return `INVALID_TRANSITION`/`CONFLICT`. Validation rejects unknown fields, and a `tenantId` inside the plugin input must match the request scope. Use the SDK's `$request` for plugin routes.

The plugin implements the plugin `purge` callback: when `iam.purgeDeleted()` removes a deleted tenant after its retention window, the tenant's project records are removed in the same transaction. Audit records survive.

The default hierarchy `root → organization → project` places projects under any tenant, including the installation root tenant; tenant type does not restrict project records. Tenant isolation comes from the server's authorization service, not from this plugin.

License: Apache-2.0.
