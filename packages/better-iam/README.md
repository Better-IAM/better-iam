# Better IAM

Independent authentication, tenant-isolated identity provisioning, configurable tenant trees, AWS-inspired policies and delegation, root administration, service credentials, OAuth/OIDC, SAML, and SCIM. This umbrella installs all @better-iam packages together. Protocol and database features are available via subpath exports.

```ts
import { betterIam, definePolicy } from 'better-iam';
import { sqliteAdapter } from 'better-iam/adapter-sqlite';
import { createIamClient } from 'better-iam/client';
```

Node.js 22.12+ server runtime; PostgreSQL and SQLite adapters. All packages are ESM with TypeScript declarations. Version 0.1.0 packages are synchronized. The browser client and core do not import server drivers.

Configuration, threat-model documentation, and runnable SQLite/PostgreSQL examples are included in the Better IAM source repository. No AWS wire compatibility is claimed. Publication does not grant rights; see LICENSE. Dependencies retain their own licenses.
