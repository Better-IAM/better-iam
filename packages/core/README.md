# Core

Browser-safe types, policy validation and evaluation, and adapter/plugin contracts.

```ts
import { definePolicy, evaluatePolicy } from '@better-iam/core';
```

Node.js 22.12+ server runtime; PostgreSQL and SQLite adapters. All packages are ESM with TypeScript declarations. Version 0.1.0 packages are synchronized. The browser client and core do not import server drivers.

Configuration, threat-model documentation, and runnable SQLite/PostgreSQL examples are included in the Better IAM source repository. No AWS wire compatibility is claimed. Publication does not grant rights; see LICENSE. Dependencies retain their own licenses.
