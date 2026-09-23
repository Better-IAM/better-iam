# PostgreSQL application example

This runs the same account, IAM provisioning, document, OAuth/OIDC, and SCIM application as the SQLite example using the PostgreSQL adapter.

Provide a PostgreSQL database and a connection string in `DATABASE_URL`. From the repository root:

```powershell
pnpm install
pnpm build
$env:DATABASE_URL = 'postgres://postgres:postgres@localhost:5432/better_iam'
$env:BETTER_IAM_SECRET = node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
$env:BETTER_IAM_BASE_URL = 'http://localhost:3000'
$env:DEMO_DELIVERY = '1'
$env:BETTER_IAM_ROOT_EMAIL = 'root@example.com'
$env:BETTER_IAM_ROOT_NAME = 'Platform administrator'
$env:BETTER_IAM_ROOT_PASSWORD = Read-Host -MaskInput 'Root password (at least 12 characters)'
pnpm --filter @better-iam/example-postgres migrate
pnpm --filter @better-iam/example-postgres bootstrap
Remove-Item Env:BETTER_IAM_ROOT_PASSWORD
pnpm --filter @better-iam/example-postgres start
```

Replace the local development connection string with your actual database credentials. These environment examples use PowerShell 7; other shells can set equivalent environment variables. Keep the IAM secret stable across workers and restarts.

Open [the application](http://localhost:3000), enroll root MFA, create an organization, accept its owner invitation, and provision a document-reader role for a second user. The [SQLite walkthrough](../sqlite/README.md) describes each step, the local inbox, and deployment configuration. No PostgreSQL-specific application logic is required.

Use a distinct port/base URL when running both database examples simultaneously. Use [the shared enterprise guide](../shared/README.md) to enable the optional persistent OAuth provider and try SCIM provisioning.
