# SQLite application example

This is a working Node HTTP application with local SQLite storage, application-owned login/MFA/account forms, organization invitations, custom IAM policies, and protected documents. The same application runs against PostgreSQL in the neighboring example.

From the repository root, use Node 22.12+ and pnpm:

```powershell
pnpm install
pnpm build
$env:BETTER_IAM_SECRET = node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
$env:BETTER_IAM_BASE_URL = 'http://localhost:3000'
$env:DEMO_DELIVERY = '1'
$env:BETTER_IAM_ROOT_EMAIL = 'root@example.com'
$env:BETTER_IAM_ROOT_NAME = 'Platform administrator'
$env:BETTER_IAM_ROOT_PASSWORD = Read-Host -MaskInput 'Root password (at least 12 characters)'
pnpm --filter @better-iam/example-sqlite migrate
pnpm --filter @better-iam/example-sqlite bootstrap
Remove-Item Env:BETTER_IAM_ROOT_PASSWORD
pnpm --filter @better-iam/example-sqlite start
```

The environment snippets use PowerShell 7; use your shell's equivalent environment exports elsewhere. Keep `BETTER_IAM_SECRET` stable between processes and restarts. The default database is `examples/sqlite/better-iam.db`; override `BETTER_IAM_DATABASE` to choose another file.

Open [the local application](http://localhost:3000). The bootstrap command creates the protected root exactly once. The page displays the root tenant identifier for this example.

1. Sign in as the root administrator. Use **Start authenticator enrollment**, add its secret to your authenticator, and submit a code. Save the one-time recovery codes.
2. Create an organization, keeping the root as its parent, and give it a sign-in alias. Refresh the local delivery inbox and use **Fill invitation**, then enter the invited owner's name and password. Accepting the invitation signs into a separate organization identity. Anyone can now use **Find your organization** with the alias instead of a tenant ID.
3. As the owner, create a custom role from permissions (for example `documents:read, workspaces:read`), then invite a member with that role ID. Fill the member invitation from the inbox and accept it in another browser session: the member is signed in with the role already applied. Alternatively, create a document as the owner and register a second user through the signup form; signup creates no role assignments until the owner provisions a policy, role, and binding.
4. Register a tenant-defined resource type (for example `invoice` with `read` and `approve`), create a workspace, and use **List workspaces with my permissions** as different people: the list comes from one advisory batch decision and every read is still enforced by the server.
5. Create another organization as root to observe tenant isolation. Membership in one organization does not grant access to another; use **List linked accounts** after linking two identities to see the account switcher data.

MFA codes are single-use within their time step. Wait for the authenticator's next code when repeating an authentication ceremony immediately after enrollment.

`DEMO_DELIVERY=1` enables a memory-only inbox on `/dev/inbox`, restricted to a loopback URL, exact Host header, and loopback remote address. It is deliberately a local demonstration feature: every local user can read its messages. Without this flag, configure an HTTPS `DELIVERY_WEBHOOK_URL` and optional `DELIVERY_WEBHOOK_TOKEN`; the webhook receives `{id, tenantId, to, template, payload}` and must deduplicate by `id`. Never enable the development inbox behind a public proxy.

The HTTP server binds to `127.0.0.1`; `PORT` can override its backend listen port. For deployment, put it behind a TLS reverse proxy that preserves the configured application Host header, and disable the local inbox. The persistent outbox worker runs once per second.

See [enterprise protocol instructions](../shared/README.md) for actual OAuth/OIDC, device authorization, and SCIM flows, or use `pnpm --filter @better-iam/example-sqlite doctor` for a database/root check.
