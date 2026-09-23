# Better IAM Console

A Next.js application with two panels on one Better IAM installation:

- **Administration panel** (`/admin`) — for platform staff. Root administrators (MFA required) create organizations and delegate ownership, manage root administrators, review any tenant's audit trail, inspect the permission catalog, see queued deliveries, watch operations (database reachability, outbox backlog, live sessions, and the process's Prometheus counters; set `METRICS_TOKEN` to expose `GET /api/iam/metrics` to a scraper), inspect live sessions across organizations with a per-person sign-out for incident response, and watch sign-in failures across the platform (source addresses with a one-click platform-wide block for a day, targeted accounts with their current streak and an unlock, the latest attempts, and the platform's blocked networks) to spot and stop credential stuffing early.
- **Cloud console** (`/cloud`) — the multi-tenant product surface. Every organization is an account: people sign in to it by alias with their own identity and roles, manage workspaces (IAM-managed resources, shareable with members and groups through relationships), members, roles, groups, policies, access requests (request roles, review and approve them as temporary grants), access reviews (who can perform an action, what an identity can do), resource types with relations, service accounts and API keys, webhooks with delivery history, the audit log with chain verification and JSONL export, the organization's authentication policy (required MFA, allowed sign-in methods, session lifetimes), incident response (sign a member or everyone out, block a network from signing in), per-member data exports, and their own account (sessions with device and sign-in method, sign-out-everywhere, MFA, linked accounts, previous sign-in and failed attempts since, with a notice above every page when someone guessed against the account, and an email after five failed attempts when the server has a mail transport).

Sign-in covers password (with "keep me signed in", otherwise the cookie ends with the browser session), emailed sign-in links (`/cloud/magic`) or six-digit codes typed on the login page (passwordless email is on whenever the server has a mail transport), authenticator enrollment and verification (with "remember this device" and, when the organization allows it, emailed one-time codes), recovery codes, self-service password reset (`/cloud/reset`, linked from the login page; the deliveries page opens reset links in development), passkeys (register and name them on the account page, which shows when each was added and last used and whether it is synced; sign in with one without typing an email, including through the browser's passkey autofill on the login page, or use it as the second factor), email changes confirmed at `/cloud/confirm-email`, email verification completed at `/cloud/verify-email` (with a resend button on the account page while the address is unverified), and invitation redemption.

Both panels warn two minutes before a session lapses for inactivity (with "Stay signed in") or reaches its maximum length, and return to the login page once it has. Both panels call the same authenticated Better IAM services: server components read through `iam.api.*` with the request cookies as the credential, browser forms post through the typed client to `/api/iam/*` (Better IAM's own handler with CSRF, cookies, authorization, and audit), and protected pages enforce with `iam.require` before rendering.

## Run it

From the repository root (Node 22.12+, workspace built with `pnpm build`):

```powershell
$env:BETTER_IAM_SECRET = node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
$env:BETTER_IAM_BASE_URL = 'http://localhost:3000'
$env:BETTER_IAM_DATABASE = './console.db'          # or DATABASE_URL for PostgreSQL
$env:BETTER_IAM_ROOT_EMAIL = 'root@example.com'
$env:BETTER_IAM_ROOT_NAME = 'Platform administrator'
$env:BETTER_IAM_ROOT_PASSWORD = Read-Host -MaskInput 'Root password (at least 12 characters)'
pnpm --filter @better-iam/console migrate
pnpm --filter @better-iam/console bootstrap
Remove-Item Env:BETTER_IAM_ROOT_PASSWORD
pnpm --filter @better-iam/console dev
```

Open <http://localhost:3000>. Keep `BETTER_IAM_SECRET` stable between restarts; it seals MFA secrets and queued deliveries.

1. **Admin panel** → sign in as the root administrator and enroll an authenticator.
2. **Organizations** → create one with a sign-in alias and an owner email. Without `DELIVERY_WEBHOOK_URL`, deliveries stay in memory and root administrators can open the owner's join link from **Deliveries**.
3. Accept the owner invitation (it signs you in to the organization), then in the **cloud console** create roles from permissions, invite members with those roles, define resource types, register workspaces, and watch the overview's advisory decisions change per person.
4. Sign in as an invited member at `/cloud/login?org=<alias>` to see the enforced view.

`pnpm --filter @better-iam/console typecheck` checks the app; `next build` produces a production build (`pnpm --filter @better-iam/console build` then `start`).

## Configuration

`better-iam.config.mjs` is shared by the app and the CLI scripts. It declares the product's resource catalog — the managed `workspace` type with `workspaces:read`/`workspaces:manage` — and enables tenant-defined resource types. `src/lib/iam.ts` creates the singleton, runs migrations on first use, drives the delivery outbox and audit hooks once per second, and delivers messages to `DELIVERY_WEBHOOK_URL` (with optional `DELIVERY_WEBHOOK_TOKEN`) or the in-memory inbox.

Environment: `BETTER_IAM_SECRET` (required), `BETTER_IAM_PREVIOUS_SECRETS`, `BETTER_IAM_BASE_URL`, `BETTER_IAM_DATABASE` or `DATABASE_URL`, `DELIVERY_WEBHOOK_URL`, `DELIVERY_WEBHOOK_TOKEN`.

To rotate the secret, follow the steps in [docs/deployment.md](../../docs/deployment.md): set the new value as `BETTER_IAM_SECRET` and list the old one (comma-separated if several) in `BETTER_IAM_PREVIOUS_SECRETS`. The console derives its App provisioning (outbound SCIM) token key from the secret too; while previous secrets are set it opens tokens with their keys and re-seals every stored token with the current key once per start. Run `better-iam rotate-secrets` with the same configuration for everything else, then remove `BETTER_IAM_PREVIOUS_SECRETS`.

The console also runs, in-process and hourly, the retention sweep (`iam.sweepExpired()`) and the invariant monitor (`iam.checkInvariants()`), and records which actions people use (`accessUsage`) for the Role mining and Governance pages.

## Notes

- One session cookie per browser: signing in to an organization replaces an admin session and vice versa, exactly as the IAM server scopes it.
- Operations that Better IAM protects with recent authentication (creating organizations, changing status, issuing keys, changing passwords, and so on) prompt for the password and authenticator again in place.
- Account linking (`/cloud/<org>/account`) proves the other organization's credentials on the server (`src/app/api/console/link/route.ts`) so the browser cookie is never replaced; switching still signs in to the target organization, by design.
- The in-memory inbox is a development convenience shown only to root administrators. Configure a webhook before exposing the console.
