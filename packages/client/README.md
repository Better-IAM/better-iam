# @better-iam/client

Browser-safe typed client for Better IAM. It depends on no server runtime. Import your configured server instance **as a type** so database and authentication code are excluded from browser bundles.

```ts
import { createIamClient } from '@better-iam/client';
import type { iam } from './server.js';

const client = createIamClient<typeof iam>({ baseURL: 'https://app.example.com' });
const { tenantId } = await client.tenants.lookup({ slug: 'acme' }); // public alias discovery for login screens
const result = await client.auth.signIn({ tenantId, email: 'user@example.com', password });
const current = await client.auth.getSession();
const decision = await client.authorize({
  tenantId,
  action: 'documents:read',
  resource: { type: 'document', id: 'doc-id' },
});
const { results } = await client.authorizeMany({
  tenantId,
  checks: [{ action: 'documents:write', resource: { type: 'document', id: 'doc-id' } }],
});
const accounts = await client.links.list(); // linked identities in other organizations, for an account switcher
```

Member invitations are redeemed without a session: `client.identities.acceptInvitation({ tenantId, token, name, password })` creates the account, applies the invited roles, and signs the person in. Cookies use Fetch's `credentials: 'include'`. For service or bearer sessions, provide `token: () => currentToken`; the client never writes tokens to browser storage. The server still authenticates and authorizes every call. Client permission decisions are advisory.

Requests use `POST /api/iam/{group}/{method}` with the input as the JSON body, `Content-Type: application/json`, and `X-Better-IAM: 1`. You can configure `basePath`, headers, Fetch, and per-call cancellation. `IamClientError` exposes `code`, `message`, and HTTP `status`. Plugin routes use `client.$request<Result>('plugins/my-plugin/action', input)`.

WebAuthn ceremony helpers are exported separately from `@better-iam/client/passkeys`:

```ts
import { startRegistration } from '@better-iam/client/passkeys';
const challenge = await client.auth.beginPasskeyRegistration();
const response = await startRegistration({ optionsJSON: challenge.options });
await client.auth.finishPasskeyRegistration({ challengeId: challenge.challengeId, response });
```

For MFA enrollment after a restricted login challenge, call `client.auth.beginMfa({ tenantId, challenge })`, then `client.auth.confirmMfa({ credential: { tenantId, challenge }, code })`. During an authenticated session, call `beginMfa()` and `confirmMfa({ code })`.
