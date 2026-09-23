# @better-iam/react

React bindings for the Better IAM browser client: a session store, hooks for the current session and advisory authorization decisions, and a `Can` component. Requires React 18.2 or later. Everything here is advisory UI state; the server enforces every operation.

```tsx
import { createIamClient } from '@better-iam/client';
import { Can, IamProvider, useAccessible, useAuthorize, useSession } from '@better-iam/react';
import type { iam } from './server.js';

const client = createIamClient<typeof iam>({ baseURL: 'https://app.example.com' });

export function App() {
  return (
    <IamProvider client={client}>
      <Workspace tenantId="…" />
    </IamProvider>
  );
}

function Workspace({ tenantId }: { tenantId: string }) {
  const { status, session, signOut } = useSession<typeof client>();
  const { allowed } = useAuthorize({
    tenantId,
    checks: [{ action: 'projects:manage', resource: { type: 'project', id: 'website' } }],
  });
  const { resources } = useAccessible({ tenantId, action: 'projects:read', type: 'project' });
  if (status === 'loading') return <p>Loading…</p>;
  if (status !== 'authenticated') return <a href="/login">Sign in</a>;
  return (
    <>
      <p>
        {session.identity.name} <button onClick={() => void signOut()}>Sign out</button>
      </p>
      <ul>
        {resources.map((project) => (
          <li key={project.id}>{project.resourceId}</li>
        ))}
      </ul>
      {allowed('projects:manage', { type: 'project', id: 'website' }) && <button>Manage</button>}
      <Can tenantId={tenantId} action="iam:identities:create" fallback={null}>
        <a href="/invite">Invite a member</a>
      </Can>
    </>
  );
}
```

- `IamProvider` loads the session on mount unless `initialSession` is supplied (pass `null` for a known signed-out render), refreshes on focus by default, and can poll with `refreshIntervalMs`.
- `useSession` returns the snapshot (`status`, `session`, `error`) plus `refresh`, `signOut`, and `setSession` for applying a sign-in response directly.
- `useAuthorize` batches checks through `authorizeMany` and re-runs when the checks or the signed-in identity change. `allowed(action, resource?)` defaults the resource to `iam/{tenantId}`.
- `useAccessible` wraps the reverse query for managed resource types.
- `useAgreements({ tenantId })` lists the person's terms of use with `pending` (required, not yet accepted in their current version) and `accept(agreement)`; render the pending text and an accept button before the rest of the app when policies require acceptance.
- `useAccessPaths({ tenantId, action, resource })` answers "how do I get access?": `allowed`, and when denied the self-service `paths` (`mfa`, `accept-agreements`, `activate`, `request-package`) the server verified would allow the person. Call `refresh()` after the person takes one.
- `useDelegations({ tenantId })` lists the AI agents acting (`active`) or asking to act (`requests`) for the signed-in person, with `grant`, `approve` (optionally narrowing scopes or adding `confirm` actions), `deny`, and `revoke`; `useConfirmations({ tenantId })` lists the actions agents ask the person to confirm one at a time, with `approve` and `reject`; `useAgentCatalog({ tenantId })` lists the agents the person may delegate to; `useModels({ tenantId })` lists the AI models the caller may use. See [AI agents](../../docs/agents.md).
- `useTeams({ tenantId })` lists the signed-in person's teams (with role, expiry, and the teams above each), their `pending` join requests, and the teams they may ask to join (`joinable`), with `requestToJoin(teamId, justification?)`, `cancelRequest(requestId)`, and `leave(teamId)`. See [teams and departments](../../docs/teams-and-departments.md).
- `useMySpend({ tenantId, period?, groupBy? })` loads the signed-in person's own spend for a month (their usage and their agents', by meter, day, agent, tenant or tag) with a projection and the budgets set on them; `useSpendCheck({ tenantId, meter? })` tells whether an enforced spend budget blocks them (`allowed`, `blockedBy`). See [billing](../../docs/billing.md).
- `createSessionStore(client)` is the framework-agnostic core the hooks use; it works with `useSyncExternalStore` or any subscription mechanism.

License: MIT.
