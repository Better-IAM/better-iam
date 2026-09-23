import { iam, iamRouter } from '../iam.server';
import type { Route } from './+types/admin';

// Only people with iam:identities:read on their tenant get past the guard; others see the root error boundary (403).
export const loader = iamRouter.guard(
  async (args: Route.LoaderArgs, session) => {
    const identities = await iam.api.identities.list(iamRouter.helpers(args).credential(), {
      tenantId: session.session.tenantId,
      limit: 50,
    });
    return { members: identities.map((identity) => ({ id: identity.id, email: identity.email })) };
  },
  { authorize: { action: 'iam:identities:read' } },
);

export default function Admin({ loaderData }: Route.ComponentProps) {
  return (
    <>
      <h1 id="admin-title">Admin</h1>
      <ul>
        {loaderData.members.map((member) => (
          <li key={member.id}>{member.email}</li>
        ))}
      </ul>
    </>
  );
}
