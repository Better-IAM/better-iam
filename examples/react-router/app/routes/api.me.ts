import { iamRouter } from '../iam.server';
import type { Route } from './+types/api.me';

export async function loader(args: Route.LoaderArgs) {
  const iam = iamRouter.helpers(args);
  const session = await iam.getSession();
  if (!session) return Response.json({ code: 'UNAUTHENTICATED' }, { status: 401 });
  return Response.json({
    id: session.identity.id,
    email: session.identity.email,
    canReadMembers: await iam.can('iam:identities:read'),
  });
}
