import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ locals }) => {
  const session = await locals.iam.getSession();
  if (!session) return json({ code: 'UNAUTHENTICATED' }, { status: 401 });
  return json({
    id: session.identity.id,
    email: session.identity.email,
    canReadMembers: await locals.iam.can('iam:identities:read'),
  });
};
