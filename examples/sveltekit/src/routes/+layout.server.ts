import { iamKit } from '$lib/server/iam';
import type { LayoutServerLoad } from './$types';

/** The session and the decisions the first render needs, handed to the browser stores as initial values. */
export const load: LayoutServerLoad = async (event) => {
  const { session } = await iamKit.sessionData(event);
  const permissions = session
    ? await event.locals.iam.authorize([{ action: 'iam:identities:read' }])
    : [];
  return { session, permissions, origin: event.url.origin };
};
