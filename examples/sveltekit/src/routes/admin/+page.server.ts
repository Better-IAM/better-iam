import { iam, iamKit } from '$lib/server/iam';

// A server load also makes client-side navigations to /admin ask the server, so `handle`'s protect rule runs for
// them too: SvelteKit renders pages without a server load entirely in the browser.
export const load = iamKit.guard(
  async (event, session) => {
    const identities = await iam.api.identities.list(event.locals.iam.credential(), {
      tenantId: session.session.tenantId,
      limit: 50,
    });
    return { members: identities.map((identity) => ({ id: identity.id, email: identity.email })) };
  },
  { authorize: { action: 'iam:identities:read' } },
);
