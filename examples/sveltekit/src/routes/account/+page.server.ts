import { iam, iamKit } from '$lib/server/iam';

// `handle` already requires a session for /account; the guard hands it to the load, typed.
export const load = iamKit.guard(async (_event, session) => ({
  email: session.identity.email,
  name: session.identity.name,
}));

export const actions = {
  // Renaming other people needs iam:identities:update; a plain member gets fail(403) back in `form`.
  rename: iamKit.action(
    async (event, session) => {
      const name = String((await event.request.formData()).get('name') ?? '');
      await iam.api.identities.update(event.locals.iam.credential(), {
        tenantId: session.session.tenantId,
        identityId: session.identity.id,
        name,
      });
      return { renamed: name };
    },
    { authorize: { action: 'iam:identities:update' } },
  ),
};
