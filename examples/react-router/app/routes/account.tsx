import { Form } from 'react-router';
import { iam, iamRouter } from '../iam.server';
import type { Route } from './+types/account';

export const loader = iamRouter.guard(async (_args: Route.LoaderArgs, session) => ({
  email: session.identity.email,
  name: session.identity.name,
}));

// Renaming needs iam:identities:update; a plain member gets data({ code: 'ACCESS_DENIED' }, 403) back.
export const action = iamRouter.action(
  async (args: Route.ActionArgs, session) => {
    const name = String((await args.request.formData()).get('name') ?? '');
    await iam.api.identities.update(iamRouter.helpers(args).credential(), {
      tenantId: session.session.tenantId,
      identityId: session.identity.id,
      name,
    });
    return { renamed: name };
  },
  { authorize: { action: 'iam:identities:update' } },
);

export default function Account({ loaderData, actionData }: Route.ComponentProps) {
  return (
    <>
      <h1>Account</h1>
      <p id="account-email">{loaderData.email}</p>
      <Form method="post">
        <label>
          Name <input name="name" defaultValue={loaderData.name} />
        </label>
        <button>Rename</button>
      </Form>
      {actionData && 'code' in actionData ? <p id="rename-error">{actionData.code}</p> : null}
    </>
  );
}
