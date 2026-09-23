import { Form, data, redirect } from 'react-router';
import { safeRedirectPath } from '@better-iam/react-router';
import { demo, iamRouter } from '../iam.server';
import type { Route } from './+types/login';

// The in-process client signs in; the root middleware puts the session cookie on the redirect.
export async function action(args: Route.ActionArgs) {
  const form = await args.request.formData();
  const email = String(form.get('email') ?? '');
  let result;
  try {
    result = await iamRouter.helpers(args).client.auth.signIn({
      tenantId: demo.tenantId ?? String(form.get('tenantId') ?? ''),
      email,
      password: String(form.get('password') ?? ''),
    });
  } catch (error) {
    return data(
      { email, message: error instanceof Error ? error.message : 'Sign-in failed' },
      { status: 400 },
    );
  }
  if (!('token' in result))
    return data({ email, message: 'This demo does not handle MFA' }, { status: 400 });
  throw redirect(safeRedirectPath(new URL(args.request.url).searchParams.get('next')));
}

export default function Login({ actionData }: Route.ComponentProps) {
  return (
    <>
      <h1>Sign in</h1>
      <Form method="post">
        <label>
          Email{' '}
          <input
            name="email"
            type="email"
            autoComplete="username"
            defaultValue={actionData?.email}
          />
        </label>
        <label>
          Password <input name="password" type="password" autoComplete="current-password" />
        </label>
        <button>Sign in</button>
      </Form>
      {actionData?.message ? <p id="login-error">{actionData.message}</p> : null}
    </>
  );
}
