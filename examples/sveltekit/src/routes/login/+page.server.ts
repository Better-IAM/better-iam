import { fail, redirect } from '@sveltejs/kit';
import { safeRedirectPath } from '@better-iam/svelte/kit';
import { demo } from '$lib/server/iam';
import type { Actions } from './$types';

export const actions: Actions = {
  // The in-process client signs in and writes the session cookie onto this response.
  default: async ({ request, locals, url }) => {
    const form = await request.formData();
    const email = String(form.get('email') ?? '');
    try {
      const result = await locals.iam.client.auth.signIn({
        tenantId: demo.tenantId ?? String(form.get('tenantId') ?? ''),
        email,
        password: String(form.get('password') ?? ''),
      });
      if (!('token' in result))
        return fail(400, { email, message: 'This demo does not handle MFA' });
    } catch (error) {
      return fail(400, {
        email,
        message: error instanceof Error ? error.message : 'Sign-in failed',
      });
    }
    redirect(303, safeRedirectPath(url.searchParams.get('next')));
  },
};
