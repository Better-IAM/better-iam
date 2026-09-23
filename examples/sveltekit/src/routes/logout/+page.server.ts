import { redirect } from '@sveltejs/kit';
import type { Actions } from './$types';

export const actions: Actions = {
  default: async ({ locals }) => {
    await locals.iam.signOut();
    redirect(303, '/');
  },
};
