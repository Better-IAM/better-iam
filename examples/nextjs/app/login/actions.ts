'use server';
import { iamNext } from '@/lib/iam';

// Drop-in server actions: password sign-in with MFA, enrollment, recovery and emailed codes, step-up, sign-out,
// and password reset. They work with the client forms from @better-iam/next/client, with or without JavaScript.
const auth = iamNext.authActions({ afterSignIn: '/acme' });

export const signIn = auth.signIn;
export const reauthenticate = auth.reauthenticate;
export const requestPasswordReset = auth.requestPasswordReset;
export const resetPassword = auth.resetPassword;

export async function signOut(): Promise<void> {
  await auth.signOut();
}
