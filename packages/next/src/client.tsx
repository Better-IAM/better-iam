'use client';
import { useCallback, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation.js';
import {
  IamProvider,
  useSession,
  type IamProviderProps,
  type SessionClient,
} from '@better-iam/react';

export { useSession, useAuthorize, useAccessible, useIamClient, Can } from '@better-iam/react';
// Named, not `export *`: Next refuses `export *` in a 'use client' module imported from a server component.
export {
  SignInForm,
  SignInFormView,
  ReauthenticateForm,
  ReauthenticateFormView,
  PasswordResetRequestForm,
  PasswordResetRequestFormView,
  PasswordResetForm,
  PasswordResetFormView,
  SignUpForm,
  SignUpFormView,
  InvitationForm,
  InvitationFormView,
} from './forms.js';
export type {
  AuthFormViewProps,
  AuthFormOptions,
  AuthFormViewOf,
  MfaLabels,
  SignInLabels,
  ReauthenticateLabels,
  PasswordResetRequestLabels,
  PasswordResetLabels,
  SignUpLabels,
  InvitationLabels,
  SignInFormProps,
  ReauthenticateFormProps,
  PasswordResetRequestFormProps,
  PasswordResetFormProps,
  SignUpFormProps,
  InvitationFormProps,
} from './forms.js';
export type {
  AuthAction,
  AuthFormError,
  AuthFormState,
  AuthIntent,
  AuthMfaChallenge,
  AuthStep,
} from './auth-types.js';

function identityOf(session: unknown): string | null {
  const identity = (session as { identity?: { id?: unknown } } | null)?.identity;
  return typeof identity?.id === 'string' ? identity.id : null;
}

/**
 * Calls `router.refresh()` whenever the signed-in identity changes in the client (sign-in, sign-out, account switch,
 * or a session that expired while the tab was open), so server components re-render with the new cookies.
 */
export function useRouterSync(): void {
  const { status, session } = useSession();
  const router = useRouter();
  const last = useRef<string | null | undefined>(undefined);
  const current = status === 'loading' || status === 'error' ? undefined : identityOf(session);
  useEffect(() => {
    if (current === undefined) return;
    if (last.current === undefined) {
      last.current = current;
      return;
    }
    if (last.current !== current) {
      last.current = current;
      router.refresh();
    }
  }, [current, router]);
}

function RouterSync() {
  useRouterSync();
  return null;
}

/**
 * `IamProvider` for the App Router: pass `initialSession` from `iamNext.sessionForClient()` in a server layout, and
 * server components refresh automatically when the session changes on the client.
 */
export function IamNextProvider<T extends SessionClient>({
  children,
  ...props
}: IamProviderProps<T>) {
  return (
    <IamProvider {...props}>
      <RouterSync />
      {children}
    </IamProvider>
  );
}

/**
 * Signs out through the client session store, then navigates (when `redirectTo` is given) and refreshes server
 * components so no page keeps rendering the previous session.
 */
export function useSignOut(options: { redirectTo?: string } = {}): () => Promise<void> {
  const { signOut } = useSession();
  const router = useRouter();
  const { redirectTo } = options;
  return useCallback(async () => {
    await signOut();
    if (redirectTo) router.replace(redirectTo);
    router.refresh();
  }, [signOut, router, redirectTo]);
}
