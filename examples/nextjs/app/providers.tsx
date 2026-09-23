'use client';
import type { ReactNode } from 'react';
import { createIamClient } from '@better-iam/client';
import { IamNextProvider, useSession, useSignOut } from '@better-iam/next/client';
import type { BetterIam } from '@better-iam/server';

// One browser client for the app; it calls /api/iam with the session cookie. During server rendering it is never
// called (the provider starts from initialSession), but it needs an origin to be constructed.
const client = createIamClient<BetterIam>({
  baseURL: typeof window === 'undefined' ? 'http://localhost' : window.location.origin,
});
type Session = Awaited<ReturnType<BetterIam['api']['auth']['getSession']>>;

export function Providers(props: { initialSession: Session | null; children: ReactNode }) {
  return (
    <IamNextProvider client={client} initialSession={props.initialSession}>
      {props.children}
    </IamNextProvider>
  );
}

/** Client-side session state; signing out here refreshes the server components through IamNextProvider. */
export function ClientSession() {
  const { session, status } = useSession<typeof client>();
  const signOut = useSignOut({ redirectTo: '/login' });
  return (
    <p>
      Client view: {status === 'authenticated' ? session?.identity.name : status}{' '}
      <button type="button" onClick={() => void signOut()}>
        Sign out (client)
      </button>
    </p>
  );
}
