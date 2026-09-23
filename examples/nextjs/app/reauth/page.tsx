import { ReauthenticateForm } from '@better-iam/next/client';
import { iamNext } from '@/lib/iam';
import { reauthenticate } from '../login/actions';

const reasons: Record<string, string> = {
  recent: 'This page needs a recent sign-in. Confirm your password to continue.',
  mfa: 'This page needs a second factor.',
  impersonation: 'This page is unavailable while viewing as another member.',
};

// The step-up page guards redirect to (stepUpPath), with ?next= and ?reason=.
export default async function Reauthenticate(props: {
  searchParams: Promise<{ next?: string; reason?: string }>;
}) {
  const { next, reason } = await props.searchParams;
  const session = await iamNext.requireSession({ returnTo: '/reauth' });
  return (
    <main>
      <h1>Confirm it’s you</h1>
      <p>{reasons[reason ?? 'recent'] ?? reasons.recent}</p>
      <p>
        Signed in as <code>{session.identity.email}</code>.
      </p>
      <ReauthenticateForm action={reauthenticate} {...(next ? { next } : {})} />
    </main>
  );
}
