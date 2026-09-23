import Link from 'next/link';
import { SignInForm } from '@better-iam/next/client';
import { demo } from '@/lib/iam';
import { signIn } from './actions';

export default async function Login(props: {
  searchParams: Promise<{ next?: string; org?: string; reset?: string }>;
}) {
  const { next, org, reset } = await props.searchParams;
  return (
    <main>
      <h1>Sign in</h1>
      {reset && <p className="ok">Your password was changed. Sign in with the new one.</p>}
      <SignInForm
        action={signIn}
        org={org ?? demo.org}
        email={demo.reader.email}
        keepSignedIn
        passwordless
        {...(next ? { next } : {})}
      />
      <p>
        <Link href="/forgot">Forgot your password?</Link>
      </p>
      {next && (
        <p>
          You will return to <code>{next}</code>.
        </p>
      )}
    </main>
  );
}
