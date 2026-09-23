import { PasswordResetRequestForm } from '@better-iam/next/client';
import { demo } from '@/lib/iam';
import { requestPasswordReset } from '../login/actions';

export default function Forgot() {
  return (
    <main>
      <h1>Reset your password</h1>
      <PasswordResetRequestForm action={requestPasswordReset} org={demo.org} />
      <p>In development the email lands on /dev/inbox.</p>
    </main>
  );
}
