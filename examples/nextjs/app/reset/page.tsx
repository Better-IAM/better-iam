import { PasswordResetForm } from '@better-iam/next/client';
import { resetPassword } from '../login/actions';

// The page a password-reset email links to: /reset?tenantId=...&token=...
export default async function Reset(props: {
  searchParams: Promise<{ tenantId?: string; token?: string }>;
}) {
  const { tenantId, token } = await props.searchParams;
  if (!tenantId || !token) return <p className="error">This reset link is incomplete.</p>;
  return (
    <main>
      <h1>Choose a new password</h1>
      <PasswordResetForm action={resetPassword} tenantId={tenantId} token={token} />
    </main>
  );
}
