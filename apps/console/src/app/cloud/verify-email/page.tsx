import Link from 'next/link';
import type { Tenant } from 'better-iam';
import { VerifyEmailLanding } from '@/components/auth-forms';
import { getIam } from '@/lib/iam';

export const dynamic = 'force-dynamic';

/** The landing page of a `verify-email` link: marks the address of the account that requested it as verified. */
export default async function VerifyEmail({
  searchParams,
}: {
  searchParams: Promise<{ tenant?: string; token?: string }>;
}) {
  const { tenant: tenantId, token } = await searchParams;
  const iam = await getIam();
  const tenant = tenantId ? await iam.store.get<Tenant>('tenants', tenantId) : undefined;
  const alias = tenant ? (tenant.slug ?? tenant.id) : undefined;
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>Verify your email</strong>
            <p>{tenant ? tenant.name : 'Open the link from the email we sent you'}</p>
          </div>
          {tenant && token ? (
            <VerifyEmailLanding
              tenantId={tenant.id}
              token={token}
              next={`/cloud/${encodeURIComponent(alias!)}/account`}
            />
          ) : (
            <div className="alert warning">
              This link is incomplete. Request a new verification email from your account page.
            </div>
          )}
          <p className="small muted">
            {alias ? (
              <Link href={`/cloud/login?org=${encodeURIComponent(alias)}`}>Back to sign in</Link>
            ) : (
              <Link href="/cloud">Back to the organization picker</Link>
            )}
          </p>
        </div>
      </div>
    </main>
  );
}
