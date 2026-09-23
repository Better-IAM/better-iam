import Link from 'next/link';
import type { Tenant } from 'better-iam';
import { ConfirmEmailChange } from '@/components/auth-forms';
import { getIam } from '@/lib/iam';

export const dynamic = 'force-dynamic';

/** The landing page of an `email-change` link: confirms the new address for the account that requested it. */
export default async function ConfirmEmail({
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
            <strong>Confirm your new email</strong>
            <p>{tenant ? tenant.name : 'Open the link from the email we sent you'}</p>
          </div>
          {tenant && token ? (
            <ConfirmEmailChange
              tenantId={tenant.id}
              token={token}
              next={`/cloud/login?org=${encodeURIComponent(alias!)}`}
            />
          ) : (
            <div className="alert warning">
              This link is incomplete. Request the change again from your account page.
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
