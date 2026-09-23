import Link from 'next/link';
import { cookies } from 'next/headers';
import type { Tenant } from 'better-iam';
import { KeepSignedIn, MagicLinkLanding } from '@/components/auth-forms';
import { getIam } from '@/lib/iam';
import { initialRemember, REMEMBER_COOKIE } from '@/lib/persistence';

export const dynamic = 'force-dynamic';

/** The landing page of a `magic-link` email: redeems the single-use token for the address it was sent to. */
export default async function Magic({
  searchParams,
}: {
  searchParams: Promise<{ tenant?: string; token?: string; to?: string }>;
}) {
  const { tenant: tenantId, token, to } = await searchParams;
  const iam = await getIam();
  const tenant = tenantId ? await iam.store.get<Tenant>('tenants', tenantId) : undefined;
  const alias = tenant ? (tenant.slug ?? tenant.id) : undefined;
  // The link may open in a browser (or tab) where the sign-in page's choice was never made, so ask here too.
  const remember = initialRemember((await cookies()).get(REMEMBER_COOKIE)?.value, iam.endpoint);
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>Sign in with your link</strong>
            <p>{tenant ? tenant.name : 'Open the link from the email we sent you'}</p>
          </div>
          {tenant && tenant.status === 'active' && token && to ? (
            <>
              <KeepSignedIn initial={remember} />
              <MagicLinkLanding
                tenantId={tenant.id}
                destination={to}
                token={token}
                next={`/cloud/${encodeURIComponent(alias!)}`}
                signInHref={`/cloud/login?org=${encodeURIComponent(alias!)}`}
              />
            </>
          ) : (
            <div className="alert warning">
              This link is incomplete or the organization is unavailable. Request a new link from
              the sign-in page.
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
