import Link from 'next/link';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { KeepSignedIn, LoginFlow, MagicLinkForm } from '@/components/auth-forms';
import { PasskeySignIn } from '@/components/passkeys';
import { SessionEndedNotice } from '@/components/session-notice';
import { getIam } from '@/lib/iam';
import { initialRemember, REMEMBER_COOKIE } from '@/lib/persistence';
import { currentSession, resolveTenant } from '@/lib/session';

export const dynamic = 'force-dynamic';

export default async function CloudLogin({
  searchParams,
}: {
  searchParams: Promise<{ org?: string; reason?: string }>;
}) {
  const { org, reason } = await searchParams;
  if (!org) redirect('/cloud');
  const [tenant, session, jar, iam] = await Promise.all([
    resolveTenant(org),
    currentSession(),
    cookies(),
    getIam(),
  ]);
  const next = `/cloud/${encodeURIComponent(org)}`;
  if (tenant && session?.session.tenantId === tenant.id) redirect(next);
  // Offer only the methods the organization's policy accepts; an unset list accepts every method.
  const allows = (method: 'passkey' | 'passwordless-email') =>
    tenant?.authPolicy?.allowedMethods?.includes(method) ?? true;
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>Cloud console</strong>
            <p>{tenant ? `Sign in to ${tenant.name}` : 'Organization not found'}</p>
          </div>
          <SessionEndedNotice reason={reason} />
          {tenant && tenant.status === 'active' && tenant.parentId !== null ? (
            <>
              {/* One choice for every method below, including passkey autofill in the email field. */}
              <KeepSignedIn
                initial={initialRemember(jar.get(REMEMBER_COOKIE)?.value, iam.endpoint)}
              />
              <LoginFlow tenantId={tenant.id} next={next} tenantName={tenant.name} />
              {/* Also keeps page loads from starting passkey ceremonies the policy would refuse. */}
              {allows('passkey') && <PasskeySignIn tenantId={tenant.id} next={next} />}
              {allows('passwordless-email') && <MagicLinkForm tenantId={tenant.id} next={next} />}
            </>
          ) : (
            <div className="alert warning">
              No active organization answers to <code>{org}</code>. Check the alias with your
              administrator.
            </div>
          )}
          <p className="small muted">
            <Link href="/cloud">Use a different organization</Link> ·{' '}
            <Link href="/cloud/join">Redeem an invitation</Link>
            {tenant && (
              <>
                {' '}
                ·{' '}
                <Link href={`/cloud/reset?org=${encodeURIComponent(org)}`}>
                  Forgot your password?
                </Link>
              </>
            )}
          </p>
        </div>
      </div>
    </main>
  );
}
