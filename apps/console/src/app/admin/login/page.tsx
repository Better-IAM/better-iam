import Link from 'next/link';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { KeepSignedIn, LoginFlow } from '@/components/auth-forms';
import { SessionEndedNotice } from '@/components/session-notice';
import { getIam } from '@/lib/iam';
import { initialRemember, REMEMBER_COOKIE } from '@/lib/persistence';
import { currentSession, rootTenant } from '@/lib/session';

export const dynamic = 'force-dynamic';

export default async function AdminLogin({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const [session, root, { reason }, jar, iam] = await Promise.all([
    currentSession(),
    rootTenant(),
    searchParams,
    cookies(),
    getIam(),
  ]);
  if (session?.identity.rootAdmin) redirect('/admin');
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>Better IAM · Administration</strong>
            <p>Root administrators only. Multi-factor authentication is required.</p>
          </div>
          <SessionEndedNotice reason={reason} />
          {root ? (
            <>
              <KeepSignedIn
                initial={initialRemember(jar.get(REMEMBER_COOKIE)?.value, iam.endpoint)}
              />
              <LoginFlow tenantId={root.id} next="/admin" tenantName={root.name} />
            </>
          ) : (
            <div className="alert warning">
              No installation root exists. Bootstrap one with the CLI before signing in.
            </div>
          )}
          {session && !session.identity.rootAdmin && (
            <div className="alert warning">
              You are signed in as {session.identity.email}, who is not a root administrator.
              Signing in here replaces that session.
            </div>
          )}
          <p className="small muted">
            <Link href="/">Back to the console home</Link>
          </p>
        </div>
      </div>
    </main>
  );
}
