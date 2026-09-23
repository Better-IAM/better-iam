import Link from 'next/link';
import { currentSession, rootTenant } from '@/lib/session';

export const dynamic = 'force-dynamic';

export default async function Landing() {
  const [session, root] = await Promise.all([currentSession(), rootTenant()]);
  return (
    <main className="landing">
      <div className="hero">
        <div>
          <p className="muted">Better IAM Console</p>
          <h1>One identity platform. Two panels.</h1>
          <p className="muted" style={{ marginTop: 8, maxWidth: 640 }}>
            The administration panel manages the installation and every organization. The cloud
            console is what your customers use: each organization is an account that many people
            sign in to with their own roles.
          </p>
        </div>
        {!root && (
          <div className="alert warning">
            The installation has no root yet. Run{' '}
            <code>pnpm --filter @better-iam/console bootstrap</code> with{' '}
            <code>BETTER_IAM_ROOT_EMAIL</code> and <code>BETTER_IAM_ROOT_PASSWORD</code> set, then
            sign in below.
          </div>
        )}
        <div className="choices">
          <div className="card choice">
            <h2>Administration panel</h2>
            <p>
              Root administrators create organizations, delegate ownership, review audit trails, and
              manage the platform catalog. Requires MFA.
            </p>
            <div>
              <Link className="btn" href="/admin">
                Open admin panel
              </Link>
            </div>
          </div>
          <div className="card choice">
            <h2>Cloud console</h2>
            <p>
              Members sign in to their organization by alias, manage workspaces, teammates, roles,
              policies, resource types, and service credentials.
            </p>
            <div>
              <Link className="btn" href="/cloud">
                Open cloud console
              </Link>
            </div>
          </div>
        </div>
        {session && (
          <p className="muted small">
            Signed in as {session.identity.email} in tenant <code>{session.session.tenantId}</code>.
          </p>
        )}
      </div>
    </main>
  );
}
