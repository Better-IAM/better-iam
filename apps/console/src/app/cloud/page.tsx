import Link from 'next/link';
import { currentSession } from '@/lib/session';
import { getIam } from '@/lib/iam';
import type { Tenant } from 'better-iam';

export const dynamic = 'force-dynamic';

export default async function CloudHome() {
  const session = await currentSession();
  const iam = await getIam();
  const tenant = session
    ? await iam.store.get<Tenant>('tenants', session.session.tenantId)
    : undefined;
  const current =
    tenant && tenant.parentId !== null && tenant.status === 'active' ? tenant : undefined;
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>Cloud console</strong>
            <p>Sign in to your organization.</p>
          </div>
          {current && (
            <div className="alert success">
              You are signed in to <strong>{current.name}</strong>.{' '}
              <Link href={`/cloud/${encodeURIComponent(current.slug ?? current.id)}`}>
                Open the console →
              </Link>
            </div>
          )}
          <form className="form" action="/cloud/login" method="get">
            <div className="field">
              <label htmlFor="org">Organization alias</label>
              <input
                id="org"
                className="input"
                name="org"
                placeholder="acme"
                autoFocus
                required
                pattern="[a-z0-9-]{1,63}"
              />
              <span className="help">
                The alias your administrator chose, like an AWS account alias. Ask them if you
                don&apos;t know it.
              </span>
            </div>
            <div className="form-actions">
              <button className="btn">Continue</button>
            </div>
          </form>
          <form className="form" action="/cloud/discover" method="get">
            <div className="field">
              <label htmlFor="email">Or use your work email</label>
              <input
                id="email"
                className="input"
                name="email"
                type="email"
                placeholder="you@company.com"
                required
              />
              <span className="help">
                Works when your organization has verified its email domain.
              </span>
            </div>
            <div className="form-actions">
              <button className="btn secondary">Find my organization</button>
            </div>
          </form>
          <p className="small muted">
            Received an invitation? <Link href="/cloud/join">Redeem it here</Link>. Platform staff
            use the <Link href="/admin">administration panel</Link>.
          </p>
        </div>
      </div>
    </main>
  );
}
