import Link from 'next/link';
import type { Tenant } from 'better-iam';
import { JoinForm } from '@/components/auth-forms';
import { getIam } from '@/lib/iam';

export const dynamic = 'force-dynamic';

export default async function Join({
  searchParams,
}: {
  searchParams: Promise<{ kind?: string; tenant?: string; token?: string }>;
}) {
  const { kind, tenant: tenantId, token } = await searchParams;
  const iam = await getIam();
  const tenant = tenantId ? await iam.store.get<Tenant>('tenants', tenantId) : undefined;
  const ready = tenant && token && (kind === 'owner' || kind === 'member');
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>
              {kind === 'owner' ? 'Set up your organization' : 'Join an organization'}
            </strong>
            <p>{tenant ? tenant.name : 'Paste the details from your invitation'}</p>
          </div>
          {ready ? (
            <JoinForm
              kind={kind}
              tenantId={tenant.id}
              token={token}
              next={`/cloud/${encodeURIComponent(tenant.slug ?? tenant.id)}`}
            />
          ) : (
            <form className="form" method="get" action="/cloud/join">
              <div className="field">
                <label htmlFor="kind">Invitation type</label>
                <select id="kind" className="select" name="kind" defaultValue={kind ?? 'member'}>
                  <option value="member">Member invitation</option>
                  <option value="owner">Owner invitation</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="tenant">Tenant ID</label>
                <input
                  id="tenant"
                  className="input"
                  name="tenant"
                  defaultValue={tenantId ?? ''}
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="token">Invitation token</label>
                <input
                  id="token"
                  className="input"
                  name="token"
                  defaultValue={token ?? ''}
                  required
                  autoComplete="off"
                />
              </div>
              {tenantId && !tenant && <div className="alert danger">Unknown tenant.</div>}
              <div className="form-actions">
                <button className="btn">Continue</button>
              </div>
            </form>
          )}
          <p className="small muted">
            <Link href="/cloud">Already have an account? Sign in</Link>
          </p>
        </div>
      </div>
    </main>
  );
}
