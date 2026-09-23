import Link from 'next/link';
import type { Tenant } from 'better-iam';
import { ForgotPasswordForm, ResetPasswordForm } from '@/components/auth-forms';
import { getIam } from '@/lib/iam';
import { resolveTenant } from '@/lib/session';

export const dynamic = 'force-dynamic';

/**
 * Self-service password recovery. With `?org=` it asks for the address and requests the reset email; with
 * `?tenant=&token=` (the link from that email) it lets the person choose a new password, confirms the change, and
 * sends them to the sign-in page (a reset signs the account out everywhere and issues no session).
 */
export default async function Reset({
  searchParams,
}: {
  searchParams: Promise<{ org?: string; tenant?: string; token?: string }>;
}) {
  const { org, tenant: tenantId, token } = await searchParams;
  const iam = await getIam();
  const tenant = tenantId
    ? await iam.store.get<Tenant>('tenants', tenantId)
    : org
      ? await resolveTenant(org)
      : undefined;
  const alias = tenant ? (tenant.slug ?? tenant.id) : org;
  const resetting = Boolean(tenant && token);
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>{resetting ? 'Choose a new password' : 'Forgot your password?'}</strong>
            <p>{tenant ? tenant.name : 'Tell us which organization you sign in to'}</p>
          </div>
          {resetting ? (
            <ResetPasswordForm
              tenantId={tenant!.id}
              token={token!}
              next={`/cloud/login?org=${encodeURIComponent(alias!)}`}
            />
          ) : tenant && tenant.status === 'active' ? (
            <ForgotPasswordForm tenantId={tenant.id} />
          ) : (
            <form className="form" method="get" action="/cloud/reset">
              <div className="field">
                <label htmlFor="org">Organization alias</label>
                <input
                  id="org"
                  className="input"
                  name="org"
                  defaultValue={org ?? ''}
                  placeholder="acme"
                  required
                />
              </div>
              {org && !tenant && (
                <div className="alert danger">
                  No active organization answers to <code>{org}</code>.
                </div>
              )}
              <div className="form-actions">
                <button className="btn">Continue</button>
              </div>
            </form>
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
