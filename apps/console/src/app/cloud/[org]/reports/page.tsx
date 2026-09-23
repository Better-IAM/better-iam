import Link from 'next/link';
import { ApiButton } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const day = 86400_000;

/** Access hygiene at a glance: what ends soon, who is elevated right now, and which keys nobody uses. */
export default async function Reports({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ within?: string; unused?: string }>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const within = Math.min(3650, Math.max(0, Number(query.within) || 30));
  const unused = Math.min(3650, Math.max(0, Number(query.unused) || 30));
  const { iam, auth, tenantId, base } = await orgPage(org);
  const report = await tryRead(() =>
    iam.api.reports.access(auth, { tenantId, withinMs: within * day, unusedForMs: unused * day }),
  );
  return (
    <>
      <PageHeader
        title="Reports"
        description="What ends soon, who holds elevated roles right now, and which API keys nobody uses. Everything here is also available as better-iam report --tenant."
      />
      <div className="stack">
        {!report && (
          <Alert tone="warning">
            Requires <code>iam:identities:read</code>; the binding and key sections need{' '}
            <code>iam:bindings:read</code> and <code>iam:credentials:read</code>.
          </Alert>
        )}
        {report && (
          <>
            <form className="row" method="get">
              <label className="small">
                Within days{' '}
                <input
                  className="input"
                  name="within"
                  type="number"
                  defaultValue={within}
                  min={0}
                />
              </label>
              <label className="small">
                Unused for days{' '}
                <input
                  className="input"
                  name="unused"
                  type="number"
                  defaultValue={unused}
                  min={0}
                />
              </label>
              <button className="btn small secondary">Refresh</button>
            </form>
            <div className="grid cols-4">
              <Stat
                label="Identities ending soon"
                value={report.identities.expiring.length}
                hint={`${report.identities.total} identities, ${report.identities.disabled} disabled`}
              />
              <Stat
                label="Bindings ending soon"
                value={report.bindings ? report.bindings.expiring.length : '—'}
                hint={
                  report.bindings
                    ? `${report.bindings.total} live, ${report.bindings.eligible} eligible, ${report.bindings.windowed} windowed`
                    : 'Requires iam:bindings:read'
                }
              />
              <Stat
                label="Elevated right now"
                value={report.bindings ? report.bindings.activations.length : '—'}
                hint={
                  report.bindings
                    ? `${report.bindings.pendingRequests} request(s) awaiting approval`
                    : 'Requires iam:bindings:read'
                }
              />
              <Stat
                label="Unused API keys"
                value={report.credentials ? report.credentials.unused.length : '—'}
                hint={
                  report.credentials
                    ? `${report.credentials.expiring.length} of ${report.credentials.total} end within ${within} days`
                    : 'Requires iam:credentials:read'
                }
              />
            </div>
            <Card
              title="Identities scheduled to deactivate"
              description="Contractors and temporary accounts with a deadline inside the window. Expired ones are refused already and disabled by the retention worker."
              flush
            >
              <Table
                head={['Name', 'Kind', 'Status', 'Deadline', '']}
                rows={report.identities.expiring.map((identity) => [
                  <Link key="n" href={`${base}/members/${identity.id}`}>
                    {identity.name}
                  </Link>,
                  identity.kind,
                  <span key="s" className="row">
                    <Badge tone={identity.expired ? 'danger' : 'warning'}>
                      {identity.expired ? 'expired' : identity.status}
                    </Badge>
                  </span>,
                  <Time key="d" value={identity.expiresAt} />,
                  <ApiButton
                    key="c"
                    path="identities/update"
                    body={{ tenantId, identityId: identity.id, expiresAt: null }}
                    label="Clear deadline"
                    tenantId={tenantId}
                  />,
                ])}
                empty="Nothing scheduled to deactivate in this window."
              />
            </Card>
            {report.bindings && (
              <div className="grid cols-2">
                <Card title="Temporary bindings ending soon" flush>
                  <Table
                    head={['Role', 'Subject', 'Ends', '']}
                    rows={report.bindings.expiring.map((binding) => [
                      <Link key="r" href={`${base}/roles/${binding.roleId}`}>
                        {binding.roleName ?? binding.roleId}
                      </Link>,
                      <Link
                        key="s"
                        href={`${base}/${binding.subjectType === 'identity' ? 'members' : 'groups'}/${binding.subjectId}`}
                      >
                        {binding.subjectName ?? binding.subjectId}
                      </Link>,
                      <Time key="e" value={binding.expiresAt} />,
                      <ApiButton
                        key="x"
                        path="bindings/update"
                        body={{ tenantId, bindingId: binding.id, expiresAt: null }}
                        label="Make permanent"
                        tenantId={tenantId}
                      />,
                    ])}
                    empty="No temporary bindings end in this window."
                  />
                </Card>
                <Card
                  title="Live activations"
                  description="Eligible roles members have activated; ending one is recorded as binding:deactivate."
                  flush
                >
                  <Table
                    head={['Member', 'Role', 'Since', 'Until', '']}
                    rows={report.bindings.activations.map((activation) => [
                      <Link key="m" href={`${base}/members/${activation.identityId}`}>
                        {activation.identityName ?? activation.identityId}
                      </Link>,
                      <Link key="r" href={`${base}/roles/${activation.roleId}`}>
                        {activation.roleName ?? activation.roleId}
                      </Link>,
                      <Time key="s" value={activation.activatedAt} />,
                      <Time key="u" value={activation.expiresAt} />,
                      <ApiButton
                        key="e"
                        path="bindings/revokeActivation"
                        body={{ tenantId, activationId: activation.id }}
                        label="End"
                        tone="danger"
                        tenantId={tenantId}
                      />,
                    ])}
                    empty="Nobody is elevated right now."
                  />
                </Card>
              </div>
            )}
            {report.credentials && (
              <div className="grid cols-2">
                <Card
                  title="Unused API keys"
                  description="Keys that authenticated nothing in the window, including keys never used since they were issued."
                  flush
                >
                  <Table
                    head={['Key', 'Created', 'Last used', '']}
                    rows={report.credentials.unused.map((key) => [
                      key.name ?? (
                        <code key="k" className="small">
                          {key.id.slice(0, 8)}
                        </code>
                      ),
                      <Time key="c" value={key.createdAt} />,
                      key.lastUsedAt ? <Time key="l" value={key.lastUsedAt} /> : 'never',
                      <ApiButton
                        key="r"
                        path="credentials/revoke"
                        body={{ tenantId, credentialId: key.id }}
                        label="Revoke"
                        tone="danger"
                        confirm="Revoke this key?"
                        tenantId={tenantId}
                      />,
                    ])}
                    empty="Every key was used recently."
                  />
                </Card>
                <Card title="API keys ending soon" flush>
                  <Table
                    head={['Key', 'Ends', '']}
                    rows={report.credentials.expiring.map((key) => [
                      key.name ?? (
                        <code key="k" className="small">
                          {key.id.slice(0, 8)}
                        </code>
                      ),
                      <Time key="e" value={key.expiresAt} />,
                      <ApiButton
                        key="r"
                        path="credentials/rotate"
                        body={{ tenantId, credentialId: key.id }}
                        label="Rotate"
                        showResult
                        tenantId={tenantId}
                      />,
                    ])}
                    empty="No keys end in this window."
                  />
                </Card>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
