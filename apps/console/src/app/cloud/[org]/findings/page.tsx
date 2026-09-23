import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const subjectPaths: Record<string, string | undefined> = {
  identity: 'members',
  role: 'roles',
  policy: 'policies',
  group: 'groups',
  team: 'teams',
  department: 'departments',
};

export default async function Findings({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ dormantDays?: string; suppressed?: string }>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const dormantDays = Number(query.dormantDays) || 90;
  const includeSuppressed = query.suppressed === '1';
  const report = await tryRead(() =>
    iam.api.analysis.findings(auth, { tenantId, dormantDays, includeSuppressed }),
  );
  return (
    <>
      <PageHeader
        title="Security findings"
        description="A read-only scan of this organization's policies, roles, groups, trusts, and members for risky or stale access. Suppress a finding to record that the risk is accepted."
      />
      {!report ? (
        <Alert tone="warning">
          Requires <code>iam:analysis:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="grid cols-4">
            <Stat label="High" value={report.summary.high} />
            <Stat label="Medium" value={report.summary.medium} />
            <Stat label="Low" value={report.summary.low} />
            <Stat
              label="Suppressed"
              value={report.summary.suppressed}
              hint={
                includeSuppressed ? (
                  <Link href={`${base}/findings?dormantDays=${dormantDays}`}>hide</Link>
                ) : (
                  <Link href={`${base}/findings?dormantDays=${dormantDays}&suppressed=1`}>
                    show
                  </Link>
                )
              }
            />
          </div>
          <Card
            title="Findings"
            description={
              <>
                Generated <Time value={report.generatedAt} />. Members count as dormant after{' '}
                {report.dormantDays} days without signing in.
              </>
            }
            flush
          >
            <form className="row" method="get" style={{ padding: '0 16px 12px' }}>
              <label className="small muted" htmlFor="dormantDays">
                Dormant after (days)
              </label>
              <input
                id="dormantDays"
                className="input"
                name="dormantDays"
                type="number"
                min={1}
                max={3650}
                defaultValue={dormantDays}
                style={{ width: 100 }}
              />
              {includeSuppressed && <input type="hidden" name="suppressed" value="1" />}
              <button className="btn secondary">Rescan</button>
            </form>
            <Table
              head={['Severity', 'Finding', 'Subject', '']}
              rows={report.findings.map((finding) => {
                const path = subjectPaths[finding.subject.type];
                return [
                  <Badge
                    key="s"
                    tone={
                      finding.severity === 'high'
                        ? 'danger'
                        : finding.severity === 'medium'
                          ? 'warning'
                          : 'neutral'
                    }
                  >
                    {finding.severity}
                  </Badge>,
                  <span key="f" className="stack">
                    <strong>{finding.title}</strong>
                    <span className="small muted">{finding.detail}</span>
                    {finding.suppressed && (
                      <span className="small">
                        Suppressed: {finding.suppressed.reason} (
                        <Time value={finding.suppressed.at} />)
                      </span>
                    )}
                  </span>,
                  path ? (
                    <Link key="l" href={`${base}/${path}/${finding.subject.id}`}>
                      {finding.subject.name ?? finding.subject.id}
                    </Link>
                  ) : (
                    <code key="l" className="small">
                      {finding.subject.type}/{finding.subject.id}
                    </code>
                  ),
                  finding.suppressed ? (
                    <ApiButton
                      key="a"
                      path="analysis/unsuppress"
                      body={{ tenantId, findingId: finding.id }}
                      label="Unsuppress"
                      tenantId={tenantId}
                    />
                  ) : (
                    <details key="a">
                      <summary className="small">Suppress</summary>
                      <ApiForm
                        path="analysis/suppress"
                        tenantId={tenantId}
                        submitLabel="Suppress"
                        compact
                        fields={[
                          {
                            name: 'tenantId',
                            label: 'Tenant',
                            type: 'hidden',
                            defaultValue: tenantId,
                          },
                          {
                            name: 'findingId',
                            label: 'Finding',
                            type: 'hidden',
                            defaultValue: finding.id,
                          },
                          { name: 'reason', label: 'Reason', required: true },
                        ]}
                      />
                    </details>
                  ),
                ];
              })}
              empty="No findings. Nice."
            />
          </Card>
        </div>
      )}
    </>
  );
}
