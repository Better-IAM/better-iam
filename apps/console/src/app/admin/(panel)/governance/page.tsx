import Link from 'next/link';
import type { AccessInvariant } from 'better-iam/server';
import { Alert, Badge, Card, PageHeader, Stat, StatusBadge, Table, Time } from '@/components/ui';
import { tenantTree } from '@/lib/admin';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession, tryRead } from '@/lib/session';

/** Organizations shown per page; each costs one findings scan and one invariant run. */
const pageSize = 50;

export default async function PlatformGovernance() {
  await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const organizations = (await tenantTree())
    .filter((node) => node.tenant.type === 'organization' && node.tenant.status === 'active')
    .slice(0, pageSize);
  const rows = await Promise.all(
    organizations.map(async ({ tenant }) => {
      const tenantId = tenant.id;
      const [findings, invariants, agreements, campaigns] = await Promise.all([
        tryRead(() => iam.api.analysis.findings(auth, { tenantId })),
        tryRead(() => iam.api.invariants.run(auth, { tenantId })),
        tryRead(() => iam.api.agreements.list(auth, { tenantId })),
        tryRead(() => iam.api.certifications.list(auth, { tenantId, status: 'open' })),
      ]);
      // The scheduled monitor's last run, straight from the stored invariants.
      const lastChecked = (
        await iam.store.find<AccessInvariant>('accessInvariants', { tenantId })
      ).reduce((latest, invariant) => Math.max(latest, invariant.lastCheck?.at ?? 0), 0);
      return { tenant, findings, invariants, agreements, campaigns, lastChecked };
    }),
  );
  const high = rows.reduce((count, row) => count + (row.findings?.summary.high ?? 0), 0);
  const broken = rows.reduce(
    (count, row) =>
      count + (row.invariants ? row.invariants.summary.failed + row.invariants.summary.errors : 0),
    0,
  );
  const guarded = rows.filter((row) => row.invariants?.results.length).length;
  const reviewing = rows.reduce((count, row) => count + (row.campaigns?.length ?? 0), 0);
  const ranked = [...rows].sort(
    (a, b) =>
      (b.findings?.summary.high ?? 0) - (a.findings?.summary.high ?? 0) ||
      (b.invariants?.summary.failed ?? 0) - (a.invariants?.summary.failed ?? 0) ||
      a.tenant.name.localeCompare(b.tenant.name),
  );
  return (
    <>
      <PageHeader
        title="Organization health"
        description="Governance across every active organization: configuration risks, guardrails, reviews, and terms of use. Read under your root authority; each organization's owners see the same detail on their Governance page."
      />
      <div className="stack">
        <div className="grid cols-4">
          <Stat
            label="High-severity findings"
            value={high}
            hint={`across ${rows.length} organizations`}
          />
          <Stat label="Broken invariants" value={broken} hint="enforced and monitored" />
          <Stat
            label="Organizations with guardrails"
            value={`${guarded} / ${rows.length}`}
            hint="at least one invariant"
          />
          <Stat label="Open certification campaigns" value={reviewing} />
        </div>
        {rows.length === pageSize && (
          <Alert tone="info">Showing the first {pageSize} active organizations.</Alert>
        )}
        <Card
          title="Organizations"
          description={
            <>
              Most urgent first. Schedule <code>better-iam monitor-invariants</code> to have breaks
              recorded in each organization&apos;s audit log.
            </>
          }
          flush
        >
          <Table
            head={[
              'Organization',
              'Findings',
              'Invariants',
              'Last monitor run',
              'Reviews',
              'Terms',
            ]}
            rows={ranked.map((row) => [
              <span key="o" className="stack" style={{ gap: 2 }}>
                <Link href={`/admin/organizations/${row.tenant.id}`}>{row.tenant.name}</Link>
                <span className="row">
                  <StatusBadge status={row.tenant.status} />
                  {row.tenant.slug && (
                    <Link className="small" href={`/cloud/${row.tenant.slug}/governance`}>
                      console ↗
                    </Link>
                  )}
                </span>
              </span>,
              row.findings ? (
                <span key="f" className="row">
                  <Badge tone={row.findings.summary.high ? 'danger' : 'neutral'}>
                    {row.findings.summary.high} high
                  </Badge>
                  <Badge tone={row.findings.summary.medium ? 'warning' : 'neutral'}>
                    {row.findings.summary.medium} medium
                  </Badge>
                </span>
              ) : (
                <span key="f" className="muted">
                  —
                </span>
              ),
              row.invariants ? (
                row.invariants.results.length ? (
                  <Badge
                    key="i"
                    tone={
                      row.invariants.summary.failed + row.invariants.summary.errors
                        ? 'danger'
                        : 'success'
                    }
                  >
                    {row.invariants.summary.passed} / {row.invariants.results.length} hold
                  </Badge>
                ) : (
                  <span key="i" className="small muted">
                    none defined
                  </span>
                )
              ) : (
                <span key="i" className="muted">
                  —
                </span>
              ),
              <Time key="m" value={row.lastChecked || undefined} />,
              row.campaigns ? (
                row.campaigns.length ? (
                  <span key="c" className="small">
                    {row.campaigns.length} open,{' '}
                    {row.campaigns.reduce(
                      (count, campaign) =>
                        count + campaign.progress.total - campaign.progress.decided,
                      0,
                    )}{' '}
                    undecided
                  </span>
                ) : (
                  <span key="c" className="small muted">
                    none open
                  </span>
                )
              ) : (
                <span key="c" className="muted">
                  —
                </span>
              ),
              row.agreements ? (
                <span key="t" className="small">
                  {row.agreements.length
                    ? `${row.agreements.length} (${row.agreements.filter((agreement) => agreement.required).length} required)`
                    : 'none'}
                </span>
              ) : (
                <span key="t" className="muted">
                  —
                </span>
              ),
            ])}
            empty="No active organizations yet."
          />
        </Card>
      </div>
    </>
  );
}
