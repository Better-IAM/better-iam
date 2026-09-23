import Link from 'next/link';
import { Badge, Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { tenantTree } from '@/lib/admin';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession } from '@/lib/session';

export default async function AuditLog({
  searchParams,
}: {
  searchParams: Promise<{ tenant?: string }>;
}) {
  const session = await requireRootSession();
  const { tenant } = await searchParams;
  const iam = await getIam();
  const auth = await credential();
  const tree = await tenantTree();
  const tenantId =
    tenant && tree.some((node) => node.tenant.id === tenant) ? tenant : session.session.tenantId;
  const [events, chain] = await Promise.all([
    iam.api.audit.list(auth, { tenantId, limit: 200 }),
    iam.api.audit.verify(auth, { tenantId }),
  ]);
  const selected = tree.find((node) => node.tenant.id === tenantId)?.tenant;
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every authorization denial, root override, and administrative mutation is recorded with its original actor. Records never contain credentials."
      />
      <div className="stack">
        <Card title="Tenant">
          <div className="row">
            {tree.map((node) => (
              <Link
                key={node.tenant.id}
                className={node.tenant.id === tenantId ? 'btn small' : 'btn small secondary'}
                href={`/admin/audit?tenant=${node.tenant.id}`}
              >
                {node.tenant.name}
              </Link>
            ))}
          </div>
        </Card>
        <Card
          title={`${selected?.name ?? 'Tenant'} · ${events.length} most recent events`}
          description={
            chain.valid
              ? `Hash chain intact: ${chain.checked} events verified, head at sequence ${chain.head?.sequence ?? 0}.`
              : `Hash chain BROKEN at sequence ${chain.failure?.sequence}: ${chain.failure?.reason}.`
          }
          flush
        >
          <Table
            head={[
              'When',
              'Actor',
              'Original actor',
              'Action',
              'Resource',
              'Outcome',
              'Root override',
              'Metadata',
            ]}
            rows={[...events]
              .sort((a, b) => b.timestamp - a.timestamp)
              .map((event) => [
                <Time key="w" value={event.timestamp} />,
                <code key="a" className="small">
                  {event.actorId}
                </code>,
                event.originalActorId ? (
                  <code key="oa" className="small">
                    {event.originalActorId}
                  </code>
                ) : (
                  '—'
                ),
                <code key="c">{event.action}</code>,
                <code key="r" className="small truncate">
                  {event.resourceId}
                </code>,
                <StatusBadge key="o" status={event.outcome === 'allow' ? 'active' : 'disabled'} />,
                event.rootOverride ? (
                  <Badge key="ro" tone="danger">
                    yes
                  </Badge>
                ) : (
                  ''
                ),
                event.metadata ? (
                  <code key="m" className="small">
                    {JSON.stringify(event.metadata)}
                  </code>
                ) : (
                  ''
                ),
              ])}
            empty="No audit events for this tenant."
          />
        </Card>
      </div>
    </>
  );
}
