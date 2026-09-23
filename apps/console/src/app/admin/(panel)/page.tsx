import Link from 'next/link';
import { Card, PageHeader, Stat, StatusBadge, Table, Time } from '@/components/ui';
import { tenantTree } from '@/lib/admin';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession } from '@/lib/session';

export default async function AdminDashboard() {
  const session = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const [tree, administrators, audit] = await Promise.all([
    tenantTree(),
    iam.api.identities.list(auth, { tenantId: session.session.tenantId }),
    iam.api.audit.list(auth, { tenantId: session.session.tenantId, limit: 12 }),
  ]);
  const organizations = tree.filter((node) => node.tenant.type === 'organization');
  const pending = tree.filter((node) => node.tenant.status === 'pending');
  const suspended = tree.filter((node) => node.tenant.status === 'suspended');
  return (
    <>
      <PageHeader
        title="Platform overview"
        description="Everything below is read through Better IAM's authenticated services under your root authority; each access is recorded."
      />
      <div className="stack">
        <div className="grid cols-4">
          <Stat
            label="Organizations"
            value={organizations.length}
            hint={`${tree.length - 1} tenants below the root`}
          />
          <Stat
            label="Pending onboarding"
            value={pending.length}
            hint="Owner invitation not accepted yet"
          />
          <Stat label="Suspended" value={suspended.length} hint="Access revoked for the subtree" />
          <Stat
            label="Root administrators"
            value={
              administrators.filter(
                (identity) => identity.rootAdmin && identity.status === 'active',
              ).length
            }
            hint={`${administrators.length} identities in the root tenant`}
          />
        </div>
        <div className="grid cols-2">
          <Card
            title="Recently created tenants"
            flush
            actions={
              <Link className="btn small secondary" href="/admin/organizations">
                All organizations
              </Link>
            }
          >
            <Table
              head={['Name', 'Type', 'Status', 'Created']}
              rows={[...tree]
                .filter((node) => node.depth > 0)
                .sort((a, b) => b.tenant.createdAt - a.tenant.createdAt)
                .slice(0, 8)
                .map(({ tenant }) => [
                  <Link key="n" href={`/admin/organizations/${tenant.id}`}>
                    {tenant.name}
                  </Link>,
                  tenant.type,
                  <StatusBadge key="s" status={tenant.status} />,
                  <Time key="t" value={tenant.createdAt} />,
                ])}
              empty="No organizations yet. Create the first one from the Organizations page."
            />
          </Card>
          <Card
            title="Latest root-tenant audit events"
            flush
            actions={
              <Link className="btn small secondary" href="/admin/audit">
                Audit log
              </Link>
            }
          >
            <Table
              head={['When', 'Action', 'Outcome']}
              rows={[...audit]
                .sort((a, b) => b.timestamp - a.timestamp)
                .map((event) => [
                  <Time key="w" value={event.timestamp} />,
                  <code key="a">{event.action}</code>,
                  <StatusBadge
                    key="o"
                    status={event.outcome === 'allow' ? 'active' : 'disabled'}
                  />,
                ])}
            />
          </Card>
        </div>
      </div>
    </>
  );
}
