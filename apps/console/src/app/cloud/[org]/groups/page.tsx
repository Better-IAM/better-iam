import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Badge, Card, PageHeader, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Groups({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const groups = await tryRead(() => iam.api.groups.list(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Groups"
        description="Bind roles to a group once; every member inherits them. Changing membership therefore requires authority over the group's bindings."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Groups" flush>
          {groups ? (
            <Table
              head={['Name', 'Description']}
              rows={groups.map((group) => [
                group.teamId ? (
                  // A team's backing group: its members come from the team.
                  <span key="n">
                    <Link href={`${base}/teams/${group.teamId}`}>{group.name}</Link>{' '}
                    <Badge tone="info">team</Badge>
                  </span>
                ) : (
                  <Link key="n" href={`${base}/groups/${group.id}`}>
                    {group.name}
                  </Link>
                ),
                group.description ?? <span className="muted">—</span>,
              ])}
            />
          ) : (
            <div className="empty">
              Requires <code>iam:groups:read</code>.
            </div>
          )}
        </Card>
        <Card title="Create a group">
          <ApiForm
            path="groups/create"
            tenantId={tenantId}
            submitLabel="Create group"
            redirectTo={`${base}/groups/{id}`}
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'name', label: 'Name', required: true, placeholder: 'Engineering' },
              { name: 'description', label: 'Description' },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
