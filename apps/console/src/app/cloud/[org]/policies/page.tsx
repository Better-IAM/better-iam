import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Badge, Card, PageHeader, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const starter = {
  version: 1,
  statements: [
    {
      sid: 'ReadOwnWorkspaces',
      effect: 'allow',
      actions: ['workspaces:read'],
      resources: ['workspace/*'],
      conditions: { StringEquals: { 'resource.ownerId': '<identity-id>' } },
    },
  ],
};

export default async function Policies({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const policies = await tryRead(() => iam.api.policies.list(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Policies"
        description="Versioned JSON documents with allow/deny statements, resource patterns, and conditions. Attach them to roles; an explicit deny always wins."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Policies" flush>
          {policies ? (
            <Table
              head={['Name', 'Description', 'Version', 'Statements', '']}
              rows={policies.map((policy) => [
                <Link key="n" href={`${base}/policies/${policy.id}`}>
                  {policy.name}
                </Link>,
                policy.description ?? <span className="muted">—</span>,
                `v${policy.version}`,
                policy.document.statements.length,
                policy.uniqueKey === 'system:owner' ? (
                  <Badge key="p" tone="warning">
                    protected
                  </Badge>
                ) : (
                  ''
                ),
              ])}
            />
          ) : (
            <div className="empty">
              Requires <code>iam:policies:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Create a policy"
          description="Actions must exist in the catalog; resource types must be declared when the catalog is strict."
        >
          <ApiForm
            path="policies/create"
            tenantId={tenantId}
            submitLabel="Create policy"
            redirectTo={`${base}/policies/{id}`}
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'name', label: 'Name', required: true, placeholder: 'Own workspaces only' },
              { name: 'description', label: 'Description' },
              {
                name: 'document',
                label: 'Policy document',
                type: 'json',
                required: true,
                rows: 12,
                defaultValue: JSON.stringify(starter, null, 2),
              },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
