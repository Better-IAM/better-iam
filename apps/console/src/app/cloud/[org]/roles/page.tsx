import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Roles({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [roles, actions] = await Promise.all([
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.actions.list(auth, { tenantId })),
  ]);
  const suggestions = (actions ?? [])
    .filter((action) => !action.name.startsWith('iam:'))
    .map((action) => action.name);
  return (
    <>
      <PageHeader
        title="Roles"
        description="A role is a named set of permissions. Build one from a permissions list, or attach policies for conditional access. Bindings assign roles to members and groups."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Roles" flush>
          {roles ? (
            <Table
              head={['Name', 'Description', 'Permissions', 'Policies', '']}
              rows={roles.map((role) => [
                <Link key="n" href={`${base}/roles/${role.id}`}>
                  {role.name}
                </Link>,
                role.description ?? <span className="muted">—</span>,
                <code key="p" className="small">
                  {role.document
                    ? role.document.statements.flatMap((statement) => statement.actions).join(', ')
                    : '—'}
                </code>,
                role.policyIds.length,
                role.protected ? (
                  <Badge key="b" tone="warning">
                    protected
                  </Badge>
                ) : (
                  ''
                ),
              ])}
            />
          ) : (
            <div className="empty">
              Requires <code>iam:roles:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Create a role"
          description="The permissions list becomes an inline allow statement over every resource of this organization. Unknown action names are rejected."
        >
          <ApiForm
            path="roles/create"
            tenantId={tenantId}
            submitLabel="Create role"
            redirectTo={`${base}/roles/{id}`}
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'name', label: 'Name', required: true, placeholder: 'Editor' },
              { name: 'description', label: 'Description' },
              {
                name: 'permissions',
                label: 'Permissions',
                type: 'list',
                required: true,
                placeholder: 'workspaces:read, workspaces:manage',
                help: `Comma separated. Available: ${suggestions.slice(0, 12).join(', ')}${suggestions.length > 12 ? ', …' : ''}`,
              },
            ]}
          />
          <Alert tone="info">
            Need conditions such as <code>resource.ownerId</code> or MFA? Create a policy and attach
            it from the role page.
          </Alert>
        </Card>
      </div>
    </>
  );
}
