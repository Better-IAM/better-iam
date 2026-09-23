import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { tenantTree } from '@/lib/admin';
import { requireRootSession } from '@/lib/session';

export default async function Organizations() {
  const session = await requireRootSession();
  const tree = await tenantTree();
  const parents = tree.filter(
    (node) => node.tenant.status === 'active' && node.tenant.type !== 'project',
  );
  return (
    <>
      <PageHeader
        title="Organizations"
        description="Each organization is an account. Creating one sends an owner invitation; the organization stays pending until the owner enrolls."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '2fr 1fr' }}>
        <Card title="Tenant tree" flush>
          <Table
            head={['Name', 'Alias', 'Type', 'Status', 'Created']}
            rows={tree.map(({ tenant, depth }) => [
              <span key="n" style={{ paddingLeft: depth * 18 }}>
                {depth > 0 && <span className="muted">└ </span>}
                <Link href={`/admin/organizations/${tenant.id}`}>{tenant.name}</Link>
              </span>,
              tenant.slug ? (
                <code key="s">{tenant.slug}</code>
              ) : (
                <span key="s" className="muted">
                  —
                </span>
              ),
              tenant.type,
              <StatusBadge key="st" status={tenant.status} />,
              <Time key="t" value={tenant.createdAt} />,
            ])}
          />
        </Card>
        <Card
          title="Create an organization"
          description="The owner receives a single-use invitation; no secret is shown here."
        >
          <ApiForm
            path="tenants/create"
            tenantId={session.session.tenantId}
            submitLabel="Create and invite owner"
            redirectTo="/admin/organizations/{tenant.id}"
            fields={[
              {
                name: 'parentId',
                label: 'Parent tenant',
                type: 'select',
                required: true,
                options: parents.map((node) => ({
                  value: node.tenant.id,
                  label: `${'— '.repeat(node.depth)}${node.tenant.name} (${node.tenant.type})`,
                })),
              },
              {
                name: 'type',
                label: 'Type',
                type: 'select',
                required: true,
                options: [
                  { value: 'organization', label: 'Organization' },
                  { value: 'project', label: 'Project' },
                ],
              },
              { name: 'name', label: 'Name', required: true, placeholder: 'Acme Corp' },
              {
                name: 'slug',
                label: 'Sign-in alias',
                placeholder: 'acme',
                help: 'Lowercase letters, digits, and hyphens. Members sign in with this alias.',
              },
              { name: 'ownerEmail', label: 'Owner email', type: 'email', required: true },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
