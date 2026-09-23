import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function ResourceTypes({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const types = await tryRead(() => iam.api.resourceTypes.list(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Resource types"
        description="Platform types come from the product's configuration. Your organization can define its own managed types; their actions are namespaced as {type}:{verb} and can be used in roles and policies immediately."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Catalog" flush>
          {types ? (
            <Table
              head={[
                'Type',
                'Source',
                'Managed',
                'Parent',
                'Actions',
                'Attributes',
                'Relations',
                '',
              ]}
              rows={types.map((type) => [
                <code key="n">{type.name}</code>,
                type.source === 'platform' ? (
                  <Badge key="s">platform</Badge>
                ) : (
                  <Badge key="s" tone="accent">
                    this organization
                  </Badge>
                ),
                type.managed ? 'yes' : 'no',
                type.parent ?? '—',
                <code key="a" className="small">
                  {type.actions.join(', ') || '—'}
                </code>,
                <code key="at" className="small">
                  {Object.entries(type.attributes)
                    .map(([name, kind]) => `${name}: ${kind}`)
                    .join(', ') || '—'}
                </code>,
                <code key="rl" className="small">
                  {type.relations.join(', ') || '—'}
                </code>,
                type.source === 'tenant' && (
                  <ApiButton
                    key="d"
                    path="resourceTypes/delete"
                    body={{ tenantId, name: type.name }}
                    label="Delete"
                    tone="danger"
                    confirm={`Delete resource type ${type.name}? Its resources and actions must be unused.`}
                    tenantId={tenantId}
                  />
                ),
              ])}
            />
          ) : (
            <div className="empty">
              Requires <code>iam:resource-types:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Define a resource type"
          description="Requires iam:resource-types:create. Names cannot collide with platform types or action namespaces."
        >
          <ApiForm
            path="resourceTypes/register"
            tenantId={tenantId}
            submitLabel="Register type"
            successMessage="Resource type registered."
            resetOnSuccess
            showResult
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              {
                name: 'name',
                label: 'Name',
                required: true,
                placeholder: 'invoice',
                help: 'Lowercase letters, digits, hyphens.',
              },
              { name: 'description', label: 'Description' },
              {
                name: 'actions',
                label: 'Action verbs',
                type: 'list',
                placeholder: 'read, approve',
                help: 'Registered as {name}:{verb}.',
              },
              {
                name: 'attributes',
                label: 'Attribute schema',
                type: 'json',
                rows: 4,
                defaultValue: JSON.stringify({ amount: 'number' }, null, 2),
                help: 'string, number, or boolean per attribute; exposed to conditions as resource.{name}.',
              },
              {
                name: 'relations',
                label: 'Relations',
                type: 'list',
                placeholder: 'viewer, editor, owner',
                help: 'Names members and groups can hold on a resource; exposed to conditions as resource.relations.',
              },
              {
                name: 'parent',
                label: 'Parent type',
                type: 'select',
                options: (types ?? [])
                  .filter((type) => type.managed)
                  .map((type) => ({ value: type.name, label: type.name })),
              },
            ]}
          />
          <Alert tone="info">
            Registering a type or action grants nothing until a role or policy names it.
          </Alert>
        </Card>
      </div>
    </>
  );
}
