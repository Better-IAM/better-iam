import { Alert, Badge, Card, PageHeader, Table } from '@/components/ui';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession } from '@/lib/session';

export default async function Catalog() {
  const session = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const tenantId = session.session.tenantId;
  const [types, actions] = await Promise.all([
    iam.api.resourceTypes.list(auth, { tenantId }),
    iam.api.actions.list(auth, { tenantId }),
  ]);
  const platformActions = actions.filter((action) => action.source === 'platform');
  const builtIn = platformActions.filter((action) => action.name.startsWith('iam:'));
  const product = platformActions.filter((action) => !action.name.startsWith('iam:'));
  return (
    <>
      <PageHeader
        title="Permission catalog"
        description="Declared in the console configuration (better-iam.config.mjs). Organizations may add their own resource types and actions on top; those appear on each organization's page."
      />
      <div className="stack">
        <Alert tone="info">
          Registering an action grants nothing. Policies may only name actions that exist here or in
          the organization's own catalog; exact unknown names are rejected when a policy is saved.
        </Alert>
        <Card title="Platform resource types" flush>
          <Table
            head={['Type', 'Managed', 'Parent', 'Actions', 'Attributes', 'Description']}
            rows={types.map((type) => [
              <code key="n">{type.name}</code>,
              type.managed ? (
                <Badge key="m" tone="success">
                  IAM registry
                </Badge>
              ) : (
                <Badge key="m">resolveResource</Badge>
              ),
              type.parent ?? '—',
              <code key="a" className="small">
                {type.actions.join(', ') || '—'}
              </code>,
              <code key="at" className="small">
                {Object.entries(type.attributes)
                  .map(([key, kind]) => `${key}: ${kind}`)
                  .join(', ') || '—'}
              </code>,
              type.description ?? '',
            ])}
          />
        </Card>
        <div className="grid cols-2">
          <Card title="Product actions" flush>
            <Table
              head={['Action', 'Resource type']}
              rows={product.map((action) => [
                <code key="n">{action.name}</code>,
                action.resourceType ?? '—',
              ])}
              empty="No product actions declared."
            />
          </Card>
          <Card title={`Built-in IAM actions (${builtIn.length})`} flush>
            <div style={{ maxHeight: 520, overflow: 'auto' }}>
              <Table
                head={['Action']}
                rows={builtIn.map((action) => [<code key="n">{action.name}</code>])}
              />
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
