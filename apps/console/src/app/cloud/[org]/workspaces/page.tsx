import Link from 'next/link';
import type { ResourceRecord } from 'better-iam/server';
import { ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';

export default async function Workspaces({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, tenantId, base } = page;
  // The product owns the workspace list; IAM decides, per workspace, what this member may do with it.
  const workspaces = (
    await iam.store.find<ResourceRecord>('resources', { tenantId, type: 'workspace' })
  ).sort((a, b) => a.resourceId.localeCompare(b.resourceId));
  const decisions = await can(page, [
    { action: 'iam:resources:create' },
    ...workspaces.flatMap((workspace) =>
      ['workspaces:read', 'workspaces:manage'].map((action) => ({
        action,
        resource: { type: 'workspace', id: workspace.resourceId },
      })),
    ),
  ]);
  const canCreate = decisions[key('iam:resources:create', undefined, tenantId)];
  return (
    <>
      <PageHeader
        title="Workspaces"
        description="Workspaces are IAM-managed resources: the console registers them with Better IAM, so policies can target them by ID, owner, or attribute without any resolver code."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card
          title="All workspaces"
          description="Rendered from one authorizeMany batch. Opening a workspace is enforced again on the server."
          flush
        >
          <Table
            head={['Workspace', 'Environment', 'State', 'Your access', 'Registered']}
            rows={workspaces.map((workspace) => {
              const read =
                decisions[key('workspaces:read', { type: 'workspace', id: workspace.resourceId })];
              const manage =
                decisions[
                  key('workspaces:manage', { type: 'workspace', id: workspace.resourceId })
                ];
              return [
                read ? (
                  <Link
                    key="n"
                    href={`${base}/workspaces/${encodeURIComponent(workspace.resourceId)}`}
                  >
                    {workspace.resourceId}
                  </Link>
                ) : (
                  <span key="n" className="muted">
                    {workspace.resourceId}
                  </span>
                ),
                String(workspace.attributes.environment ?? '—'),
                workspace.attributes.archived ? (
                  <Badge key="s" tone="warning">
                    archived
                  </Badge>
                ) : (
                  <Badge key="s" tone="success">
                    active
                  </Badge>
                ),
                <span key="a" className="row">
                  {read && <Badge tone="accent">read</Badge>}
                  {manage && <Badge tone="accent">manage</Badge>}
                  {!read && !manage && <Badge tone="danger">no access</Badge>}
                </span>,
                <Time key="t" value={workspace.createdAt} />,
              ];
            })}
            empty="No workspaces registered yet."
          />
        </Card>
        <Card
          title="Create a workspace"
          description="Requires iam:resources:create on iam/workspace/{id}."
        >
          {canCreate ? (
            <ApiForm
              path="resources/register"
              tenantId={tenantId}
              submitLabel="Register workspace"
              successMessage="Workspace registered."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'type', label: 'Type', type: 'hidden', defaultValue: 'workspace' },
                {
                  name: 'id',
                  label: 'Workspace ID',
                  required: true,
                  placeholder: 'engineering',
                  help: 'Lowercase, used in policies as workspace/{id}.',
                },
                {
                  name: 'attributes',
                  label: 'Attributes',
                  type: 'json',
                  rows: 4,
                  defaultValue: JSON.stringify(
                    { environment: 'production', archived: false },
                    null,
                    2,
                  ),
                  help: 'Validated against the workspace attribute schema.',
                },
                {
                  name: 'ownerId',
                  label: 'Owner identity ID',
                  help: 'Policies can match resource.ownerId.',
                },
              ]}
            />
          ) : (
            <Alert tone="warning">
              You do not hold <code>iam:resources:create</code> here. Ask an owner for a role that
              includes it.
            </Alert>
          )}
        </Card>
      </div>
    </>
  );
}
