import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ResourceRecord } from 'better-iam/server';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { isIamError } from '@/lib/errors';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Workspace({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base } = page;
  const resource = { type: 'workspace', id };
  // Enforcement: the read permission is required before any workspace data is rendered.
  try {
    await iam.require({ ...auth, tenantId, action: 'workspaces:read', resource });
  } catch (error) {
    if (isIamError(error) && error.code === 'NOT_FOUND') notFound();
    if (isIamError(error))
      return (
        <>
          <PageHeader title={id} description="Workspace" />
          <Alert tone="danger">
            Access denied: your roles do not allow <code>workspaces:read</code> on{' '}
            <code>workspace/{id}</code>. <Link href={`${base}/workspaces`}>Back to workspaces</Link>
          </Alert>
        </>
      );
    throw error;
  }
  const record = (
    await iam.store.find<ResourceRecord>('resources', { tenantId, uniqueKey: `workspace/${id}` })
  )[0]!;
  const iamResource = { type: 'iam', id: `workspace/${id}` };
  const [decisions, shares, members, groups, definition] = await Promise.all([
    can(page, [
      { action: 'workspaces:manage', resource },
      { action: 'iam:resources:delete', resource: iamResource },
      { action: 'iam:relationships:create', resource: iamResource },
    ]),
    tryRead(() => iam.api.relationships.list(auth, { tenantId, type: 'workspace', id })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() => iam.api.resourceTypes.get(auth, { tenantId, name: 'workspace' })),
  ]);
  const manage = decisions[key('workspaces:manage', resource)];
  const share = decisions[key('iam:relationships:create', iamResource)];
  const relations = definition?.relations ?? [];
  const subjectName = (type: 'identity' | 'group', subjectId: string) =>
    type === 'identity'
      ? (members?.find((identity) => identity.id === subjectId)?.name ?? subjectId)
      : (groups?.find((group) => group.id === subjectId)?.name ?? subjectId);
  return (
    <>
      <PageHeader
        title={
          <>
            {id}{' '}
            {record.attributes.archived ? (
              <Badge tone="warning">archived</Badge>
            ) : (
              <Badge tone="success">active</Badge>
            )}
          </>
        }
        description={
          <>
            Workspace · <Link href={`${base}/workspaces`}>all workspaces</Link>
          </>
        }
        actions={
          decisions[key('iam:resources:delete', { type: 'iam', id: `workspace/${id}` })] && (
            <ApiButton
              path="resources/delete"
              body={{ tenantId, type: 'workspace', id }}
              label="Delete workspace"
              tone="danger"
              confirm="Delete this workspace registration?"
              redirectTo={`${base}/workspaces`}
              tenantId={tenantId}
            />
          )
        }
      />
      <div className="grid cols-2">
        <Card title="Details">
          <KeyValues
            items={[
              ['Resource', <code key="r">workspace/{record.resourceId}</code>],
              ['Environment', String(record.attributes.environment ?? '—')],
              [
                'Owner',
                record.ownerId ? (
                  <code key="o" className="small">
                    {record.ownerId}
                  </code>
                ) : (
                  '—'
                ),
              ],
              ['Registered', <Time key="c" value={record.createdAt} />],
              ['Updated', <Time key="u" value={record.updatedAt} />],
            ]}
          />
          <Alert tone="success">
            You reached this page because <code>workspaces:read</code> was granted by one of your
            roles and re-checked by the server.
          </Alert>
        </Card>
        <Card
          title="Manage"
          description="Requires workspaces:manage for the UI and iam:resources:update for the registry write."
        >
          {manage ? (
            <ApiForm
              path="resources/update"
              tenantId={tenantId}
              submitLabel="Update attributes"
              successMessage="Workspace updated."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'type', label: 'Type', type: 'hidden', defaultValue: 'workspace' },
                { name: 'id', label: 'ID', type: 'hidden', defaultValue: id },
                {
                  name: 'attributes',
                  label: 'Attributes',
                  type: 'json',
                  rows: 4,
                  defaultValue: JSON.stringify(record.attributes, null, 2),
                },
              ]}
            />
          ) : (
            <Alert tone="warning">You can read this workspace but not manage it.</Alert>
          )}
        </Card>
      </div>
      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <Card
          title="Sharing"
          description="Relationships this workspace carries. Roles read them as resource.relations, so a “viewer” relation can grant workspaces:read without naming the workspace in a policy."
          flush
        >
          {shares ? (
            <Table
              head={['Relation', 'Subject', 'Expires', '']}
              rows={shares.map((tuple) => [
                <Badge key="r" tone="accent">
                  {tuple.relation}
                </Badge>,
                <span key="s">
                  {tuple.subjectType === 'identity' ? (
                    <Link href={`${base}/members/${tuple.subjectId}`}>
                      {subjectName('identity', tuple.subjectId)}
                    </Link>
                  ) : (
                    <>
                      group{' '}
                      <Link href={`${base}/groups/${tuple.subjectId}`}>
                        {subjectName('group', tuple.subjectId)}
                      </Link>
                    </>
                  )}
                </span>,
                <Time key="e" value={tuple.expiresAt} />,
                <ApiButton
                  key="d"
                  path="relationships/delete"
                  body={{ tenantId, relationshipId: tuple.id }}
                  label="Remove"
                  tone="danger"
                  tenantId={tenantId}
                />,
              ])}
              empty="Not shared with anyone through relationships."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:relationships:read</code> on this workspace.
            </div>
          )}
        </Card>
        <Card
          title="Share this workspace"
          description="Requires iam:relationships:create on iam/workspace/{id}; owners of a workspace typically hold it through their owner relation."
        >
          {share && relations.length ? (
            <div className="stack">
              <ApiForm
                path="relationships/create"
                tenantId={tenantId}
                submitLabel="Share with member"
                compact
                successMessage="Shared."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'type', label: 'Type', type: 'hidden', defaultValue: 'workspace' },
                  { name: 'id', label: 'ID', type: 'hidden', defaultValue: id },
                  {
                    name: 'subjectType',
                    label: 'Subject type',
                    type: 'hidden',
                    defaultValue: 'identity',
                  },
                  {
                    name: 'subjectId',
                    label: 'Member',
                    type: 'select',
                    required: true,
                    options: (members ?? []).map((identity) => ({
                      value: identity.id,
                      label: identity.name,
                    })),
                  },
                  {
                    name: 'relation',
                    label: 'Relation',
                    type: 'select',
                    required: true,
                    options: relations.map((relation) => ({ value: relation, label: relation })),
                  },
                  {
                    name: 'expiresAt',
                    label: 'Expires at (epoch ms)',
                    type: 'number',
                    help: 'Leave empty for a standing share.',
                  },
                ]}
              />
              {groups && groups.length > 0 && (
                <ApiForm
                  path="relationships/create"
                  tenantId={tenantId}
                  submitLabel="Share with group"
                  compact
                  successMessage="Shared."
                  resetOnSuccess
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'type', label: 'Type', type: 'hidden', defaultValue: 'workspace' },
                    { name: 'id', label: 'ID', type: 'hidden', defaultValue: id },
                    {
                      name: 'subjectType',
                      label: 'Subject type',
                      type: 'hidden',
                      defaultValue: 'group',
                    },
                    {
                      name: 'subjectId',
                      label: 'Group',
                      type: 'select',
                      required: true,
                      options: groups.map((group) => ({ value: group.id, label: group.name })),
                    },
                    {
                      name: 'relation',
                      label: 'Relation',
                      type: 'select',
                      required: true,
                      options: relations.map((relation) => ({
                        value: relation,
                        label: relation,
                      })),
                    },
                  ]}
                />
              )}
            </div>
          ) : (
            <Alert tone="warning">
              {relations.length
                ? 'You cannot share this workspace.'
                : 'The workspace type declares no relations.'}
            </Alert>
          )}
        </Card>
      </div>
    </>
  );
}
