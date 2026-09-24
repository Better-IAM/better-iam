import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Applications({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [apps, usage, people, groups, packages, allAssignments] = await Promise.all([
    tryRead(() => iam.api.applications.list(auth, { tenantId })),
    tryRead(() => iam.api.applications.usage(auth, { tenantId, unusedDays: 90 })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() => iam.api.packages.list(auth, { tenantId })),
    // Every app's assignments in one call.
    tryRead(() => iam.api.applications.listAssignments(auth, { tenantId })),
  ]);
  const assignments = (apps ?? []).map((app) =>
    (allAssignments ?? []).filter((assignment) => assignment.appId === app.id),
  );
  const subjectOptions = [
    ...(groups ?? []).map((group) => ({
      value: `group:${group.id}`,
      label: `Group: ${group.name}`,
    })),
    ...(people ?? [])
      .filter((person) => person.kind === 'user' && person.status === 'active')
      .map((person) => ({ value: `identity:${person.id}`, label: person.email ?? person.name })),
  ];
  const usageById = new Map((usage ?? []).map((item) => [item.appId, item]));
  return (
    <>
      <PageHeader
        title="Applications"
        description="The apps people see on their My apps page: OpenID Connect clients of this deployment or links to any tool. Give an app to everyone, or assign it to people and groups; people who lack it can request it through an access package."
      />
      {!apps ? (
        <Alert tone="warning">
          Requires <code>iam:applications:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          {apps.map((app, index) => {
            const assigned = assignments[index] ?? [];
            const stats = usageById.get(app.id);
            return (
              <Card
                key={app.id}
                title={
                  <span className="row">
                    {app.name} <code className="small">{app.key}</code>
                    <Badge tone={app.visibility === 'everyone' ? 'accent' : 'neutral'}>
                      {app.visibility}
                    </Badge>
                    {app.kind === 'oidc' && <Badge>OIDC</Badge>}
                    {!app.enabled && <Badge tone="warning">disabled</Badge>}
                  </span>
                }
                description={
                  <>
                    <a href={app.launchUrl} target="_blank" rel="noreferrer noopener">
                      {app.launchUrl}
                    </a>
                    {stats &&
                      ` · ${stats.people} people have it · ${stats.launchedLast30Days} opened it in 30 days`}
                  </>
                }
                actions={
                  <span className="row">
                    <ApiButton
                      path="applications/update"
                      body={{ tenantId, appId: app.id, enabled: !app.enabled }}
                      label={app.enabled ? 'Disable' : 'Enable'}
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="applications/delete"
                      body={{
                        tenantId,
                        appId: app.id,
                        ...(app.oauthClientId ? { releaseClient: true } : {}),
                      }}
                      label="Delete"
                      tone="danger"
                      confirm={
                        app.oauthClientId
                          ? `Delete ${app.name}? Everyone in the organization will then be able to sign in to its OAuth client (disable it instead to keep refusing).`
                          : `Delete ${app.name} with its assignments and launch history?`
                      }
                      tenantId={tenantId}
                    />
                  </span>
                }
              >
                <div className="stack">
                  <Table
                    head={['Assigned to', 'Until', 'Last opened', '']}
                    rows={assigned.map((assignment) => [
                      <span key="s">
                        {assignment.subjectType === 'group' ? 'Group: ' : ''}
                        {assignment.subjectType === 'identity' ? (
                          <a href={`${base}/members/${assignment.subjectId}`}>
                            {assignment.subjectName ?? assignment.subjectId}
                          </a>
                        ) : (
                          (assignment.subjectName ?? assignment.subjectId)
                        )}
                      </span>,
                      <Time key="u" value={assignment.expiresAt} />,
                      <Time key="l" value={assignment.lastLaunchedAt} />,
                      <ApiButton
                        key="x"
                        path="applications/unassign"
                        body={{ tenantId, assignmentId: assignment.id }}
                        label="Remove"
                        tenantId={tenantId}
                      />,
                    ])}
                    empty={
                      app.visibility === 'everyone' ? 'Everyone has this app.' : 'Not assigned yet.'
                    }
                  />
                  {stats && stats.unused.length > 0 && (
                    <Alert tone="warning">
                      {stats.unused.length} direct assignment{stats.unused.length === 1 ? '' : 's'}{' '}
                      unused for 90 days:{' '}
                      {stats.unused.map((item) => item.name ?? item.identityId).join(', ')}.{' '}
                      <ApiButton
                        path="applications/removeUnused"
                        body={{ tenantId, appId: app.id, unusedDays: 90 }}
                        label="Remove unused"
                        confirm="Remove the direct assignments unused for 90 days?"
                        tenantId={tenantId}
                      />
                    </Alert>
                  )}
                  <details>
                    <summary className="small">Assign</summary>
                    <AssignForm tenantId={tenantId} appId={app.id} options={subjectOptions} />
                  </details>
                </div>
              </Card>
            );
          })}
          <Card title="Add an application">
            <ApiForm
              path="applications/create"
              tenantId={tenantId}
              submitLabel="Add application"
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'CRM' },
                { name: 'key', label: 'Key', required: true, placeholder: 'crm' },
                {
                  name: 'launchUrl',
                  label: 'Launch URL',
                  required: true,
                  placeholder: 'https://crm.example.com/login',
                },
                { name: 'description', label: 'Description' },
                { name: 'category', label: 'Category', placeholder: 'Sales' },
                { name: 'logoUrl', label: 'Logo URL' },
                {
                  name: 'oauthClientId',
                  label: 'OAuth client ID (for apps that sign in through this deployment)',
                },
                {
                  name: 'visibility',
                  label: 'Who sees it',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'assigned', label: 'Assigned people and groups' },
                    { value: 'everyone', label: 'Everyone in the organization' },
                  ],
                },
                {
                  name: 'requestPackageId',
                  label: 'Access package people request to get it',
                  type: 'select',
                  options: (packages ?? [])
                    .filter((pkg) => pkg.requestable)
                    .map((pkg) => ({ value: pkg.id, label: pkg.name })),
                },
              ]}
            />
          </Card>
        </div>
      )}
    </>
  );
}

function AssignForm({
  tenantId,
  appId,
  options,
}: {
  tenantId: string;
  appId: string;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="stack">
      {(['group', 'identity'] as const).map((kind) => (
        <ApiForm
          key={kind}
          path="applications/assign"
          tenantId={tenantId}
          submitLabel={kind === 'group' ? 'Assign to group' : 'Assign to person'}
          compact
          resetOnSuccess
          fields={[
            { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
            { name: 'appId', label: 'App', type: 'hidden', defaultValue: appId },
            { name: 'subjectType', label: 'Type', type: 'hidden', defaultValue: kind },
            {
              name: 'subjectId',
              label: kind === 'group' ? 'Group' : 'Person',
              type: 'select',
              required: true,
              options: options
                .filter((option) => option.value.startsWith(`${kind}:`))
                .map((option) => ({
                  value: option.value.slice(kind.length + 1),
                  label: option.label,
                })),
            },
            { name: 'expiresAt', label: 'Until', type: 'datetime' },
          ]}
        />
      ))}
    </div>
  );
}
