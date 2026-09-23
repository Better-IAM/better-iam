import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { getProvisioner } from '@/lib/iam';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Provisioning({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const provisioner = await getProvisioner();
  const [targets, groups] = await Promise.all([
    tryRead(() => provisioner.listTargets(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
  ]);
  const groupNames = new Map((groups ?? []).map((group) => [group.id, group.name]));
  const problems = (targets ?? []).flatMap((target) =>
    (target.lastRun?.errors ?? []).map((error) => ({ target: target.name, ...error })),
  );
  return (
    <>
      <PageHeader
        title="App provisioning"
        description="Keep the user directories of your SaaS applications in step with this organization over SCIM 2.0. Members are created, updated, and deactivated downstream as they join, change, and leave."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Applications" flush>
            {targets ? (
              <Table
                head={['Application', 'Scope', 'Provisioned', 'Last sync', '']}
                rows={targets.map((target) => [
                  <span key="n" className="stack">
                    <strong>{target.name}</strong>
                    <code className="small truncate">{target.baseUrl}</code>
                    <span className="row">
                      {target.enabled ? (
                        <Badge tone="success">enabled</Badge>
                      ) : (
                        <Badge tone="warning">paused</Badge>
                      )}
                      {target.pushGroups && <Badge>groups</Badge>}
                      <Badge>{target.deprovision}</Badge>
                    </span>
                  </span>,
                  <span key="s" className="small">
                    {target.groupIds.length
                      ? target.groupIds.map((id) => groupNames.get(id) ?? id).join(', ')
                      : 'All members'}
                  </span>,
                  <strong key="p">{target.provisioned}</strong>,
                  target.lastRun ? (
                    <span key="l" className="stack small">
                      <Time value={target.lastRun.finishedAt} />
                      <span className="muted">
                        +{target.lastRun.created} ~{target.lastRun.updated} −
                        {target.lastRun.deactivated + target.lastRun.deleted}
                      </span>
                      {target.lastRun.failed > 0 && (
                        <Badge tone="danger">{target.lastRun.failed} failed</Badge>
                      )}
                    </span>
                  ) : (
                    <span key="l" className="muted small">
                      never
                    </span>
                  ),
                  <span key="a" className="actions">
                    <ApiButton
                      path="provisioning/targets/preview"
                      body={{ tenantId, targetId: target.id }}
                      label="Preview"
                      tenantId={tenantId}
                      showResult
                    />
                    <ApiButton
                      path="provisioning/targets/sync"
                      body={{ tenantId, targetId: target.id }}
                      label="Sync now"
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="provisioning/targets/update"
                      body={{ tenantId, targetId: target.id, enabled: !target.enabled }}
                      label={target.enabled ? 'Pause' : 'Resume'}
                      confirm={
                        target.enabled
                          ? `Pause ${target.name}? The next sync deactivates everyone it provisioned.`
                          : undefined
                      }
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="provisioning/targets/delete"
                      body={{ tenantId, targetId: target.id }}
                      label="Remove"
                      tone="danger"
                      confirm={`Remove ${target.name}? Accounts already created there stay as they are.`}
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No applications connected yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:scim:targets:read</code>.
              </div>
            )}
          </Card>
          {problems.length > 0 && (
            <Card title="Problems in the last sync" flush>
              <Table
                head={['Application', 'Subject', 'Status', 'Message']}
                rows={problems.map((problem, index) => [
                  <span key={`t${index}`}>{problem.target}</span>,
                  <code key={`s${index}`} className="small">
                    {problem.groupId
                      ? `group ${groupNames.get(problem.groupId) ?? problem.groupId}`
                      : problem.identityId}
                  </code>,
                  <span key={`c${index}`}>{problem.status ?? '—'}</span>,
                  <span key={`m${index}`} className="small">
                    {problem.message}
                  </span>,
                ])}
              />
            </Card>
          )}
        </div>
        <div className="stack">
          <Card
            title="Connect an application"
            description="Requires iam:scim:targets:create. Enter the SCIM base URL and bearer token the application issued for provisioning; the token is encrypted and never shown again."
          >
            <ApiForm
              path="provisioning/targets/create"
              tenantId={tenantId}
              submitLabel="Connect"
              resetOnSuccess
              successMessage="Connected. Choose Sync now to provision members immediately."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Slack' },
                {
                  name: 'baseUrl',
                  label: 'SCIM base URL',
                  required: true,
                  placeholder: 'https://api.example.com/scim/v2',
                },
                { name: 'token', label: 'Bearer token', type: 'password', required: true },
                {
                  name: 'groupIds',
                  label: 'Only members of',
                  type: 'multiselect',
                  options: (groups ?? []).map((group) => ({ value: group.id, label: group.name })),
                  help: 'Leave empty to provision every member.',
                },
                {
                  name: 'pushGroups',
                  label: 'Also create these groups in the application',
                  type: 'checkbox',
                },
                {
                  name: 'deprovision',
                  label: 'When someone leaves',
                  type: 'select',
                  required: true,
                  defaultValue: 'deactivate',
                  options: [
                    { value: 'deactivate', label: 'Deactivate the account' },
                    { value: 'delete', label: 'Delete the account' },
                  ],
                },
                {
                  name: 'attributeMapping',
                  label: 'Attribute mapping',
                  type: 'json',
                  rows: 3,
                  placeholder: '{ "department": "department", "title": "title" }',
                  help: 'SCIM title/department/division/employeeNumber → member attribute.',
                },
              ]}
            />
          </Card>
          {targets && targets.length > 0 && (
            <Card title="Replace a token" description="Requires iam:scim:targets:update.">
              <ApiForm
                path="provisioning/targets/update"
                tenantId={tenantId}
                submitLabel="Replace token"
                resetOnSuccess
                successMessage="Token replaced."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'targetId',
                    label: 'Application',
                    type: 'select',
                    required: true,
                    options: targets.map((target) => ({ value: target.id, label: target.name })),
                  },
                  { name: 'token', label: 'New bearer token', type: 'password', required: true },
                ]}
              />
            </Card>
          )}
          <Alert tone="info">
            Only active people with an email address are provisioned. Service accounts never are.
            Syncs also run automatically a few seconds after members, groups, or settings change.
          </Alert>
        </div>
      </div>
    </>
  );
}
