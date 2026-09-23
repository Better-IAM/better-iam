import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, Json, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Role({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const role = await tryRead(() => iam.api.roles.get(auth, { tenantId, roleId: id }));
  if (!role) notFound();
  const [bindings, policies, activations, roles] = await Promise.all([
    tryRead(() => iam.api.roles.listBindings(auth, { tenantId, roleId: id })),
    tryRead(() => iam.api.policies.list(auth, { tenantId })),
    tryRead(() => iam.api.bindings.listActivations(auth, { tenantId, roleId: id })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
  ]);
  const inherited = (role.inherits ?? []).map(
    (roleId) => roles?.find((candidate) => candidate.id === roleId) ?? { id: roleId, name: roleId },
  );
  const inheritedBy = roles?.filter((candidate) => candidate.inherits?.includes(role.id)) ?? [];
  const holders = activations?.length
    ? await tryRead(() => iam.api.identities.list(auth, { tenantId }))
    : undefined;
  const permissions =
    role.document?.statements
      .filter(
        (statement) =>
          statement.effect === 'allow' &&
          statement.resources.length === 1 &&
          statement.resources[0] === '*' &&
          !statement.conditions,
      )
      .flatMap((statement) => statement.actions) ?? [];
  return (
    <>
      <PageHeader
        title={
          <>
            {role.name} {role.protected && <Badge tone="warning">protected</Badge>}
          </>
        }
        description={
          <>
            {role.description ?? 'Role'} · <Link href={`${base}/roles`}>all roles</Link>
          </>
        }
        actions={
          !role.protected && (
            <ApiButton
              path="roles/delete"
              body={{ tenantId, roleId: id }}
              label="Delete role"
              tone="danger"
              confirm="Delete this role and all of its bindings?"
              redirectTo={`${base}/roles`}
              tenantId={tenantId}
            />
          )
        }
      />
      <div className="stack">
        {role.protected && (
          <Alert tone="warning">
            The Owner role is protected: it cannot be edited or bound directly. Use the owner
            controls on a member's page instead.
          </Alert>
        )}
        <div className="grid cols-2">
          <Card
            title="Permissions"
            description="Replaces the inline document with a plain allow list."
          >
            {role.protected ? (
              <Json value={role.document ?? { version: 1, statements: [] }} />
            ) : (
              <ApiForm
                path="roles/update"
                tenantId={tenantId}
                submitLabel="Update role"
                successMessage="Role updated."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'roleId', label: 'Role', type: 'hidden', defaultValue: id },
                  { name: 'name', label: 'Name', required: true, defaultValue: role.name },
                  {
                    name: 'description',
                    label: 'Description',
                    defaultValue: role.description ?? '',
                  },
                  {
                    name: 'permissions',
                    label: 'Permissions',
                    type: 'list',
                    defaultValue: permissions.join(', '),
                    help: 'Leave empty to keep the current inline document.',
                  },
                ]}
              />
            )}
          </Card>
          <Card
            title="Inline policy document"
            description="Advanced: statements with resource patterns and conditions. Bounded by your grant authority."
          >
            {role.protected ? (
              <p className="muted">Not editable.</p>
            ) : (
              <ApiForm
                path="roles/update"
                tenantId={tenantId}
                submitLabel="Replace document"
                successMessage="Document replaced."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'roleId', label: 'Role', type: 'hidden', defaultValue: id },
                  {
                    name: 'document',
                    label: 'Policy document',
                    type: 'json',
                    required: true,
                    rows: 10,
                    defaultValue: JSON.stringify(
                      role.document ?? {
                        version: 1,
                        statements: [
                          {
                            effect: 'allow',
                            actions: ['workspaces:read'],
                            resources: ['workspace/*'],
                            conditions: { Bool: { 'principal.mfa': true } },
                          },
                        ],
                      },
                      null,
                      2,
                    ),
                  },
                ]}
              />
            )}
          </Card>
        </div>
        <div className="grid cols-2">
          <Card
            title="Attached policies"
            description="Reusable, versioned policies this role grants."
          >
            {policies ? (
              role.protected ? (
                <p className="muted">{role.policyIds.length} protected policy</p>
              ) : (
                <ApiForm
                  path="roles/update"
                  tenantId={tenantId}
                  submitLabel="Save attachments"
                  compact
                  successMessage="Attachments saved."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'roleId', label: 'Role', type: 'hidden', defaultValue: id },
                    {
                      name: 'policyIds',
                      label: 'Policies',
                      type: 'multiselect',
                      required: true,
                      options: policies
                        .filter((policy) => policy.uniqueKey !== 'system:owner')
                        .map((policy) => ({
                          value: policy.id,
                          label: `${policy.name} (v${policy.version})`,
                        })),
                      help: role.policyIds.length
                        ? `Currently attached: ${role.policyIds.map((policyId) => policies.find((policy) => policy.id === policyId)?.name ?? policyId).join(', ')}`
                        : 'Nothing attached yet. Hold Ctrl/Cmd to select several.',
                    },
                  ]}
                />
              )
            ) : (
              <Alert tone="warning">
                Requires <code>iam:policies:read</code>.
              </Alert>
            )}
          </Card>
          <Card
            title="Inherits"
            description="A role includes the grants of the roles it inherits, bounded by its own authority ceiling. Cycles and protected roles are refused."
          >
            {inherited.length > 0 && (
              <p className="small">
                Currently inherits:{' '}
                {inherited.map((parent, index) => (
                  <span key={parent.id}>
                    {index > 0 && ', '}
                    <Link href={`${base}/roles/${parent.id}`}>{parent.name}</Link>
                  </span>
                ))}
              </p>
            )}
            {inheritedBy.length > 0 && (
              <p className="small muted">
                Inherited by:{' '}
                {inheritedBy.map((child, index) => (
                  <span key={child.id}>
                    {index > 0 && ', '}
                    <Link href={`${base}/roles/${child.id}`}>{child.name}</Link>
                  </span>
                ))}
                . It cannot be deleted while they do.
              </p>
            )}
            {role.protected ? (
              <p className="muted">Not editable.</p>
            ) : roles ? (
              <>
                <ApiForm
                  path="roles/update"
                  tenantId={tenantId}
                  submitLabel="Save inheritance"
                  compact
                  successMessage="Inheritance saved."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'roleId', label: 'Role', type: 'hidden', defaultValue: id },
                    {
                      name: 'inherits',
                      label: 'Roles to inherit',
                      type: 'multiselect',
                      required: true,
                      options: roles
                        .filter((candidate) => !candidate.protected && candidate.id !== id)
                        .map((candidate) => ({ value: candidate.id, label: candidate.name })),
                      help: 'Hold Ctrl/Cmd to select several; replaces the current list.',
                    },
                  ]}
                />
                {inherited.length > 0 && (
                  <ApiButton
                    path="roles/update"
                    body={{ tenantId, roleId: id, inherits: [] }}
                    label="Clear inheritance"
                    tenantId={tenantId}
                  />
                )}
              </>
            ) : (
              <Alert tone="warning">
                Requires <code>iam:roles:read</code>.
              </Alert>
            )}
          </Card>
        </div>
        <div className="grid cols-2">
          <Card
            title="Who holds this role"
            description="Standing bindings apply always; eligible ones only while the subject has activated them."
            flush
          >
            {bindings ? (
              <Table
                head={['Subject', 'Type', 'Mode', '']}
                rows={bindings.map((binding) => [
                  binding.subject ? (
                    <Link
                      key="s"
                      href={`${base}/${binding.subjectType === 'identity' ? 'members' : 'groups'}/${binding.subjectId}`}
                    >
                      {binding.subject.name}
                    </Link>
                  ) : (
                    <code key="s" className="small">
                      {binding.subjectId}
                    </code>
                  ),
                  binding.subjectType,
                  binding.eligible ? (
                    <span key="m" className="row">
                      <Badge tone="accent">eligible</Badge>
                      <span className="small muted">
                        {Math.round((binding.maxActivationMs ?? 3_600_000) / 60_000)} min
                        {binding.requireJustification ? ' · justification' : ''}
                        {binding.requireMfa ? ' · MFA' : ''}
                        {binding.requireApproval ? ' · approval' : ''}
                      </span>
                    </span>
                  ) : (
                    <span key="m" className="small muted">
                      standing
                    </span>
                  ),
                  <span key="d" className="actions">
                    {!role.protected && binding.eligible && (
                      <ApiButton
                        path="bindings/update"
                        body={{ tenantId, bindingId: binding.id, eligible: false }}
                        label="Make standing"
                        confirm="Grant this role permanently and end its activations?"
                        tenantId={tenantId}
                      />
                    )}
                    {!role.protected && !binding.eligible && (
                      <ApiButton
                        path="bindings/update"
                        body={{ tenantId, bindingId: binding.id, eligible: true }}
                        label="Make eligible"
                        confirm="Require activation before this role applies?"
                        tenantId={tenantId}
                      />
                    )}
                    {!role.protected && (
                      <ApiButton
                        path="bindings/delete"
                        body={{ tenantId, bindingId: binding.id }}
                        label="Remove"
                        tone="danger"
                        tenantId={tenantId}
                      />
                    )}
                  </span>,
                ])}
                empty="No bindings."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:bindings:read</code>.
              </div>
            )}
          </Card>
        </div>
        {activations && activations.length > 0 && (
          <Card
            title="Live activations"
            description="Members currently holding this role through an eligible binding. Ending one is recorded as binding:deactivate."
            flush
          >
            <Table
              head={['Member', 'Since', 'Until', 'Justification', '']}
              rows={activations.map((activation) => [
                <Link key="m" href={`${base}/members/${activation.identityId}`}>
                  {holders?.find((identity) => identity.id === activation.identityId)?.name ??
                    activation.identityId}
                </Link>,
                <Time key="s" value={activation.activatedAt} />,
                <Time key="u" value={activation.expiresAt} />,
                activation.justification ?? <span className="muted">—</span>,
                <ApiButton
                  key="e"
                  path="bindings/revokeActivation"
                  body={{ tenantId, activationId: activation.id }}
                  label="End"
                  tone="danger"
                  tenantId={tenantId}
                />,
              ])}
            />
          </Card>
        )}
      </div>
    </>
  );
}
