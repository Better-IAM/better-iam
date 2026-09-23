import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Group({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const group = await tryRead(() => iam.api.groups.get(auth, { tenantId, groupId: id }));
  if (!group) notFound();
  // A team's backing group is managed from its team page.
  if (group.teamId) redirect(`${base}/teams/${group.teamId}`);
  const [members, bindings, identities, roles] = await Promise.all([
    tryRead(() => iam.api.groups.listMembers(auth, { tenantId, groupId: id })),
    tryRead(() => iam.api.bindings.list(auth, { tenantId, subjectType: 'group', subjectId: id })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
  ]);
  return (
    <>
      <PageHeader
        title={group.name}
        description={
          <>
            {group.description ?? 'Group'} · <Link href={`${base}/groups`}>all groups</Link>
          </>
        }
        actions={
          <ApiButton
            path="groups/delete"
            body={{ tenantId, groupId: id }}
            label="Delete group"
            tone="danger"
            confirm="Delete this group, its memberships, and its bindings?"
            redirectTo={`${base}/groups`}
            tenantId={tenantId}
          />
        }
      />
      <div className="stack">
        <div className="grid cols-2">
          <Card title="Members" flush>
            {members ? (
              <Table
                head={['Name', 'Email', 'Until', '']}
                rows={members.map((member) => [
                  <Link key="n" href={`${base}/members/${member.id}`}>
                    {member.name}
                  </Link>,
                  member.email ?? '—',
                  member.membershipExpiresAt ? (
                    <Time key="u" value={member.membershipExpiresAt} />
                  ) : (
                    <span key="u" className="muted">
                      permanent
                    </span>
                  ),
                  <span key="r" className="actions">
                    {member.membershipExpiresAt && (
                      <ApiButton
                        path="groups/updateMember"
                        body={{ tenantId, groupId: id, identityId: member.id, expiresAt: null }}
                        label="Make permanent"
                        tenantId={tenantId}
                      />
                    )}
                    <ApiButton
                      path="groups/removeMember"
                      body={{ tenantId, groupId: id, identityId: member.id }}
                      label="Remove"
                      tone="danger"
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No members."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:groups:read</code>.
              </div>
            )}
            {identities && (
              <div className="card-body">
                <ApiForm
                  path="groups/addMembers"
                  tenantId={tenantId}
                  submitLabel="Add members"
                  compact
                  successMessage="Members added."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'groupId', label: 'Group', type: 'hidden', defaultValue: id },
                    {
                      name: 'identityIds',
                      label: 'Identities',
                      type: 'multiselect',
                      required: true,
                      help: 'Hold Ctrl/Cmd to select several; the whole batch is added or nothing is.',
                      options: identities
                        .filter((identity) => !members?.some((member) => member.id === identity.id))
                        .map((identity) => ({
                          value: identity.id,
                          label: `${identity.name} (${identity.email ?? identity.kind})`,
                        })),
                    },
                    {
                      name: 'expiresAt',
                      label: 'Member until',
                      type: 'datetime',
                      help: 'Optional: a temporary membership ends by itself (project teams, rotations).',
                    },
                  ]}
                />
              </div>
            )}
          </Card>
          <Card title="Roles bound to this group" flush>
            {bindings ? (
              <Table
                head={['Role', '']}
                rows={bindings.map((binding) => [
                  <Link key="r" href={`${base}/roles/${binding.roleId}`}>
                    {roles?.find((role) => role.id === binding.roleId)?.name ?? binding.roleId}
                  </Link>,
                  <ApiButton
                    key="d"
                    path="bindings/delete"
                    body={{ tenantId, bindingId: binding.id }}
                    label="Remove"
                    tone="danger"
                    tenantId={tenantId}
                  />,
                ])}
                empty="No roles bound."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:bindings:read</code>.
              </div>
            )}
            <div className="card-body">
              {roles ? (
                <ApiForm
                  path="bindings/create"
                  tenantId={tenantId}
                  submitLabel="Bind role"
                  compact
                  successMessage="Role bound."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'subjectType',
                      label: 'Subject',
                      type: 'hidden',
                      defaultValue: 'group',
                    },
                    { name: 'subjectId', label: 'Group', type: 'hidden', defaultValue: id },
                    {
                      name: 'roleId',
                      label: 'Role',
                      type: 'select',
                      required: true,
                      options: roles
                        .filter((role) => !role.protected)
                        .map((role) => ({ value: role.id, label: role.name })),
                    },
                  ]}
                />
              ) : (
                <Alert tone="warning">
                  Requires <code>iam:roles:read</code>.
                </Alert>
              )}
            </div>
          </Card>
        </div>
        <Card title="Rename">
          <ApiForm
            path="groups/update"
            tenantId={tenantId}
            submitLabel="Save"
            compact
            successMessage="Saved."
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'groupId', label: 'Group', type: 'hidden', defaultValue: id },
              { name: 'name', label: 'Name', required: true, defaultValue: group.name },
              { name: 'description', label: 'Description', defaultValue: group.description ?? '' },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
