import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { getDirectory } from '@/lib/iam';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function DirectorySync({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const directory = await getDirectory();
  const [connections, roles] = await Promise.all([
    tryRead(() => directory.listConnections(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
  ]);
  const now = Date.now();
  const live = (connections ?? []).filter(
    (connection) => !connection.revoked && connection.expiresAt > now,
  );
  const groupsByConnection = await Promise.all(
    live.map(async (connection) => ({
      connection,
      groups: await tryRead(() =>
        directory.listGroups(auth, { tenantId, connectionId: connection.id }),
      ),
    })),
  );
  const roleName = new Map((roles ?? []).map((role) => [role.id, role.name]));
  const assignable = (roles ?? [])
    .filter((role) => !role.protected)
    .map((role) => ({ value: role.id, label: role.name }));
  const origin = iam.endpoint.origin;
  return (
    <>
      <PageHeader
        title="Directory sync"
        description="Let your identity provider (Microsoft Entra ID, Okta, Google, JumpCloud, …) create, update, and deactivate members and groups here over SCIM 2.0."
      />
      <div className="stack">
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card title="Connections" flush>
            {connections ? (
              <Table
                head={['Connection', 'SCIM endpoint', 'Provisioned', 'Last used', 'Token', '']}
                rows={connections.map((connection) => {
                  const expired = connection.expiresAt <= now;
                  return [
                    <span key="n" className="stack">
                      <strong>{connection.name}</strong>
                      {connection.revoked ? (
                        <Badge tone="danger">revoked</Badge>
                      ) : expired ? (
                        <Badge tone="warning">token expired</Badge>
                      ) : (
                        <Badge tone="success">active</Badge>
                      )}
                    </span>,
                    <code key="e" className="small truncate">
                      {origin}
                      {connection.path}
                    </code>,
                    `${connection.users} ${connection.users === 1 ? 'person' : 'people'} · ${connection.groups} ${connection.groups === 1 ? 'group' : 'groups'}`,
                    <Time key="u" value={connection.lastUsedAt} />,
                    <span key="t" className="small">
                      expires <Time value={connection.expiresAt} />
                      {connection.rotatedAt ? (
                        <>
                          <br />
                          rotated <Time value={connection.rotatedAt} />
                        </>
                      ) : null}
                    </span>,
                    connection.revoked ? (
                      ''
                    ) : (
                      <span key="a" className="actions">
                        <ApiButton
                          path="scim-admin/connections/rotate"
                          body={{ tenantId, connectionId: connection.id }}
                          label="New token"
                          confirm="Issue a new token? The current one stops working immediately; paste the new one into your identity provider."
                          tenantId={tenantId}
                          showResult
                        />
                        <ApiButton
                          path="scim-admin/connections/revoke"
                          body={{ tenantId, connectionId: connection.id }}
                          label="Revoke"
                          tone="danger"
                          confirm={`Revoke ${connection.name}? Provisioning stops at once and the role bindings its group mappings created are removed.`}
                          tenantId={tenantId}
                        />
                      </span>
                    ),
                  ];
                })}
                empty="No connections yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:scim:connections:read</code>.
              </div>
            )}
          </Card>
          <div className="stack">
            <Card
              title="Connect an identity provider"
              description="Requires iam:scim:connections:create. The token is shown once."
            >
              <ApiForm
                path="scim-admin/connections/create"
                tenantId={tenantId}
                submitLabel="Create connection"
                resetOnSuccess
                showResult
                successMessage="Copy the token now and paste it, with the endpoint, into your identity provider."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'name',
                    label: 'Name',
                    required: true,
                    placeholder: 'Microsoft Entra ID',
                  },
                  {
                    name: 'expiresIn',
                    label: 'Token lifetime (days)',
                    type: 'number',
                    placeholder: '90',
                    multiplier: 86_400,
                    help: 'One day to one year; issue a new token before it expires.',
                  },
                ]}
              />
            </Card>
            <Alert tone="info">
              In the identity provider, set the tenant URL to the connection&apos;s SCIM endpoint
              and the secret token to the one shown when you created it. Job title and department
              fill member attributes, and each person&apos;s manager is linked when both are
              provisioned. Provisioning never takes over an existing account by email.
            </Alert>
          </div>
        </div>
        {groupsByConnection.map(({ connection, groups }) => (
          <Card
            key={connection.id}
            title={`Groups from ${connection.name}`}
            description="Map a pushed group to roles: everyone the provider puts in the group holds them, and loses them when removed. Requires iam:scim:mappings:update and the right to grant each role."
            flush
          >
            {groups ? (
              <Table
                head={['Group', 'Members', 'Roles', 'Change roles']}
                rows={groups.map((group) => [
                  <span key="g" className="stack">
                    <strong>{group.displayName}</strong>
                    {group.externalId && <code className="small muted">{group.externalId}</code>}
                  </span>,
                  group.members,
                  group.roleIds.length ? (
                    <span key="r" className="stack" style={{ alignItems: 'flex-start' }}>
                      {group.roleIds.map((roleId) => (
                        <Badge key={roleId}>{roleName.get(roleId) ?? roleId}</Badge>
                      ))}
                      <ApiButton
                        path="scim-admin/connections/mappings"
                        body={{
                          tenantId,
                          connectionId: connection.id,
                          groupId: group.id,
                          roleIds: [],
                        }}
                        label="Clear"
                        tone="danger"
                        confirm={`Stop granting roles to members of ${group.displayName}?`}
                        tenantId={tenantId}
                      />
                    </span>
                  ) : (
                    <span key="r" className="muted">
                      none
                    </span>
                  ),
                  <ApiForm
                    key="f"
                    path="scim-admin/connections/mappings"
                    tenantId={tenantId}
                    submitLabel="Set roles"
                    compact
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      {
                        name: 'connectionId',
                        label: 'Connection',
                        type: 'hidden',
                        defaultValue: connection.id,
                      },
                      { name: 'groupId', label: 'Group', type: 'hidden', defaultValue: group.id },
                      {
                        name: 'roleIds',
                        label: 'Roles',
                        type: 'multiselect',
                        required: true,
                        options: assignable,
                      },
                    ]}
                  />,
                ])}
                empty="The identity provider has not pushed any groups yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:scim:connections:read</code>.
              </div>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
