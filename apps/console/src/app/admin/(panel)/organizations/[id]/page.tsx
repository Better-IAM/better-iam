import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import {
  Alert,
  Badge,
  Card,
  KeyValues,
  PageHeader,
  StatusBadge,
  Table,
  Time,
} from '@/components/ui';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession, tryRead } from '@/lib/session';

export default async function OrganizationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const session = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const tenant = await tryRead(() => iam.api.tenants.get(auth, { tenantId: id }));
  if (!tenant) notFound();
  const [
    children,
    identities,
    roles,
    ownerInvitations,
    memberInvitations,
    resourceTypes,
    audit,
    usage,
  ] = await Promise.all([
    iam.api.tenants.listChildren(auth, { tenantId: id }),
    iam.api.identities.list(auth, { tenantId: id }),
    iam.api.roles.list(auth, { tenantId: id }),
    iam.api.tenants.listInvitations(auth, { tenantId: id }),
    iam.api.identities.listInvitations(auth, { tenantId: id }),
    iam.api.resourceTypes.list(auth, { tenantId: id }),
    iam.api.audit.list(auth, { tenantId: id, limit: 15 }),
    iam.api.tenants.usage(auth, { tenantId: id }),
  ]);
  const limitFields = (
    [
      ['identities', 'Members'],
      ['serviceAccounts', 'Service accounts'],
      ['groups', 'Groups'],
      ['roles', 'Roles'],
      ['policies', 'Policies'],
      ['resources', 'Resources'],
      ['webhooks', 'Webhooks'],
    ] as const
  ).map(([key, label]) => ({
    name: key,
    label,
    type: 'number' as const,
    group: 'limits',
    defaultValue: usage.limits[key]?.toString() ?? '',
    placeholder: 'unlimited',
  }));
  const root = tenant.parentId === null;
  const rootTenantId = session.session.tenantId;
  return (
    <>
      <PageHeader
        title={
          <>
            {tenant.name} <StatusBadge status={tenant.status} />
          </>
        }
        description={
          <>
            {tenant.type}
            {tenant.slug && (
              <>
                {' '}
                · alias <code>{tenant.slug}</code>
              </>
            )}{' '}
            · <code className="small">{tenant.id}</code>
          </>
        }
        actions={
          !root &&
          tenant.status !== 'deleted' && (
            <>
              {tenant.status === 'active' && (
                <ApiButton
                  path="tenants/setStatus"
                  body={{ tenantId: id, status: 'suspended' }}
                  label="Suspend"
                  confirm="Suspend this tenant and every descendant? Their sessions are revoked."
                  tenantId={rootTenantId}
                />
              )}
              {tenant.status === 'suspended' && (
                <ApiButton
                  path="tenants/setStatus"
                  body={{ tenantId: id, status: 'active' }}
                  label="Reactivate"
                  tone="primary"
                  tenantId={rootTenantId}
                />
              )}
              <ApiButton
                path="tenants/setStatus"
                body={{ tenantId: id, status: 'deleted' }}
                label="Delete"
                tone="danger"
                confirm="Tombstone this tenant and its descendants? Data is purged after the retention window."
                tenantId={rootTenantId}
              />
            </>
          )
        }
      />
      <div className="stack">
        {tenant.status === 'pending' && (
          <Alert tone="warning">
            This organization is waiting for its owner to accept the invitation. Open{' '}
            <Link href="/admin/deliveries">Deliveries</Link> to find the join link in development.
          </Alert>
        )}
        {tenant.status === 'deleted' && (
          <Alert tone="danger">
            Tombstoned
            {tenant.deletedAt && (
              <>
                {' '}
                on <Time value={tenant.deletedAt} />
              </>
            )}
            . It will be purged by the retention worker.
          </Alert>
        )}
        <div className="grid cols-3">
          <Card title="Details">
            <KeyValues
              items={[
                ['Tenant ID', <code key="i">{tenant.id}</code>],
                [
                  'Parent',
                  tenant.parentId ? (
                    <Link key="p" href={`/admin/organizations/${tenant.parentId}`}>
                      {tenant.parentId}
                    </Link>
                  ) : (
                    'installation root'
                  ),
                ],
                ['Created', <Time key="c" value={tenant.createdAt} />],
                [
                  'Boundary',
                  tenant.boundary ? `${tenant.boundary.statements.length} statement(s)` : 'none',
                ],
                ['Members', identities.length],
                ['Roles', roles.length],
              ]}
            />
          </Card>
          <Card title="Rename">
            <ApiForm
              path="tenants/update"
              tenantId={rootTenantId}
              submitLabel="Rename"
              compact
              successMessage="Renamed."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: id },
                { name: 'name', label: 'Name', required: true, defaultValue: tenant.name },
              ]}
            />
          </Card>
          <Card title="Sign-in alias">
            <ApiForm
              path="tenants/setSlug"
              tenantId={rootTenantId}
              submitLabel="Set alias"
              compact
              successMessage="Alias updated."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: id },
                {
                  name: 'slug',
                  label: 'Alias',
                  defaultValue: tenant.slug ?? '',
                  placeholder: 'acme',
                  help: 'Members sign in at /cloud/login?org=alias.',
                },
              ]}
            />
          </Card>
        </div>
        <div className="grid cols-2">
          <Card
            title="Members"
            description="Identities are isolated per tenant; the same email elsewhere is a different account."
            flush
          >
            <Table
              head={['Name', 'Email', 'Kind', 'Status', 'Flags', '']}
              rows={identities.map((identity) => [
                identity.name,
                identity.email ?? <span className="muted">service</span>,
                identity.kind,
                <StatusBadge key="s" status={identity.status} />,
                <span key="f" className="row">
                  {identity.owner && <Badge tone="accent">owner</Badge>}
                  {identity.rootAdmin && <Badge tone="danger">root</Badge>}
                  {identity.emailVerified && <Badge tone="success">verified</Badge>}
                </span>,
                <span key="a" className="actions">
                  {identity.status === 'active' ? (
                    <ApiButton
                      path="identities/setStatus"
                      body={{ tenantId: id, identityId: identity.id, status: 'disabled' }}
                      label="Disable"
                      confirm={`Disable ${identity.name}? Their sessions are revoked.`}
                      tenantId={rootTenantId}
                    />
                  ) : (
                    <ApiButton
                      path="identities/setStatus"
                      body={{ tenantId: id, identityId: identity.id, status: 'active' }}
                      label="Enable"
                      tone="primary"
                      tenantId={rootTenantId}
                    />
                  )}
                </span>,
              ])}
              empty="No identities yet."
            />
          </Card>
          <Card
            title="Invite a member"
            description="Roles are applied when the invitation is accepted, under your root authority."
          >
            {tenant.status === 'active' ? (
              <ApiForm
                path="identities/invite"
                tenantId={rootTenantId}
                submitLabel="Send invitation"
                successMessage="Invitation queued for delivery."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: id },
                  { name: 'email', label: 'Email', type: 'email', required: true },
                  { name: 'name', label: 'Name' },
                  {
                    name: 'roleIds',
                    label: 'Roles',
                    type: 'multiselect',
                    options: roles.map((role) => ({ value: role.id, label: role.name })),
                    help: 'Hold Ctrl/Cmd to select several.',
                  },
                ]}
              />
            ) : (
              <Alert tone="warning">Members can be invited once the organization is active.</Alert>
            )}
          </Card>
        </div>
        <div className="grid cols-2">
          <Card title="Owner invitations" flush>
            <Table
              head={['Email', 'Expires', 'State', '']}
              rows={ownerInvitations.map((invitation) => [
                invitation.email,
                <Time key="e" value={invitation.expiresAt} />,
                invitation.consumed ? (
                  <Badge key="s" tone="success">
                    accepted
                  </Badge>
                ) : invitation.revoked ? (
                  <Badge key="s" tone="danger">
                    revoked
                  </Badge>
                ) : invitation.expiresAt < Date.now() ? (
                  <Badge key="s" tone="warning">
                    expired
                  </Badge>
                ) : (
                  <Badge key="s" tone="accent">
                    pending
                  </Badge>
                ),
                !invitation.consumed && !invitation.revoked && (
                  <span key="a" className="actions">
                    <ApiButton
                      path="tenants/resendInvitation"
                      body={{ tenantId: id, invitationId: invitation.id }}
                      label="Resend"
                      tenantId={rootTenantId}
                    />
                    <ApiButton
                      path="tenants/revokeInvitation"
                      body={{ tenantId: id, invitationId: invitation.id }}
                      label="Revoke"
                      tone="danger"
                      tenantId={rootTenantId}
                    />
                  </span>
                ),
              ])}
              empty="No owner invitations."
            />
          </Card>
          <Card title="Member invitations" flush>
            <Table
              head={['Email', 'Roles', 'Expires', 'State', '']}
              rows={memberInvitations.map((invitation) => [
                invitation.email,
                invitation.roleIds
                  .map((roleId) => roles.find((role) => role.id === roleId)?.name ?? roleId)
                  .join(', ') || <span className="muted">none</span>,
                <Time key="e" value={invitation.expiresAt} />,
                invitation.consumed ? (
                  <Badge key="s" tone="success">
                    accepted
                  </Badge>
                ) : invitation.revoked ? (
                  <Badge key="s" tone="danger">
                    revoked
                  </Badge>
                ) : invitation.expiresAt < Date.now() ? (
                  <Badge key="s" tone="warning">
                    expired
                  </Badge>
                ) : (
                  <Badge key="s" tone="accent">
                    pending
                  </Badge>
                ),
                !invitation.consumed && !invitation.revoked && (
                  <ApiButton
                    key="r"
                    path="identities/revokeInvitation"
                    body={{ tenantId: id, invitationId: invitation.id }}
                    label="Revoke"
                    tone="danger"
                    tenantId={rootTenantId}
                  />
                ),
              ])}
              empty="No member invitations."
            />
          </Card>
        </div>
        <div className="grid cols-2">
          <Card title="Roles" flush>
            <Table
              head={['Name', 'Description', 'Policies', 'Inline', 'Protected']}
              rows={roles.map((role) => [
                role.name,
                role.description ?? <span className="muted">—</span>,
                role.policyIds.length,
                role.document ? `${role.document.statements.length} statement(s)` : '—',
                role.protected ? (
                  <Badge key="p" tone="warning">
                    protected
                  </Badge>
                ) : (
                  ''
                ),
              ])}
              empty="No roles."
            />
          </Card>
          <Card
            title="Resource types"
            description="Platform types plus any this organization defined."
            flush
          >
            <Table
              head={['Name', 'Source', 'Managed', 'Actions']}
              rows={resourceTypes.map((type) => [
                type.name,
                type.source,
                type.managed ? 'yes' : 'no',
                <code key="a" className="small">
                  {type.actions.join(', ')}
                </code>,
              ])}
            />
          </Card>
        </div>
        {!root && (
          <div className="grid cols-2">
            <Card
              title="Usage"
              description="Current counts against the plan limits. Creation past a limit fails with LIMIT_EXCEEDED."
            >
              <KeyValues
                items={(
                  [
                    ['Members', usage.identities, usage.limits.identities],
                    ['Service accounts', usage.serviceAccounts, usage.limits.serviceAccounts],
                    ['Groups', usage.groups, usage.limits.groups],
                    ['Roles', usage.roles, usage.limits.roles],
                    ['Policies', usage.policies, usage.limits.policies],
                    ['Resources', usage.resources, usage.limits.resources],
                    ['Webhooks', usage.webhooks, usage.limits.webhooks],
                    ['Relationships', usage.relationships, undefined],
                    ['Active sessions', usage.activeSessions, undefined],
                  ] as const
                ).map(([label, value, limit]) => [
                  label,
                  limit === undefined ? String(value) : `${value} / ${limit}`,
                ])}
              />
            </Card>
            <Card
              title="Plan limits"
              description="Platform-controlled. Leave a field empty for no limit; audited as tenant:limits."
            >
              <ApiForm
                path="tenants/setLimits"
                tenantId={rootTenantId}
                submitLabel="Save limits"
                compact
                successMessage="Limits saved."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: id },
                  ...limitFields,
                ]}
              />
              {Object.keys(usage.limits).length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <ApiButton
                    path="tenants/setLimits"
                    body={{ tenantId: id, limits: null }}
                    label="Clear limits"
                    tone="danger"
                    tenantId={rootTenantId}
                  />
                </div>
              )}
            </Card>
          </div>
        )}
        <div className="grid cols-2">
          <Card title="Child tenants" flush>
            <Table
              head={['Name', 'Type', 'Status', 'Alias']}
              rows={children.map((child) => [
                <Link key="n" href={`/admin/organizations/${child.id}`}>
                  {child.name}
                </Link>,
                child.type,
                <StatusBadge key="s" status={child.status} />,
                child.slug ?? '—',
              ])}
              empty="No child tenants."
            />
          </Card>
          <Card
            title="Tenant boundary"
            description="A platform-controlled ceiling: it can only restrict what any member of this tenant may do."
          >
            <ApiForm
              path="tenants/setBoundary"
              tenantId={rootTenantId}
              submitLabel="Set boundary"
              compact
              successMessage="Boundary updated."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: id },
                {
                  name: 'boundary',
                  label: 'Boundary policy document',
                  type: 'json',
                  required: true,
                  rows: 6,
                  defaultValue: JSON.stringify(
                    tenant.boundary ?? {
                      version: 1,
                      statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
                    },
                    null,
                    2,
                  ),
                },
              ]}
            />
          </Card>
        </div>
        <Card
          title="Recent audit events"
          flush
          actions={
            <Link className="btn small secondary" href={`/admin/audit?tenant=${tenant.id}`}>
              Full log
            </Link>
          }
        >
          <Table
            head={['When', 'Actor', 'Action', 'Resource', 'Outcome', 'Root override']}
            rows={[...audit]
              .sort((a, b) => b.timestamp - a.timestamp)
              .map((event) => [
                <Time key="w" value={event.timestamp} />,
                <code key="a" className="small">
                  {event.actorId}
                </code>,
                <code key="c">{event.action}</code>,
                <code key="r" className="small truncate">
                  {event.resourceId}
                </code>,
                <StatusBadge key="o" status={event.outcome === 'allow' ? 'active' : 'disabled'} />,
                event.rootOverride ? (
                  <Badge key="ro" tone="danger">
                    yes
                  </Badge>
                ) : (
                  ''
                ),
              ])}
          />
        </Card>
      </div>
    </>
  );
}
