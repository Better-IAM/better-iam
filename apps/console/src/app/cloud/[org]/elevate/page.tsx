import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/** Just-in-time access: the member's own roles, activation for the eligible ones, and the requests they may decide on. */
export default async function Elevate({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base, session } = await orgPage(org);
  const [mine, groups, approvals, packages, packageApprovals] = await Promise.all([
    tryRead(() => iam.api.bindings.listMine(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() => iam.api.bindings.listApprovals(auth, { tenantId })),
    tryRead(() => iam.api.packages.listMine(auth, { tenantId })),
    tryRead(() => iam.api.packages.listApprovals(auth, { tenantId })),
  ]);
  const eligible = mine?.filter((binding) => binding.eligible) ?? [];
  const standing = mine?.filter((binding) => !binding.eligible) ?? [];
  const groupName = (groupId: string) =>
    groups?.find((group) => group.id === groupId)?.name ?? groupId;
  return (
    <>
      <PageHeader
        title="Elevate"
        description="Roles you hold outright, and eligible roles you can activate for a limited time when you need them. Every activation is recorded with its justification."
      />
      <div className="stack">
        {!mine && (
          <Alert tone="warning">
            Listing your own roles requires <code>iam:bindings:activate</code> on this organization.
            Ask an administrator to grant it, typically through a group every member belongs to.
          </Alert>
        )}
        {approvals && approvals.length > 0 && (
          <Card
            title="Requests awaiting your decision"
            description="Activation requests for roles you approve. Approving makes the role live for the requested time; the requester is emailed either way."
            flush
          >
            <Table
              head={['Member', 'Role', 'Requested', 'For', 'Justification', 'Lapses', '']}
              rows={approvals.map((request) => [
                request.requester ? (
                  <Link key="m" href={`${base}/members/${request.requester.id}`}>
                    {request.requester.name}
                  </Link>
                ) : (
                  <code key="m" className="small">
                    {request.identityId}
                  </code>
                ),
                request.role ? (
                  <Link key="r" href={`${base}/roles/${request.role.id}`}>
                    {request.role.name}
                  </Link>
                ) : (
                  request.roleId
                ),
                <Time key="t" value={request.activatedAt} />,
                `${Math.round((request.requestedDurationMs ?? 3_600_000) / 60_000)} min`,
                request.justification ?? <span className="muted">—</span>,
                <Time key="l" value={request.expiresAt} />,
                <span key="a" className="actions">
                  <ApiButton
                    path="bindings/approveActivation"
                    body={{ tenantId, activationId: request.id }}
                    label="Approve"
                    tone="primary"
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="bindings/denyActivation"
                    body={{ tenantId, activationId: request.id }}
                    label="Deny"
                    tone="danger"
                    confirm="Deny this request?"
                    tenantId={tenantId}
                  />
                </span>,
              ])}
            />
          </Card>
        )}
        {packageApprovals && packageApprovals.length > 0 && (
          <Card
            title="Package requests awaiting your decision"
            description="Approving assigns the package to the requester under your authority for the time they asked for; the requester is emailed either way."
            flush
          >
            <Table
              head={['Member', 'Package', 'Requested', 'Until', 'Justification', 'Lapses', '']}
              rows={packageApprovals.map((request) => [
                <Link key="m" href={`${base}/members/${request.identityId}`}>
                  {request.identityName}
                </Link>,
                request.packageName,
                <Time key="t" value={request.requestedAt} />,
                request.desiredExpiresAt ? (
                  <Time key="u" value={request.desiredExpiresAt} />
                ) : (
                  <span key="u" className="muted">
                    open-ended
                  </span>
                ),
                request.justification ?? <span className="muted">—</span>,
                <Time key="l" value={request.expiresAt} />,
                <span key="a" className="actions">
                  <ApiButton
                    path="packages/approveRequest"
                    body={{ tenantId, requestId: request.id }}
                    label="Approve"
                    tone="primary"
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="packages/denyRequest"
                    body={{ tenantId, requestId: request.id }}
                    label="Deny"
                    tone="danger"
                    confirm="Deny this request?"
                    tenantId={tenantId}
                  />
                </span>,
              ])}
            />
          </Card>
        )}
        {packages && packages.packages.length > 0 && (
          <Card
            title="Access packages"
            description="Bundles of roles and groups you can ask for. A request waits for an approver; once granted, the package applies until the end you asked for."
            flush
          >
            <Table
              head={['Package', 'Includes', 'Rules', 'Status', '']}
              rows={packages.packages.map((pkg) => [
                <span key="n">
                  <strong>{pkg.name}</strong>
                  {pkg.description && <div className="muted small">{pkg.description}</div>}
                </span>,
                [
                  ...pkg.roles.map((role) => role.name),
                  ...pkg.groups.map((group) => `group ${group.name}`),
                ].join(', '),
                <span key="rules" className="small">
                  {pkg.maxDurationMs
                    ? `up to ${Math.round(pkg.maxDurationMs / 86400000)} days`
                    : 'no time limit'}
                  {pkg.requireJustification ? ' · justification' : ''}
                  {pkg.approverGroupName ? ` · approval by ${pkg.approverGroupName}` : ''}
                  {pkg.managerApproval ? ' · your manager may approve' : ''}
                </span>,
                pkg.assignment && !pkg.assignment.broken ? (
                  <span key="s" className="row">
                    <Badge tone="success">held</Badge>
                    {pkg.assignment.expiresAt && (
                      <span className="small">
                        until <Time value={pkg.assignment.expiresAt} />
                      </span>
                    )}
                  </span>
                ) : pkg.pending ? (
                  <span key="s" className="row">
                    <Badge tone="warning">awaiting approval</Badge>
                    <span className="small">
                      lapses <Time value={pkg.pending.expiresAt} />
                    </span>
                  </span>
                ) : pkg.assignment?.broken ? (
                  <Badge key="s" tone="danger">
                    no longer granting
                  </Badge>
                ) : (
                  <Badge key="s">not held</Badge>
                ),
                pkg.assignment && !pkg.assignment.broken ? (
                  <span key="a" className="small muted">
                    granted by an administrator
                  </span>
                ) : pkg.pending ? (
                  <ApiButton
                    key="c"
                    path="packages/cancelRequest"
                    body={{ tenantId, requestId: pkg.pending.id }}
                    label="Cancel request"
                    tenantId={tenantId}
                  />
                ) : (
                  <ApiForm
                    key="r"
                    path="packages/request"
                    tenantId={tenantId}
                    submitLabel="Request"
                    compact
                    successMessage="Requested."
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      { name: 'packageId', label: 'Package', type: 'hidden', defaultValue: pkg.id },
                      {
                        name: 'expiresAt',
                        label: 'Until',
                        type: 'datetime',
                        required: pkg.maxDurationMs !== undefined,
                      },
                      {
                        name: 'justification',
                        label: 'Justification',
                        required: pkg.requireJustification === true,
                        placeholder: 'Ticket or reason',
                      },
                    ]}
                  />
                ),
              ])}
            />
          </Card>
        )}
        {mine && (
          <Card
            title="Eligible roles"
            description="Activate a role for up to its allowed window; it applies to every request you make until the activation ends or you end it. Roles that require approval start as a request."
            flush
          >
            <Table
              head={['Role', 'Via', 'Rules', 'Status', '']}
              rows={eligible.map((binding) => {
                const via = binding.via;
                const maxMinutes = Math.round((binding.maxActivationMs ?? 3_600_000) / 60_000);
                return [
                  <Link key="r" href={`${base}/roles/${binding.roleId}`}>
                    {binding.role?.name ?? binding.roleId}
                  </Link>,
                  via === 'identity' ? 'direct' : `group ${groupName(via.groupId)}`,
                  <span key="rules" className="small">
                    up to {maxMinutes} min
                    {binding.requireJustification ? ' · justification' : ''}
                    {binding.requireMfa ? ' · MFA' : ''}
                    {binding.requireApproval
                      ? ` · approval${binding.approverGroupId ? ` by ${groupName(binding.approverGroupId)}` : ''}`
                      : ''}
                    {binding.managerApproval ? ' · your manager may approve' : ''}
                  </span>,
                  binding.activation ? (
                    <span key="s" className="row">
                      <Badge tone="success">active</Badge>
                      <span className="small">
                        until <Time value={binding.activation.expiresAt} />
                      </span>
                    </span>
                  ) : binding.pendingActivation ? (
                    <span key="s" className="row">
                      <Badge tone="warning">awaiting approval</Badge>
                      <span className="small">
                        lapses <Time value={binding.pendingActivation.expiresAt} />
                      </span>
                    </span>
                  ) : (
                    <Badge key="s">inactive</Badge>
                  ),
                  binding.activation ? (
                    <ApiButton
                      key="d"
                      path="bindings/deactivate"
                      body={{ tenantId, activationId: binding.activation.id }}
                      label="End now"
                      tenantId={tenantId}
                    />
                  ) : binding.pendingActivation ? (
                    <ApiButton
                      key="c"
                      path="bindings/deactivate"
                      body={{ tenantId, activationId: binding.pendingActivation.id }}
                      label="Cancel request"
                      tenantId={tenantId}
                    />
                  ) : binding.requireMfa && !session.session.mfa ? (
                    <span key="m" className="small muted">
                      Sign in with MFA to activate
                    </span>
                  ) : (
                    <ApiForm
                      key="a"
                      path="bindings/activate"
                      tenantId={tenantId}
                      submitLabel={binding.requireApproval ? 'Request' : 'Activate'}
                      compact
                      successMessage={binding.requireApproval ? 'Requested.' : 'Activated.'}
                      fields={[
                        {
                          name: 'tenantId',
                          label: 'Tenant',
                          type: 'hidden',
                          defaultValue: tenantId,
                        },
                        {
                          name: 'bindingId',
                          label: 'Binding',
                          type: 'hidden',
                          defaultValue: binding.id,
                        },
                        {
                          name: 'durationMs',
                          label: 'Minutes',
                          type: 'number',
                          multiplier: 60_000,
                          placeholder: String(maxMinutes),
                        },
                        {
                          name: 'justification',
                          label: 'Justification',
                          required: binding.requireJustification === true,
                          placeholder: 'Ticket or reason',
                        },
                      ]}
                    />
                  ),
                ];
              })}
              empty="No eligible roles. Administrators can make a role binding eligible instead of standing."
            />
          </Card>
        )}
        {mine && (
          <Card title="Standing roles" description="Roles that apply to you at all times." flush>
            <Table
              head={['Role', 'Via', 'Expires']}
              rows={standing.map((binding) => {
                const via = binding.via;
                return [
                  <Link key="r" href={`${base}/roles/${binding.roleId}`}>
                    {binding.role?.name ?? binding.roleId}
                  </Link>,
                  via === 'identity' ? 'direct' : `group ${groupName(via.groupId)}`,
                  <Time key="e" value={binding.expiresAt} />,
                ];
              })}
              empty="No standing roles."
            />
          </Card>
        )}
      </div>
    </>
  );
}
