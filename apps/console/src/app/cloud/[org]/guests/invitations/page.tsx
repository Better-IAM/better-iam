import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import {
  batches,
  invitationFilter,
  invitationStatusLabels,
  invitationStatusTone,
  invitationStatuses,
  relativeDays,
  revokedReasonLabels,
} from '@/lib/guests';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const invitationResource = (invitationId: string) => ({
  type: 'iam',
  id: `guests/invitations/${invitationId}`,
});

export default async function GuestInvitations({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ status?: string }>;
}) {
  const { org } = await params;
  const status = invitationFilter((await searchParams).status);
  const context = await orgPage(org);
  const { iam, auth, tenantId, base } = context;
  const [invitations, roles, groups, packages] = await Promise.all([
    tryRead(() =>
      iam.api.guests.listInvitations(auth, { tenantId, ...(status ? { status } : {}) }),
    ),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() => iam.api.packages.list(auth, { tenantId })),
  ]);
  // Resending needs iam:guests:invite and revoking iam:guests:manage, each on the invitation itself.
  const open = (invitations ?? []).filter(
    (invitation) => invitation.status === 'pending' || invitation.status === 'expired',
  );
  const checks = open.flatMap((invitation) => [
    { action: 'iam:guests:invite', resource: invitationResource(invitation.id) },
    { action: 'iam:guests:manage', resource: invitationResource(invitation.id) },
  ]);
  const allowed = Object.assign(
    {},
    ...(await Promise.all(batches(checks).map((batch) => can(context, batch)))),
  ) as Record<string, boolean>;
  const may = (action: string, invitationId: string) =>
    allowed[key(action, invitationResource(invitationId))] === true;
  const nameOf = (list: { id: string; name: string }[] | undefined, id: string) =>
    list?.find((item) => item.id === id)?.name ?? id;
  const now = Date.now();
  return (
    <>
      <PageHeader
        title="Guest invitations"
        description={
          <>
            Invitations sent to people outside the organization. A pending invitation can be sent
            again with a new link (the old one stops working) or revoked; a lapsed one can be sent
            again. Back to <Link href={`${base}/guests`}>guests</Link>.
          </>
        }
      />
      {!invitations ? (
        <Alert tone="warning">
          Requires <code>iam:guests:read</code> on <code>iam/guests/invitations</code>.
        </Alert>
      ) : (
        <Card
          title={status ? `${invitationStatusLabels[status]} invitations` : 'All invitations'}
          description="Newest first. Tokens are never shown: only the invited address receives one."
          flush
        >
          <form method="get" className="row" style={{ padding: '0 16px 12px' }}>
            <select
              className="select"
              name="status"
              defaultValue={status ?? ''}
              aria-label="Status"
              style={{ width: 'auto' }}
            >
              <option value="">Any status</option>
              {invitationStatuses.map((item) => (
                <option key={item} value={item}>
                  {invitationStatusLabels[item]}
                </option>
              ))}
            </select>
            <button className="btn small secondary">Filter</button>
            {status && (
              <Link className="btn small ghost" href={`${base}/guests/invitations`}>
                clear
              </Link>
            )}
          </form>
          <Table
            head={['Invited', 'Status', 'Sponsor', 'Grants', 'Sent', 'Valid until', '']}
            rows={invitations.map((invitation) => {
              const grants = [
                ...invitation.roleIds.map((id) => `role ${nameOf(roles, id)}`),
                ...invitation.groupIds.map((id) => `group ${nameOf(groups, id)}`),
                ...invitation.packageIds.map((id) => `package ${nameOf(packages, id)}`),
              ];
              const mayResend = may('iam:guests:invite', invitation.id);
              const mayRevoke =
                invitation.status === 'pending' && may('iam:guests:manage', invitation.id);
              return [
                <span key="i" className="stack" style={{ gap: 2 }}>
                  <strong>{invitation.email}</strong>
                  <span className="small muted">
                    by {invitation.inviterName ?? invitation.invitedBy}
                    {invitation.homeTenantId ? ' · from a partner organization' : ''}
                  </span>
                  {invitation.message && (
                    <span className="small muted">“{invitation.message}”</span>
                  )}
                </span>,
                <span key="s" className="stack" style={{ gap: 2 }}>
                  <Badge tone={invitationStatusTone(invitation.status)}>
                    {invitationStatusLabels[invitation.status]}
                  </Badge>
                  {invitation.status === 'redeemed' && invitation.identityId && (
                    <Link
                      className="small"
                      href={`${base}/guests/${encodeURIComponent(invitation.identityId)}`}
                    >
                      Guest →
                    </Link>
                  )}
                  {invitation.status === 'revoked' && (
                    <span className="small muted">
                      {invitation.revokedReason
                        ? revokedReasonLabels[invitation.revokedReason]
                        : 'by an administrator'}
                    </span>
                  )}
                </span>,
                <Link key="p" href={`${base}/members/${encodeURIComponent(invitation.sponsorId)}`}>
                  {invitation.sponsorName ?? invitation.sponsorId}
                </Link>,
                <span key="g" className="small">
                  {grants.length ? grants.join(', ') : <span className="muted">nothing</span>}
                  <span className="muted"> · {invitation.accessDays} days</span>
                </span>,
                <Time key="t" value={invitation.sentAt} />,
                invitation.status === 'pending' ? (
                  <span key="v" className="stack small" style={{ gap: 2 }}>
                    <Time value={invitation.expiresAt} />
                    <span className="muted">{relativeDays(invitation.expiresAt, now)}</span>
                  </span>
                ) : invitation.status === 'redeemed' ? (
                  <span key="v" className="small">
                    accepted <Time value={invitation.redeemedAt} />
                  </span>
                ) : (
                  <span key="v" className="muted">
                    —
                  </span>
                ),
                mayResend || mayRevoke ? (
                  <span key="a" className="stack" style={{ gap: 6 }}>
                    {mayResend && (
                      <details>
                        <summary className="small">Send again</summary>
                        <ApiForm
                          path="guests/resendInvitation"
                          tenantId={tenantId}
                          submitLabel="Send"
                          successMessage="Sent with a new link."
                          compact
                          fields={[
                            {
                              name: 'tenantId',
                              label: 'Tenant',
                              type: 'hidden',
                              defaultValue: tenantId,
                            },
                            {
                              name: 'invitationId',
                              label: 'Invitation',
                              type: 'hidden',
                              defaultValue: invitation.id,
                            },
                            {
                              name: 'expiresInDays',
                              label: 'Valid for (days)',
                              type: 'number',
                              placeholder: '14',
                            },
                          ]}
                        />
                      </details>
                    )}
                    {mayRevoke && (
                      <ApiButton
                        path="guests/revokeInvitation"
                        body={{ tenantId, invitationId: invitation.id }}
                        label="Revoke"
                        tone="danger"
                        confirm={`Revoke the invitation to ${invitation.email}? Its link stops working.`}
                        tenantId={tenantId}
                      />
                    )}
                  </span>
                ) : (
                  ''
                ),
              ];
            })}
            empty={status ? 'No invitation has this status.' : 'No guest invitations yet.'}
          />
        </Card>
      )}
    </>
  );
}
