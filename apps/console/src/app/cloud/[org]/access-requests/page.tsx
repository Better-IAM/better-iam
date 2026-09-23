import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const tones: Record<string, Tone> = {
  pending: 'warning',
  approved: 'success',
  denied: 'danger',
  cancelled: 'neutral',
  expired: 'neutral',
};

export default async function AccessRequests({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base, session } = await orgPage(org);
  const [mine, queue, roles, members] = await Promise.all([
    tryRead(() => iam.api.accessRequests.listMine(auth, { tenantId })),
    tryRead(() => iam.api.accessRequests.list(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
  ]);
  const roleName = (roleId: string) => roles?.find((role) => role.id === roleId)?.name ?? roleId;
  const memberName = (identityId: string) =>
    members?.find((identity) => identity.id === identityId)?.name ?? identityId;
  const pendingQueue = queue?.filter((request) => request.status === 'pending') ?? [];
  const decided = queue?.filter((request) => request.status !== 'pending') ?? [];
  return (
    <>
      <PageHeader
        title="Access requests"
        description="Ask for roles instead of asking an administrator to bind them. Approval creates bindings under the reviewer's own authority, optionally for a limited time."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card
            title="Review queue"
            description="Pending requests from members. Requires iam:access-requests:read; deciding requires iam:access-requests:review and iam:bindings:create on each role."
            flush
          >
            {queue ? (
              <Table
                head={['Requester', 'Roles', 'Duration', 'Justification', 'Expires', '']}
                rows={pendingQueue.map((request) => [
                  <Link key="r" href={`${base}/members/${request.requesterId}`}>
                    {memberName(request.requesterId)}
                  </Link>,
                  request.roleIds.map(roleName).join(', '),
                  request.durationSeconds
                    ? `${Math.round(request.durationSeconds / 3600)} h`
                    : 'standing',
                  request.justification ?? <span className="muted">—</span>,
                  <Time key="e" value={request.expiresAt} />,
                  request.requesterId !== session.identity.id && (
                    <span key="a" className="actions">
                      <ApiButton
                        path="accessRequests/approve"
                        body={{ tenantId, requestId: request.id }}
                        label="Approve"
                        tone="primary"
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path="accessRequests/deny"
                        body={{ tenantId, requestId: request.id }}
                        label="Deny"
                        tone="danger"
                        tenantId={tenantId}
                      />
                    </span>
                  ),
                ])}
                empty="Nothing waiting for review."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:access-requests:read</code>.
              </div>
            )}
          </Card>
          {decided.length > 0 && (
            <Card title="Recent decisions" flush>
              <Table
                head={['Requester', 'Roles', 'Status', 'Reviewer', 'Decided', 'Note']}
                rows={decided.slice(0, 50).map((request) => [
                  memberName(request.requesterId),
                  request.roleIds.map(roleName).join(', '),
                  <Badge key="s" tone={tones[request.status] ?? 'neutral'}>
                    {request.status}
                  </Badge>,
                  request.reviewerId ? memberName(request.reviewerId) : '—',
                  <Time key="d" value={request.reviewedAt} />,
                  request.note ?? '',
                ])}
              />
            </Card>
          )}
          <Card title="Your requests" flush>
            {mine ? (
              <Table
                head={['Roles', 'Status', 'Requested', 'Grant expires', '']}
                rows={mine.map((request) => [
                  request.roleIds.map(roleName).join(', '),
                  <Badge key="s" tone={tones[request.status] ?? 'neutral'}>
                    {request.status}
                  </Badge>,
                  <Time key="c" value={request.createdAt} />,
                  <Time key="g" value={request.grantExpiresAt} />,
                  request.status === 'pending' && (
                    <ApiButton
                      key="x"
                      path="accessRequests/cancel"
                      body={{ tenantId, requestId: request.id }}
                      label="Cancel"
                      tenantId={tenantId}
                    />
                  ),
                ])}
                empty="You have not requested anything."
              />
            ) : (
              <div className="empty">
                Requesting access requires <code>iam:access-requests:create</code>.
              </div>
            )}
          </Card>
        </div>
        <div className="stack">
          <Card
            title="Request access"
            description="Requires iam:access-requests:create. Owner roles cannot be requested."
          >
            {mine && roles ? (
              <ApiForm
                path="accessRequests/create"
                tenantId={tenantId}
                submitLabel="Submit request"
                successMessage="Request submitted."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'roleIds',
                    label: 'Roles',
                    type: 'multiselect',
                    required: true,
                    options: roles
                      .filter((role) => !role.protected)
                      .map((role) => ({ value: role.id, label: role.name })),
                  },
                  {
                    name: 'durationSeconds',
                    label: 'Duration in seconds',
                    type: 'number',
                    placeholder: '28800',
                    help: 'Leave empty for a standing grant.',
                  },
                  { name: 'justification', label: 'Justification', type: 'textarea', rows: 3 },
                ]}
              />
            ) : (
              <Alert tone="warning">
                {mine
                  ? 'Roles are not listed because you lack iam:roles:read.'
                  : 'You cannot request access here.'}
              </Alert>
            )}
          </Card>
          <Alert tone="info">
            Approved grants appear as bindings with an expiry on the member&apos;s page and stop
            granting the moment they expire. The retention worker removes them afterwards.
          </Alert>
        </div>
      </div>
    </>
  );
}
