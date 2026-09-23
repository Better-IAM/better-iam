import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const pageSize = 50;

export default async function Members({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ q?: string; page?: string }>;
}) {
  const { org } = await params;
  const { q, page: pageParam } = await searchParams;
  const query = q?.trim() || undefined;
  const page = Math.max(1, Number.parseInt(pageParam ?? '1', 10) || 1);
  const { iam, auth, tenantId, base, session } = await orgPage(org);
  const [people, invitations, roles, groups] = await Promise.all([
    tryRead(() =>
      iam.api.identities.list(auth, {
        tenantId,
        kind: 'user',
        query,
        limit: pageSize + 1,
        offset: (page - 1) * pageSize,
      }),
    ),
    tryRead(() => iam.api.identities.listInvitations(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
  ]);
  const hasMore = (people?.length ?? 0) > pageSize;
  const visible = people?.slice(0, pageSize);
  const pageLink = (target: number) =>
    `${base}/members?${new URLSearchParams({ ...(query ? { q: query } : {}), page: String(target) })}`;
  return (
    <>
      <PageHeader
        title="Members"
        description="People who can sign in to this organization. Invitations create the account when accepted and apply the chosen roles and groups under your authority."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card
            title="People"
            flush
            actions={
              <form method="get" className="row">
                <input
                  className="input"
                  name="q"
                  defaultValue={query ?? ''}
                  placeholder="Search name or email"
                  aria-label="Search members"
                />
                <button className="btn small secondary">Search</button>
                {query && (
                  <Link className="btn small ghost" href={`${base}/members`}>
                    clear
                  </Link>
                )}
              </form>
            }
          >
            {visible ? (
              <Table
                head={['Name', 'Email', 'Status', 'Flags', '']}
                rows={visible.map((identity) => [
                  <Link key="n" href={`${base}/members/${identity.id}`}>
                    {identity.name}
                  </Link>,
                  identity.email ?? '—',
                  <StatusBadge key="s" status={identity.status} />,
                  <span key="f" className="row">
                    {identity.owner && <Badge tone="accent">owner</Badge>}
                    {identity.emailVerified && <Badge tone="success">verified</Badge>}
                    {identity.id === session.identity.id && <Badge>you</Badge>}
                  </span>,
                  <span key="a" className="actions">
                    {identity.id !== session.identity.id &&
                      (identity.status === 'active' ? (
                        <ApiButton
                          path="identities/setStatus"
                          body={{ tenantId, identityId: identity.id, status: 'disabled' }}
                          label="Disable"
                          confirm={`Disable ${identity.name}?`}
                          tenantId={tenantId}
                        />
                      ) : (
                        <ApiButton
                          path="identities/setStatus"
                          body={{ tenantId, identityId: identity.id, status: 'active' }}
                          label="Enable"
                          tone="primary"
                          tenantId={tenantId}
                        />
                      ))}
                  </span>,
                ])}
                empty={query ? `Nobody matches “${query}”.` : 'No members yet.'}
              />
            ) : (
              <div className="empty">
                Listing members requires <code>iam:identities:read</code>.
              </div>
            )}
            {visible && (page > 1 || hasMore) && (
              <div className="card-body row spread">
                <span className="small muted">Page {page}</span>
                <span className="row">
                  {page > 1 && (
                    <Link className="btn small secondary" href={pageLink(page - 1)}>
                      Previous
                    </Link>
                  )}
                  {hasMore && (
                    <Link className="btn small secondary" href={pageLink(page + 1)}>
                      Next
                    </Link>
                  )}
                </span>
              </div>
            )}
          </Card>
          <Card title="Pending invitations" flush>
            {invitations ? (
              <Table
                head={['Email', 'Name', 'Roles', 'Expires', 'State', '']}
                rows={invitations.map((invitation) => [
                  invitation.email,
                  invitation.name ?? '—',
                  invitation.roleIds
                    .map((roleId) => roles?.find((role) => role.id === roleId)?.name ?? roleId)
                    .join(', ') || '—',
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
                        path="identities/resendInvitation"
                        body={{ tenantId, invitationId: invitation.id }}
                        label="Resend"
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path="identities/revokeInvitation"
                        body={{ tenantId, invitationId: invitation.id }}
                        label="Revoke"
                        tone="danger"
                        tenantId={tenantId}
                      />
                    </span>
                  ),
                ])}
                empty="No invitations."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:identities:read</code>.
              </div>
            )}
          </Card>
        </div>
        <Card
          title="Invite a member"
          description="Requires iam:identities:create, plus iam:bindings:create on each role and iam:groups:update on each group."
        >
          <ApiForm
            path="identities/invite"
            tenantId={tenantId}
            submitLabel="Send invitation"
            successMessage="Invitation queued. In development, root administrators can find the join link under Deliveries."
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'email', label: 'Email', type: 'email', required: true },
              { name: 'name', label: 'Name' },
              {
                name: 'roleIds',
                label: 'Roles',
                type: 'multiselect',
                options: (roles ?? [])
                  .filter((role) => !role.protected)
                  .map((role) => ({ value: role.id, label: role.name })),
              },
              {
                name: 'groupIds',
                label: 'Groups',
                type: 'multiselect',
                options: (groups ?? []).map((group) => ({ value: group.id, label: group.name })),
              },
            ]}
          />
          {!roles && (
            <Alert tone="warning">
              Roles are not listed because you lack <code>iam:roles:read</code>; invitations can
              still be sent without roles.
            </Alert>
          )}
        </Card>
      </div>
    </>
  );
}
