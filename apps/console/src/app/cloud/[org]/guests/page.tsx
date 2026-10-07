import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import {
  accountStatusLabels,
  accountStatusTone,
  accountStatuses,
  attentionDays,
  batches,
  endingOptions,
  guestAttention,
  guestFilterQuery,
  guestFilters,
  guestSummary,
  relativeDays,
  type GuestFilterParams,
} from '@/lib/guests';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const pageSize = 50;
/** The tiles count guests up to this many. */
const summaryLimit = 1000;
const guestsResource = { type: 'iam', id: 'guests' };
const invitationsResource = { type: 'iam', id: 'guests/invitations' };
const settingsResource = { type: 'iam', id: 'guests/settings' };
const guestResource = (identityId: string) => ({ type: 'iam', id: `guests/${identityId}` });

export default async function Guests({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<GuestFilterParams>;
}) {
  const { org } = await params;
  const { filters, page } = guestFilters(await searchParams);
  const context = await orgPage(org);
  const { iam, auth, tenantId, base, session } = context;
  const allowed = await can(context, [
    { action: 'iam:guests:read', resource: guestsResource },
    { action: 'iam:guests:read', resource: invitationsResource },
    { action: 'iam:guests:invite', resource: invitationsResource },
    { action: 'iam:guests:read', resource: settingsResource },
  ]);
  const mayRead = allowed[key('iam:guests:read', guestsResource)] === true;
  const mayReadInvitations = allowed[key('iam:guests:read', invitationsResource)] === true;
  const mayInvite = allowed[key('iam:guests:invite', invitationsResource)] === true;
  const [summary, listed, pending, mine, settings, people, roles, groups, packages] =
    await Promise.all([
      mayRead
        ? tryRead(() => iam.api.guests.list(auth, { tenantId, limit: summaryLimit }))
        : undefined,
      mayRead
        ? tryRead(() =>
            iam.api.guests.list(auth, {
              tenantId,
              ...filters,
              limit: pageSize,
              offset: (page - 1) * pageSize,
            }),
          )
        : undefined,
      mayReadInvitations
        ? tryRead(() => iam.api.guests.listInvitations(auth, { tenantId, status: 'pending' }))
        : undefined,
      // The guests the signed-in person sponsors: no permission needed.
      tryRead(() => iam.api.guests.mine(auth, { tenantId })),
      allowed[key('iam:guests:read', settingsResource)]
        ? tryRead(() => iam.api.guests.getSettings(auth, { tenantId }))
        : undefined,
      tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', limit: 1000 })),
      mayInvite ? tryRead(() => iam.api.roles.list(auth, { tenantId })) : undefined,
      mayInvite ? tryRead(() => iam.api.groups.list(auth, { tenantId })) : undefined,
      mayInvite ? tryRead(() => iam.api.packages.list(auth, { tenantId })) : undefined,
    ]);
  // Renewing needs iam:guests:manage on each guest, except for the guest's own sponsor.
  const rows = listed?.guests ?? [];
  const manageChecks = rows.map((guest) => ({
    action: 'iam:guests:manage',
    resource: guestResource(guest.identityId),
  }));
  const manageable = Object.assign(
    {},
    ...(await Promise.all(batches(manageChecks).map((batch) => can(context, batch)))),
  ) as Record<string, boolean>;
  const me = session.identity.id;
  const mayRenew = (guest: { identityId: string; sponsorId: string }) =>
    guest.sponsorId === me ||
    manageable[key('iam:guests:manage', guestResource(guest.identityId))] === true;
  const now = Date.now();
  const counts = summary ? guestSummary(summary.guests, now) : undefined;
  const accessDays = settings?.accessDays;
  const pages = listed ? Math.max(1, Math.ceil(listed.total / pageSize)) : 1;
  const href = (target: number) => `${base}/guests${guestFilterQuery(filters, target)}`;
  const filtering = Object.keys(filters).length > 0;
  const sponsors = (people ?? []).filter(
    (person) =>
      person.status === 'active' &&
      !person.guest &&
      (person.expiresAt === undefined || person.expiresAt > now),
  );
  const renewLabel = accessDays ? `Renew ${accessDays} days` : 'Renew';
  const renewConfirm = (name: string) =>
    accessDays
      ? `Renew ${name}'s access for ${accessDays} days from today?`
      : `Renew ${name}'s access for the organization's standard length?`;
  return (
    <>
      <PageHeader
        title="Guests"
        description="People from outside the organization, or from another organization, who joined by email invitation. Each has a sponsor who vouches for them; their access ends unless the sponsor renews it, and the cross-tenant access settings decide who may join at all. Policies see them as principal.guest."
        actions={
          <>
            {mayReadInvitations && (
              <Link className="btn small secondary" href={`${base}/guests/invitations`}>
                Invitations
              </Link>
            )}
            <Link className="btn small secondary" href={`${base}/guests/settings`}>
              Cross-tenant access
            </Link>
          </>
        }
      />
      <div className="stack">
        {mine && mine.length > 0 && (
          <Card
            title="Guests you sponsor"
            description={`You vouch for these people. Renew their access while they still need it; otherwise let it end. You are emailed ${attentionDays} days before a review or an access end.`}
            flush
          >
            <Table
              head={['Guest', 'Access ends', 'Next review', 'Last sign-in', '']}
              rows={mine.map((guest) => [
                <span key="g" className="stack" style={{ gap: 2 }}>
                  <span className="row">
                    {mayRead ? (
                      <Link href={`${base}/guests/${encodeURIComponent(guest.identityId)}`}>
                        {guest.name}
                      </Link>
                    ) : (
                      <strong>{guest.name}</strong>
                    )}
                    {guestAttention(guest, now).map((item) => (
                      <Badge key={item.label} tone={item.tone}>
                        {item.label}
                      </Badge>
                    ))}
                  </span>
                  {guest.email && <span className="small muted">{guest.email}</span>}
                </span>,
                guest.expiresAt ? (
                  <span key="e" className="stack small" style={{ gap: 2 }}>
                    <Time value={guest.expiresAt} />
                    <span className="muted">{relativeDays(guest.expiresAt, now)}</span>
                  </span>
                ) : (
                  <span key="e" className="muted">
                    never
                  </span>
                ),
                <Time key="r" value={guest.reviewDueAt} />,
                <Time key="l" value={guest.lastSignInAt} />,
                guest.accountStatus === 'active' && guest.status === 'active' ? (
                  <ApiButton
                    key="a"
                    path="guests/attest"
                    body={{ tenantId, identityId: guest.identityId }}
                    label={renewLabel}
                    confirm={renewConfirm(guest.name)}
                    tenantId={tenantId}
                  />
                ) : (
                  ''
                ),
              ])}
            />
          </Card>
        )}
        {!mayRead ? (
          <Alert tone="warning">
            The guest directory requires <code>iam:guests:read</code>.
            {mine && mine.length === 0 && ' You sponsor no guests.'}
          </Alert>
        ) : !summary || !listed ? (
          <Alert tone="warning">
            Requires <code>iam:guests:read</code> on <code>iam/guests</code>.
          </Alert>
        ) : (
          <>
            {counts && (
              <div className="tiles">
                <Stat
                  label="Active guests"
                  value={counts.active}
                  hint={counts.ended ? `${counts.ended} whose access ended` : undefined}
                />
                <Stat
                  label="Need a sponsor"
                  value={counts.needSponsor}
                  hint="Their sponsor left: assign another or remove them"
                />
                <Stat
                  label="Reviews due"
                  value={counts.reviewDue}
                  hint={`Overdue or due within ${attentionDays} days`}
                />
                <Stat
                  label="Access ending"
                  value={counts.endingSoon}
                  hint={
                    counts.endingSoon ? (
                      <Link href={`${base}/guests?status=active&ending=${attentionDays}`}>
                        within {attentionDays} days
                      </Link>
                    ) : (
                      `within ${attentionDays} days`
                    )
                  }
                />
                {pending && (
                  <Stat
                    label="Pending invitations"
                    value={pending.length}
                    hint={
                      <Link href={`${base}/guests/invitations?status=pending`}>
                        waiting to be accepted
                      </Link>
                    }
                  />
                )}
              </div>
            )}
            {summary.total > summary.guests.length && (
              <p className="small muted">
                The counts cover the first {summaryLimit.toLocaleString()} of {summary.total}{' '}
                guests.
              </p>
            )}
            <Card
              title="Guest directory"
              description="Guests are ordinary accounts of this organization: roles, groups, packages and reviews apply to them as to anyone. Their access and what their invitation granted end together."
              flush
            >
              <form method="get" className="row" style={{ padding: '0 16px 12px' }}>
                {people && (
                  <select
                    className="select"
                    name="sponsor"
                    defaultValue={filters.sponsorId ?? ''}
                    aria-label="Sponsor"
                    style={{ width: 'auto' }}
                  >
                    <option value="">Any sponsor</option>
                    {sponsors.map((person) => (
                      <option key={person.id} value={person.id}>
                        {person.name}
                        {person.email ? ` (${person.email})` : ''}
                      </option>
                    ))}
                  </select>
                )}
                <select
                  className="select"
                  name="status"
                  defaultValue={filters.status ?? ''}
                  aria-label="Status"
                  style={{ width: 'auto' }}
                >
                  <option value="">Any status</option>
                  {accountStatuses.map((status) => (
                    <option key={status} value={status}>
                      {accountStatusLabels[status]}
                    </option>
                  ))}
                </select>
                <select
                  className="select"
                  name="ending"
                  defaultValue={
                    filters.expiringWithinDays === undefined
                      ? ''
                      : String(filters.expiringWithinDays)
                  }
                  aria-label="Access ends within"
                  style={{ width: 'auto' }}
                >
                  <option value="">Access ends any time</option>
                  {endingOptions.map((days) => (
                    <option key={days} value={days}>
                      Ends within {days} days
                    </option>
                  ))}
                </select>
                <button className="btn small secondary">Filter</button>
                {filtering && (
                  <Link className="btn small ghost" href={`${base}/guests`}>
                    clear
                  </Link>
                )}
              </form>
              <Table
                head={[
                  'Guest',
                  'Sponsor',
                  'Status',
                  'Access ends',
                  'Next review',
                  'Last sign-in',
                  '',
                ]}
                rows={listed.guests.map((guest) => [
                  <span key="g" className="stack" style={{ gap: 2 }}>
                    <Link href={`${base}/guests/${encodeURIComponent(guest.identityId)}`}>
                      <strong>{guest.name}</strong>
                    </Link>
                    <span className="small muted">
                      {[guest.email, guest.homeTenantId ? 'from a partner organization' : undefined]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  </span>,
                  guest.sponsorMissing ? (
                    <span key="s" className="row">
                      <Badge tone="danger">needs a sponsor</Badge>
                      <span className="small muted">
                        was {guest.sponsorName ?? guest.sponsorId}
                      </span>
                    </span>
                  ) : (
                    <Link key="s" href={`${base}/members/${encodeURIComponent(guest.sponsorId)}`}>
                      {guest.sponsorName ?? guest.sponsorId}
                    </Link>
                  ),
                  <span key="t" className="row">
                    <Badge tone={accountStatusTone(guest.accountStatus)}>
                      {accountStatusLabels[guest.accountStatus]}
                    </Badge>
                    {guest.status !== 'active' && guest.accountStatus === 'active' && (
                      <Badge tone="danger">{guest.status}</Badge>
                    )}
                    {guestAttention(guest, now)
                      .filter((item) => item.label !== 'needs a sponsor')
                      .map((item) => (
                        <Badge key={item.label} tone={item.tone}>
                          {item.label}
                        </Badge>
                      ))}
                  </span>,
                  guest.expiresAt ? (
                    <span key="e" className="stack small" style={{ gap: 2 }}>
                      <Time value={guest.expiresAt} />
                      <span className="muted">{relativeDays(guest.expiresAt, now)}</span>
                    </span>
                  ) : (
                    <span key="e" className="muted">
                      never
                    </span>
                  ),
                  guest.accountStatus === 'active' ? (
                    <Time key="r" value={guest.reviewDueAt} />
                  ) : (
                    <span key="r" className="muted">
                      —
                    </span>
                  ),
                  <Time key="l" value={guest.lastSignInAt} />,
                  guest.accountStatus === 'active' &&
                  guest.status === 'active' &&
                  mayRenew(guest) ? (
                    <ApiButton
                      key="a"
                      path="guests/attest"
                      body={{ tenantId, identityId: guest.identityId }}
                      label={renewLabel}
                      confirm={renewConfirm(guest.name)}
                      tenantId={tenantId}
                    />
                  ) : (
                    ''
                  ),
                ])}
                empty={
                  filtering
                    ? 'No guest matches these filters.'
                    : 'No guests yet. Invite someone from outside the organization below.'
                }
              />
              {pages > 1 && (
                <div className="card-body row spread">
                  <span className="small muted">
                    Page {page} of {pages} · {listed.total} guests
                  </span>
                  <span className="row">
                    {page > 1 && (
                      <Link className="btn small secondary" href={href(page - 1)}>
                        Previous
                      </Link>
                    )}
                    {page < pages && (
                      <Link className="btn small secondary" href={href(page + 1)}>
                        Next
                      </Link>
                    )}
                  </span>
                </div>
              )}
            </Card>
          </>
        )}
        {mayInvite && (
          <Card
            title="Invite a guest"
            description="Emails the person a personal invitation. When they accept it they choose a password, and their guest account starts with the roles, groups and packages below until their access ends. You can grant only what you could grant yourself; it is checked again when they accept."
          >
            <ApiForm
              path="guests/invite"
              tenantId={tenantId}
              submitLabel="Send invitation"
              successMessage="Invitation sent."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'email',
                  label: 'Email address',
                  type: 'email',
                  required: true,
                  placeholder: 'alex@partner.example',
                  help: "Not at one of this organization's verified domains: invite members from the Members page.",
                },
                {
                  name: 'sponsorId',
                  label: 'Sponsor',
                  type: 'select',
                  options: sponsors.map((person) => ({
                    value: person.id,
                    label: person.email ? `${person.name} (${person.email})` : person.name,
                  })),
                  help: 'Who vouches for the guest and renews their access; you, when left empty.',
                },
                {
                  name: 'message',
                  label: 'Message',
                  placeholder: 'Welcome to the Q3 launch project.',
                  help: 'Included in the email; one line, at most 1000 characters.',
                },
                ...(roles && roles.some((role) => !role.protected)
                  ? [
                      {
                        name: 'roleIds',
                        label: 'Roles',
                        type: 'multiselect' as const,
                        options: roles
                          .filter((role) => !role.protected)
                          .map((role) => ({ value: role.id, label: role.name })),
                      },
                    ]
                  : []),
                ...(groups && groups.some((group) => !group.teamId)
                  ? [
                      {
                        name: 'groupIds',
                        label: 'Groups',
                        type: 'multiselect' as const,
                        options: groups
                          .filter((group) => !group.teamId)
                          .map((group) => ({ value: group.id, label: group.name })),
                      },
                    ]
                  : []),
                ...(packages && packages.length
                  ? [
                      {
                        name: 'packageIds',
                        label: 'Access packages',
                        type: 'multiselect' as const,
                        options: packages.map((pkg) => ({ value: pkg.id, label: pkg.name })),
                        help: "A package's maximum duration can end its assignment before the guest's access.",
                      },
                    ]
                  : []),
                {
                  name: 'accessDays',
                  label: 'Access lasts (days)',
                  type: 'number',
                  placeholder: String(accessDays ?? 90),
                  help: `1 to 365 from acceptance; ${accessDays ? `the organization's standard is ${accessDays}` : "empty uses the organization's standard"}.`,
                },
                {
                  name: 'expiresInDays',
                  label: 'Invitation valid for (days)',
                  type: 'number',
                  placeholder: '14',
                  help: '1 to 30; the default is 14.',
                },
              ]}
            />
          </Card>
        )}
      </div>
    </>
  );
}
