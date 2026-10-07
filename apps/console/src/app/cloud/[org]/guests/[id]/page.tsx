import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, KeyValues, PageHeader, StatusBadge, Time } from '@/components/ui';
import { accountStatusLabels, accountStatusTone, guestAttention, relativeDays } from '@/lib/guests';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const settingsResource = { type: 'iam', id: 'guests/settings' };
const invitationsResource = { type: 'iam', id: 'guests/invitations' };

export default async function Guest({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base, session } = context;
  const guestResource = { type: 'iam', id: `guests/${id}` };
  // Administrators read any guest; a sponsor without iam:guests:read still sees the guests they sponsor.
  const guest =
    (await tryRead(() => iam.api.guests.get(auth, { tenantId, identityId: id }))) ??
    (await tryRead(() => iam.api.guests.mine(auth, { tenantId })))?.find(
      (candidate) => candidate.identityId === id,
    );
  if (!guest) notFound();
  const allowed = await can(context, [
    { action: 'iam:guests:manage', resource: guestResource },
    { action: 'iam:guests:read', resource: settingsResource },
    { action: 'iam:guests:read', resource: invitationsResource },
  ]);
  const mayManage = allowed[key('iam:guests:manage', guestResource)] === true;
  const [settings, members, invitations, roles, groups, packages] = await Promise.all([
    allowed[key('iam:guests:read', settingsResource)]
      ? tryRead(() => iam.api.guests.getSettings(auth, { tenantId }))
      : undefined,
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', limit: 1000 })),
    allowed[key('iam:guests:read', invitationsResource)]
      ? tryRead(() => iam.api.guests.listInvitations(auth, { tenantId, status: 'redeemed' }))
      : undefined,
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() => iam.api.packages.list(auth, { tenantId })),
  ]);
  const invitation = invitations?.find((item) => item.id === guest.invitationId);
  const person = (identityId: string) => {
    const member = members?.find((candidate) => candidate.id === identityId);
    return member ? member.name || member.email || member.id : identityId;
  };
  const nameOf = (list: { id: string; name: string }[] | undefined, itemId: string) =>
    list?.find((item) => item.id === itemId)?.name ?? itemId;
  const now = Date.now();
  const isSponsor = guest.sponsorId === session.identity.id;
  const active = guest.accountStatus === 'active' && guest.status === 'active';
  const sponsors = (members ?? []).filter(
    (member) =>
      member.status === 'active' &&
      !member.guest &&
      member.id !== guest.identityId &&
      member.id !== guest.sponsorId &&
      (member.expiresAt === undefined || member.expiresAt > now),
  );
  const accessDays = settings?.accessDays;
  const reviewEveryDays = settings?.reviewEveryDays;
  return (
    <>
      <PageHeader
        title={
          <>
            {guest.name} <Badge tone="accent">Guest</Badge>{' '}
            <Badge tone={accountStatusTone(guest.accountStatus)}>
              {accountStatusLabels[guest.accountStatus]}
            </Badge>
          </>
        }
        description={
          <>
            {guest.email ?? 'no email address'}
            {guest.homeDomain && <> · from {guest.homeDomain}</>} ·{' '}
            <Link href={`${base}/members/${encodeURIComponent(guest.identityId)}`}>
              roles, groups and sessions
            </Link>{' '}
            · <Link href={`${base}/guests`}>all guests</Link>
          </>
        }
      />
      <div className="stack">
        {guestAttention(guest, now).map((item) => (
          <Alert key={item.label} tone={item.tone === 'danger' ? 'danger' : 'warning'}>
            {item.label === 'needs a sponsor'
              ? `${guest.sponsorName ?? 'The sponsor'} is no longer an active member who can sponsor guests. Assign a new sponsor, or remove the guest if nobody vouches for them.`
              : item.label === 'access ends soon'
                ? `Access ends ${relativeDays(guest.expiresAt!, now)} unless someone renews it.`
                : item.label === 'review overdue'
                  ? 'The sponsor has not confirmed that this guest still needs access.'
                  : `The sponsor's review is due ${relativeDays(guest.reviewDueAt, now)}.`}
          </Alert>
        ))}
        {guest.accountStatus === 'active' && guest.status !== 'active' && (
          <Alert tone="warning">
            The account is {guest.status}: the guest cannot sign in, and their access cannot be
            renewed until an administrator restores it on the member page.
          </Alert>
        )}
        {guest.accountStatus === 'expired' && (
          <Alert tone="info">
            This guest&apos;s access ended. An administrator can restore it on the member page
            (activate the account and move its deactivation date), or delete the account there and
            invite the person again.
          </Alert>
        )}
        <div className="grid cols-2">
          <Card title="Guest access">
            <KeyValues
              items={[
                [
                  'Sponsor',
                  <span key="s" className="row">
                    <Link href={`${base}/members/${encodeURIComponent(guest.sponsorId)}`}>
                      {guest.sponsorName ?? person(guest.sponsorId)}
                    </Link>
                    {guest.sponsorMissing && <Badge tone="danger">left</Badge>}
                    {isSponsor && <Badge>you</Badge>}
                  </span>,
                ],
                [
                  'Home organization',
                  guest.homeTenantId ? (
                    <code key="h" className="small">
                      {guest.homeTenantId}
                    </code>
                  ) : (
                    <span key="h" className="muted">
                      {guest.homeDomain
                        ? `none (no organization verified ${guest.homeDomain})`
                        : 'none'}
                    </span>
                  ),
                ],
                ['Account', <StatusBadge key="a" status={guest.status} />],
                [
                  'Access ends',
                  guest.expiresAt ? (
                    <span key="e" className="row">
                      <Time value={guest.expiresAt} />
                      <span className="small muted">{relativeDays(guest.expiresAt, now)}</span>
                    </span>
                  ) : (
                    'never'
                  ),
                ],
                [
                  'Next review',
                  guest.accountStatus === 'active' ? (
                    <Time key="r" value={guest.reviewDueAt} />
                  ) : (
                    <span key="r" className="muted">
                      —
                    </span>
                  ),
                ],
                [
                  'Last renewed',
                  guest.attestedAt ? (
                    <span key="t">
                      <Time value={guest.attestedAt} />
                      {guest.attestedBy && <> by {person(guest.attestedBy)}</>}
                    </span>
                  ) : (
                    <span key="t" className="muted">
                      never
                    </span>
                  ),
                ],
                ['Joined', <Time key="j" value={guest.redeemedAt} />],
                ['Invited by', person(guest.invitedBy)],
                ['Last sign-in', <Time key="l" value={guest.lastSignInAt} />],
              ]}
            />
          </Card>
          <Card
            title="Invited with"
            description="What the invitation granted at acceptance. Renewing the guest moves the end of these grants with their access; grants changed since keep their own end."
          >
            {invitation ? (
              <KeyValues
                items={[
                  [
                    'Roles',
                    invitation.roleIds.length ? (
                      <span key="r">
                        {invitation.roleIds.map((roleId, index) => (
                          <span key={roleId}>
                            {index > 0 && ', '}
                            <Link href={`${base}/roles/${encodeURIComponent(roleId)}`}>
                              {nameOf(roles, roleId)}
                            </Link>
                          </span>
                        ))}
                      </span>
                    ) : (
                      <span key="r" className="muted">
                        none
                      </span>
                    ),
                  ],
                  [
                    'Groups',
                    invitation.groupIds.length ? (
                      <span key="g">
                        {invitation.groupIds.map((groupId, index) => (
                          <span key={groupId}>
                            {index > 0 && ', '}
                            <Link href={`${base}/groups/${encodeURIComponent(groupId)}`}>
                              {nameOf(groups, groupId)}
                            </Link>
                          </span>
                        ))}
                      </span>
                    ) : (
                      <span key="g" className="muted">
                        none
                      </span>
                    ),
                  ],
                  [
                    'Access packages',
                    invitation.packageIds.length ? (
                      invitation.packageIds
                        .map((packageId) => nameOf(packages, packageId))
                        .join(', ')
                    ) : (
                      <span key="p" className="muted">
                        none
                      </span>
                    ),
                  ],
                  ['Access length', `${invitation.accessDays} days`],
                  ...(invitation.message
                    ? ([['Message', `“${invitation.message}”`]] as [string, string][])
                    : []),
                ]}
              />
            ) : (
              <p className="muted">
                The invitation is not readable (<code>iam:guests:read</code> on{' '}
                <code>iam/guests/invitations</code>). The member page lists what the guest holds
                now.
              </p>
            )}
          </Card>
        </div>
        {active && (isSponsor || mayManage) && (
          <Card
            title="Renew access"
            description={
              isSponsor
                ? 'You sponsor this guest: confirm they still need access and choose how long it lasts from today.'
                : 'Extends the guest’s access from today, together with what their invitation granted.'
            }
          >
            <ApiForm
              path="guests/attest"
              tenantId={tenantId}
              submitLabel="Renew"
              successMessage="Access renewed."
              compact
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'identityId', label: 'Guest', type: 'hidden', defaultValue: id },
                {
                  name: 'days',
                  label: 'Access lasts (days from today)',
                  type: 'number',
                  placeholder: String(accessDays ?? 90),
                  help: `1 to 365; empty uses the organization's standard${accessDays ? ` of ${accessDays} days` : ''}. The next review is due ${reviewEveryDays ? `${reviewEveryDays} days from today` : 'after the organization’s review period'}, or at the new end if sooner.`,
                },
              ]}
            />
          </Card>
        )}
        {mayManage && guest.accountStatus === 'active' && (
          <div className="grid cols-2">
            {active && (
              <Card
                title="Change sponsor"
                description="The new sponsor must be an active member who is not a guest. Needs a recent sign-in."
              >
                {sponsors.length ? (
                  <ApiForm
                    path="guests/setSponsor"
                    tenantId={tenantId}
                    submitLabel="Change sponsor"
                    successMessage="Sponsor changed."
                    compact
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      { name: 'identityId', label: 'Guest', type: 'hidden', defaultValue: id },
                      {
                        name: 'sponsorId',
                        label: 'New sponsor',
                        type: 'select',
                        required: true,
                        options: sponsors.map((member) => ({
                          value: member.id,
                          label: member.email ? `${member.name} (${member.email})` : member.name,
                        })),
                      },
                    ]}
                  />
                ) : (
                  <p className="muted">Nobody else can sponsor guests.</p>
                )}
              </Card>
            )}
            {active && (
              <Card
                title="Make a member"
                description="The person stops being a guest: policies see principal.guest as false, birthright rules apply to them like to anyone, and their guest account closes. Needs a recent sign-in."
              >
                <ApiForm
                  path="guests/convertToMember"
                  tenantId={tenantId}
                  submitLabel="Make a member"
                  redirectTo={`${base}/members/{id}`}
                  compact
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'identityId', label: 'Guest', type: 'hidden', defaultValue: id },
                    {
                      name: 'clearExpiry',
                      label:
                        'Also remove the end date (of the account and of what the invitation granted)',
                      type: 'checkbox',
                    },
                  ]}
                />
              </Card>
            )}
          </div>
        )}
        {mayManage &&
          guest.accountStatus !== 'removed' &&
          guest.accountStatus !== 'converted' &&
          guest.identityId !== session.identity.id && (
            <Card
              title="Remove guest"
              description="Disables the account and, in one transaction, ends its sessions, keys and delegations, removes every role, group, team and package it holds, cancels its pending requests, and closes the guest account. Needs a recent sign-in."
            >
              <ApiForm
                path="guests/remove"
                tenantId={tenantId}
                submitLabel="Remove guest"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'identityId', label: 'Guest', type: 'hidden', defaultValue: id },
                  {
                    name: 'reason',
                    label: 'Reason',
                    required: true,
                    placeholder: 'Project finished',
                  },
                ]}
              />
            </Card>
          )}
      </div>
    </>
  );
}
