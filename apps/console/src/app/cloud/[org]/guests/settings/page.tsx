import Link from 'next/link';
import type { CrossTenantPartner } from 'better-iam';
import { GuestSettingsForm } from '@/components/guest-forms';
import { Alert, Badge, Card, Json, KeyValues, PageHeader, Time } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const settingsResource = { type: 'iam', id: 'guests/settings' };

function List({ items, none }: { items: readonly string[]; none: string }) {
  return items.length ? (
    <code className="small">{items.join(', ')}</code>
  ) : (
    <span className="muted">{none}</span>
  );
}

function Partners({
  partners,
  allow,
}: {
  partners: readonly CrossTenantPartner[];
  allow: boolean;
}) {
  return (
    <List
      items={partners
        .filter((partner) => partner.allow === allow)
        .map((partner) => partner.tenantId)}
      none="none"
    />
  );
}

export default async function GuestSettings({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base } = context;
  const [settings, members, allowed] = await Promise.all([
    tryRead(() => iam.api.guests.getSettings(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
    can(context, [{ action: 'iam:guests:settings', resource: settingsResource }]),
  ]);
  const mayConfigure = allowed[key('iam:guests:settings', settingsResource)] === true;
  const person = (identityId: string) => {
    const member = members?.find((candidate) => candidate.id === identityId);
    return member ? member.name || member.email || member.id : identityId;
  };
  return (
    <>
      <PageHeader
        title="Cross-tenant access"
        description={
          <>
            Who may join this organization as a guest, whether your own people may be guests
            elsewhere, how long guest access lasts, and a boundary on what guests may ever do. An
            invitation is checked against both sides when it is sent and again when it is accepted.
            Back to <Link href={`${base}/guests`}>guests</Link>.
          </>
        }
      />
      {!settings ? (
        <Alert tone="warning">
          Requires <code>iam:guests:read</code> on <code>iam/guests/settings</code>.
        </Alert>
      ) : (
        <div className="stack">
          <Alert tone="info">
            Another organization is recognized by the email domains it verified: a person at one of
            them is from that organization, and its own outbound settings must allow them to join
            you. Organizations are named by their ID (shown on their Settings page); this
            organization&apos;s ID is <code>{tenantId}</code>.
          </Alert>
          <Card
            title="Settings"
            description={
              settings.configured && settings.updatedAt ? (
                <>
                  Last changed <Time value={settings.updatedAt} />
                  {settings.updatedBy && <> by {person(settings.updatedBy)}</>}. Changes need{' '}
                  <code>iam:guests:settings</code> and a recent sign-in.
                </>
              ) : (
                <>
                  Everything is at its default: anyone outside your verified domains may be invited,
                  for {settings.accessDays} days, reviewed every {settings.reviewEveryDays} days.
                </>
              )
            }
          >
            {mayConfigure ? (
              <GuestSettingsForm tenantId={tenantId} settings={settings} />
            ) : (
              <div className="stack">
                <KeyValues
                  items={[
                    [
                      'Accept guests',
                      <Badge key="a" tone={settings.inbound.allowGuests ? 'success' : 'neutral'}>
                        {settings.inbound.allowGuests ? 'yes' : 'no'}
                      </Badge>,
                    ],
                    [
                      'Only from domains',
                      <List key="d" items={settings.inbound.allowedDomains} none="any domain" />,
                    ],
                    [
                      'Never from domains',
                      <List key="b" items={settings.inbound.blockedDomains} none="none" />,
                    ],
                    [
                      'Always admitted organizations',
                      <Partners key="ia" partners={settings.inbound.partners} allow />,
                    ],
                    [
                      'Refused organizations',
                      <Partners key="ir" partners={settings.inbound.partners} allow={false} />,
                    ],
                    [
                      'Your people may be guests elsewhere',
                      <Badge
                        key="o"
                        tone={settings.outbound.allowGuestInvitations ? 'success' : 'neutral'}
                      >
                        {settings.outbound.allowGuestInvitations ? 'yes' : 'no'}
                      </Badge>,
                    ],
                    [
                      'Always allowed to join',
                      <Partners key="oa" partners={settings.outbound.partners} allow />,
                    ],
                    [
                      'Never allowed to join',
                      <Partners key="or" partners={settings.outbound.partners} allow={false} />,
                    ],
                    ['Guest access lasts', `${settings.accessDays} days`],
                    ['Sponsors review every', `${settings.reviewEveryDays} days`],
                    [
                      'Guest boundary',
                      settings.guestBoundary ? 'set (below)' : <span key="g">none</span>,
                    ],
                  ]}
                />
                {settings.guestBoundary && <Json value={settings.guestBoundary} />}
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
