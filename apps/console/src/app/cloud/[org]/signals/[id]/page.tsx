import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
import { ApiButton } from '@/components/api-form';
import { SignalEventsTable } from '@/components/signal-events';
import {
  ActionsForm,
  MappingForm,
  PollNow,
  RotatePushToken,
  SourceSettingsForm,
} from '@/components/signal-forms';
import { Alert, Badge, Card, KeyValues, PageHeader, StatusBadge, Time } from '@/components/ui';
import { getDirectory } from '@/lib/iam';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { actionableEventTypes, eventTypeLabels } from '@/lib/signals';

const eventsResource = { type: 'iam', id: 'signals/events' };

export default async function SignalSourcePage({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base } = page;
  const source = await tryRead(() => iam.api.signals.getSource(auth, { tenantId, sourceId: id }));
  if (!source) notFound();
  const sourceResource = { type: 'iam', id: `signals/sources/${source.id}` };
  const [allowed, events] = await Promise.all([
    can(page, [
      { action: 'iam:signals:manage', resource: sourceResource },
      { action: 'iam:signals:manage', resource: eventsResource },
    ]),
    tryRead(() => iam.api.signals.listEvents(auth, { tenantId, sourceId: source.id, limit: 25 })),
  ]);
  const mayManage = allowed[key('iam:signals:manage', sourceResource)] === true;
  const mayReprocess = allowed[key('iam:signals:manage', eventsResource)] === true;
  const matched = [...new Set((events?.events ?? []).flatMap((event) => event.identityId ?? []))];
  const directory = mayManage ? await getDirectory() : undefined;
  const [members, scimConnections, domains] = await Promise.all([
    matched.length
      ? tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 }))
      : Promise.resolve(undefined),
    directory ? tryRead(() => directory.listConnections(auth, { tenantId })) : undefined,
    mayManage ? tryRead(() => iam.api.domains.list(auth, { tenantId })) : undefined,
  ]);
  const people = Object.fromEntries(
    (members ?? [])
      .filter((member) => matched.includes(member.id))
      .map((member) => [member.id, member.name || member.email || member.id]),
  );
  const scimOptions = scimConnections?.map((connection) => ({
    id: connection.id,
    name: connection.name,
    revoked: connection.revoked,
  }));
  const scimName = (connectionId: string) =>
    scimConnections?.find((connection) => connection.id === connectionId)?.name ?? connectionId;
  const verifiedDomains = domains
    ?.filter((domain) => domain.status === 'verified')
    .map((domain) => domain.domain);
  const revoking = actionableEventTypes.filter(
    (type) => source.actions[type] === 'revoke-sessions',
  );
  const keys = source.jwks
    ? `${source.jwks.keys.length} static key${source.jwks.keys.length === 1 ? '' : 's'}${
        source.jwks.keys.some((jwk) => jwk.kid)
          ? ` (${source.jwks.keys.map((jwk) => jwk.kid ?? 'no kid').join(', ')})`
          : ''
      }`
    : undefined;
  const transmitter: [ReactNode, ReactNode][] = [['Issuer', <code key="i">{source.issuer}</code>]];
  if (source.issuerAliases.length)
    transmitter.push(['Also known as', <code key="a">{source.issuerAliases.join(', ')}</code>]);
  transmitter.push(
    ['Audiences', <code key="u">{source.audiences.join(', ')}</code>],
    [
      'Signing keys',
      source.jwksUri ? (
        <code key="k">{source.jwksUri}</code>
      ) : (
        (keys ?? 'Discovered from the issuer (/.well-known/ssf-configuration)')
      ),
    ],
    ['Algorithms', source.algorithms.join(', ')],
    [
      'Token type',
      source.requireTyp ? (
        <span key="t">
          <code>secevent+jwt</code> required
        </span>
      ) : (
        'any (legacy RISC tolerated)'
      ),
    ],
  );
  if (source.delivery === 'push')
    transmitter.push(
      [
        'Push URL',
        <code key="p" style={{ wordBreak: 'break-all' }}>
          {source.pushUrl}
        </code>,
      ],
      [
        'Bearer token',
        <span key="b" className="stack" style={{ gap: 6 }}>
          <span>{source.hasPushToken ? 'required' : 'not required'}</span>
          {mayManage && (
            <RotatePushToken
              tenantId={tenantId}
              sourceId={source.id}
              hasToken={source.hasPushToken}
            />
          )}
        </span>,
      ],
    );
  if (source.poll)
    transmitter.push(
      ['Poll endpoint', <code key="e">{source.poll.endpoint}</code>],
      ['Events per request', String(source.poll.maxEvents)],
      ['Waiting acknowledgements', String(source.poll.pendingAcks)],
      ['Last polled', <Time key="l" value={source.poll.lastPolledAt} />],
    );
  transmitter.push(
    ['Status', <StatusBadge key="s" status={source.status} />],
    ['Last event', <Time key="e" value={source.lastEventAt} />],
    [
      'Last verification',
      source.lastVerifiedAt ? (
        <Time key="v" value={source.lastVerifiedAt} />
      ) : (
        <span key="v" className="muted">
          none received
        </span>
      ),
    ],
    ['Added', <Time key="c" value={source.createdAt} />],
    ['Changed', <Time key="m" value={source.updatedAt} />],
  );
  return (
    <>
      <PageHeader
        title={source.name}
        description={
          <>
            A Shared Signals transmitter for <code>{source.issuer}</code>. Back to{' '}
            <Link href={`${base}/signals`}>all sources and events</Link>.
          </>
        }
        actions={
          mayManage && (
            <>
              {source.delivery === 'poll' && source.status === 'active' && (
                <PollNow tenantId={tenantId} sourceId={source.id} />
              )}
              <ApiButton
                path="signals/updateSource"
                body={{
                  tenantId,
                  sourceId: source.id,
                  status: source.status === 'active' ? 'disabled' : 'active',
                }}
                label={source.status === 'active' ? 'Disable' : 'Enable'}
                confirm={
                  source.status === 'active'
                    ? 'Disable this source? Its pushes are refused (404) and it is not polled until you enable it again.'
                    : undefined
                }
                tenantId={tenantId}
              />
              <ApiButton
                path="signals/deleteSource"
                body={{ tenantId, sourceId: source.id }}
                label="Delete"
                tone="danger"
                confirm={`Delete ${source.name}? Its pushes are refused from now on; the events it sent stay until they expire.`}
                redirectTo={`${base}/signals`}
                tenantId={tenantId}
              />
            </>
          )
        }
      />
      <div className="stack">
        {source.status === 'disabled' && (
          <Alert tone="warning">
            This source is disabled: its pushes are refused and it is not polled.
          </Alert>
        )}
        {source.lastError && (
          <Alert tone="danger">
            <strong>Last error</strong> (<Time value={source.lastError.at} />
            ): {source.lastError.message}
          </Alert>
        )}
        <div className="grid cols-2">
          <Card
            title="Transmitter"
            description={
              source.delivery === 'push'
                ? 'Give the transmitter the push URL (and the bearer token, when the source requires one). Ask it to send a verification event to check the setup: its arrival is recorded here.'
                : 'Events are fetched from the poll endpoint every minute and acknowledged on the next request once they are stored.'
            }
          >
            <KeyValues items={transmitter} />
          </Card>
          <div className="stack">
            <Card
              title="Who events are about"
              description="How the transmitter's subjects are matched to members of this organization. Service accounts, agents and deleted members never match."
            >
              {mayManage ? (
                <MappingForm
                  tenantId={tenantId}
                  source={source}
                  scimConnections={scimOptions}
                  verifiedDomains={verifiedDomains}
                />
              ) : (
                <KeyValues
                  items={[
                    [
                      'Sign-in connections',
                      source.subjects.connectionIds.length ? (
                        <code key="c">{source.subjects.connectionIds.join(', ')}</code>
                      ) : (
                        'none'
                      ),
                    ],
                    [
                      'Directory sync',
                      source.subjects.scimConnectionIds.length
                        ? source.subjects.scimConnectionIds.map(scimName).join(', ')
                        : 'none',
                    ],
                    ['Email at verified domains', source.subjects.matchEmail ? 'yes' : 'no'],
                  ]}
                />
              )}
            </Card>
            <Card
              title="Actions"
              description="Matched events are always recorded. Events set to end sessions sign the person out everywhere."
            >
              {mayManage ? (
                <ActionsForm tenantId={tenantId} source={source} />
              ) : revoking.length ? (
                <span className="row" style={{ flexWrap: 'wrap' }}>
                  <span className="small muted">Ends sessions on</span>
                  {revoking.map((type) => (
                    <Badge key={type} tone="warning">
                      {eventTypeLabels[type]}
                    </Badge>
                  ))}
                </span>
              ) : (
                <span className="small muted">Every event is recorded only.</span>
              )}
            </Card>
          </div>
        </div>
        <Card
          title="Recent events"
          description={
            events && events.total > events.events.length ? (
              <>
                The newest {events.events.length} of {events.total}.{' '}
                <Link href={`${base}/signals?sourceId=${encodeURIComponent(source.id)}`}>
                  See all
                </Link>
              </>
            ) : undefined
          }
          flush
        >
          {events ? (
            <SignalEventsTable
              events={events.events}
              base={base}
              tenantId={tenantId}
              sourceNames={{ [source.id]: source.name }}
              people={people}
              mayReprocess={mayReprocess}
              showSource={false}
              empty="Nothing received from this source yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:signals:read</code> on <code>iam/signals/events</code>.
            </div>
          )}
        </Card>
        {mayManage && (
          <Card
            title="Settings"
            description="Changes need a recent sign-in. Cached keys are dropped when you save, so a key change takes effect with the next event."
          >
            <SourceSettingsForm tenantId={tenantId} source={source} />
          </Card>
        )}
      </div>
    </>
  );
}
