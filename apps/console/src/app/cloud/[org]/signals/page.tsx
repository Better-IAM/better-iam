import Link from 'next/link';
import type { SignalEventType } from 'better-iam/server';
import { SignalEventsTable } from '@/components/signal-events';
import { CreateSourceForm, PollNow } from '@/components/signal-forms';
import { Alert, Badge, Card, PageHeader, Stat, StatusBadge, Table, Time } from '@/components/ui';
import { getDirectory } from '@/lib/iam';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { eventTypeLabels, signalStatuses } from '@/lib/signals';

const pageSize = 50;
const sourcesResource = { type: 'iam', id: 'signals/sources' };
const eventsResource = { type: 'iam', id: 'signals/events' };
const eventTypes = Object.keys(eventTypeLabels) as SignalEventType[];

export default async function Signals({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{
    status?: string;
    eventType?: string;
    sourceId?: string;
    identityId?: string;
    page?: string;
  }>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base } = page;
  const status = signalStatuses.find((candidate) => candidate === query.status);
  const eventType = eventTypes.find((candidate) => candidate === query.eventType);
  const sourceId = query.sourceId?.trim() || undefined;
  const identityId = query.identityId?.trim() || undefined;
  const pageNumber = Math.max(0, Math.floor(Number(query.page) || 0));
  const filtered = Boolean(status || eventType || sourceId || identityId);
  const [sources, events, unmatched, failed, allowed] = await Promise.all([
    tryRead(() => iam.api.signals.listSources(auth, { tenantId })),
    tryRead(() =>
      iam.api.signals.listEvents(auth, {
        tenantId,
        ...(status ? { status } : {}),
        ...(eventType ? { eventType } : {}),
        ...(sourceId ? { sourceId } : {}),
        ...(identityId ? { identityId } : {}),
        limit: pageSize,
        offset: pageNumber * pageSize,
      }),
    ),
    tryRead(() => iam.api.signals.listEvents(auth, { tenantId, status: 'unmatched', limit: 1 })),
    tryRead(() => iam.api.signals.listEvents(auth, { tenantId, status: 'failed', limit: 1 })),
    can(page, [
      { action: 'iam:signals:manage', resource: sourcesResource },
      { action: 'iam:signals:manage', resource: eventsResource },
    ]),
  ]);
  const mayManage = allowed[key('iam:signals:manage', sourcesResource)] === true;
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
  const sourceNames = Object.fromEntries((sources ?? []).map((source) => [source.id, source.name]));
  const people = Object.fromEntries(
    (members ?? [])
      .filter((member) => matched.includes(member.id))
      .map((member) => [member.id, member.name || member.email || member.id]),
  );
  const link = (target: number) => {
    const search = new URLSearchParams({
      ...(status ? { status } : {}),
      ...(eventType ? { eventType } : {}),
      ...(sourceId ? { sourceId } : {}),
      ...(identityId ? { identityId } : {}),
      ...(target ? { page: String(target) } : {}),
    }).toString();
    return `${base}/signals${search ? `?${search}` : ''}`;
  };
  const hasMore = events ? (pageNumber + 1) * pageSize < events.total : false;
  const active = (sources ?? []).filter((source) => source.status === 'active');
  const lastEventAt = Math.max(0, ...(sources ?? []).map((source) => source.lastEventAt ?? 0));
  return (
    <>
      <PageHeader
        title="Shared Signals"
        description="Security events your identity providers send about your people over the OpenID Shared Signals Framework (CAEP and RISC): sessions they ended, compromised credentials, disabled accounts, and risk changes. Events are matched to members, kept for 90 days, fed to threat detection, and can end the person's sessions here."
        actions={
          mayManage &&
          sources && (
            <a className="btn small" href="#add-source">
              Add a source
            </a>
          )
        }
      />
      {!sources ? (
        <Alert tone="warning">
          Requires <code>iam:signals:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="grid cols-4">
            <Stat
              label="Sources"
              value={sources.length}
              hint={
                sources.length === active.length
                  ? 'All active'
                  : `${active.length} active · ${sources.length - active.length} disabled`
              }
            />
            <Stat label="Last event" value={lastEventAt ? <Time value={lastEventAt} /> : 'never'} />
            <Stat
              label="Unmatched"
              value={unmatched?.total ?? '—'}
              hint="No member matched the subject; fix the mapping and reprocess"
            />
            <Stat
              label="Failed"
              value={failed?.total ?? '—'}
              hint="Processing failed; reprocess once the cause is fixed"
            />
          </div>
          <Card
            title="Sources"
            description="Transmitters this organization trusts. Each one is an issuer with its own signing keys, audiences, subject mapping, and actions."
            flush
          >
            <Table
              head={['Source', 'Delivery', 'Status', 'Last event', 'Health', '']}
              rows={sources.map((source) => [
                <span key="n" className="stack" style={{ gap: 2 }}>
                  <Link href={`${base}/signals/${source.id}`}>
                    <strong>{source.name}</strong>
                  </Link>
                  <code className="small truncate">{source.issuer}</code>
                </span>,
                <span key="d" className="stack small" style={{ gap: 2 }}>
                  <span>{source.delivery}</span>
                  {source.delivery === 'push' && (
                    <span className="muted">
                      {source.hasPushToken ? 'bearer token' : 'no token'}
                    </span>
                  )}
                  {source.poll?.lastPolledAt && (
                    <span className="muted">
                      polled <Time value={source.poll.lastPolledAt} />
                    </span>
                  )}
                </span>,
                <StatusBadge key="s" status={source.status} />,
                <Time key="l" value={source.lastEventAt} />,
                source.lastError ? (
                  <span key="h" className="stack small" style={{ gap: 2 }}>
                    <Badge tone="danger">error</Badge>
                    <span className="muted">
                      {source.lastError.message} (<Time value={source.lastError.at} />)
                    </span>
                  </span>
                ) : source.lastVerifiedAt ? (
                  <span key="h" className="small">
                    <Badge tone="success">verified</Badge>{' '}
                    <span className="muted">
                      <Time value={source.lastVerifiedAt} />
                    </span>
                  </span>
                ) : (
                  <span key="h" className="small muted">
                    no verification yet
                  </span>
                ),
                mayManage && source.delivery === 'poll' && source.status === 'active' ? (
                  <PollNow key="a" tenantId={tenantId} sourceId={source.id} />
                ) : (
                  ''
                ),
              ])}
              empty="No sources yet: add your identity provider's transmitter below."
            />
          </Card>
          <Card
            title={
              events
                ? `${events.total} ${filtered ? 'matching ' : ''}event${events.total === 1 ? '' : 's'}`
                : 'Received events'
            }
            description={
              identityId ? (
                <>
                  About <strong>{people[identityId] ?? identityId}</strong> ·{' '}
                  <Link href={`${base}/signals`}>show everyone</Link>
                </>
              ) : (
                'Newest first. Control events (verification, stream status) are recorded against the source.'
              )
            }
            actions={
              (pageNumber > 0 || hasMore) && (
                <span className="row">
                  {pageNumber > 0 && (
                    <Link className="btn small secondary" href={link(pageNumber - 1)}>
                      Newer
                    </Link>
                  )}
                  {hasMore && (
                    <Link className="btn small secondary" href={link(pageNumber + 1)}>
                      Older
                    </Link>
                  )}
                </span>
              )
            }
            flush
          >
            {events ? (
              <>
                <form className="row" method="get" style={{ padding: '0 16px 12px' }}>
                  <label className="small muted" htmlFor="signal-status">
                    Outcome
                  </label>
                  <select
                    id="signal-status"
                    className="select"
                    name="status"
                    defaultValue={status ?? ''}
                    style={{ width: 'auto' }}
                  >
                    <option value="">any</option>
                    {signalStatuses.map((candidate) => (
                      <option key={candidate} value={candidate}>
                        {candidate}
                      </option>
                    ))}
                  </select>
                  <label className="small muted" htmlFor="signal-type">
                    Event
                  </label>
                  <select
                    id="signal-type"
                    className="select"
                    name="eventType"
                    defaultValue={eventType ?? ''}
                    style={{ width: 'auto' }}
                  >
                    <option value="">any</option>
                    {eventTypes.map((candidate) => (
                      <option key={candidate} value={candidate}>
                        {eventTypeLabels[candidate]}
                      </option>
                    ))}
                  </select>
                  {sources.length > 0 && (
                    <>
                      <label className="small muted" htmlFor="signal-source">
                        Source
                      </label>
                      <select
                        id="signal-source"
                        className="select"
                        name="sourceId"
                        defaultValue={sourceId ?? ''}
                        style={{ width: 'auto' }}
                      >
                        <option value="">any</option>
                        {sources.map((source) => (
                          <option key={source.id} value={source.id}>
                            {source.name}
                          </option>
                        ))}
                      </select>
                    </>
                  )}
                  {identityId && <input type="hidden" name="identityId" value={identityId} />}
                  <button className="btn secondary">Filter</button>
                </form>
                <SignalEventsTable
                  events={events.events}
                  base={base}
                  tenantId={tenantId}
                  sourceNames={sourceNames}
                  people={people}
                  mayReprocess={mayReprocess}
                  empty={filtered ? 'No events match.' : 'No events received yet.'}
                />
              </>
            ) : (
              <div className="empty">
                Requires <code>iam:signals:read</code> on <code>iam/signals/events</code>.
              </div>
            )}
          </Card>
          {mayManage && (
            <div id="add-source">
              <Card
                title="Add a source"
                description="Register a transmitter such as Okta, Microsoft Entra, Google, or another Better IAM deployment. Requires iam:signals:manage and a recent sign-in; nothing is fetched until the first event arrives. At most 20 sources, one per issuer."
              >
                <CreateSourceForm
                  tenantId={tenantId}
                  base={base}
                  scimConnections={scimConnections?.map((connection) => ({
                    id: connection.id,
                    name: connection.name,
                    revoked: connection.revoked,
                  }))}
                  verifiedDomains={domains
                    ?.filter((domain) => domain.status === 'verified')
                    .map((domain) => domain.domain)}
                />
              </Card>
            </div>
          )}
        </div>
      )}
    </>
  );
}
