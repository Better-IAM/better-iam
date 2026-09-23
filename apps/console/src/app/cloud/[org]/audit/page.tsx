import Link from 'next/link';
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
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

interface Query {
  action?: string;
  actor?: string;
  resource?: string;
  outcome?: string;
  from?: string;
  to?: string;
  page?: string;
}

const PAGE_SIZE = 100;

/** A `datetime-local` value is wall-clock time in the browser's zone; the server treats it as such. */
function parseTime(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : parsed;
}

export default async function Audit({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<Query>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const page = Math.max(1, Number.parseInt(query.page ?? '1', 10) || 1);
  const outcome: 'allow' | 'deny' | undefined =
    query.outcome === 'allow' || query.outcome === 'deny' ? query.outcome : undefined;
  const filters = {
    action: query.action?.trim() || undefined,
    actorId: query.actor?.trim() || undefined,
    resourceId: query.resource?.trim() || undefined,
    outcome,
    from: parseTime(query.from),
    to: parseTime(query.to),
  };
  const filtering = Object.values(filters).some((value) => value !== undefined);
  const [events, chain, members] = await Promise.all([
    tryRead(() =>
      iam.api.audit.list(auth, {
        tenantId,
        ...filters,
        limit: PAGE_SIZE + 1,
        offset: (page - 1) * PAGE_SIZE,
      }),
    ),
    tryRead(() => iam.api.audit.verify(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, includeDeleted: true })),
  ]);
  const hasMore = (events?.length ?? 0) > PAGE_SIZE;
  const visible = events?.slice(0, PAGE_SIZE) ?? [];
  const nameOf = (identityId: string) =>
    members?.find((identity) => identity.id === identityId)?.name;
  const pageLink = (target: number) => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query))
      if (value && key !== 'page') params.set(key, value);
    if (target > 1) params.set('page', String(target));
    const encoded = params.toString();
    return `${base}/audit${encoded ? `?${encoded}` : ''}`;
  };
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Authentication events, administrative changes, denials, and any platform root override that touched this organization. Events form a hash chain, so alteration or removal is detectable."
        actions={
          events && (
            <a
              className="btn small secondary"
              href={`/api/console/audit-export?org=${encodeURIComponent(org)}`}
            >
              Export chain (JSONL)
            </a>
          )
        }
      />
      <div className="stack">
        {chain && (
          <Card
            title="Chain integrity"
            description="Recomputed from every stored event on this page load."
          >
            <div className="grid cols-2">
              <KeyValues
                items={[
                  [
                    'Status',
                    chain.valid ? (
                      <Badge key="v" tone="success">
                        intact
                      </Badge>
                    ) : (
                      <Badge key="v" tone="danger">
                        broken
                      </Badge>
                    ),
                  ],
                  ['Events checked', String(chain.checked)],
                  ['Head sequence', chain.head ? String(chain.head.sequence) : '—'],
                  [
                    'Head hash',
                    chain.head ? (
                      <code key="h" className="small truncate">
                        {chain.head.hash}
                      </code>
                    ) : (
                      '—'
                    ),
                  ],
                ]}
              />
              {chain.failure ? (
                <Alert tone="danger">
                  Verification failed at sequence {chain.failure.sequence} (event{' '}
                  <code>{chain.failure.id}</code>): {chain.failure.reason}. Compare against your
                  exported archive.
                </Alert>
              ) : (
                <div className="stack">
                  <Alert tone="info">
                    Export the chain regularly and keep the archive elsewhere. An export holds every
                    event through the head at the moment you download it, so its last line carries
                    the head hash above unless events arrived since this page loaded.
                  </Alert>
                  {events && (
                    <form method="get" action="/api/console/audit-export" className="row">
                      <input type="hidden" name="org" value={org} />
                      <input
                        className="input"
                        type="number"
                        name="from"
                        min={1}
                        placeholder="from sequence"
                        aria-label="Export from sequence"
                        style={{ maxWidth: 180 }}
                      />
                      <button className="btn small secondary">Export from sequence</button>
                    </form>
                  )}
                </div>
              )}
            </div>
          </Card>
        )}
        <Card
          title="Search"
          description="Action accepts a glob such as iam:identities:* or auth:*; actor and resource match IDs exactly."
        >
          <form method="get" className="form">
            <div className="grid cols-3">
              <div className="field">
                <label htmlFor="action">Action</label>
                <input
                  id="action"
                  className="input"
                  name="action"
                  defaultValue={query.action ?? ''}
                  placeholder="iam:bindings:*"
                />
              </div>
              <div className="field">
                <label htmlFor="actor">Actor</label>
                <select id="actor" className="select" name="actor" defaultValue={query.actor ?? ''}>
                  <option value="">anyone</option>
                  {(members ?? []).map((identity) => (
                    <option key={identity.id} value={identity.id}>
                      {identity.name}
                      {identity.kind === 'service' ? ' (service account)' : ''}
                      {identity.status === 'deleted' ? ' (deleted)' : ''}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="outcome">Outcome</label>
                <select id="outcome" className="select" name="outcome" defaultValue={outcome ?? ''}>
                  <option value="">any</option>
                  <option value="allow">allowed</option>
                  <option value="deny">denied</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="resource">Resource ID</label>
                <input
                  id="resource"
                  className="input"
                  name="resource"
                  defaultValue={query.resource ?? ''}
                  placeholder="usr_… or a tenant ID"
                />
              </div>
              <div className="field">
                <label htmlFor="from">From</label>
                <input
                  id="from"
                  className="input"
                  type="datetime-local"
                  name="from"
                  defaultValue={query.from ?? ''}
                />
              </div>
              <div className="field">
                <label htmlFor="to">To</label>
                <input
                  id="to"
                  className="input"
                  type="datetime-local"
                  name="to"
                  defaultValue={query.to ?? ''}
                />
              </div>
            </div>
            <div className="form-actions row">
              <button className="btn">Search</button>
              {filtering && (
                <Link className="btn secondary" href={`${base}/audit`}>
                  Clear
                </Link>
              )}
            </div>
          </form>
        </Card>
        <Card
          title={
            events
              ? `${filtering ? 'Matching' : 'Recent'} events · page ${page}${hasMore ? '' : ' (last)'}`
              : 'Audit log'
          }
          flush
          actions={
            events && (
              <span className="row">
                {page > 1 && (
                  <Link className="btn small secondary" href={pageLink(page - 1)}>
                    Newer
                  </Link>
                )}
                {hasMore && (
                  <Link className="btn small secondary" href={pageLink(page + 1)}>
                    Older
                  </Link>
                )}
              </span>
            )
          }
        >
          {events ? (
            <Table
              head={[
                '#',
                'When',
                'Actor',
                'Action',
                'Resource',
                'Outcome',
                'Root override',
                'Metadata',
              ]}
              rows={[...visible]
                .sort((a, b) => b.timestamp - a.timestamp)
                .map((event) => [
                  <code key="s" className="small">
                    {event.sequence ?? '—'}
                  </code>,
                  <Time key="w" value={event.timestamp} />,
                  <span key="a" title={event.actorId}>
                    {nameOf(event.actorId) ?? <code className="small">{event.actorId}</code>}
                    {event.impersonatorId && (
                      <>
                        {' '}
                        <Badge tone="warning">
                          via {nameOf(event.impersonatorId) ?? event.impersonatorId}
                        </Badge>
                      </>
                    )}
                  </span>,
                  <code key="c">{event.action}</code>,
                  <code key="r" className="small truncate">
                    {event.resourceId}
                  </code>,
                  <StatusBadge
                    key="o"
                    status={event.outcome === 'allow' ? 'active' : 'disabled'}
                  />,
                  event.rootOverride ? (
                    <Badge key="ro" tone="danger">
                      platform
                    </Badge>
                  ) : (
                    ''
                  ),
                  event.metadata ? (
                    <code key="m" className="small">
                      {JSON.stringify(event.metadata)}
                    </code>
                  ) : (
                    ''
                  ),
                ])}
              empty={filtering ? 'No events match.' : 'No events yet.'}
            />
          ) : (
            <div className="empty">
              Requires <code>iam:audit:read</code>.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
