import Link from 'next/link';
import type { Identity, Session, Tenant } from 'better-iam';
import { ApiButton } from '@/components/api-form';
import { Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { pageOf, recordsById } from '@/lib/admin-views';
import { clientLine } from '@/lib/device';
import { getIam } from '@/lib/iam';
import { requireRootSession } from '@/lib/session';

interface Query {
  tenant?: string;
  q?: string;
  kind?: string;
  page?: string;
}

const PAGE_SIZE = 200;

/** Platform-wide view of live sessions for incident response; root's override authorizes the sign-outs. */
export default async function Sessions({ searchParams }: { searchParams: Promise<Query> }) {
  const admin = await requireRootSession();
  const query = await searchParams;
  const iam = await getIam();
  const now = Date.now();
  const needle = query.q?.trim().toLowerCase() ?? '';
  const kind =
    query.kind === 'user' ||
    query.kind === 'api-key' ||
    query.kind === 'role' ||
    query.kind === 'session-token'
      ? query.kind
      : undefined;
  // The organization filter is pushed down to storage, so a filtered view reads that organization's sessions only.
  const filter: Record<string, string> = {};
  if (query.tenant) filter.tenantId = query.tenant;
  if (kind) filter.kind = kind;
  const [tenants, sessions] = await Promise.all([
    iam.store.find<Tenant>('tenants'),
    iam.store.find<Session>('sessions', filter),
  ]);
  const unexpired = sessions.filter((session) => session.expiresAt > now);
  const tenantById = new Map(tenants.map((tenant) => [tenant.id, tenant]));
  // People are read for the sessions searched or shown, never the whole identities collection.
  const searched = needle
    ? await recordsById<Identity>(
        iam.store,
        'identities',
        unexpired.map((session) => session.identityId),
      )
    : new Map<string, Identity>();
  const live = unexpired
    .filter((session) => {
      if (!needle) return true;
      const identity = searched.get(session.identityId);
      return (
        identity?.name.toLowerCase().includes(needle) ||
        identity?.email?.toLowerCase().includes(needle) ||
        session.client?.ip?.includes(needle) ||
        false
      );
    })
    .sort((a, b) => b.lastSeenAt - a.lastSeenAt);
  const shown = pageOf(live, Number(query.page ?? '1'), PAGE_SIZE);
  const identityById = new Map([
    ...searched,
    ...(await recordsById<Identity>(
      iam.store,
      'identities',
      shown.rows.flatMap((session) =>
        session.impersonatorId
          ? [session.identityId, session.impersonatorId]
          : [session.identityId],
      ),
    )),
  ]);
  const pageLink = (target: number) => {
    const params = new URLSearchParams();
    if (query.tenant) params.set('tenant', query.tenant);
    if (query.q) params.set('q', query.q);
    if (kind) params.set('kind', kind);
    if (target > 1) params.set('page', String(target));
    const encoded = params.toString();
    return `/admin/sessions${encoded ? `?${encoded}` : ''}`;
  };
  const byKind = (value: Session['kind']) =>
    live.filter((session) => session.kind === value).length;
  return (
    <>
      <PageHeader
        title="Live sessions"
        description="Every unexpired session on the platform: people, API keys, assumed roles (including web-identity sessions), and session tokens. Signing a person out ends all of their sessions in that organization and needs your recent authentication."
      />
      <div className="stack">
        <Card title="Filter">
          <form method="get" className="form">
            <div className="grid cols-3">
              <div className="field">
                <label htmlFor="tenant">Organization</label>
                <select
                  id="tenant"
                  className="select"
                  name="tenant"
                  defaultValue={query.tenant ?? ''}
                >
                  <option value="">all</option>
                  {[...tenants]
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((tenant) => (
                      <option key={tenant.id} value={tenant.id}>
                        {tenant.name}
                        {tenant.slug ? ` (${tenant.slug})` : ''}
                      </option>
                    ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="kind">Kind</label>
                <select id="kind" className="select" name="kind" defaultValue={kind ?? ''}>
                  <option value="">any</option>
                  <option value="user">people</option>
                  <option value="api-key">API keys</option>
                  <option value="role">assumed roles</option>
                  <option value="session-token">session tokens</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="q">Name, email, or IP</label>
                <input id="q" className="input" name="q" defaultValue={query.q ?? ''} />
              </div>
            </div>
            <div className="form-actions row">
              <button className="btn">Filter</button>
              {(query.tenant || query.q || kind) && (
                <Link className="btn secondary" href="/admin/sessions">
                  Clear
                </Link>
              )}
            </div>
          </form>
        </Card>
        <Card
          title={`${live.length} live session${live.length === 1 ? '' : 's'} · ${byKind('user')} people · ${byKind('api-key')} API keys · ${byKind('role')} assumed roles · ${byKind('session-token')} session tokens`}
          description={
            shown.pages > 1
              ? `Most recently active first · page ${shown.page} of ${shown.pages} (${PAGE_SIZE} per page).`
              : undefined
          }
          actions={
            shown.pages > 1 && (
              <span className="row">
                {shown.page > 1 && (
                  <Link className="btn small secondary" href={pageLink(shown.page - 1)}>
                    More recent
                  </Link>
                )}
                {shown.page < shown.pages && (
                  <Link className="btn small secondary" href={pageLink(shown.page + 1)}>
                    Older
                  </Link>
                )}
              </span>
            )
          }
          flush
        >
          <Table
            head={['Who', 'Organization', 'Kind', 'Method', 'Client', 'Last seen', 'Expires', '']}
            rows={shown.rows.map((session) => {
              const identity = identityById.get(session.identityId);
              const tenant = tenantById.get(session.tenantId);
              return [
                <span key="w">
                  {identity ? (
                    <>
                      {identity.name}
                      {identity.email && <span className="small muted"> · {identity.email}</span>}
                    </>
                  ) : (
                    <code className="small">{session.identityId}</code>
                  )}
                  {session.impersonatorId && (
                    <>
                      {' '}
                      <Badge tone="warning">
                        via{' '}
                        {identityById.get(session.impersonatorId)?.name ?? session.impersonatorId}
                      </Badge>
                    </>
                  )}
                </span>,
                tenant ? (
                  <Link key="t" href={`/admin/organizations/${tenant.id}`}>
                    {tenant.name}
                  </Link>
                ) : (
                  <code key="t" className="small">
                    {session.tenantId}
                  </code>
                ),
                <span key="k">
                  <Badge tone={session.kind === 'user' ? 'accent' : 'neutral'}>
                    {session.kind}
                  </Badge>
                  {/* Temporary credentials: the caller-chosen name and, for web identity, the verified subject. */}
                  {session.sessionName && (
                    <span className="small muted"> · {session.sessionName}</span>
                  )}
                  {session.webIdentity && (
                    <span className="small muted" title={session.webIdentity.issuer}>
                      {' '}
                      · web identity <code className="small">{session.webIdentity.subject}</code>
                    </span>
                  )}
                </span>,
                session.method ?? (session.kind === 'user' ? '—' : ''),
                <span key="c" className="small" title={session.client?.userAgent}>
                  {clientLine(session.client) || '—'}
                </span>,
                <Time key="l" value={session.lastSeenAt} />,
                <Time key="e" value={session.expiresAt} />,
                identity && session.kind === 'user' ? (
                  <ApiButton
                    key="r"
                    path="identities/revokeSessions"
                    body={{ tenantId: session.tenantId, identityId: session.identityId }}
                    label="Sign out"
                    tone="danger"
                    confirm={`End every session of ${identity.name} in ${tenant?.name ?? 'this organization'}?`}
                    // Step-up MFA is verified in the administrator's own (root) tenant; the body names the target.
                    tenantId={admin.session.tenantId}
                  />
                ) : (
                  ''
                ),
              ];
            })}
            empty="No live sessions match."
          />
        </Card>
      </div>
    </>
  );
}
