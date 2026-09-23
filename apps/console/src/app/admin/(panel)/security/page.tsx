import Link from 'next/link';
import type { AuditEvent, Identity, SignInRecord, Tenant } from 'better-iam';
import { ipMatches } from 'better-iam/core';
import { ApiButton } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { auditWindow, platformBlockFor, recordsById } from '@/lib/admin-views';
import { describeUserAgent } from '@/lib/device';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession, rootTenant } from '@/lib/session';

interface Query {
  hours?: string;
  tenant?: string;
  q?: string;
}

const WINDOWS = [
  { hours: 1, label: 'last hour' },
  { hours: 24, label: 'last 24 hours' },
  { hours: 168, label: 'last 7 days' },
];
const FAILURE = 'auth:signin:fail';
const SIGN_IN = 'auth:session:create';
const TOP = 20;
const RECENT = 100;
const REASONS: Record<string, string> = {
  password: 'password',
  mfa: 'authenticator / emailed code',
  'recovery-code': 'recovery code',
};

/** The per-person sign-in record as stored (`authSignIns`, keyed by identity ID). */
interface Ledger extends SignInRecord {
  id: string;
  tenantId: string;
  [key: string]: unknown;
}

const text = (event: AuditEvent, key: string): string | undefined => {
  const value = event.metadata?.[key];
  return typeof value === 'string' ? value : undefined;
};

/**
 * Platform-wide view of failed sign-in attempts (`auth:signin:fail` events) for spotting credential stuffing and
 * password spraying: by source address, by targeted account, and the latest attempts. Read straight from storage
 * for root; the unlock goes through `identities.unlock` under root's override and recent authentication.
 */
export default async function Security({ searchParams }: { searchParams: Promise<Query> }) {
  const admin = await requireRootSession();
  const query = await searchParams;
  const hours = WINDOWS.some((window) => window.hours === Number(query.hours))
    ? Number(query.hours)
    : 24;
  const iam = await getIam();
  const now = Date.now();
  const since = now - hours * 3_600_000;
  const needle = query.q?.trim().toLowerCase() ?? '';
  // One audit read for both actions, narrowed to the chosen organization in SQL, instead of two scans of the
  // whole platform's audit plus every identity.
  const [tenants, events, root] = await Promise.all([
    iam.store.find<Tenant>('tenants'),
    auditWindow(iam.store, {
      actions: [FAILURE, SIGN_IN],
      since,
      tenantId: query.tenant || undefined,
    }),
    rootTenant(),
  ]);
  const failures = events.get(FAILURE) ?? [];
  const signIns = events.get(SIGN_IN) ?? [];
  const blocks = root
    ? await iam.api.security.listBlocks(await credential(), { tenantId: root.id })
    : [];
  // Only platform blocks stop an address everywhere; root-organization blocks are listed but do not count here.
  const blockedBy = (ip: string) => platformBlockFor(blocks, ip, ipMatches);
  const tenantById = new Map(tenants.map((tenant) => [tenant.id, tenant]));
  // People are read by ID: everyone the window names only when searching by name, otherwise just the rows shown.
  const searched = needle
    ? await recordsById<Identity>(iam.store, 'identities', [
        ...failures.map((event) => event.actorId),
        ...signIns.map((event) => event.actorId),
      ])
    : new Map<string, Identity>();
  // Root administrators always sign in to the root tenant; step-up MFA must be verified there, not in the
  // organization whose member an action targets.
  const stepUpTenantId = admin.session.tenantId;
  const recordsAddresses = Boolean(admin.session.client?.ip);
  const inScope = (event: AuditEvent) => {
    if (!needle) return true;
    const identity = searched.get(event.actorId);
    return (
      identity?.name.toLowerCase().includes(needle) ||
      identity?.email?.toLowerCase().includes(needle) ||
      text(event, 'ip')?.includes(needle) ||
      false
    );
  };
  const attempts = failures.filter(inScope).sort((a, b) => b.timestamp - a.timestamp);
  const successes = signIns.filter(inScope).length;

  interface Source {
    ip: string;
    count: number;
    accounts: Set<string>;
    tenants: Set<string>;
    lastAt: number;
    userAgent?: string;
  }
  const sources = new Map<string, Source>();
  interface Target {
    identityId: string;
    tenantId: string;
    count: number;
    ips: Set<string>;
    lastAt: number;
    lastReason?: string;
  }
  const targets = new Map<string, Target>();
  for (const event of attempts) {
    const ip = text(event, 'ip') ?? '(no recorded IP)';
    const source = sources.get(ip) ?? {
      ip,
      count: 0,
      accounts: new Set<string>(),
      tenants: new Set<string>(),
      lastAt: 0,
    };
    source.count++;
    source.accounts.add(event.actorId);
    source.tenants.add(event.tenantId);
    if (event.timestamp >= source.lastAt) {
      source.lastAt = event.timestamp;
      source.userAgent = text(event, 'userAgent');
    }
    sources.set(ip, source);
    const target = targets.get(event.actorId) ?? {
      identityId: event.actorId,
      tenantId: event.tenantId,
      count: 0,
      ips: new Set<string>(),
      lastAt: 0,
    };
    target.count++;
    if (text(event, 'ip')) target.ips.add(text(event, 'ip')!);
    if (event.timestamp >= target.lastAt) {
      target.lastAt = event.timestamp;
      target.lastReason = text(event, 'reason');
    }
    targets.set(event.actorId, target);
  }
  const topSources = [...sources.values()]
    .sort((a, b) => b.count - a.count || b.lastAt - a.lastAt)
    .slice(0, TOP);
  const topTargets = [...targets.values()]
    .sort((a, b) => b.count - a.count || b.lastAt - a.lastAt)
    .slice(0, TOP);
  // The current streak (failures since the person's last sign-in) comes from their sign-in record.
  const streaks = new Map(
    await Promise.all(
      topTargets.map(async (target) => {
        const ledger = await iam.store.get<Ledger>('authSignIns', target.identityId);
        return [target.identityId, ledger] as const;
      }),
    ),
  );
  const identityById = new Map([
    ...searched,
    ...(await recordsById<Identity>(iam.store, 'identities', [
      ...topTargets.map((target) => target.identityId),
      ...attempts.slice(0, RECENT).map((event) => event.actorId),
      ...blocks.map((block) => block.createdBy),
    ])),
  ]);
  const filtered = Boolean(query.tenant || needle || hours !== 24);

  return (
    <>
      <PageHeader
        title="Sign-in failures"
        description="Wrong passwords, factors, and recovery codes presented for real accounts, across every organization. Many accounts from one address is credential stuffing; many attempts on one account is a targeted guess. Unlocking clears a person's rate-limit counters and needs your recent authentication."
      />
      <div className="stack">
        <Card title="Window and filter">
          <form method="get" className="form">
            <div className="grid cols-3">
              <div className="field">
                <label htmlFor="hours">Window</label>
                <select id="hours" className="select" name="hours" defaultValue={String(hours)}>
                  {WINDOWS.map((window) => (
                    <option key={window.hours} value={window.hours}>
                      {window.label}
                    </option>
                  ))}
                </select>
              </div>
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
                <label htmlFor="q">Name, email, or IP</label>
                <input id="q" className="input" name="q" defaultValue={query.q ?? ''} />
              </div>
            </div>
            <div className="form-actions row">
              <button className="btn">Apply</button>
              {filtered && (
                <Link className="btn secondary" href="/admin/security">
                  Clear
                </Link>
              )}
            </div>
          </form>
        </Card>
        <div className="grid cols-4">
          <Stat
            label="Failed attempts"
            value={attempts.length}
            hint={`in the ${WINDOWS.find((window) => window.hours === hours)?.label}`}
          />
          <Stat label="Source addresses" value={sources.size} hint="distinct recorded IPs" />
          <Stat label="Targeted accounts" value={targets.size} hint="real, active accounts named" />
          <Stat
            label="Successful sign-ins"
            value={successes}
            hint={
              attempts.length > 0
                ? `${Math.round((attempts.length / Math.max(1, attempts.length + successes)) * 100)}% of attempts failed`
                : 'no failures in this window'
            }
          />
        </div>
        <div className="grid cols-2">
          <Card
            title="By source address"
            description="Addresses are recorded only when the deployment derives them (http.clientInfo; the console's TRUSTED_PROXY_HOPS). Consider rateLimits.ipAttempts when one address names many accounts."
            flush
          >
            {!recordsAddresses && (
              <Alert tone="warning">
                This deployment does not record client addresses (your own session has none):
                failures are grouped under “(no recorded IP)”, and network blocks and allowed
                networks are not enforced. Run the console behind a reverse proxy you control and
                set <code>TRUSTED_PROXY_HOPS</code>.
              </Alert>
            )}
            <Table
              head={['Address', 'Attempts', 'Accounts', 'Orgs', 'Latest', 'User agent', '']}
              rows={topSources.map((source) => [
                <code key="i" className="small">
                  {source.ip}
                </code>,
                <Badge key="c" tone={source.accounts.size > 2 ? 'danger' : 'warning'}>
                  {source.count}
                </Badge>,
                source.accounts.size,
                source.tenants.size,
                <Time key="l" value={source.lastAt} />,
                <span key="u" className="small muted" title={source.userAgent}>
                  {describeUserAgent(source.userAgent) ?? '—'}
                </span>,
                root && source.ip !== '(no recorded IP)' ? (
                  blockedBy(source.ip) ? (
                    <Badge key="b" tone="danger">
                      blocked
                    </Badge>
                  ) : (
                    <ApiButton
                      key="b"
                      path="security/blockNetwork"
                      body={{
                        tenantId: root.id,
                        network: source.ip,
                        reason: `Sign-in failures page: ${source.count} attempts on ${source.accounts.size} account${source.accounts.size === 1 ? '' : 's'}`,
                        durationMs: 86_400_000,
                        platform: true,
                      }}
                      label="Block for a day"
                      tone="danger"
                      confirm={`Refuse every sign-in and session from ${source.ip} across the platform for 24 hours?`}
                      tenantId={root.id}
                    />
                  )
                ) : (
                  ''
                ),
              ])}
              empty="No failed attempts in this window."
            />
          </Card>
          <Card
            title="By targeted account"
            description="The streak is the number of failures since the person's last successful sign-in; they see it on their next sign-in."
            flush
          >
            <Table
              head={['Account', 'Organization', 'Attempts', 'Addresses', 'Streak', 'Latest', '']}
              rows={topTargets.map((target) => {
                const identity = identityById.get(target.identityId);
                const tenant = tenantById.get(target.tenantId);
                const ledger = streaks.get(target.identityId);
                return [
                  <span key="w">
                    {identity ? (
                      <>
                        {identity.name}
                        {identity.email && <span className="small muted"> · {identity.email}</span>}
                      </>
                    ) : (
                      <code className="small">{target.identityId}</code>
                    )}
                  </span>,
                  tenant ? (
                    <Link key="t" href={`/admin/organizations/${tenant.id}`}>
                      {tenant.name}
                    </Link>
                  ) : (
                    <code key="t" className="small">
                      {target.tenantId}
                    </code>
                  ),
                  <Badge key="c" tone={target.count >= 5 ? 'danger' : 'warning'}>
                    {target.count}
                  </Badge>,
                  target.ips.size,
                  ledger && ledger.failedAttempts > 0 ? (
                    <span key="s" title={REASONS[target.lastReason ?? ''] ?? target.lastReason}>
                      {ledger.failedAttempts}
                      {ledger.lastAt === undefined && (
                        <span className="small muted"> (no sign-in on record)</span>
                      )}
                    </span>
                  ) : (
                    <span key="s" className="muted">
                      ended
                    </span>
                  ),
                  <Time key="l" value={target.lastAt} />,
                  identity && identity.status === 'active' ? (
                    <ApiButton
                      key="u"
                      path="identities/unlock"
                      body={{ tenantId: target.tenantId, identityId: target.identityId }}
                      label="Unlock"
                      confirm={`Clear the sign-in rate limits of ${identity.name}? Their counters restart; the network's do not.`}
                      tenantId={stepUpTenantId}
                    />
                  ) : (
                    ''
                  ),
                ];
              })}
              empty="No failed attempts in this window."
            />
          </Card>
        </div>
        {root && (
          <Card
            title="Blocked networks"
            description="Platform-wide blocks refuse every sign-in flow and live session from these networks with IP_BLOCKED in every organization; root-organization blocks apply to the root organization only. Lifting a block needs your recent authentication."
            flush
          >
            <Table
              head={['Network', 'Scope', 'Reason', 'By', 'Since', 'Until', 'Status', '']}
              rows={blocks.map((block) => [
                <code key="n" className="small">
                  {block.network}
                </code>,
                block.platform ? (
                  <Badge key="p" tone="accent">
                    platform-wide
                  </Badge>
                ) : (
                  <span key="p" className="small muted">
                    root organization only
                  </span>
                ),
                block.reason,
                identityById.get(block.createdBy)?.name ?? (
                  <code key="c" className="small">
                    {block.createdBy}
                  </code>
                ),
                <Time key="s" value={block.createdAt} />,
                block.expiresAt ? (
                  <Time key="u" value={block.expiresAt} />
                ) : (
                  <span key="u" className="muted">
                    until lifted
                  </span>
                ),
                <Badge key="st" tone={block.active ? 'danger' : 'neutral'}>
                  {block.active ? 'active' : 'lapsed'}
                </Badge>,
                <ApiButton
                  key="x"
                  path="security/unblockNetwork"
                  body={{ tenantId: root.id, blockId: block.id }}
                  label={block.active ? 'Lift' : 'Remove'}
                  tenantId={root.id}
                />,
              ])}
              empty="No networks are blocked."
            />
          </Card>
        )}
        <Card
          title={`Latest attempts${attempts.length > RECENT ? ` (${RECENT} of ${attempts.length})` : ''}`}
          flush
        >
          <Table
            head={['When', 'Account', 'Organization', 'Presented', 'Address', 'User agent']}
            rows={attempts.slice(0, RECENT).map((event) => {
              const identity = identityById.get(event.actorId);
              const tenant = tenantById.get(event.tenantId);
              const reason = text(event, 'reason');
              return [
                <Time key="w" value={event.timestamp} />,
                identity ? (
                  <span key="a">
                    {identity.name}
                    {identity.email && <span className="small muted"> · {identity.email}</span>}
                  </span>
                ) : (
                  <code key="a" className="small">
                    {event.actorId}
                  </code>
                ),
                tenant?.name ?? (
                  <code key="t" className="small">
                    {event.tenantId}
                  </code>
                ),
                reason ? `wrong ${REASONS[reason] ?? reason}` : '—',
                <code key="i" className="small">
                  {text(event, 'ip') ?? '—'}
                </code>,
                <span key="u" className="small muted" title={text(event, 'userAgent')}>
                  {describeUserAgent(text(event, 'userAgent')) ?? '—'}
                </span>,
              ];
            })}
            empty="No failed attempts in this window."
          />
        </Card>
      </div>
    </>
  );
}
