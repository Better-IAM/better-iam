import Link from 'next/link';
import { ApiButton } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const kindLabels: Record<string, string> = {
  'redundant-binding': 'Redundant',
  'group-binding': 'Bind to group',
  'duplicate-roles': 'Duplicate roles',
  bundle: 'Bundle',
};

export default async function RoleMining({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ minIdentities?: string; peerBy?: string; unusedDays?: string }>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const minIdentities = Math.max(2, Number(query.minIdentities) || 3);
  const peerBy = query.peerBy?.trim() || 'manager';
  const mining = await tryRead(() => iam.api.roleMining.suggest(auth, { tenantId, minIdentities }));
  const peers = await tryRead(() => iam.api.roleMining.outliers(auth, { tenantId, peerBy }));
  const unusedDays = Math.min(3650, Math.max(1, Number(query.unusedDays) || 90));
  const sizing = await tryRead(() => iam.api.roleMining.rightSize(auth, { tenantId, unusedDays }));
  const refs = (items: { id: string; name: string }[], path: string, max = 6) => (
    <span className="small">
      {items.slice(0, max).map((item, index) => (
        <span key={item.id}>
          {index > 0 && ', '}
          <Link href={`${base}/${path}/${item.id}`}>{item.name}</Link>
        </span>
      ))}
      {items.length > max && ` and ${items.length - max} more`}
    </span>
  );
  return (
    <>
      <PageHeader
        title="Role mining"
        description="Suggestions derived from who holds which roles today: combinations to bundle into access packages, roles to grant through a group instead of one by one, direct bindings a group already covers, and roles that duplicate each other. Peer outliers show access few colleagues share."
      />
      {!mining ? (
        <Alert tone="warning">
          Requires <code>iam:analysis:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="grid cols-4">
            <Stat label="Redundant bindings" value={mining.summary['redundant-binding']} />
            <Stat label="Bind to group" value={mining.summary['group-binding']} />
            <Stat label="Duplicate roles" value={mining.summary['duplicate-roles']} />
            <Stat label="Role bundles" value={mining.summary.bundle} />
          </div>
          <Card
            title="Suggestions"
            description={
              <>
                Generated <Time value={mining.generatedAt} />. A pattern must be shared by at least{' '}
                {minIdentities} people.
              </>
            }
            flush
          >
            <form className="row" method="get" style={{ padding: '0 16px 12px' }}>
              <label className="small muted" htmlFor="minIdentities">
                Minimum people
              </label>
              <input
                id="minIdentities"
                className="input"
                name="minIdentities"
                type="number"
                min={2}
                max={10000}
                defaultValue={minIdentities}
                style={{ width: 100 }}
              />
              <input type="hidden" name="peerBy" value={peerBy} />
              <input type="hidden" name="unusedDays" value={unusedDays} />
              <button className="btn secondary">Rescan</button>
            </form>
            <Table
              head={['Kind', 'Suggestion', 'Roles', 'People', 'Saves', '']}
              rows={mining.suggestions.map((suggestion) => [
                <Badge key="k" tone={suggestion.applicable ? 'success' : 'neutral'}>
                  {kindLabels[suggestion.kind] ?? suggestion.kind}
                </Badge>,
                <span key="s" className="stack">
                  <strong>{suggestion.title}</strong>
                  <span className="small muted">{suggestion.detail}</span>
                  {suggestion.group && (
                    <span className="small">
                      Group:{' '}
                      <Link href={`${base}/groups/${suggestion.group.id}`}>
                        {suggestion.group.name}
                      </Link>
                    </span>
                  )}
                </span>,
                refs(suggestion.roles, 'roles'),
                suggestion.identities.length ? (
                  refs(suggestion.identities, 'members', 4)
                ) : (
                  <span key="p" className="muted small">
                    —
                  </span>
                ),
                suggestion.savings,
                suggestion.applicable ? (
                  <ApiButton
                    key="a"
                    path="roleMining/apply"
                    body={{ tenantId, suggestionId: suggestion.id, minIdentities }}
                    label="Apply"
                    confirm={
                      suggestion.kind === 'group-binding'
                        ? `Bind the role to ${suggestion.group?.name} and remove ${suggestion.bindingIds?.length} direct binding(s)?`
                        : `Remove ${suggestion.bindingIds?.length} redundant direct binding(s)?`
                    }
                    tenantId={tenantId}
                  />
                ) : suggestion.kind === 'bundle' ? (
                  <ApiButton
                    key="a"
                    path="packages/create"
                    body={{
                      tenantId,
                      name: suggestion.roles
                        .map((role) => role.name)
                        .join(' + ')
                        .slice(0, 100),
                      description: 'Created from a role-mining bundle suggestion.',
                      roleIds: suggestion.roles.map((role) => role.id),
                      groupIds: [],
                    }}
                    label="Create package"
                    redirectTo={`${base}/packages`}
                    tenantId={tenantId}
                  />
                ) : (
                  <span key="a" />
                ),
              ])}
              empty="Nothing to simplify with these thresholds."
            />
          </Card>
          <Card
            title="Peer outliers"
            description="Roles a person holds that fewer than a quarter of their peers hold (unusual), and roles most peers hold that they lack (missing). Just-in-time bindings count as held."
            flush
          >
            <form className="row" method="get" style={{ padding: '0 16px 12px' }}>
              <label className="small muted" htmlFor="peerBy">
                Peers share
              </label>
              <input
                id="peerBy"
                className="input"
                name="peerBy"
                defaultValue={peerBy}
                placeholder="manager or attribute:department"
                style={{ width: 240 }}
              />
              <input type="hidden" name="minIdentities" value={minIdentities} />
              <input type="hidden" name="unusedDays" value={unusedDays} />
              <button className="btn secondary">Compare</button>
            </form>
            {!peers ? (
              <div style={{ padding: '0 16px 16px' }}>
                <Alert tone="warning">
                  Peers can be grouped by <code>manager</code> or by a declared identity attribute
                  as <code>attribute:NAME</code>.
                </Alert>
              </div>
            ) : (
              <Table
                head={['Person', 'Peers', 'Unusual access', 'Missing access']}
                rows={peers.outliers.map((outlier) => [
                  <Link key="i" href={`${base}/members/${outlier.identity.id}`}>
                    {outlier.identity.name}
                  </Link>,
                  <span key="p" className="small">
                    {outlier.peers} sharing <code>{outlier.peerValue}</code>
                  </span>,
                  <span key="u" className="stack small">
                    {outlier.unusualRoles.map((entry) => (
                      <span key={entry.role.id}>
                        <Link href={`${base}/roles/${entry.role.id}`}>{entry.role.name}</Link>{' '}
                        <span className="muted">
                          ({entry.peersHolding} of {outlier.peers} peers)
                        </span>
                      </span>
                    ))}
                  </span>,
                  <span key="m" className="stack small">
                    {outlier.missingRoles.map((entry) => (
                      <span key={entry.role.id}>
                        <Link href={`${base}/roles/${entry.role.id}`}>{entry.role.name}</Link>{' '}
                        <span className="muted">
                          ({entry.peersHolding} of {outlier.peers} peers)
                        </span>
                      </span>
                    ))}
                  </span>,
                ])}
                empty={`No outliers among ${peers.identitiesCompared} people compared.`}
              />
            )}
          </Card>
          {sizing && (
            <Card
              title="Least privilege"
              description={
                !sizing.tracking ? (
                  'Access usage tracking is off (the accessUsage option), so nothing has been recorded.'
                ) : (
                  <>
                    Role grants compared with the actions each holder was actually allowed to use in
                    the last {sizing.unusedDays} days.{' '}
                    {sizing.trackingSince === undefined ? (
                      'No usage recorded yet.'
                    ) : sizing.complete ? (
                      <>
                        Usage recorded since <Time value={sizing.trackingSince} />.
                      </>
                    ) : (
                      <>
                        Usage recorded only since <Time value={sizing.trackingSince} />, so
                        &quot;unused&quot; is not conclusive yet.
                      </>
                    )}
                  </>
                )
              }
              flush
            >
              <form className="row" method="get" style={{ padding: '0 16px 12px' }}>
                <label className="small muted" htmlFor="unusedDays">
                  Window (days)
                </label>
                <input
                  id="unusedDays"
                  className="input"
                  name="unusedDays"
                  type="number"
                  min={1}
                  max={3650}
                  defaultValue={unusedDays}
                  style={{ width: 100 }}
                />
                <input type="hidden" name="minIdentities" value={minIdentities} />
                <input type="hidden" name="peerBy" value={peerBy} />
                <button className="btn secondary">Recompute</button>
              </form>
              <Table
                head={['Person', 'Role', 'Status', 'Used', 'Never used', '']}
                rows={sizing.entries.slice(0, 200).map((entry) => [
                  <Link key="i" href={`${base}/members/${entry.identity.id}`}>
                    {entry.identity.name}
                  </Link>,
                  <span key="r" className="stack small">
                    <Link href={`${base}/roles/${entry.role.id}`}>{entry.role.name}</Link>
                    <span className="muted">
                      {entry.via.type === 'group' ? `via ${entry.via.name}` : 'direct'}
                      {entry.eligible && ', eligible'}
                    </span>
                  </span>,
                  <Badge key="s" tone={entry.status === 'unused' ? 'warning' : 'neutral'}>
                    {entry.status}
                  </Badge>,
                  <span key="u" className="small">
                    {entry.usedActions.length} of {entry.grantedActions}
                    {entry.lastUsedAt !== undefined && (
                      <>
                        {' '}
                        (last <Time value={entry.lastUsedAt} />)
                      </>
                    )}
                  </span>,
                  <span key="n" className="small">
                    {entry.unusedActions.slice(0, 5).map((action) => (
                      <code key={action} style={{ marginRight: 4 }}>
                        {action}
                      </code>
                    ))}
                    {entry.unusedCount > 5 && ` and ${entry.unusedCount - 5} more`}
                  </span>,
                  entry.status === 'unused' && entry.via.type === 'identity' ? (
                    <ApiButton
                      key="a"
                      path="bindings/delete"
                      body={{ tenantId, bindingId: entry.bindingId }}
                      label="Remove"
                      confirm={`Remove ${entry.role.name} from ${entry.identity.name}?`}
                      tenantId={tenantId}
                    />
                  ) : (
                    <span key="a" />
                  ),
                ])}
                empty="Every holder used every action their roles grant."
              />
            </Card>
          )}
        </div>
      )}
    </>
  );
}
