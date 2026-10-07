import Link from 'next/link';
import { GrantClearanceForm } from '@/components/clearance-forms';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import {
  anyClearanceResource,
  attempt,
  attentionDays,
  clearanceAttention,
  clearanceFilterQuery,
  clearanceFilters,
  clearanceStatuses,
  clearanceSummary,
  compartmentName,
  effectiveStatusLabels,
  endingOptions,
  featureDisabled,
  isLive,
  levelName,
  levelOptions,
  relativeDays,
  statusLabels,
  statusTone,
  valueOf,
  type ClearanceFilterParams,
} from '@/lib/clearances';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const pageSize = 50;
/** The tiles count clearances up to this many (the API's page limit). */
const summaryLimit = 500;

export default async function Clearances({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<ClearanceFilterParams>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base, session } = context;
  const [schemeRead, mineRead, allowed] = await Promise.all([
    attempt(() => iam.api.clearances.getScheme(auth, { tenantId })),
    // The signed-in person's own clearance: no permission needed (not while impersonating).
    attempt(() => iam.api.clearances.mine(auth, { tenantId })),
    can(context, [{ action: 'iam:clearances:adjudicate', resource: anyClearanceResource }]),
  ]);
  const scheme = valueOf(schemeRead) ?? undefined;
  // Only a scheme read with iam:clearances:read names compartments; without it they show as ids.
  const definition = scheme?.definition;
  const { filters, page } = clearanceFilters(
    query,
    definition?.levels.map((level) => level.id),
  );
  const [summaryRead, listedRead, people] = await Promise.all([
    attempt(() => iam.api.clearances.list(auth, { tenantId, limit: summaryLimit })),
    attempt(() =>
      iam.api.clearances.list(auth, {
        tenantId,
        ...filters,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      }),
    ),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
  ]);
  const disabled = featureDisabled(schemeRead, mineRead, summaryRead);
  const summary = valueOf(summaryRead);
  const listed = valueOf(listedRead);
  const mine = valueOf(mineRead);
  const mayAdjudicate =
    allowed[key('iam:clearances:adjudicate', anyClearanceResource)] === true &&
    !session.session.impersonatorId;
  const now = Date.now();
  const counts = summary ? clearanceSummary(summary.clearances, now) : undefined;
  const pages = listed ? Math.max(1, Math.ceil(listed.total / pageSize)) : 1;
  const href = (target: number) => `${base}/clearances${clearanceFilterQuery(filters, target)}`;
  const filtering = Object.keys(filters).length > 0;
  // Grant candidates: active people and agents without a live clearance (the server refuses the rest).
  const cleared = new Set(
    (summary?.clearances ?? [])
      .filter((item) => isLive(item.status))
      .map((item) => item.identityId),
  );
  const candidates = (people ?? [])
    .filter(
      (person) =>
        person.status === 'active' &&
        person.id !== session.identity.id &&
        !cleared.has(person.id) &&
        (person.expiresAt === undefined || person.expiresAt > now),
    )
    .map((person) => ({
      value: person.id,
      label: `${person.name}${person.email ? ` (${person.email})` : ''}${person.kind === 'user' ? '' : ` · ${person.kind}`}`,
    }));
  return (
    <>
      <PageHeader
        title="Clearances"
        description="Personnel security clearances: the level each person is cleared to, the compartments they are read into, their adjudicated citizenship, and when they are reinvestigated. On a labeled resource every party of a session must hold a clearance that dominates the label, whatever roles and policies allow; root administrators included."
        actions={
          <Link className="btn small secondary" href={`${base}/classification`}>
            Classification
          </Link>
        }
      />
      {disabled ? (
        <Alert tone="info">
          This deployment does not enable security clearances. The operator turns them on with the{' '}
          <code>clearances</code> option.
        </Alert>
      ) : (
        <div className="stack">
          {mine?.clearance && mine.scheme && (
            <Card
              title="Your clearance"
              description={`Under the ${mine.scheme.name} scheme. A read-in whose NDA is not current does not count until you accept it again on Terms of use.`}
            >
              <div className="row" style={{ flexWrap: 'wrap' }}>
                <strong>
                  {mine.scheme.levels.find((level) => level.id === mine.clearance!.level.id)
                    ?.name ?? mine.clearance.level.id}
                </strong>
                <Badge tone={statusTone(mine.clearance.effectiveStatus)}>
                  {effectiveStatusLabels[mine.clearance.effectiveStatus]}
                </Badge>
                {mine.clearance.expiresAt && (
                  <span className="small muted">
                    ends <Time value={mine.clearance.expiresAt} />
                  </span>
                )}
                {mine.clearance.reinvestigationDue && (
                  <span className="small muted">
                    reinvestigation due <Time value={mine.clearance.reinvestigationDue} />
                  </span>
                )}
                {mine.clearance.readIns.length > 0 && (
                  <span className="small muted">
                    read into{' '}
                    {mine.clearance.readIns
                      .map(
                        (readIn) =>
                          `${compartmentName(definition, readIn.compartmentId)}${readIn.current ? '' : ' (NDA not current)'}`,
                      )
                      .join(', ')}
                  </span>
                )}
              </div>
            </Card>
          )}
          {schemeRead.ok && !scheme && (
            <Alert tone="info">
              No classification scheme applies to this organization yet, so nothing is enforced.
              Define one on <Link href={`${base}/classification`}>Classification</Link>.
            </Alert>
          )}
          {!summary || !listed ? (
            <Alert tone="warning">
              The clearance register requires <code>iam:clearances:read</code>.
            </Alert>
          ) : (
            <>
              {counts && (
                <div className="tiles">
                  <Stat
                    label="In force"
                    value={counts.inForce}
                    hint={counts.interim ? `${counts.interim} interim` : undefined}
                  />
                  <Stat
                    label="Suspended"
                    value={counts.suspended}
                    hint="Not counted until an officer reinstates them"
                  />
                  <Stat
                    label="Not counted"
                    value={counts.notCounted}
                    hint="Expired, or the account or scheme no longer lets them count"
                  />
                  <Stat
                    label="Ending"
                    value={counts.endingSoon}
                    hint={
                      counts.endingSoon ? (
                        <Link href={`${base}/clearances?ending=${attentionDays}`}>
                          within {attentionDays} days
                        </Link>
                      ) : (
                        `within ${attentionDays} days`
                      )
                    }
                  />
                  <Stat
                    label="Reinvestigations"
                    value={counts.reinvestigationDue}
                    hint={`Overdue or due within ${attentionDays} days`}
                  />
                </div>
              )}
              {summary.total > summary.clearances.length && (
                <p className="small muted">
                  The counts cover the first {summaryLimit} of {summary.total} clearances.
                </p>
              )}
              <Card
                title="Register"
                description="Every clearance held in this organization, by name. Revoked and ended clearances stay as history; a new clearance needs a new grant."
                flush
              >
                <form method="get" className="row" style={{ padding: '0 16px 12px' }}>
                  <select
                    className="select"
                    name="status"
                    defaultValue={filters.status ?? ''}
                    aria-label="Status"
                    style={{ width: 'auto' }}
                  >
                    <option value="">Any status</option>
                    {clearanceStatuses.map((status) => (
                      <option key={status} value={status}>
                        {statusLabels[status]}
                      </option>
                    ))}
                  </select>
                  {definition && (
                    <select
                      className="select"
                      name="level"
                      defaultValue={filters.level ?? ''}
                      aria-label="Level"
                      style={{ width: 'auto' }}
                    >
                      <option value="">Any level</option>
                      {levelOptions(definition).map((level) => (
                        <option key={level.value} value={level.value}>
                          {level.label}
                        </option>
                      ))}
                    </select>
                  )}
                  <select
                    className="select"
                    name="ending"
                    defaultValue={
                      filters.expiringWithinDays === undefined
                        ? ''
                        : String(filters.expiringWithinDays)
                    }
                    aria-label="Ends within"
                    style={{ width: 'auto' }}
                  >
                    <option value="">Ends any time</option>
                    {endingOptions.map((days) => (
                      <option key={days} value={days}>
                        Ends within {days} days
                      </option>
                    ))}
                  </select>
                  <button className="btn small secondary">Filter</button>
                  {filtering && (
                    <Link className="btn small ghost" href={`${base}/clearances`}>
                      clear
                    </Link>
                  )}
                </form>
                <Table
                  head={['Person', 'Level', 'Status', 'Read-ins', 'Reinvestigation', 'Ends']}
                  rows={listed.clearances.map((item) => [
                    <span key="p" className="stack" style={{ gap: 2 }}>
                      <Link href={`${base}/clearances/${encodeURIComponent(item.identityId)}`}>
                        <strong>{item.identity.name}</strong>
                      </Link>
                      <span className="small muted">
                        {[
                          item.identity.email,
                          item.identity.kind === 'user' ? undefined : item.identity.kind,
                          item.identity.guest ? 'guest' : undefined,
                          item.identity.status === 'active' ? undefined : item.identity.status,
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                      </span>
                    </span>,
                    <span key="l" className="stack" style={{ gap: 2 }}>
                      <span>{item.level.name ?? levelName(definition, item.level.id)}</span>
                      {item.effectiveLevel && item.effectiveLevel !== item.level.id && (
                        <span className="small muted">
                          counts as {levelName(definition, item.effectiveLevel)}
                        </span>
                      )}
                      {item.citizenship.length > 0 && (
                        <span className="small muted">{item.citizenship.join(', ')}</span>
                      )}
                    </span>,
                    <span key="s" className="row" style={{ flexWrap: 'wrap' }}>
                      <Badge tone={statusTone(item.status)}>{statusLabels[item.status]}</Badge>
                      {isLive(item.status) && item.effectiveStatus !== item.status && (
                        <Badge tone={statusTone(item.effectiveStatus)}>
                          {effectiveStatusLabels[item.effectiveStatus]}
                        </Badge>
                      )}
                      {clearanceAttention(item, now)
                        .filter(
                          (entry) => entry.label !== 'expired' && entry.label !== 'not counted',
                        )
                        .map((entry) => (
                          <Badge key={entry.label} tone={entry.tone}>
                            {entry.label}
                          </Badge>
                        ))}
                    </span>,
                    // A count only: names are on the person's page.
                    item.readIns.length || (
                      <span key="r" className="muted">
                        —
                      </span>
                    ),
                    item.reinvestigationDue ? (
                      <span key="d" className="stack small" style={{ gap: 2 }}>
                        <Time value={item.reinvestigationDue} />
                        <span className="muted">{relativeDays(item.reinvestigationDue, now)}</span>
                      </span>
                    ) : (
                      <span key="d" className="muted">
                        —
                      </span>
                    ),
                    item.expiresAt ? (
                      <span key="e" className="stack small" style={{ gap: 2 }}>
                        <Time value={item.expiresAt} />
                        <span className="muted">{relativeDays(item.expiresAt, now)}</span>
                      </span>
                    ) : (
                      <span key="e" className="muted">
                        never
                      </span>
                    ),
                  ])}
                  empty={
                    filtering
                      ? 'No clearance matches these filters.'
                      : 'Nobody holds a clearance yet.'
                  }
                />
                {pages > 1 && (
                  <div className="card-body row spread">
                    <span className="small muted">
                      Page {page} of {pages} · {listed.total} clearances
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
          {mayAdjudicate && definition && scheme && (
            <Card
              title="Grant a clearance"
              description={`Under the ${scheme.name} scheme (${scheme.adjudication === 'within-own' ? 'officers grant only what their own clearance holds' : 'unrestricted adjudication'}). Nobody grants their own clearance. Needs iam:clearances:adjudicate and a recent sign-in; read people into compartments on their clearance page.`}
            >
              <GrantClearanceForm
                tenantId={tenantId}
                people={candidates}
                levels={levelOptions(definition)}
                interimAllowed={scheme.interimAllowed}
                openBase={`${base}/clearances`}
              />
            </Card>
          )}
        </div>
      )}
    </>
  );
}
