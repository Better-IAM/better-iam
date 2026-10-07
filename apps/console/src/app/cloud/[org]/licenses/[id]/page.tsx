import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { LicenseSeatView } from 'better-iam/server';
import { ApiButton, ApiForm } from '@/components/api-form';
import { SeatBadge, UsageMeter } from '@/components/licenses';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import {
  assignableGroups,
  assignablePeople,
  assignFields,
  assignManyFields,
  plural,
  poolEditFields,
  poolFields,
  poolState,
  poolStateTone,
  poolTenantOptions,
  productEditFields,
  productStatusTone,
  scopeLabel,
  seatInactive,
  subscriptionOptions,
  usageSummary,
} from '@/lib/licenses';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { identityHref } from '@/lib/threats';

/** Seats listed per status; the counts above the tables always cover every seat. */
const seatLimit = 500;
const poolsResource = { type: 'iam', id: 'licenses/pools' };
const assignmentsResource = { type: 'iam', id: 'licenses/assignments' };
const subscriptionsResource = { type: 'iam', id: 'billing/subscriptions' };

export default async function LicenseProduct({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, tenant, base } = page;
  const productResource = { type: 'iam', id: `licenses/products/${id}` };
  const allowed = await can(page, [
    { action: 'iam:licenses:read', resource: productResource },
    { action: 'iam:licenses:manage', resource: productResource },
    { action: 'iam:licenses:manage', resource: poolsResource },
    { action: 'iam:licenses:assign', resource: assignmentsResource },
    { action: 'iam:billing:read', resource: subscriptionsResource },
  ]);
  if (!allowed[key('iam:licenses:read', productResource)])
    return (
      <>
        <PageHeader
          title="License"
          description={<Link href={`${base}/licenses`}>All licenses</Link>}
        />
        <Alert tone="warning">
          Requires <code>iam:licenses:read</code>.
        </Alert>
      </>
    );
  const product = await tryRead(() =>
    iam.api.licenses.getProduct(auth, { tenantId, productId: id }),
  );
  if (!product) notFound();
  const active = product.status === 'active';
  // Only the defining organization changes a product and grants its seats; platform products belong to the platform.
  const mayEdit =
    active && product.definedHere && allowed[key('iam:licenses:manage', productResource)] === true;
  const mayPool =
    active && product.definedHere && allowed[key('iam:licenses:manage', poolsResource)] === true;
  // Assignments of a retired product can still be removed; nobody can be given it any more.
  const mayUnassign = allowed[key('iam:licenses:assign', assignmentsResource)] === true;
  const mayAssign = active && mayUnassign;
  const [usage, pools, assignments, seated, waiting, people, groups, children, subscriptions] =
    await Promise.all([
      tryRead(() => iam.api.licenses.usage(auth, { tenantId })),
      tryRead(() =>
        iam.api.licenses.listPools(auth, {
          tenantId,
          productId: id,
          includeEnded: true,
          limit: 200,
        }),
      ),
      tryRead(() =>
        iam.api.licenses.listAssignments(auth, { tenantId, productId: id, limit: 1000 }),
      ),
      tryRead(() =>
        iam.api.licenses.listSeats(auth, {
          tenantId,
          productId: id,
          status: 'active',
          limit: seatLimit,
        }),
      ),
      tryRead(() =>
        iam.api.licenses.listSeats(auth, {
          tenantId,
          productId: id,
          status: 'waiting',
          limit: seatLimit,
        }),
      ),
      tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
      tryRead(() => iam.api.groups.list(auth, { tenantId })),
      mayPool ? tryRead(() => iam.api.tenants.listChildren(auth, { tenantId })) : undefined,
      mayPool && allowed[key('iam:billing:read', subscriptionsResource)]
        ? tryRead(() => iam.api.billing.listSubscriptions(auth, { tenantId }))
        : undefined,
    ]);
  const figures = usage?.products.find((item) => item.productId === id) ?? {
    productId: id,
    key: product.key,
    name: product.name,
    scope: product.scope,
    status: product.status,
    capacity: 0,
    active: 0,
    waiting: 0,
    available: 0,
    pools: 0,
    assignments: 0,
    reclaimable: 0,
    reclaimableThroughGroups: 0,
  };
  const reclaimAfterDays = usage?.reclaimAfterDays;
  const now = Date.now();
  const personName = (identityId: string) => {
    const person = people?.find((candidate) => candidate.id === identityId);
    return person ? person.name || person.email || person.id : identityId;
  };
  const groupName = (groupId: string) =>
    groups?.find((group) => group.id === groupId)?.name ?? groupId;
  const seats = [...(seated?.seats ?? []), ...(waiting?.seats ?? [])];
  // Only people who are active and not expired hold or wait for a seat; a direct assignment without one is theirs.
  const allSeatsListed =
    seated !== undefined &&
    waiting !== undefined &&
    seated.total <= seated.seats.length &&
    waiting.total <= waiting.seats.length;
  const seatOf = (identityId: string) => seats.find((seat) => seat.identityId === identityId);
  const direct = (assignments?.assignments ?? []).filter(
    (assignment) => assignment.subjectType === 'identity',
  );
  const byGroup = (assignments?.assignments ?? []).filter(
    (assignment) => assignment.subjectType === 'group',
  );
  const peopleOptions = assignablePeople(people ?? [], assignments?.assignments ?? []);
  const groupOptions = assignableGroups(groups ?? [], assignments?.assignments ?? []);
  const through = (seat: LicenseSeatView) => (
    <span className="small">
      {seat.direct && 'direct'}
      {seat.direct && seat.groupIds.length > 0 && ', '}
      {seat.groupIds.map((groupId, index) => (
        <span key={groupId}>
          {index > 0 && ', '}
          group <Link href={`${base}/groups/${groupId}`}>{groupName(groupId)}</Link>
        </span>
      ))}
    </span>
  );
  const person = (
    seat: Pick<LicenseSeatView, 'identityId' | 'identityName' | 'identityEmail' | 'identityKind'>,
  ) => (
    <span className="stack" style={{ gap: 2 }}>
      <Link href={identityHref(base, seat.identityId, seat.identityKind)}>{seat.identityName}</Link>
      {seat.identityEmail && <span className="small muted">{seat.identityEmail}</span>}
    </span>
  );
  return (
    <>
      <PageHeader
        title={
          <>
            {product.name} <Badge tone={productStatusTone(product.status)}>{product.status}</Badge>
          </>
        }
        description={
          <>
            <code>{product.key}</code> · {scopeLabel(product)} ·{' '}
            <Link href={`${base}/licenses`}>all licenses</Link>
          </>
        }
        actions={
          mayEdit && (
            <ApiButton
              path="licenses/retireProduct"
              body={{ tenantId, productId: id }}
              label="Retire product"
              tone="danger"
              confirm={`Retire ${product.name} for good? Every seat of it is released in this organization and its projects, and nobody can be given it again. Pools and assignments stay as a record, and the key stays taken.`}
              tenantId={tenantId}
            />
          )
        }
      />
      <div className="stack">
        {!active && (
          <Alert tone="info">
            This product is retired: it holds no seats anywhere, and its pools and assignments are
            kept read-only as a record.
          </Alert>
        )}
        {product.shadowed && (
          <Alert tone="warning">
            An enclosing tenant also defines a product with the key <code>{product.key}</code>. That
            product wins: seats of this one stay but no longer grant the key or its feature keys to
            policies, birthright rules or applications. Move people to the enclosing product.
          </Alert>
        )}
        <div className="grid cols-2">
          <section className="card tile">
            <div className="tile-head">
              <h2>Seats in this organization</h2>
              {figures.waiting > 0 ? (
                <Badge tone="danger">{`${figures.waiting} waiting`}</Badge>
              ) : figures.capacity > 0 && figures.available === 0 ? (
                <Badge tone="warning">full</Badge>
              ) : null}
            </div>
            <div className="figure">
              {figures.active}
              <small>
                of {figures.capacity} {figures.capacity === 1 ? 'seat' : 'seats'} in use
              </small>
            </div>
            <UsageMeter usage={figures} />
            <p>{usageSummary(figures)}</p>
            {reclaimAfterDays !== undefined && figures.reclaimableThroughGroups > 0 && (
              <p>
                {plural(figures.reclaimableThroughGroups, 'inactive seat')} held only through
                groups: reclaim leaves those; remove the people from the group instead.
              </p>
            )}
          </section>
          <Card title="Product">
            <KeyValues
              items={[
                ['Key', <code key="k">{product.key}</code>],
                [
                  'Defined by',
                  product.scope === 'platform'
                    ? 'the platform (every organization sees it)'
                    : product.definedHere
                      ? 'this organization (its projects see it too)'
                      : 'an enclosing organization',
                ],
                [
                  'Feature keys',
                  product.featureKeys.length ? (
                    <span key="f">
                      {product.featureKeys.map((feature, index) => (
                        <span key={feature}>
                          {index > 0 && ', '}
                          <code>{feature}</code>
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span key="f" className="muted">
                      none
                    </span>
                  ),
                ],
                ['Description', product.description ?? <span className="muted">—</span>],
                ['Created', <Time key="c" value={product.createdAt} />],
                ['Updated', <Time key="u" value={product.updatedAt} />],
              ]}
            />
            {mayEdit && (
              <details>
                <summary className="small">Edit</summary>
                <ApiForm
                  path="licenses/updateProduct"
                  tenantId={tenantId}
                  submitLabel="Save product"
                  compact
                  successMessage="Saved."
                  fields={productEditFields(tenantId, product)}
                />
                {product.featureKeys.length > 0 && (
                  <ApiButton
                    path="licenses/updateProduct"
                    body={{ tenantId, productId: id, featureKeys: [] }}
                    label="Remove all feature keys"
                    confirm={`People holding ${product.name} lose its feature keys. Continue?`}
                    tenantId={tenantId}
                  />
                )}
              </details>
            )}
          </Card>
        </div>

        <Card
          title="Pools"
          description="Seats bought or granted, each for a period. Capacity is the sum of the pools that are live now; when capacity drops below the seats in use, the newest active seats join the waiting list."
          flush
        >
          {pools ? (
            <Table
              head={['Seats for', 'Seats', 'State', 'From', 'Until', 'Source', 'Note', '']}
              rows={pools.pools.map((pool) => {
                const state = poolState(pool, now);
                return [
                  <span key="t" className="row">
                    {pool.tenantName}
                    {pool.tenantId !== tenantId && <Badge>project</Badge>}
                  </span>,
                  pool.quantity,
                  <Badge key="s" tone={poolStateTone(state)}>
                    {state}
                  </Badge>,
                  <Time key="f" value={pool.startsAt ?? pool.createdAt} />,
                  pool.endsAt ? (
                    <Time key="u" value={pool.endsAt} />
                  ) : (
                    <span key="u" className="muted">
                      no end
                    </span>
                  ),
                  pool.subscriptionId ? (
                    <span key="o" className="small">
                      subscription <code>{pool.subscriptionId}</code>
                    </span>
                  ) : (
                    <span key="o" className="small muted">
                      manual
                    </span>
                  ),
                  pool.note ?? <span className="muted">—</span>,
                  mayPool ? (
                    <span key="a" className="stack" style={{ gap: 4 }}>
                      <details>
                        <summary className="small">Change</summary>
                        <ApiForm
                          path="licenses/updatePool"
                          tenantId={tenantId}
                          submitLabel="Save pool"
                          compact
                          successMessage="Saved."
                          fields={poolEditFields(pool)}
                        />
                      </details>
                      <ApiButton
                        path="licenses/removePool"
                        body={{ tenantId: pool.tenantId, poolId: pool.id }}
                        label="Remove"
                        tone="danger"
                        confirm={`Remove this pool of ${pool.quantity} seats from ${pool.tenantName}? The newest active seats beyond the remaining capacity join the waiting list.`}
                        tenantId={tenantId}
                      />
                    </span>
                  ) : (
                    ''
                  ),
                ];
              })}
              empty={
                product.scope === 'platform'
                  ? 'No seats of this platform product yet. The platform operator grants them.'
                  : 'No seats yet.'
              }
            />
          ) : (
            <div className="empty">
              Requires <code>iam:licenses:read</code> on <code>iam/licenses/pools</code>.
            </div>
          )}
          {pools && pools.total > pools.pools.length && (
            <div className="card-body small muted">
              Showing the newest {pools.pools.length} of {pools.total} pools.
            </div>
          )}
          <div className="card-body">
            {mayPool ? (
              <details>
                <summary className="small">Add seats</summary>
                <ApiForm
                  path="licenses/addPool"
                  tenantId={tenantId}
                  submitLabel="Add seats"
                  successMessage="Seats added; people waiting take them in order."
                  resetOnSuccess
                  fields={poolFields(
                    tenantId,
                    id,
                    poolTenantOptions(tenant, children ?? []),
                    subscriptionOptions(subscriptions ?? []),
                  )}
                />
              </details>
            ) : (
              active &&
              !product.definedHere && (
                <p className="small muted">
                  {product.scope === 'platform'
                    ? 'Seats of platform products are granted by the platform operator; ask them for more capacity.'
                    : 'Seats of this product are granted by the organization that defines it.'}
                </p>
              )
            )}
          </div>
        </Card>

        <div className="grid cols-2">
          <Card
            title="People"
            description="Given the product directly. Reclaim removes these assignments when the person has been inactive for the configured time."
            flush
          >
            {assignments ? (
              <Table
                head={['Person', 'Seat', 'Given', '']}
                rows={direct.map((assignment) => {
                  const seat = seatOf(assignment.subjectId);
                  return [
                    <span key="p" className="stack" style={{ gap: 2 }}>
                      <Link href={identityHref(base, assignment.subjectId, seat?.identityKind)}>
                        {assignment.subjectName}
                      </Link>
                      {assignment.subjectEmail && (
                        <span className="small muted">{assignment.subjectEmail}</span>
                      )}
                    </span>,
                    seat ? (
                      <SeatBadge key="s" seat={seat} />
                    ) : (
                      <span key="s" className="small muted">
                        {!active ? 'released' : allSeatsListed ? 'none: account not active' : '—'}
                      </span>
                    ),
                    <span key="g" className="small">
                      <Time value={assignment.assignedAt} />
                      <span className="muted"> by {personName(assignment.assignedBy)}</span>
                    </span>,
                    mayUnassign ? (
                      <ApiButton
                        key="r"
                        path="licenses/unassign"
                        body={{ tenantId, assignmentId: assignment.id }}
                        label="Remove"
                        tone="danger"
                        confirm={
                          seat?.groupIds.length
                            ? `Remove ${assignment.subjectName}'s direct assignment? Their seat stays while a group still gives it.`
                            : `Take ${product.name} away from ${assignment.subjectName}?`
                        }
                        tenantId={tenantId}
                      />
                    ) : (
                      ''
                    ),
                  ];
                })}
                empty="Nobody has been given it directly."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:licenses:read</code> on <code>iam/licenses/assignments</code>.
              </div>
            )}
            {mayAssign && people && (
              <div className="card-body stack">
                {peopleOptions.length ? (
                  <>
                    <ApiForm
                      path="licenses/assign"
                      tenantId={tenantId}
                      submitLabel="Give"
                      compact
                      successMessage="Assigned."
                      fields={assignFields(tenantId, id, 'identity', peopleOptions)}
                    />
                    {peopleOptions.length > 1 && (
                      <details>
                        <summary className="small">Give to several people</summary>
                        <ApiForm
                          path="licenses/assignMany"
                          tenantId={tenantId}
                          submitLabel="Give to all"
                          compact
                          successMessage="Assigned."
                          fields={assignManyFields(tenantId, id, peopleOptions)}
                        />
                      </details>
                    )}
                  </>
                ) : (
                  <p className="small muted">Every active person has been given it.</p>
                )}
              </div>
            )}
          </Card>
          <Card
            title="Groups"
            description="Every live member of a group claims a seat, including people who join later; leaving the group gives the seat up."
            flush
          >
            {assignments ? (
              <Table
                head={['Group', 'Seats through it', 'Given', '']}
                rows={byGroup.map((assignment) => {
                  const members = seats.filter((seat) =>
                    seat.groupIds.includes(assignment.subjectId),
                  );
                  const holding = members.filter((seat) => seat.status === 'active').length;
                  return [
                    <Link key="g" href={`${base}/groups/${assignment.subjectId}`}>
                      {assignment.subjectName}
                    </Link>,
                    <span key="n" className="small">
                      {holding} active
                      {members.length > holding && ` · ${members.length - holding} waiting`}
                    </span>,
                    <span key="a" className="small">
                      <Time value={assignment.assignedAt} />
                      <span className="muted"> by {personName(assignment.assignedBy)}</span>
                    </span>,
                    mayUnassign ? (
                      <ApiButton
                        key="r"
                        path="licenses/unassign"
                        body={{ tenantId, assignmentId: assignment.id }}
                        label="Remove"
                        tone="danger"
                        confirm={`Stop giving ${product.name} to the members of ${assignment.subjectName}? Members without another claim lose their seat.`}
                        tenantId={tenantId}
                      />
                    ) : (
                      ''
                    ),
                  ];
                })}
                empty="No group has been given it."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:licenses:read</code> on <code>iam/licenses/assignments</code>.
              </div>
            )}
            {mayAssign && groups && (
              <div className="card-body">
                {groupOptions.length ? (
                  <ApiForm
                    path="licenses/assign"
                    tenantId={tenantId}
                    submitLabel="Give to group"
                    compact
                    successMessage="Assigned."
                    fields={assignFields(tenantId, id, 'group', groupOptions)}
                  />
                ) : (
                  <p className="small muted">Every group has been given it.</p>
                )}
              </div>
            )}
          </Card>
        </div>

        <Card
          title="Active seats"
          description={
            reclaimAfterDays === undefined
              ? 'Who holds a seat, oldest claim first.'
              : `Who holds a seat, oldest claim first. Inactive: no sign-in or API key use for ${reclaimAfterDays} days, as the daily reclaim pass last saw it.`
          }
          flush
        >
          {seated ? (
            <Table
              head={['Person', 'Through', 'Active since', 'Claimed', 'Last activity']}
              rows={seated.seats.map((seat) => [
                <span key="p">{person(seat)}</span>,
                <span key="t">{through(seat)}</span>,
                <Time key="a" value={seat.activatedAt} />,
                <Time key="c" value={seat.assignedAt} />,
                <span key="l" className="row">
                  <Time value={seat.lastActivityAt} />
                  {seatInactive(seat, reclaimAfterDays, now) && (
                    <Badge tone="warning">inactive</Badge>
                  )}
                </span>,
              ])}
              empty="Nobody holds a seat."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:licenses:read</code> on <code>iam/licenses/seats</code>.
            </div>
          )}
          {seated && seated.total > seated.seats.length && (
            <div className="card-body small muted">
              Showing {seated.seats.length} of {seated.total} active seats.
            </div>
          )}
        </Card>

        <Card
          title="Waiting list"
          description="People given the product while every seat was taken, in the order they take seats as seats free up or capacity grows."
          flush
        >
          {waiting ? (
            <Table
              head={['Place', 'Person', 'Through', 'Claimed']}
              rows={waiting.seats.map((seat) => [
                <SeatBadge key="s" seat={seat} />,
                <span key="p">{person(seat)}</span>,
                <span key="t">{through(seat)}</span>,
                <Time key="c" value={seat.assignedAt} />,
              ])}
              empty="Nobody is waiting."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:licenses:read</code> on <code>iam/licenses/seats</code>.
            </div>
          )}
          {waiting && waiting.total > waiting.seats.length && (
            <div className="card-body small muted">
              Showing the first {waiting.seats.length} of {waiting.total} people waiting.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
