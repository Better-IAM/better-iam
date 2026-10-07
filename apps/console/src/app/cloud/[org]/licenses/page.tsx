import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { SeatBadge, UsageMeter } from '@/components/licenses';
import { Alert, Badge, Card, KeyValues, PageHeader, Stat, Table, Time } from '@/components/ui';
import {
  productFields,
  productStatusTone,
  scopeLabel,
  settingsFields,
  usageSummary,
  usageTotals,
} from '@/lib/licenses';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { identityHref } from '@/lib/threats';

const productsResource = { type: 'iam', id: 'licenses/products' };
const settingsResource = { type: 'iam', id: 'licenses/settings' };
/** Waiting seats listed on this page, oldest claims first; each product's page lists all of its own. */
const waitingLimit = 50;

export default async function Licenses({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base } = page;
  const allowed = await can(page, [
    { action: 'iam:licenses:read', resource: productsResource },
    { action: 'iam:licenses:manage', resource: productsResource },
    { action: 'iam:licenses:manage', resource: settingsResource },
  ]);
  const mayRead = allowed[key('iam:licenses:read', productsResource)] === true;
  const mayDefine = allowed[key('iam:licenses:manage', productsResource)] === true;
  const mayConfigure = allowed[key('iam:licenses:manage', settingsResource)] === true;
  const [usage, listing, settings, waiting] = mayRead
    ? await Promise.all([
        tryRead(() => iam.api.licenses.usage(auth, { tenantId })),
        tryRead(() => iam.api.licenses.listProducts(auth, { tenantId })),
        tryRead(() => iam.api.licenses.getSettings(auth, { tenantId })),
        tryRead(() =>
          iam.api.licenses.listSeats(auth, { tenantId, status: 'waiting', limit: waitingLimit }),
        ),
      ])
    : [];
  const totals = usageTotals(usage?.products ?? []);
  const inUse = (usage?.products ?? []).filter((product) => product.status === 'active');
  const usageOf = (productId: string) =>
    usage?.products.find((product) => product.productId === productId);
  const reclaimAfterDays = usage?.reclaimAfterDays;
  return (
    <>
      <PageHeader
        title="Licenses"
        description="Products the organization has seats of, who holds a seat, and who waits for one. Give a product to people or groups: while seats last each person holds an active seat, and the rest wait in the order they were given it. What a seat unlocks comes from birthright access packages on identity.licenses, policies on principal.licenses, and the product's feature keys."
      />
      {!usage ? (
        <Alert tone="warning">
          Requires <code>iam:licenses:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="grid cols-4">
            <Stat
              label="Seats in use"
              value={totals.active}
              hint={`of ${totals.capacity} across ${totals.products} ${totals.products === 1 ? 'product' : 'products'}`}
            />
            <Stat label="Available" value={totals.available} hint="seats nobody holds" />
            <Stat
              label="Waiting"
              value={totals.waiting}
              hint={
                totals.waiting > 0 ? (
                  <a href="#waiting">people queued for a seat</a>
                ) : (
                  'nobody is waiting'
                )
              }
            />
            <Stat
              label="Reclaimable"
              value={reclaimAfterDays === undefined ? '—' : totals.reclaimable}
              hint={
                reclaimAfterDays === undefined
                  ? 'reclaim is off'
                  : totals.reclaimableThroughGroups > 0
                    ? `inactive ${reclaimAfterDays}+ days; ${totals.reclaimableThroughGroups} through groups`
                    : `inactive ${reclaimAfterDays}+ days`
              }
            />
          </div>

          <h2 className="section-title">Usage</h2>
          {inUse.length ? (
            <div className="tiles">
              {inUse.map((product) => (
                <section key={product.productId} className="card tile">
                  <div className="tile-head">
                    <h2>
                      <Link href={`${base}/licenses/${product.productId}`}>{product.name}</Link>
                    </h2>
                    <Badge tone={product.scope === 'platform' ? 'accent' : 'neutral'}>
                      {product.scope === 'platform' ? 'platform' : 'own'}
                    </Badge>
                  </div>
                  <div className="figure">
                    {product.active}
                    <small>
                      of {product.capacity} {product.capacity === 1 ? 'seat' : 'seats'}
                    </small>
                  </div>
                  <UsageMeter usage={product} />
                  <p>{usageSummary(product)}</p>
                  <div className="tile-foot">
                    <Link href={`${base}/licenses/${product.productId}`}>
                      Seats and assignments →
                    </Link>
                  </div>
                </section>
              ))}
            </div>
          ) : (
            <Card>
              <div className="empty">
                No product is in use yet. Products appear here once the organization defines one,
                has seats of one, or gives one to someone.
              </div>
            </Card>
          )}

          <Card
            title="Products"
            description="Platform products come from the service; their seats are granted by the platform operator. Products the organization defines reach its projects, and it grants their seats itself."
            flush
          >
            {listing ? (
              <Table
                head={['Product', 'Defined by', 'Feature keys', 'Status', 'Seats']}
                rows={listing.products.map((product) => {
                  const figures = usageOf(product.id);
                  return [
                    <span key="p" className="stack" style={{ gap: 2 }}>
                      <Link href={`${base}/licenses/${product.id}`}>
                        <strong>{product.name}</strong>
                      </Link>
                      <span className="small muted">
                        <code>{product.key}</code>
                        {product.description ? ` · ${product.description}` : ''}
                      </span>
                    </span>,
                    <span key="d" className="row">
                      <span className="small">{scopeLabel(product)}</span>
                      {product.shadowed && (
                        <span title="An enclosing tenant defines the same key; its product wins and this one's seats grant nothing.">
                          <Badge tone="warning">key shadowed</Badge>
                        </span>
                      )}
                    </span>,
                    product.featureKeys.length ? (
                      <span key="f" className="small">
                        {product.featureKeys.map((feature, index) => (
                          <span key={feature}>
                            {index > 0 && ', '}
                            <code>{feature}</code>
                          </span>
                        ))}
                      </span>
                    ) : (
                      <span key="f" className="muted">
                        —
                      </span>
                    ),
                    <Badge key="s" tone={productStatusTone(product.status)}>
                      {product.status}
                    </Badge>,
                    figures ? (
                      <span key="n" className="small">
                        {figures.active} of {figures.capacity}
                        {figures.waiting > 0 && ` · ${figures.waiting} waiting`}
                      </span>
                    ) : (
                      <span key="n" className="muted small">
                        no seats here
                      </span>
                    ),
                  ];
                })}
                empty="No products yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:licenses:read</code> on <code>iam/licenses/products</code>.
              </div>
            )}
            {mayDefine && (
              <div className="card-body">
                <details>
                  <summary className="small">Define a product</summary>
                  <ApiForm
                    path="licenses/createProduct"
                    tenantId={tenantId}
                    submitLabel="Define product"
                    redirectTo={`${base}/licenses/{id}`}
                    fields={productFields(tenantId)}
                  />
                </details>
              </div>
            )}
          </Card>

          <div id="waiting">
            <Card
              title="Waiting list"
              description="People who were given a product while every seat was taken. They take seats in this order as seats free up or capacity grows."
              flush
            >
              {waiting ? (
                <Table
                  head={['Person', 'Product', 'Place', 'Given', 'Through']}
                  rows={waiting.seats.map((seat) => [
                    <span key="i" className="stack" style={{ gap: 2 }}>
                      <Link href={identityHref(base, seat.identityId, seat.identityKind)}>
                        {seat.identityName}
                      </Link>
                      {seat.identityEmail && (
                        <span className="small muted">{seat.identityEmail}</span>
                      )}
                    </span>,
                    <Link key="p" href={`${base}/licenses/${seat.productId}`}>
                      {seat.productName}
                    </Link>,
                    <SeatBadge key="s" seat={seat} />,
                    <Time key="a" value={seat.assignedAt} />,
                    <span key="t" className="small">
                      {[
                        ...(seat.direct ? ['direct'] : []),
                        ...(seat.groupIds.length
                          ? [
                              `${seat.groupIds.length} ${seat.groupIds.length === 1 ? 'group' : 'groups'}`,
                            ]
                          : []),
                      ].join(', ')}
                    </span>,
                  ])}
                  empty="Nobody is waiting for a seat."
                />
              ) : (
                <div className="empty">
                  Requires <code>iam:licenses:read</code> on <code>iam/licenses/seats</code>.
                </div>
              )}
              {waiting && waiting.total > waiting.seats.length && (
                <div className="card-body small muted">
                  Showing {waiting.seats.length} of {waiting.total} waiting seats; each
                  product&apos;s page lists its whole waiting list.
                </div>
              )}
            </Card>
          </div>

          <Card
            title="Settings"
            description="Reclaim gives unused seats back: it removes direct assignments of people who have not signed in or used an API key for a while, and the next person waiting takes the seat."
          >
            {settings ? (
              <KeyValues
                items={[
                  [
                    'Reclaim inactive seats',
                    settings.reclaimAfterDays === undefined
                      ? 'off'
                      : `after ${settings.reclaimAfterDays} days without activity`,
                  ],
                  ['Waiting-list email', settings.notifyWaiting ? 'on' : 'off'],
                  [
                    'Last changed',
                    settings.updatedAt ? (
                      <Time key="u" value={settings.updatedAt} />
                    ) : (
                      <span key="u" className="muted">
                        never
                      </span>
                    ),
                  ],
                ]}
              />
            ) : (
              <div className="empty">
                Requires <code>iam:licenses:read</code> on <code>iam/licenses/settings</code>.
              </div>
            )}
            {settings && mayConfigure && (
              <ApiForm
                path="licenses/configure"
                tenantId={tenantId}
                submitLabel="Save settings"
                compact
                successMessage="Saved."
                fields={settingsFields(tenantId, settings)}
              />
            )}
          </Card>
        </div>
      )}
    </>
  );
}
