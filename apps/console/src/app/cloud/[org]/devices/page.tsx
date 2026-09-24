import Link from 'next/link';
import { AssuranceBadge, ComplianceBadge, DeviceStatusBadge } from '@/components/device-posture';
import { Alert, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import {
  deviceFilterQuery,
  deviceFilters,
  filtering,
  platformLabels,
  platformOptions,
  vendorLabels,
  type DeviceFilterParams,
} from '@/lib/device-posture';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const pageSize = 50;
/** Counts on the tiles come from the newest devices up to this many. */
const summaryLimit = 1000;
const devicesResource = { type: 'iam', id: 'devices' };

export default async function Devices({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<DeviceFilterParams>;
}) {
  const { org } = await params;
  const { filters, page } = deviceFilters(await searchParams);
  const context = await orgPage(org);
  const { iam, auth, tenantId, base } = context;
  const allowed = await can(context, [{ action: 'iam:devices:read', resource: devicesResource }]);
  const mayRead = allowed[key('iam:devices:read', devicesResource)];
  const [summary, listed, integrations, people] = mayRead
    ? await Promise.all([
        tryRead(() => iam.api.devices.list(auth, { tenantId, limit: summaryLimit })),
        tryRead(() =>
          iam.api.devices.list(auth, {
            tenantId,
            ...filters,
            limit: pageSize,
            offset: (page - 1) * pageSize,
          }),
        ),
        tryRead(() => iam.api.devices.listIntegrations(auth, { tenantId })),
        tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', limit: 1000 })),
      ])
    : [];
  const integrationNames = new Map(
    (integrations ?? []).map((integration) => [integration.id, integration]),
  );
  const devices = summary?.devices ?? [];
  const managed = devices.filter((device) => device.compliance.managed).length;
  const compliant = devices.filter((device) => device.compliance.compliant).length;
  const nonCompliant = managed - compliant;
  const lost = devices.filter((device) => device.status === 'lost').length;
  const retired = devices.filter((device) => device.status === 'retired').length;
  const partial = summary !== undefined && summary.total > devices.length;
  const pages = listed ? Math.max(1, Math.ceil(listed.total / pageSize)) : 1;
  const href = (target: number) => `${base}/devices${deviceFilterQuery(filters, target)}`;
  return (
    <>
      <PageHeader
        title="Devices"
        description="Laptops and phones people use to reach the organization: devices they registered themselves and devices your MDM or EDR integrations report, with the assurance a proof from each one carries into policies."
        actions={
          <Link className="btn secondary" href={`${base}/device-management`}>
            Requirements and integrations
          </Link>
        }
      />
      {!summary || !listed ? (
        <Alert tone="warning">
          Requires <code>iam:devices:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="tiles">
            <Stat
              label="Devices"
              value={summary.total}
              hint={retired > 0 ? `${retired} retired` : 'registered in this organization'}
            />
            <Stat label="Managed" value={managed} hint="reported by an integration" />
            <Stat
              label="Compliant"
              value={compliant}
              hint={
                managed > 0
                  ? `${Math.round((compliant / managed) * 100)}% of managed`
                  : 'meets every requirement'
              }
            />
            <Stat
              label="Need attention"
              value={nonCompliant + lost}
              hint={
                nonCompliant > 0 ? (
                  <Link href={`${base}/devices?managed=yes&compliant=no`}>
                    {nonCompliant} non-compliant
                  </Link>
                ) : lost > 0 ? (
                  <Link href={`${base}/devices?status=lost`}>{lost} lost</Link>
                ) : (
                  'non-compliant or lost'
                )
              }
            />
          </div>
          {partial && (
            <p className="small muted">
              The counts cover the newest {summaryLimit.toLocaleString()} of {summary.total}{' '}
              devices.
            </p>
          )}
          <Card
            title="Inventory"
            description="Assurance is what a proof from the device gives policies as request.deviceAssurance; only managed devices can be compliant."
            flush
          >
            <form method="get" className="row" style={{ padding: '0 16px 12px' }}>
              <input
                className="input"
                name="q"
                defaultValue={filters.query ?? ''}
                placeholder="Name, serial, model, or owner"
                aria-label="Search devices"
                style={{ width: 220 }}
              />
              {people && (
                <select
                  className="select"
                  name="owner"
                  defaultValue={filters.ownerIdentityId ?? ''}
                  aria-label="Owner"
                  style={{ width: 'auto' }}
                >
                  <option value="">Any owner</option>
                  {people.map((person) => (
                    <option key={person.id} value={person.id}>
                      {person.name}
                      {person.email ? ` (${person.email})` : ''}
                    </option>
                  ))}
                </select>
              )}
              <select
                className="select"
                name="platform"
                defaultValue={filters.platform ?? ''}
                aria-label="Platform"
                style={{ width: 'auto' }}
              >
                <option value="">Any platform</option>
                {platformOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <select
                className="select"
                name="status"
                defaultValue={filters.status ?? ''}
                aria-label="Status"
                style={{ width: 'auto' }}
              >
                <option value="">Any status</option>
                <option value="active">Active</option>
                <option value="lost">Lost</option>
                <option value="retired">Retired</option>
              </select>
              <select
                className="select"
                name="managed"
                defaultValue={filters.managed === undefined ? '' : filters.managed ? 'yes' : 'no'}
                aria-label="Managed"
                style={{ width: 'auto' }}
              >
                <option value="">Managed or not</option>
                <option value="yes">Managed</option>
                <option value="no">Unmanaged</option>
              </select>
              <select
                className="select"
                name="compliant"
                defaultValue={
                  filters.compliant === undefined ? '' : filters.compliant ? 'yes' : 'no'
                }
                aria-label="Compliant"
                style={{ width: 'auto' }}
              >
                <option value="">Compliant or not</option>
                <option value="yes">Compliant</option>
                <option value="no">Not compliant</option>
              </select>
              <button className="btn small secondary">Filter</button>
              {filtering(filters) && (
                <Link className="btn small ghost" href={`${base}/devices`}>
                  clear
                </Link>
              )}
            </form>
            <Table
              head={['Device', 'Owner', 'Status', 'Assurance', 'Compliance', 'Source', 'Last seen']}
              rows={listed.devices.map((device) => {
                const integration = device.source
                  ? integrationNames.get(device.source.integrationId)
                  : undefined;
                const lastSeen = Math.max(device.lastSeenAt ?? 0, device.lastCheckInAt ?? 0);
                return [
                  <span key="d" className="stack" style={{ gap: 2 }}>
                    <Link href={`${base}/devices/${device.id}`}>{device.name}</Link>
                    <span className="small muted">
                      {[platformLabels[device.platform], device.model, device.serialNumber]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  </span>,
                  device.owner ? (
                    <Link key="o" href={`${base}/members/${device.owner.id}`}>
                      {device.owner.name}
                    </Link>
                  ) : device.ownerIdentityId ? (
                    <code key="o" className="small">
                      {device.ownerIdentityId}
                    </code>
                  ) : (
                    <span key="o" className="muted">
                      shared
                    </span>
                  ),
                  <DeviceStatusBadge key="s" status={device.status} />,
                  <AssuranceBadge key="a" assurance={device.assurance} />,
                  <ComplianceBadge key="c" compliance={device.compliance} />,
                  device.source ? (
                    <span key="m" className="small">
                      {integration
                        ? `${integration.name} · ${vendorLabels[integration.vendor] ?? integration.vendor}`
                        : 'removed integration'}
                    </span>
                  ) : (
                    <span key="m" className="small muted">
                      self-enrolled · {device.keys} {device.keys === 1 ? 'key' : 'keys'}
                    </span>
                  ),
                  <Time key="l" value={lastSeen || undefined} />,
                ];
              })}
              empty={
                filtering(filters)
                  ? 'No device matches these filters.'
                  : 'No devices yet. People register devices from applications that use device proofs, and integrations report the devices they manage.'
              }
            />
            {pages > 1 && (
              <div className="card-body row spread">
                <span className="small muted">
                  Page {page} of {pages} · {listed.total} devices
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
          <Alert tone="info">
            Policies see the device presenting a request as <code>request.deviceAssurance</code> (
            <code>none</code>, <code>registered</code>, <code>managed</code>, or{' '}
            <code>compliant</code>), <code>request.deviceManaged</code>,{' '}
            <code>request.deviceCompliant</code>, <code>request.deviceId</code>, and{' '}
            <code>request.devicePlatform</code>. Applications send a signed proof in the{' '}
            <code>x-better-iam-device</code> header with <code>better-iam/client/device</code>.
          </Alert>
        </div>
      )}
    </>
  );
}
