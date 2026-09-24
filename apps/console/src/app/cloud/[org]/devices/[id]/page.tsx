import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { EnrollmentCodeForm } from '@/components/device-enrollment';
import { AssuranceBadge, ComplianceBadge, DeviceStatusBadge } from '@/components/device-posture';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import {
  complianceChecks,
  enrollmentLifetimeField,
  outcomeLabels,
  outcomeTone,
  platformLabels,
  vendorLabels,
} from '@/lib/device-posture';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function DeviceDetail({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base } = context;
  const device = await tryRead(() => iam.api.devices.get(auth, { tenantId, deviceId: id }));
  if (!device) notFound();
  const deviceResource = { type: 'iam', id: `devices/${device.id}` };
  const enrollmentsResource = { type: 'iam', id: 'devices/enrollments' };
  const allowed = await can(context, [
    { action: 'iam:devices:manage', resource: deviceResource },
    { action: 'iam:devices:manage', resource: enrollmentsResource },
  ]);
  const mayManage = allowed[key('iam:devices:manage', deviceResource)];
  const mayEnroll = allowed[key('iam:devices:manage', enrollmentsResource)];
  const [settings, integrations, people, activity] = await Promise.all([
    tryRead(() => iam.api.devices.getSettings(auth, { tenantId })),
    tryRead(() => iam.api.devices.listIntegrations(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', limit: 1000 })),
    tryRead(() =>
      iam.api.audit.list(auth, { tenantId, resourceId: `devices/${device.id}`, limit: 25 }),
    ),
  ]);
  const integration = device.source
    ? integrations?.find((item) => item.id === device.source?.integrationId)
    : undefined;
  const names = new Map((people ?? []).map((person) => [person.id, person.name]));
  const nameOf = (identityId: string) => names.get(identityId) ?? identityId;
  const now = Date.now();
  const checks = complianceChecks(device, settings, integration, now);
  // The owner stays selectable even when the people list is unavailable or leaves them out, so saving the form
  // never clears the owner (which would also drop the keys the owner enrolled) by accident.
  const ownerOptions = (people ?? []).map((person) => ({
    value: person.id,
    label: `${person.name}${person.email ? ` (${person.email})` : ''}`,
  }));
  if (
    device.ownerIdentityId &&
    !ownerOptions.some((option) => option.value === device.ownerIdentityId)
  )
    ownerOptions.unshift({
      value: device.ownerIdentityId,
      label: device.owner?.name ?? device.ownerIdentityId,
    });
  const retired = device.status === 'retired';
  return (
    <>
      <PageHeader
        title={device.name}
        description={
          <>
            <Link href={`${base}/devices`}>Devices</Link> · <code>{device.id}</code>
          </>
        }
        actions={
          mayManage && (
            <>
              {!retired && (
                <ApiButton
                  path="devices/retire"
                  body={{ tenantId, deviceId: device.id }}
                  label="Retire"
                  confirm={`Retire ${device.name}? It stops proving anything and its keys and pending enrollment codes are deleted. This cannot be undone.`}
                  tenantId={tenantId}
                />
              )}
              <ApiButton
                path="devices/delete"
                body={{ tenantId, deviceId: device.id }}
                label="Delete"
                tone="danger"
                confirm={
                  device.source
                    ? `Delete ${device.name} with its keys and enrollment codes? The integration recreates it with its next report; retire it instead to keep it out.`
                    : `Delete ${device.name} with its keys and enrollment codes?`
                }
                redirectTo={`${base}/devices`}
                tenantId={tenantId}
              />
            </>
          )
        }
      />
      <div className="stack">
        {device.status === 'lost' && (
          <Alert tone="danger">
            This device is marked lost: its proofs give no assurance until it is marked active
            again.
          </Alert>
        )}
        {retired && (
          <Alert tone="info">
            This device is retired. It proves nothing, and later integration reports keep it
            retired.
          </Alert>
        )}
        <div className="grid cols-2">
          <Card title="Device">
            <KeyValues
              items={[
                ['Status', <DeviceStatusBadge key="s" status={device.status} />],
                ['Platform', platformLabels[device.platform]],
                [
                  'Owner',
                  device.owner ? (
                    <Link key="o" href={`${base}/members/${device.owner.id}`}>
                      {device.owner.name}
                      {device.owner.email ? ` (${device.owner.email})` : ''}
                    </Link>
                  ) : device.ownerIdentityId ? (
                    <code key="o" className="small">
                      {device.ownerIdentityId}
                    </code>
                  ) : (
                    <span key="o" className="muted">
                      shared: any member may present it
                    </span>
                  ),
                ],
                ['Assurance', <AssuranceBadge key="a" assurance={device.assurance} />],
                [
                  'Managed by',
                  device.source ? (
                    <span key="m" className="stack" style={{ gap: 2 }}>
                      <span>
                        {integration
                          ? `${integration.name} (${vendorLabels[integration.vendor] ?? integration.vendor})`
                          : 'a removed integration'}
                        {integration?.status === 'disabled' && (
                          <>
                            {' '}
                            <Badge tone="warning">disabled</Badge>
                          </>
                        )}
                      </span>
                      <code className="small">{device.source.externalId}</code>
                    </span>
                  ) : (
                    <span key="m" className="muted">
                      nobody: self-enrolled
                    </span>
                  ),
                ],
                ['Model', device.model ?? <span className="muted">—</span>],
                ['Serial number', device.serialNumber ?? <span className="muted">—</span>],
                [
                  'Enrolled by',
                  device.enrolledBy ? nameOf(device.enrolledBy) : <span className="muted">—</span>,
                ],
                ['Registered', <Time key="c" value={device.createdAt} />],
                ['Last check-in', <Time key="i" value={device.lastCheckInAt} />],
                ['Last proof seen', <Time key="p" value={device.lastSeenAt} />],
              ]}
            />
          </Card>
          <Card
            title="Compliance"
            description={
              <>
                Judged against the organization&apos;s{' '}
                <Link href={`${base}/device-management`}>requirements</Link>
                {device.posture && (
                  <>
                    ; last report <Time value={device.posture.reportedAt} />
                  </>
                )}
                .
              </>
            }
            flush
          >
            <div style={{ padding: '0 16px 12px' }}>
              <ComplianceBadge compliance={device.compliance} />
            </div>
            <Table
              head={['Check', 'Requirement', 'Reported', 'Result']}
              rows={checks.map((check) => [
                check.label,
                <span key="r" className="small">
                  {check.requirement}
                </span>,
                <span key="p" className="small">
                  {check.reported}
                </span>,
                <Badge key="o" tone={outcomeTone(check.outcome)}>
                  {outcomeLabels[check.outcome]}
                </Badge>,
              ])}
            />
          </Card>
        </div>
        <Card
          title="Keys"
          description="Each key signs the proofs of one browser profile or agent on the device; its thumbprint is the proof's key id."
          flush
        >
          <Table
            head={['Key', 'Algorithm', 'Enrolled', 'By', 'Last used', '']}
            rows={device.publicKeys.map((item) => [
              <code key="k" className="small">
                {item.id}
              </code>,
              item.algorithm,
              <Time key="c" value={item.createdAt} />,
              nameOf(item.createdBy),
              <Time key="u" value={item.lastUsedAt} />,
              mayManage ? (
                <ApiButton
                  key="r"
                  path="devices/removeKey"
                  body={{ tenantId, deviceId: device.id, keyId: item.id }}
                  label="Remove"
                  tone="danger"
                  confirm="Remove this key? Proofs signed with it stop verifying at once."
                  tenantId={tenantId}
                />
              ) : (
                ''
              ),
            ])}
            empty={
              retired
                ? 'No keys: retiring the device deleted them.'
                : 'No keys enrolled, so the device proves nothing yet.'
            }
          />
        </Card>
        {!retired && (mayManage || mayEnroll) && (
          <div className="grid cols-2">
            {mayManage && (
              <Card
                title="Edit"
                description="Requires iam:devices:manage and a recent sign-in. A new owner drops the keys the previous owner enrolled; a lost device proves nothing until marked active again."
              >
                <ApiForm
                  path="devices/update"
                  tenantId={tenantId}
                  submitLabel="Save"
                  successMessage="Device updated."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'deviceId', label: 'Device', type: 'hidden', defaultValue: device.id },
                    { name: 'name', label: 'Name', required: true, defaultValue: device.name },
                    {
                      name: 'ownerIdentityId',
                      label: 'Owner',
                      type: 'select',
                      defaultValue: device.ownerIdentityId ?? '',
                      emptyAsNull: true,
                      options: ownerOptions,
                      help: 'Leave empty for a shared device any member may present.',
                    },
                    {
                      name: 'status',
                      label: 'Status',
                      type: 'select',
                      required: true,
                      defaultValue: device.status,
                      options: [
                        { value: 'active', label: 'Active' },
                        { value: 'lost', label: 'Lost' },
                      ],
                    },
                  ]}
                />
              </Card>
            )}
            {mayEnroll && device.status === 'active' && (
              <Card
                title="Enrol a browser or agent"
                description={
                  device.ownerIdentityId
                    ? 'A one-time code binds a new key to this device; only its owner can use it.'
                    : 'A one-time code binds a new key to this device; any member of the organization can use it.'
                }
              >
                <EnrollmentCodeForm
                  tenantId={tenantId}
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'deviceId', label: 'Device', type: 'hidden', defaultValue: device.id },
                    enrollmentLifetimeField,
                  ]}
                />
              </Card>
            )}
          </div>
        )}
        <Card title="Recent activity" description="Changes to this device, newest first." flush>
          {activity ? (
            <Table
              head={['When', 'Action', 'Who', 'Details']}
              rows={activity.map((event) => [
                <Time key="t" value={event.timestamp} />,
                <code key="a" className="small">
                  {event.action}
                </code>,
                nameOf(event.actorId),
                event.metadata ? (
                  <code key="m" className="small truncate">
                    {JSON.stringify(event.metadata)}
                  </code>
                ) : (
                  ''
                ),
              ])}
              empty="No activity yet."
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
