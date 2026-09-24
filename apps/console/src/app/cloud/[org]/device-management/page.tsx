import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { EnrollmentCodeForm } from '@/components/device-enrollment';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time, type Tone } from '@/components/ui';
import {
  enrollmentLifetimeField,
  osVersionExamples,
  platformLabels,
  vendorLabels,
  vendorOptions,
} from '@/lib/device-posture';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const enrollmentTone: Record<string, Tone> = {
  pending: 'accent',
  used: 'success',
  expired: 'neutral',
};

const settingsResource = { type: 'iam', id: 'devices/settings' };
const integrationsResource = { type: 'iam', id: 'devices/integrations' };
const enrollmentsResource = { type: 'iam', id: 'devices/enrollments' };

export default async function DeviceManagement({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base } = context;
  const allowed = await can(context, [
    { action: 'iam:devices:manage', resource: settingsResource },
    { action: 'iam:devices:manage', resource: integrationsResource },
    { action: 'iam:devices:manage', resource: enrollmentsResource },
  ]);
  const mayConfigure = allowed[key('iam:devices:manage', settingsResource)];
  const mayIntegrate = allowed[key('iam:devices:manage', integrationsResource)];
  const mayEnroll = allowed[key('iam:devices:manage', enrollmentsResource)];
  const [settings, integrations, enrollments, people] = await Promise.all([
    tryRead(() => iam.api.devices.getSettings(auth, { tenantId })),
    tryRead(() => iam.api.devices.listIntegrations(auth, { tenantId })),
    mayEnroll
      ? tryRead(() => iam.api.devices.listEnrollments(auth, { tenantId }))
      : Promise.resolve(undefined),
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', limit: 1000 })),
  ]);
  // Device names for the codes bound to a device, read only when some code is.
  const bound = (enrollments ?? []).some((enrollment) => enrollment.deviceId !== undefined);
  const devices = bound
    ? await tryRead(() => iam.api.devices.list(auth, { tenantId, limit: 1000 }))
    : undefined;
  const deviceNames = new Map((devices?.devices ?? []).map((device) => [device.id, device.name]));
  const names = new Map((people ?? []).map((person) => [person.id, person.name]));
  const nameOf = (identityId: string) => names.get(identityId) ?? identityId;
  const pending = (enrollments ?? []).filter((enrollment) => enrollment.status === 'pending');
  return (
    <>
      <PageHeader
        title="Device management"
        description="What a managed device must meet to count as compliant, the MDM and EDR integrations that report device posture, and one-time codes for enrolling devices."
        actions={
          <Link className="btn secondary" href={`${base}/devices`}>
            Devices
          </Link>
        }
      />
      <div className="stack">
        <div className="grid cols-2">
          <Card
            title="Compliance requirements"
            description={
              settings ? (
                settings.configured ? (
                  <>
                    Updated <Time value={settings.updatedAt} />
                    {settings.updatedBy ? ` by ${nameOf(settings.updatedBy)}` : ''}. Only managed
                    devices can be compliant; unknown posture fails a requirement.
                  </>
                ) : (
                  'The defaults apply until you save. Only managed devices can be compliant; unknown posture fails a requirement.'
                )
              ) : undefined
            }
          >
            {!settings ? (
              <div className="empty">
                Requires <code>iam:devices:read</code>.
              </div>
            ) : mayConfigure ? (
              <ApiForm
                path="devices/configure"
                tenantId={tenantId}
                submitLabel="Save requirements"
                successMessage="Requirements saved. Device compliance is re-evaluated on every request."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'requireEncrypted',
                    label: 'Require disk encryption',
                    type: 'checkbox',
                    defaultValue: settings.requireEncrypted,
                  },
                  {
                    name: 'requireScreenLock',
                    label: 'Require a screen lock',
                    type: 'checkbox',
                    defaultValue: settings.requireScreenLock,
                  },
                  {
                    name: 'requireFirewall',
                    label: 'Require the firewall',
                    type: 'checkbox',
                    defaultValue: settings.requireFirewall,
                  },
                  {
                    name: 'requireEdr',
                    label: 'Require a healthy EDR agent',
                    type: 'checkbox',
                    defaultValue: settings.requireEdr,
                  },
                  {
                    name: 'blockJailbroken',
                    label: 'Refuse jailbroken or rooted devices',
                    type: 'checkbox',
                    defaultValue: settings.blockJailbroken,
                  },
                  {
                    name: 'maxCheckInAgeHours',
                    label: 'Check-in required within (hours)',
                    type: 'number',
                    required: true,
                    defaultValue: settings.maxCheckInAgeHours,
                    help: '1 to 720. A device whose integration has not reported it for longer is not compliant.',
                  },
                  ...Object.entries(platformLabels).map(([platform, label]) => ({
                    name: platform,
                    label: `Minimum ${label} version`,
                    group: 'minOsVersions',
                    defaultValue:
                      settings.minOsVersions[platform as keyof typeof platformLabels] ?? '',
                    placeholder: osVersionExamples[platform as keyof typeof osVersionExamples],
                  })),
                ]}
              />
            ) : (
              <KeyValues
                items={[
                  ['Disk encryption', settings.requireEncrypted ? 'required' : 'not required'],
                  ['Screen lock', settings.requireScreenLock ? 'required' : 'not required'],
                  ['Firewall', settings.requireFirewall ? 'required' : 'not required'],
                  ['Healthy EDR agent', settings.requireEdr ? 'required' : 'not required'],
                  ['Jailbroken or rooted', settings.blockJailbroken ? 'refused' : 'allowed'],
                  ['Check-in within', `${settings.maxCheckInAgeHours} h`],
                  [
                    'Minimum OS versions',
                    Object.keys(settings.minOsVersions).length ? (
                      Object.entries(settings.minOsVersions)
                        .map(
                          ([platform, version]) =>
                            `${platformLabels[platform as keyof typeof platformLabels] ?? platform} ${version}`,
                        )
                        .join(', ')
                    ) : (
                      <span key="o" className="muted">
                        none
                      </span>
                    ),
                  ],
                ]}
              />
            )}
          </Card>
          <div className="stack">
            {mayIntegrate && (
              <Card
                title="Add an integration"
                description="An MDM or EDR system that reports devices and their posture. Requires iam:devices:manage and a recent sign-in; at most 20."
              >
                <ApiForm
                  path="devices/createIntegration"
                  tenantId={tenantId}
                  submitLabel="Add integration"
                  resetOnSuccess
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'name',
                      label: 'Name',
                      required: true,
                      placeholder: 'Intune (corporate)',
                    },
                    {
                      name: 'vendor',
                      label: 'Vendor',
                      type: 'select',
                      required: true,
                      defaultValue: 'intune',
                      options: vendorOptions,
                    },
                    {
                      name: 'trustVendorCompliance',
                      label: "Trust the vendor's compliance verdict",
                      type: 'checkbox',
                      defaultValue: true,
                      help: 'A device the vendor reports as non-compliant is then non-compliant here too, on top of the requirements.',
                    },
                  ]}
                />
              </Card>
            )}
            <Alert tone="info">
              An integration reports devices with <code>devices.report</code>: give a{' '}
              <Link href={`${base}/service-accounts`}>service account</Link> a policy allowing{' '}
              <code>iam:devices:report</code> on{' '}
              <code>iam/devices/integrations/&#123;id&#125;</code>, issue it an API key, and have
              your connector post up to 500 devices per call to <code>/api/iam/devices/report</code>{' '}
              with <code>Authorization: Bearer</code>, <code>Content-Type: application/json</code>,
              and <code>X-Better-IAM: 1</code>. Devices are matched by the vendor&apos;s id; an
              owner email of a member assigns the device.
            </Alert>
          </div>
        </div>

        <Card
          title="Integrations"
          description="Disabling an integration makes its devices unmanaged (and so not compliant) until you enable it again."
          flush
        >
          {integrations ? (
            <Table
              head={[
                'Integration',
                'Vendor',
                'Status',
                'Vendor verdict',
                'Devices',
                'Last report',
                '',
              ]}
              rows={integrations.map((integration) => [
                <span key="n" className="stack" style={{ gap: 2 }}>
                  <strong>{integration.name}</strong>
                  <code className="small">{integration.id}</code>
                </span>,
                vendorLabels[integration.vendor] ?? integration.vendor,
                <Badge key="s" tone={integration.status === 'active' ? 'success' : 'warning'}>
                  {integration.status}
                </Badge>,
                integration.trustVendorCompliance ? (
                  <span key="t">trusted</span>
                ) : (
                  <span key="t" className="muted">
                    ignored
                  </span>
                ),
                integration.devices,
                integration.lastReportAt ? (
                  <Time key="r" value={integration.lastReportAt} />
                ) : (
                  <span key="r" className="muted">
                    never
                  </span>
                ),
                mayIntegrate ? (
                  <span key="a" className="actions">
                    <ApiButton
                      path="devices/updateIntegration"
                      body={{
                        tenantId,
                        integrationId: integration.id,
                        status: integration.status === 'active' ? 'disabled' : 'active',
                      }}
                      label={integration.status === 'active' ? 'Disable' : 'Enable'}
                      confirm={
                        integration.status === 'active' && integration.devices > 0
                          ? `Disable ${integration.name}? Its ${integration.devices} devices stop counting as managed or compliant, and its reports are refused.`
                          : undefined
                      }
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="devices/updateIntegration"
                      body={{
                        tenantId,
                        integrationId: integration.id,
                        trustVendorCompliance: !integration.trustVendorCompliance,
                      }}
                      label={integration.trustVendorCompliance ? 'Ignore verdict' : 'Trust verdict'}
                      tenantId={tenantId}
                    />
                    <details>
                      <summary className="small">Rename</summary>
                      <ApiForm
                        path="devices/updateIntegration"
                        tenantId={tenantId}
                        submitLabel="Rename"
                        compact
                        fields={[
                          {
                            name: 'tenantId',
                            label: 'Tenant',
                            type: 'hidden',
                            defaultValue: tenantId,
                          },
                          {
                            name: 'integrationId',
                            label: 'Integration',
                            type: 'hidden',
                            defaultValue: integration.id,
                          },
                          {
                            name: 'name',
                            label: 'Name',
                            required: true,
                            defaultValue: integration.name,
                          },
                        ]}
                      />
                    </details>
                    <ApiButton
                      path="devices/deleteIntegration"
                      body={{
                        tenantId,
                        integrationId: integration.id,
                        ...(integration.devices > 0 ? { detach: true } : {}),
                      }}
                      label="Delete"
                      tone="danger"
                      confirm={
                        integration.devices > 0
                          ? `Delete ${integration.name}? Its ${integration.devices} devices become unmanaged: they keep their keys and last posture but can no longer be compliant.`
                          : `Delete ${integration.name}?`
                      }
                      tenantId={tenantId}
                    />
                  </span>
                ) : (
                  ''
                ),
              ])}
              empty="No integrations. Without one, every device is unmanaged and none is compliant."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:devices:read</code>.
            </div>
          )}
        </Card>

        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card
            title="Enrollment codes"
            description={
              mayEnroll
                ? `One-time codes that let a person enrol a device key. ${pending.length} pending.`
                : undefined
            }
            flush
          >
            {enrollments ? (
              <Table
                head={['Status', 'Device', 'For', 'Expires', 'Created', 'Used', '']}
                rows={enrollments.map((enrollment) => [
                  <Badge key="s" tone={enrollmentTone[enrollment.status] ?? 'neutral'}>
                    {enrollment.status}
                  </Badge>,
                  enrollment.deviceId ? (
                    <Link key="d" href={`${base}/devices/${enrollment.deviceId}`}>
                      {deviceNames.get(enrollment.deviceId) ?? enrollment.deviceId}
                    </Link>
                  ) : (
                    <span key="d" className="muted">
                      a new device
                    </span>
                  ),
                  enrollment.ownerIdentityId ? (
                    nameOf(enrollment.ownerIdentityId)
                  ) : (
                    <span key="f" className="muted">
                      any member
                    </span>
                  ),
                  <Time key="e" value={enrollment.expiresAt} />,
                  <span key="c" className="stack" style={{ gap: 2 }}>
                    <Time value={enrollment.createdAt} />
                    <span className="small muted">by {nameOf(enrollment.createdBy)}</span>
                  </span>,
                  enrollment.usedAt ? (
                    <span key="u" className="stack" style={{ gap: 2 }}>
                      <Time value={enrollment.usedAt} />
                      {enrollment.usedBy && (
                        <span className="small muted">by {nameOf(enrollment.usedBy)}</span>
                      )}
                    </span>
                  ) : (
                    <span key="u" className="muted">
                      —
                    </span>
                  ),
                  <ApiButton
                    key="r"
                    path="devices/revokeEnrollment"
                    body={{ tenantId, enrollmentId: enrollment.id }}
                    label={enrollment.status === 'pending' ? 'Revoke' : 'Remove'}
                    tone={enrollment.status === 'pending' ? 'danger' : 'secondary'}
                    confirm={
                      enrollment.status === 'pending'
                        ? 'Revoke this code? Nobody can enrol with it afterwards.'
                        : undefined
                    }
                    tenantId={tenantId}
                  />,
                ])}
                empty="No enrollment codes."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:devices:manage</code>.
              </div>
            )}
          </Card>
          {mayEnroll && (
            <Card
              title="Create an enrollment code"
              description="The code registers a new device when used. To bind a key to an existing device, such as a managed laptop, create the code from that device's page."
            >
              <EnrollmentCodeForm
                tenantId={tenantId}
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'ownerIdentityId',
                    label: 'For',
                    type: 'select',
                    options: (people ?? [])
                      .filter((person) => person.status === 'active')
                      .map((person) => ({
                        value: person.id,
                        label: `${person.name}${person.email ? ` (${person.email})` : ''}`,
                      })),
                    help: 'Only this person can use the code, and the device becomes theirs. Leave empty for a shared device.',
                  },
                  enrollmentLifetimeField,
                ]}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
