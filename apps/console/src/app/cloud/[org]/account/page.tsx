import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { AccountLinking, MfaControls } from '@/components/account-forms';
import { PasskeyControls } from '@/components/passkeys';
import { AssuranceBadge, ComplianceBadge } from '@/components/device-posture';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { clientLine, describeClient } from '@/lib/device';
import { platformLabels } from '@/lib/device-posture';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Account({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, session } = await orgPage(org);
  const [sessions, links, devices, activity, status] = await Promise.all([
    iam.api.auth.listSessions(auth),
    iam.api.links.list(auth),
    iam.api.auth.listTrustedDevices(auth),
    iam.api.auth.listSecurityEvents(auth, { limit: 25 }),
    iam.api.auth.mfaStatus(auth),
  ]);
  // Registered devices (device posture), separate from the browsers remembered for MFA above.
  const registered = await tryRead(() => iam.api.devices.mine(auth, { tenantId }));
  const describe: Record<string, string> = {
    'auth:session:create': 'Signed in',
    'auth:session:revoke': 'Signed out / session ended',
    'auth:session:revoke-others': 'Signed out other sessions',
    'auth:password:change': 'Password changed',
    'auth:password:reset': 'Password reset',
    'auth:email:verify': 'Email verified',
    'auth:email:change': 'Email changed',
    'auth:phone:verify': 'Phone verified',
    'auth:mfa:enable': 'Authenticator enrolled',
    'auth:mfa:disable': 'Authenticator removed',
    'auth:mfa:recover': 'Recovery code used',
    'auth:mfa:recovery-codes': 'Recovery codes regenerated',
    'auth:passkey:create': 'Passkey added',
    'auth:passkey:delete': 'Passkey removed',
    'auth:device:trust': 'Device remembered',
    'auth:device:revoke': 'Device forgotten',
    'auth:identity:create': 'Account created',
    'auth:signin:fail': 'Failed sign-in attempt',
    'auth:session:mismatch': 'Session refused from another network',
  };
  const reasons: Record<string, string> = {
    password: 'wrong password',
    mfa: 'wrong authenticator or emailed code',
    'recovery-code': 'wrong recovery code',
  };
  const previous = session.session.previousSignIn;
  const client = clientLine;
  return (
    <>
      <PageHeader
        title="Your account"
        description="Sessions, password, multi-factor authentication, and the other organizations linked to you."
      />
      <div className="stack">
        <div className="grid cols-3">
          <Card title="Identity">
            <KeyValues
              items={[
                ['Name', session.identity.name],
                ['Email', session.identity.email ?? '—'],
                [
                  'Verified',
                  session.identity.emailVerified ? (
                    'yes'
                  ) : (
                    <span key="v" className="row">
                      <Badge tone="warning">no</Badge>
                      {session.identity.email && (
                        <ApiButton
                          path="auth/requestEmailVerification"
                          body={{ tenantId, email: session.identity.email }}
                          label="Resend verification email"
                          tenantId={tenantId}
                        />
                      )}
                    </span>
                  ),
                ],
                ['Owner', session.identity.owner ? 'yes' : 'no'],
                [
                  'This session',
                  <span key="m" className="row">
                    {session.session.mfa ? (
                      <Badge tone="success">MFA verified</Badge>
                    ) : (
                      <Badge>password only</Badge>
                    )}
                    {session.session.trustedDeviceId && (
                      <Badge tone="accent">remembered device</Badge>
                    )}
                  </span>,
                ],
                [
                  'Previous sign-in',
                  previous?.lastAt ? (
                    <span key="p">
                      <Time value={previous.lastAt} />
                      {previous.lastClient && (
                        <span className="small muted"> {client(previous.lastClient)}</span>
                      )}
                    </span>
                  ) : (
                    <span className="muted">none before this one</span>
                  ),
                ],
                [
                  'Failed attempts since',
                  previous && previous.failedAttempts > 0 ? (
                    <span key="f" className="row">
                      <Badge tone="warning">{previous.failedAttempts}</Badge>
                      {previous.lastFailedAt && (
                        <span className="small muted">
                          latest <Time value={previous.lastFailedAt} />
                          {previous.lastFailedClient ? ` ${client(previous.lastFailedClient)}` : ''}
                        </span>
                      )}
                    </span>
                  ) : (
                    '0'
                  ),
                ],
              ]}
            />
          </Card>
          <Card title="Change password" description="Revokes your other sessions.">
            <ApiForm
              path="auth/changePassword"
              tenantId={tenantId}
              submitLabel="Change password"
              compact
              successMessage="Password changed. Sign in again on other devices."
              fields={[
                {
                  name: 'currentPassword',
                  label: 'Current password',
                  type: 'password',
                  required: true,
                },
                {
                  name: 'password',
                  label: 'New password',
                  type: 'password',
                  required: true,
                  help: 'At least 12 characters.',
                },
              ]}
            />
          </Card>
          <Card title="Multi-factor authentication">
            <MfaControls tenantId={tenantId} mfa={session.session.mfa} />
            {status.enabled && (
              <p className="small muted" style={{ marginTop: 12 }}>
                {status.recoveryCodesRemaining} recovery code
                {status.recoveryCodesRemaining === 1 ? '' : 's'} left
                {status.recoveryCodesRemaining < 3 ? ' — generate new ones soon.' : '.'}
              </p>
            )}
          </Card>
        </div>
        <Card
          title="Passkeys"
          description="Sign in with Face ID, Touch ID, Windows Hello, or a security key, and use the same passkey instead of an authenticator code when a second factor is required."
        >
          <PasskeyControls tenantId={tenantId} />
        </Card>
        <Card
          title="Change email"
          description="We send a confirmation link to the new address; nothing changes until you open it. Requires recent authentication."
        >
          <ApiForm
            path="auth/requestEmailChange"
            tenantId={tenantId}
            submitLabel="Send confirmation"
            compact
            resetOnSuccess
            successMessage="Check the new address for a confirmation link (valid for ten minutes)."
            fields={[
              {
                name: 'email',
                label: 'New email address',
                type: 'email',
                required: true,
                placeholder: session.identity.email ?? 'you@example.com',
              },
            ]}
          />
        </Card>
        <div className="grid cols-2">
          <Card
            title="Active sessions"
            flush
            actions={
              sessions.length > 1 && (
                <ApiButton
                  path="auth/revokeOtherSessions"
                  body={{}}
                  label="Sign out other sessions"
                  tone="danger"
                  confirm="End every other session of your account in this organization?"
                  tenantId={tenantId}
                />
              )
            }
          >
            <Table
              head={['Session', 'Device', 'Method', 'Created', 'Last seen', 'Expires', 'MFA', '']}
              rows={sessions.map((item) => [
                <span key="s">
                  {item.id === session.session.id ? (
                    <Badge tone="accent">this browser</Badge>
                  ) : (
                    <code className="small">{item.id}</code>
                  )}
                </span>,
                <span key="d" className="small" title={item.client?.userAgent}>
                  {describeClient(item.client) ?? '—'}
                  {item.client?.ip && item.client.ip !== describeClient(item.client) && (
                    <span className="muted"> · {item.client.ip}</span>
                  )}
                </span>,
                item.impersonatorId ? (
                  <Badge key="m" tone="warning">
                    support · {item.impersonatorId}
                  </Badge>
                ) : (
                  (item.method ?? <span className="muted">—</span>)
                ),
                <Time key="c" value={item.createdAt} />,
                <Time key="l" value={item.lastSeenAt} />,
                <Time key="e" value={item.expiresAt} />,
                item.mfa ? 'yes' : 'no',
                item.id !== session.session.id && (
                  <ApiButton
                    key="r"
                    path="auth/revokeSession"
                    body={{ sessionId: item.id }}
                    label="Revoke"
                    tone="danger"
                    tenantId={tenantId}
                  />
                ),
              ])}
            />
          </Card>
          <Card
            title="Linked accounts"
            description="Your identities in other organizations. A link never merges permissions; switching always signs in to the target organization."
          >
            <Table
              head={['Organization', 'Identity', 'Status', '']}
              rows={links.map((link) => [
                <span key="o">
                  {link.tenantName}
                  {link.tenantSlug && <code className="small"> · {link.tenantSlug}</code>}
                </span>,
                link.email ?? link.name,
                <Badge
                  key="s"
                  tone={
                    link.status === 'active' && link.tenantStatus === 'active'
                      ? 'success'
                      : 'warning'
                  }
                >
                  {link.tenantStatus === 'active' ? link.status : link.tenantStatus}
                </Badge>,
                <span key="a" className="actions">
                  {link.tenantStatus === 'active' && (
                    <Link
                      className="btn small"
                      href={`/cloud/login?org=${encodeURIComponent(link.tenantSlug ?? link.tenantId)}`}
                    >
                      Switch
                    </Link>
                  )}
                  <ApiButton
                    path="links/revoke"
                    body={{ linkId: link.id }}
                    label="Unlink"
                    tone="danger"
                    tenantId={tenantId}
                  />
                </span>,
              ])}
              empty="No linked accounts."
            />
            <div style={{ marginTop: 16 }}>
              <AccountLinking />
            </div>
          </Card>
        </div>
        <Card
          title="Remembered devices"
          description="Browsers where you chose “remember this device” after MFA; they skip the code until they expire or you forget them. Changing your password or your factors forgets them all."
          flush
          actions={
            devices.length > 0 && (
              <ApiButton
                path="auth/revokeTrustedDevices"
                body={{}}
                label="Forget all devices"
                tone="danger"
                confirm="Ask for an authenticator code on every device again?"
                tenantId={tenantId}
              />
            )
          }
        >
          <Table
            head={['Device', 'Remembered', 'Last used', 'Expires', '']}
            rows={devices.map((device) => [
              <span key="d" className="small" title={device.client?.userAgent}>
                {device.id === session.session.trustedDeviceId && (
                  <>
                    <Badge tone="accent">this browser</Badge>{' '}
                  </>
                )}
                {clientLine(device.client) || device.id}
              </span>,
              <Time key="c" value={device.createdAt} />,
              <Time key="l" value={device.lastUsedAt} />,
              <Time key="e" value={device.expiresAt} />,
              <ApiButton
                key="r"
                path="auth/revokeTrustedDevice"
                body={{ deviceId: device.id }}
                label="Forget"
                tone="danger"
                tenantId={tenantId}
              />,
            ])}
            empty="No remembered devices."
          />
        </Card>
        <Card
          title="Registered devices"
          description="Devices that prove requests come from them with a signed key: ones you enrolled from applications that use device proofs, and ones your organization's device management assigns to you. Policies can require a registered, managed, or compliant device."
          flush
        >
          {registered ? (
            <Table
              head={['Device', 'Assurance', 'Compliance', 'Registered', 'Last seen', '']}
              rows={registered.map((device) => [
                <span key="d" className="stack" style={{ gap: 2 }}>
                  <span className="row" style={{ gap: 6 }}>
                    {device.current && <Badge tone="accent">this device</Badge>}
                    {device.name}
                    {device.status === 'lost' && <Badge tone="danger">lost</Badge>}
                  </span>
                  <span className="small muted">
                    {[
                      platformLabels[device.platform],
                      device.model,
                      device.source ? 'managed by your organization' : undefined,
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                  </span>
                </span>,
                <AssuranceBadge key="a" assurance={device.assurance} />,
                <ComplianceBadge key="c" compliance={device.compliance} />,
                <Time key="r" value={device.createdAt} />,
                <Time key="l" value={device.lastSeenAt ?? device.lastCheckInAt} />,
                !device.source && !session.session.impersonatorId ? (
                  <ApiButton
                    key="x"
                    path="devices/retireMine"
                    body={{ tenantId, deviceId: device.id }}
                    label="Retire"
                    tone="danger"
                    confirm={`Retire ${device.name}? It stops proving anything and its keys are deleted; enrol it again to use it.`}
                    tenantId={tenantId}
                  />
                ) : (
                  ''
                ),
              ])}
              empty="No registered devices."
            />
          ) : (
            <div className="empty">Your registered devices cannot be listed from this session.</div>
          )}
        </Card>
        <Card
          title="Recent security activity"
          description="Your own authentication trail: sign-ins, failed attempts, sign-outs, password and factor changes, and remembered devices. Entries marked “via” were performed by an administrator viewing as you."
          flush
        >
          <Table
            head={['When', 'Event', 'Detail']}
            rows={activity.map((event) => {
              const meta = (event.metadata ?? {}) as Record<string, unknown>;
              const text = (key: string) => (typeof meta[key] === 'string' ? meta[key] : undefined);
              const details = [
                text('reason') ? (reasons[text('reason')!] ?? text('reason')) : undefined,
                text('method'),
                client({ ip: text('ip'), userAgent: text('userAgent') }) || undefined,
              ].filter(Boolean);
              return [
                <Time key="t" value={event.timestamp} />,
                event.action === 'auth:signin:fail' ? (
                  <Badge key="a" tone="warning">
                    {describe[event.action]}
                  </Badge>
                ) : (
                  (describe[event.action] ?? <code key="a">{event.action}</code>)
                ),
                <span key="d" className="row">
                  {details.length > 0 && (
                    <span className="small muted" title={text('userAgent')}>
                      {details.join(' · ')}
                    </span>
                  )}
                  {event.impersonatorId && <Badge tone="warning">via {event.impersonatorId}</Badge>}
                </span>,
              ];
            })}
            empty="No activity yet."
          />
        </Card>
        <Alert tone="info">
          Sensitive changes ask you to confirm your password (and authenticator) again; Better IAM
          requires recent authentication for them.
        </Alert>
      </div>
    </>
  );
}
