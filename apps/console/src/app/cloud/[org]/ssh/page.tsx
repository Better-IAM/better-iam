import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const hostTone: Record<string, Tone> = { enrolled: 'success', pending: 'warning', disabled: 'danger' };
const certificateTone: Record<string, Tone> = { active: 'success', revoked: 'danger', expired: 'neutral' };
const authorityTone: Record<string, Tone> = {
  active: 'success',
  pending: 'info',
  previous: 'warning',
  retired: 'neutral',
};
const minutes = (ms: number) => Math.round(ms / 60_000);

export default async function SshAccess({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const status = await tryRead(() => iam.api.ssh.status(auth, { tenantId }));
  const hosts = await tryRead(() => iam.api.ssh.listHosts(auth, { tenantId }));
  const certificates = await tryRead(() =>
    iam.api.ssh.listCertificates(auth, { tenantId, kind: 'user', limit: 50 }),
  );
  const mine = await tryRead(() => iam.api.ssh.myAccess(auth, { tenantId }));
  const myCertificates = await tryRead(() => iam.api.ssh.myCertificates(auth, { tenantId }));
  const settings = status?.settings;
  return (
    <>
      <PageHeader
        title="SSH access"
        description="This organization's certificate authority for servers. People get short-lived SSH certificates for exactly the hosts and logins their policies allow (ssh:login on ssh-login/{host}/{login}); servers enroll once and refuse revoked certificates."
      />
      {status && !status.configured && (
        <Alert tone="info">
          The certificate authority is not set up yet.{' '}
          <ApiButton path="ssh/setup" body={{ tenantId }} label="Set up SSH authorities" tenantId={tenantId} />
        </Alert>
      )}
      {status && (
        <div className="tiles">
          <Stat label="Enrolled hosts" value={status.hosts.enrolled} hint={`${status.hosts.pending} waiting to enroll`} />
          <Stat label="Live user certificates" value={status.certificates.activeUser} />
          <Stat label="Revoked, not yet expired" value={status.certificates.revoked} hint="in the revocation list" />
          <Stat
            label="Host certificates ending soon"
            value={status.hostsExpiringSoon}
            hint="within 14 days; hosts renew at sync"
          />
        </div>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Your access" flush>
            {mine ? (
              <Table
                head={['Host', 'Logins', 'Forwarding', 'Labels']}
                rows={mine.hosts.map((host) => [
                  <span key="h" className="stack">
                    <code>{host.name}</code>
                    {host.addresses.length > 0 && (
                      <span className="small muted">{host.addresses.join(', ')}</span>
                    )}
                  </span>,
                  <code key="l" className="small">
                    {host.logins.join(', ')}
                  </code>,
                  <span key="f" className="small">
                    {[host.forwarding.port && 'ports', host.forwarding.agent && 'agent', host.forwarding.x11 && 'X11']
                      .filter(Boolean)
                      .join(', ') || '—'}
                  </span>,
                  <span key="t" className="small muted">
                    {Object.entries(host.labels)
                      .map(([name, value]) => `${name}=${value}`)
                      .join(' · ') || '—'}
                  </span>,
                ])}
                empty="No host allows you to log in yet."
              />
            ) : (
              <div className="empty">SSH access is not available in this organization.</div>
            )}
          </Card>
          <Card title="Hosts" flush>
            {hosts ? (
              <Table
                head={['Host', 'Status', 'Logins', 'Certificate', 'Last sync', '']}
                rows={hosts.map((host) => [
                  <span key="h" className="stack">
                    <code>{host.name}</code>
                    {host.description && <span className="small muted">{host.description}</span>}
                    {Object.keys(host.labels).length > 0 && (
                      <span className="small muted">
                        {Object.entries(host.labels)
                          .map(([name, value]) => `${name}=${value}`)
                          .join(' · ')}
                      </span>
                    )}
                  </span>,
                  <Badge key="s" tone={hostTone[host.status] ?? 'neutral'}>
                    {host.status}
                  </Badge>,
                  <code key="l" className="small">
                    {host.logins.join(', ')}
                  </code>,
                  host.certificateExpiresAt ? (
                    <span key="c" className="small">
                      until <Time value={host.certificateExpiresAt} />
                    </span>
                  ) : host.joinTokenExpiresAt ? (
                    <span key="c" className="small muted">
                      join token until <Time value={host.joinTokenExpiresAt} />
                    </span>
                  ) : (
                    '—'
                  ),
                  host.lastSeenAt ? <Time key="t" value={host.lastSeenAt} /> : '—',
                  <span key="a" className="actions">
                    <ApiButton
                      path="ssh/resetJoinToken"
                      body={{ tenantId, hostId: host.id }}
                      label={host.status === 'disabled' ? 'Re-enable' : 'New join token'}
                      confirm={`Issue a new join token for ${host.name}? Its current renewal token stops working until it re-enrolls.`}
                      tenantId={tenantId}
                      showResult
                    />
                    {host.status !== 'disabled' && (
                      <ApiButton
                        path="ssh/disableHost"
                        body={{ tenantId, hostId: host.id }}
                        label="Disable"
                        tone="danger"
                        confirm={`Disable ${host.name}? Its certificate is revoked and its key is published as revoked.`}
                        tenantId={tenantId}
                      />
                    )}
                    <ApiButton
                      path="ssh/deleteHost"
                      body={{ tenantId, hostId: host.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete ${host.name}?`}
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No hosts registered yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:ssh:read</code>.
              </div>
            )}
          </Card>
          <Card title="Recent certificates" flush>
            {certificates ? (
              <Table
                head={['Holder', 'Opens', 'Status', 'Valid until', '']}
                rows={certificates.certificates.map((certificate) => [
                  <span key="k" className="stack">
                    <span className="small">{certificate.keyId}</span>
                    {certificate.reason && <span className="small muted">{certificate.reason}</span>}
                  </span>,
                  <code key="p" className="small truncate">
                    {certificate.principals.join(', ')}
                  </code>,
                  <Badge key="s" tone={certificateTone[certificate.status] ?? 'neutral'}>
                    {certificate.revocationReason ?? certificate.status}
                  </Badge>,
                  <Time key="v" value={certificate.validBefore} />,
                  certificate.status === 'active' ? (
                    <ApiButton
                      key="r"
                      path="ssh/revokeCertificate"
                      body={{ tenantId, certificateId: certificate.id }}
                      label="Revoke"
                      tone="danger"
                      confirm="Revoke this certificate? Hosts refuse it from their next sync."
                      tenantId={tenantId}
                    />
                  ) : (
                    ''
                  ),
                ])}
                empty="No certificates issued yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:ssh:read</code>.
              </div>
            )}
          </Card>
          {myCertificates && myCertificates.length > 0 && (
            <Card title="Your certificates" flush>
              <Table
                head={['Opens', 'Status', 'Valid until', '']}
                rows={myCertificates.slice(0, 10).map((certificate) => [
                  <code key="p" className="small truncate">
                    {certificate.principals.join(', ')}
                  </code>,
                  <Badge key="s" tone={certificateTone[certificate.status] ?? 'neutral'}>
                    {certificate.revocationReason ?? certificate.status}
                  </Badge>,
                  <Time key="v" value={certificate.validBefore} />,
                  certificate.status === 'active' ? (
                    <ApiButton
                      key="r"
                      path="ssh/revokeCertificate"
                      body={{ tenantId, certificateId: certificate.id }}
                      label="Revoke"
                      tone="danger"
                      tenantId={tenantId}
                    />
                  ) : (
                    ''
                  ),
                ])}
              />
            </Card>
          )}
        </div>
        <div className="stack">
          {mine && (
            <Card
              title="Get a certificate"
              description="Paste your public key (~/.ssh/id_ed25519.pub). Save the result as id_ed25519-cert.pub next to it, or run better-iam ssh-cert."
            >
              <ApiForm
                path="ssh/issueCertificate"
                tenantId={tenantId}
                submitLabel="Issue certificate"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'publicKey',
                    label: 'Public key',
                    type: 'textarea',
                    rows: 3,
                    required: true,
                    placeholder: 'ssh-ed25519 AAAA... you@laptop',
                  },
                  { name: 'hosts', label: 'Hosts', type: 'list', placeholder: 'web-01, db-01', help: 'Default: every host you may open.' },
                  { name: 'logins', label: 'Logins', type: 'list', placeholder: 'deploy' },
                  {
                    name: 'ttlMs',
                    label: 'Lifetime in minutes',
                    type: 'number',
                    multiplier: 60_000,
                    placeholder: String(minutes(mine.defaultCertificateMs)),
                    help: `At most ${minutes(mine.maxCertificateMs)} minutes.`,
                  },
                  { name: 'reason', label: 'Reason', placeholder: 'Deploy release 42' },
                ]}
              />
            </Card>
          )}
          <Card
            title="Register a host"
            description="Requires iam:ssh:manage. You get a one-time join token: run better-iam ssh-host-enroll on the server with it."
          >
            <ApiForm
              path="ssh/createHost"
              tenantId={tenantId}
              submitLabel="Register host"
              showResult
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'web-01' },
                { name: 'logins', label: 'Logins', type: 'list', required: true, placeholder: 'deploy, ubuntu' },
                {
                  name: 'addresses',
                  label: 'Addresses',
                  type: 'list',
                  placeholder: 'web-01.corp.example.com, 10.0.0.5',
                },
                { name: 'labels', label: 'Labels', type: 'json', rows: 3, placeholder: '{ "environment": "staging" }' },
                { name: 'description', label: 'Description' },
              ]}
            />
          </Card>
          {settings && (
            <Card title="Settings" description="Requires iam:ssh:manage.">
              <ApiForm
                path="ssh/updateSettings"
                tenantId={tenantId}
                submitLabel="Save settings"
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'requireMfa',
                    label: 'People need an MFA session',
                    type: 'checkbox',
                    defaultValue: settings.requireMfa,
                  },
                  {
                    name: 'requireSecurityKey',
                    label: 'Only hardware security keys (ed25519-sk, ecdsa-sk)',
                    type: 'checkbox',
                    defaultValue: settings.requireSecurityKey,
                  },
                  {
                    name: 'requireUserVerification',
                    label: 'Security keys check a PIN at every login',
                    type: 'checkbox',
                    defaultValue: settings.requireUserVerification,
                  },
                  {
                    name: 'bindSourceAddress',
                    label: 'Certificates work only from the address that requested them',
                    type: 'checkbox',
                    defaultValue: settings.bindSourceAddress,
                  },
                  {
                    name: 'defaultCertificateMs',
                    label: 'Default lifetime (minutes)',
                    type: 'number',
                    multiplier: 60_000,
                    defaultValue: minutes(settings.defaultCertificateMs),
                  },
                  {
                    name: 'maxCertificateMs',
                    label: 'Longest lifetime (minutes)',
                    type: 'number',
                    multiplier: 60_000,
                    defaultValue: minutes(settings.maxCertificateMs),
                    help: `The deployment allows at most ${minutes(settings.deploymentMaxCertificateMs)}.`,
                  },
                  {
                    name: 'hostPatterns',
                    label: 'Host patterns',
                    type: 'list',
                    defaultValue: settings.hostPatterns,
                    placeholder: '*.corp.example.com',
                    help: 'known_hosts patterns the host authority may vouch for. Empty: exactly the enrolled names.',
                  },
                ]}
              />
            </Card>
          )}
          {status && status.authorities.length > 0 && (
            <Card title="Authorities" flush>
              <Table
                head={['Kind', 'Status', 'Fingerprint', '']}
                rows={status.authorities.map((authority) => [
                  authority.kind,
                  <Badge key="s" tone={authorityTone[authority.status] ?? 'neutral'}>
                    {authority.status}
                  </Badge>,
                  <code key="f" className="small truncate">
                    {authority.fingerprint}
                  </code>,
                  <span key="a" className="actions">
                    {authority.status === 'pending' && (
                      <ApiButton
                        path="ssh/activateAuthority"
                        body={{ tenantId, authorityId: authority.id }}
                        label="Activate"
                        confirm="Sign with this key from now on? Hosts that have not synced since it was published will refuse new certificates."
                        tenantId={tenantId}
                      />
                    )}
                    {authority.status === 'active' && (
                      <ApiButton
                        path="ssh/rotateAuthority"
                        body={{ tenantId, kind: authority.kind }}
                        label="Rotate"
                        confirm="Publish a new key? It is trusted from each host's next sync and signs once you activate it."
                        tenantId={tenantId}
                      />
                    )}
                    {authority.status === 'previous' && (
                      <ApiButton
                        path="ssh/retireAuthority"
                        body={{ tenantId, authorityId: authority.id }}
                        label="Retire"
                        tone="danger"
                        confirm="Stop trusting this key? Refused while certificates it signed are still valid."
                        tenantId={tenantId}
                      />
                    )}
                  </span>,
                ])}
              />
            </Card>
          )}
          <Alert tone="info">
            Servers enroll with <code>better-iam ssh-host-enroll</code> and then run{' '}
            <code>better-iam ssh-host-sync</code> every few minutes, which renews their certificate and fetches
            the revocation list. Hosts reach this console at <code>/api/iam/ssh/…</code>.
          </Alert>
        </div>
      </div>
    </>
  );
}
