import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time, type Tone } from '@/components/ui';
import { CheckoutSecret, LeaseSecret, RevealSecret } from '@/components/vault-actions';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const versionTone: Record<string, Tone> = {
  enabled: 'success',
  disabled: 'warning',
  destroyed: 'danger',
};

const leaseTone: Record<string, Tone> = {
  active: 'success',
  issuing: 'info',
  revoking: 'warning',
  failed: 'danger',
};

const actionLabel: Record<string, string> = {
  reveal: 'Revealed',
  checkout: 'Checked out',
  checkin: 'Checked in',
  lease: 'Leased',
  renew: 'Renewed',
  revoke: 'Revoked',
  put: 'New version',
  rotate: 'Rotated',
  share: 'Shared',
};

const minutes = (ms: number) =>
  ms % 3_600_000 === 0 ? `${ms / 3_600_000} h` : `${Math.round(ms / 60_000)} min`;

export default async function VaultSecret({
  params,
}: {
  params: Promise<{ org: string; name: string[] }>;
}) {
  const { org, name: segments } = await params;
  const name = segments.map((segment) => decodeURIComponent(segment)).join('/');
  const { iam, auth, tenantId, base } = await orgPage(org);
  const secret = await tryRead(() => iam.api.vault.get(auth, { tenantId, name }));
  if (!secret)
    return (
      <>
        <PageHeader title={<code>{name}</code>} />
        <Alert tone="warning">
          This secret does not exist, or reading it requires <code>iam:vault:read</code> on{' '}
          <code>iam/vault/secrets/{name}</code>. <Link href={`${base}/vault`}>Back to the vault</Link>
        </Alert>
      </>
    );
  const [versions, leases, log] = await Promise.all([
    secret.kind === 'static'
      ? tryRead(() => iam.api.vault.listVersions(auth, { tenantId, name }))
      : Promise.resolve([]),
    tryRead(() => iam.api.vault.listLeases(auth, { tenantId, name, includeEnded: true })),
    tryRead(() => iam.api.vault.accessLog(auth, { tenantId, name, limit: 50 })),
  ]);
  const deleting = secret.status === 'pending-deletion';
  const rotation = secret.rotation;
  const checkout = secret.checkout;
  return (
    <>
      <PageHeader
        title={<code>{secret.name}</code>}
        description={secret.description}
        actions={
          <>
            <Link className="btn small secondary" href={`${base}/vault`}>
              All secrets
            </Link>
            {!deleting && secret.kind === 'static' && (
              <ApiButton
                path="vault/rotate"
                body={{ tenantId, name }}
                label="Rotate now"
                confirm={`Rotate ${name}? A new value becomes current${rotation?.rotator ? ` after the ${rotation.rotator} rotator applies it` : ''}.`}
                tenantId={tenantId}
              />
            )}
          </>
        }
      />
      {deleting && (
        <Alert tone="danger">
          Scheduled for deletion on <Time value={secret.deletionAt} />. It cannot be read until it is
          restored.{' '}
          <ApiButton
            path="vault/restore"
            body={{ tenantId, name }}
            label="Restore"
            tenantId={tenantId}
          />
        </Alert>
      )}
      {rotation?.lastFailure && (
        <Alert tone="danger">
          The last rotation failed <Time value={rotation.lastFailure.at} />:{' '}
          {rotation.lastFailure.message}. The pending version waits for the next attempt.
        </Alert>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          {!deleting && (
            <Card
              title={secret.kind === 'dynamic' ? 'Credential' : checkout?.required ? 'Check out' : 'Value'}
              description={
                secret.kind === 'dynamic'
                  ? `Each request mints a credential through the ${secret.engine} engine, valid for ${minutes(secret.lease?.defaultTtlMs ?? 3_600_000)}. Requires iam:vault:lease.`
                  : checkout?.required
                    ? `Handed out only through check-outs${checkout.exclusive ? ', one holder at a time' : ''}${checkout.rotateOnCheckin ? ', rotated when returned' : ''}. Requires iam:vault:lease.`
                    : 'Requires iam:vault:reveal. Values never leave through “view as” sessions.'
              }
            >
              {secret.kind === 'dynamic' ? (
                <LeaseSecret tenantId={tenantId} name={name} />
              ) : secret.stages.current === undefined ? (
                <div className="empty">No value yet: add a version.</div>
              ) : checkout?.required ? (
                <CheckoutSecret
                  tenantId={tenantId}
                  name={name}
                  requireReason={checkout.requireReason}
                  maxDurationMinutes={Math.floor(checkout.maxDurationMs / 60_000)}
                />
              ) : (
                <RevealSecret tenantId={tenantId} name={name} />
              )}
            </Card>
          )}
          {secret.kind === 'static' && (
            <Card title="Versions" flush>
              {versions ? (
                <Table
                  head={['Version', 'State', 'Stages', 'Source', 'Created', '']}
                  rows={versions.map((version) => [
                    <strong key="v">v{version.version}</strong>,
                    <Badge key="s" tone={versionTone[version.state] ?? 'neutral'}>
                      {version.state}
                    </Badge>,
                    <span key="t" className="row">
                      {version.stages.map((stage) => (
                        <Badge key={stage} tone={stage === 'current' ? 'accent' : 'neutral'}>
                          {stage}
                        </Badge>
                      ))}
                    </span>,
                    <span key="o" className="small">
                      {version.source}
                    </span>,
                    <Time key="c" value={version.createdAt} />,
                    deleting || version.state === 'destroyed' ? (
                      <span key="a" />
                    ) : (
                      <span key="a" className="row">
                        {!version.stages.includes('current') && version.state === 'enabled' && (
                          <ApiButton
                            path="vault/promote"
                            body={{ tenantId, name, version: version.version }}
                            label="Make current"
                            tenantId={tenantId}
                          />
                        )}
                        {!version.stages.includes('current') && (
                          <ApiButton
                            path="vault/setVersionState"
                            body={{
                              tenantId,
                              name,
                              version: version.version,
                              state: version.state === 'enabled' ? 'disabled' : 'enabled',
                            }}
                            label={version.state === 'enabled' ? 'Disable' : 'Enable'}
                            tenantId={tenantId}
                          />
                        )}
                        {!version.stages.includes('current') && (
                          <ApiButton
                            path="vault/destroyVersion"
                            body={{ tenantId, name, version: version.version }}
                            label="Destroy"
                            tone="danger"
                            confirm={`Destroy version ${version.version} of ${name}? Its value is erased for good.`}
                            tenantId={tenantId}
                          />
                        )}
                      </span>
                    ),
                  ])}
                  empty="No versions yet."
                />
              ) : (
                <div className="empty">Could not list versions.</div>
              )}
            </Card>
          )}
          <Card title="Check-outs and leases" flush>
            {leases ? (
              <Table
                head={['Holder', 'Kind', 'State', 'Issued', 'Until', '']}
                rows={leases.map((lease) => [
                  <span key="h" className="stack">
                    <span>{lease.holderName ?? lease.holderId}</span>
                    {lease.reason && <span className="small muted">{lease.reason}</span>}
                  </span>,
                  <span key="k">
                    {lease.kind === 'checkout' ? `check-out${lease.version ? ` v${lease.version}` : ''}` : 'lease'}
                  </span>,
                  <span key="s" className="stack">
                    <Badge tone={leaseTone[lease.state] ?? 'neutral'}>{lease.state}</Badge>
                    {lease.lastError && <span className="small muted">{lease.lastError}</span>}
                  </span>,
                  <Time key="i" value={lease.issuedAt} />,
                  <Time key="u" value={lease.endedAt ?? lease.expiresAt} />,
                  lease.state === 'active' || lease.state === 'revoking' ? (
                    <ApiButton
                      key="r"
                      path="vault/revokeLease"
                      body={{ tenantId, leaseId: lease.id }}
                      label={lease.kind === 'checkout' ? 'End' : 'Revoke'}
                      tone="danger"
                      tenantId={tenantId}
                    />
                  ) : (
                    <span key="r" />
                  ),
                ])}
                empty="Nobody has checked this secret out or leased it."
              />
            ) : (
              <div className="empty">Could not list leases.</div>
            )}
          </Card>
          <Card title="Access log" description="Who used this secret, newest first." flush>
            {log ? (
              <Table
                head={['When', 'Who', 'What', 'Version']}
                rows={log.map((entry) => [
                  <Time key="t" value={entry.at} />,
                  <span key="w" className="stack">
                    <span>{entry.identityName ?? entry.identityId}</span>
                    {entry.agentId && <span className="small muted">through agent {entry.agentId}</span>}
                    {entry.sessionKind && entry.sessionKind !== 'user' && (
                      <span className="small muted">{entry.sessionKind} session</span>
                    )}
                  </span>,
                  <span key="a">{actionLabel[entry.action] ?? entry.action}</span>,
                  <span key="v">{entry.version !== undefined ? `v${entry.version}` : '—'}</span>,
                ])}
                empty="Nobody has used this secret yet."
              />
            ) : (
              <div className="empty">Could not read the access log.</div>
            )}
          </Card>
        </div>
        <div className="stack">
          <Card title="Details">
            <KeyValues
              items={[
                ['Kind', `${secret.kind} · ${secret.format}`],
                ['Status', <Badge key="s" tone={deleting ? 'danger' : 'success'}>{secret.status}</Badge>],
                [
                  'Tags',
                  Object.keys(secret.tags).length ? (
                    <span key="t" className="small">
                      {Object.entries(secret.tags)
                        .map(([key, value]) => `${key}=${value}`)
                        .join(' · ')}
                    </span>
                  ) : (
                    <span key="t" className="muted">none</span>
                  ),
                ],
                ...(secret.kind === 'static'
                  ? ([
                      ['Current version', secret.stages.current ? `v${secret.stages.current}` : '—'],
                      ['Versions kept', String(secret.maxVersions)],
                    ] as [string, string][])
                  : ([
                      ['Engine', secret.engine ?? '—'],
                      [
                        'Lease',
                        secret.lease
                          ? `${minutes(secret.lease.defaultTtlMs)}, at most ${minutes(secret.lease.maxTtlMs)}`
                          : '—',
                      ],
                      ['Live leases', String(secret.activeLeases)],
                    ] as [string, string][])),
                [
                  'Encryption',
                  secret.kmsKeyId ? (
                    <Link key="k" href={`${base}/keys/${secret.kmsKeyId}`}>
                      customer-managed key
                    </Link>
                  ) : (
                    'deployment secret'
                  ),
                ],
                [
                  'Rotation',
                  rotation?.intervalDays ? (
                    <span key="r" className="stack">
                      <span>
                        every {rotation.intervalDays} days
                        {rotation.rotator ? ` through ${rotation.rotator}` : ''}
                        {!rotation.rotator && !rotation.generator ? ' (manual)' : ''}
                      </span>
                      <span className="small muted">
                        {rotation.due ? 'due now' : <>next <Time value={rotation.nextRotationAt} /></>}
                      </span>
                    </span>
                  ) : (
                    'on demand'
                  ),
                ],
                ['Last rotated', <Time key="lr" value={rotation?.lastRotatedAt} />],
                [
                  'Check-out',
                  checkout ? (
                    <span key="c" className="small">
                      {[
                        checkout.required ? 'required' : 'optional',
                        checkout.exclusive ? 'exclusive' : undefined,
                        `up to ${minutes(checkout.maxDurationMs)}`,
                        checkout.rotateOnCheckin ? 'rotates on return' : undefined,
                        checkout.requireReason ? 'reason required' : undefined,
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  ) : (
                    '—'
                  ),
                ],
                ['Last used', <Time key="lu" value={secret.lastAccessedAt} />],
                ['Created', <Time key="c" value={secret.createdAt} />],
                ['Updated', <Time key="u" value={secret.updatedAt} />],
              ]}
            />
          </Card>
          {!deleting && secret.kind === 'static' && (
            <Card title="New version" description="Requires iam:vault:write.">
              <ApiForm
                path="vault/put"
                tenantId={tenantId}
                submitLabel="Save version"
                resetOnSuccess
                successMessage="Saved."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Name', type: 'hidden', defaultValue: name },
                  {
                    name: 'value',
                    label: 'Value',
                    type: 'password',
                    help: secret.format === 'json' ? 'A JSON object.' : undefined,
                  },
                  { name: 'generate', label: 'Generate a random value instead', type: 'checkbox' },
                  {
                    name: 'stage',
                    label: 'Stage',
                    type: 'select',
                    required: true,
                    defaultValue: 'current',
                    options: [
                      { value: 'current', label: 'Current (live now)' },
                      { value: 'pending', label: 'Pending (promote later)' },
                    ],
                  },
                ]}
              />
            </Card>
          )}
          {!deleting && (
            <Card title="Settings" description="Requires iam:vault:manage. Empty fields keep their value.">
              <ApiForm
                path="vault/update"
                tenantId={tenantId}
                submitLabel="Save settings"
                successMessage="Saved."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Name', type: 'hidden', defaultValue: name },
                  { name: 'description', label: 'Description', defaultValue: secret.description ?? '' },
                  {
                    name: 'tags',
                    label: 'Tags',
                    type: 'json',
                    rows: 3,
                    defaultValue: JSON.stringify(secret.tags),
                  },
                  ...(secret.kind === 'static'
                    ? [
                        {
                          name: 'maxVersions',
                          label: 'Versions to keep',
                          type: 'number' as const,
                          defaultValue: secret.maxVersions,
                        },
                        {
                          name: 'rotation',
                          label: 'Rotation',
                          type: 'json' as const,
                          rows: 3,
                          placeholder: '{ "intervalDays": 30, "generator": true }',
                          help: 'Replaces the rotation settings; null turns rotation off.',
                        },
                        {
                          name: 'checkout',
                          label: 'Check-out policy',
                          type: 'json' as const,
                          rows: 3,
                          placeholder: '{ "required": true, "exclusive": true }',
                          help: 'Replaces the policy; null removes it.',
                        },
                        {
                          name: 'kmsKey',
                          label: 'Customer-managed key',
                          placeholder: secret.kmsKeyId ?? 'alias/vault',
                          help: 'Moving to another key re-encrypts every kept version.',
                        },
                      ]
                    : []),
                ]}
              />
            </Card>
          )}
          {!deleting && (
            <Card title="Delete">
              <p className="small muted">
                The secret can be restored for 30 days; after that it is deleted with every version.
              </p>
              <ApiButton
                path="vault/delete"
                body={{ tenantId, name }}
                label="Schedule deletion"
                tone="danger"
                confirm={`Schedule ${name} for deletion? It cannot be read during the 30-day recovery window.`}
                tenantId={tenantId}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
