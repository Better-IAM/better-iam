import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { secretHref } from '@/lib/vault';

export default async function Vault({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ prefix?: string }>;
}) {
  const { org } = await params;
  const { prefix } = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const listed = await tryRead(() =>
    iam.api.vault.list(auth, {
      tenantId,
      status: 'all',
      limit: 500,
      ...(prefix ? { prefix } : {}),
    }),
  );
  const mine = (await tryRead(() => iam.api.vault.listMine(auth, { tenantId }))) ?? [];
  const secrets = listed?.secrets ?? [];
  const due = secrets.filter((secret) => secret.rotation?.due).length;
  const checkedOut = secrets.filter((secret) => secret.checkedOut.length > 0).length;
  const failing = secrets.filter((secret) => secret.rotation?.lastFailure).length;
  return (
    <>
      <PageHeader
        title="Vault"
        description="Secrets your people, services, and agents use: versioned, rotated, checked out one holder at a time, or minted per caller. Access is decided by policies on iam/vault/secrets/{name}, and every value handed out is audited."
      />
      <div className="tiles">
        <Stat label="Secrets" value={listed ? listed.total : '—'} hint="that you may read" />
        <Stat label="Rotation due" value={due} hint={failing ? `${failing} failing` : undefined} />
        <Stat label="Checked out" value={checkedOut} />
        <Stat label="Your check-outs and leases" value={mine.length} />
      </div>
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card
            title="Secrets"
            flush
            actions={
              <form className="row" method="get">
                <input
                  className="input"
                  name="prefix"
                  defaultValue={prefix ?? ''}
                  placeholder="Filter by path, e.g. prod/"
                  aria-label="Filter by path"
                />
                <button className="btn small secondary">Filter</button>
              </form>
            }
          >
            {listed ? (
              <Table
                head={['Secret', 'Kind', 'Version', 'Rotation', 'Last used']}
                rows={secrets.map((secret) => [
                  <span key="n" className="stack">
                    <Link href={secretHref(base, secret.name)}>
                      <code>{secret.name}</code>
                    </Link>
                    {secret.description && (
                      <span className="small muted truncate">{secret.description}</span>
                    )}
                    {Object.keys(secret.tags).length > 0 && (
                      <span className="small muted">
                        {Object.entries(secret.tags)
                          .map(([name, value]) => `${name}=${value}`)
                          .join(' · ')}
                      </span>
                    )}
                  </span>,
                  <span key="k" className="stack">
                    <span className="row">
                      <Badge tone={secret.kind === 'dynamic' ? 'accent' : 'neutral'}>
                        {secret.kind}
                      </Badge>
                      {secret.format === 'json' && <Badge>json</Badge>}
                      {secret.kmsKeyId && <Badge tone="info">customer key</Badge>}
                    </span>
                    {secret.status === 'pending-deletion' && (
                      <Badge tone="danger">deleting</Badge>
                    )}
                    {secret.checkout?.required && (
                      <span className="small muted">
                        check-out{secret.checkout.exclusive ? ', exclusive' : ''}
                      </span>
                    )}
                    {secret.checkedOut.length > 0 && <Badge tone="warning">checked out</Badge>}
                  </span>,
                  secret.kind === 'dynamic' ? (
                    <span key="v" className="muted">
                      {secret.activeLeases} live
                    </span>
                  ) : secret.stages.current !== undefined ? (
                    <span key="v">v{secret.stages.current}</span>
                  ) : (
                    <span key="v" className="muted">
                      no value
                    </span>
                  ),
                  secret.rotation?.intervalDays ? (
                    <span key="r" className="stack">
                      <span>every {secret.rotation.intervalDays} days</span>
                      {secret.rotation.lastFailure ? (
                        <Badge tone="danger">failing</Badge>
                      ) : secret.rotation.due ? (
                        <Badge tone="warning">due</Badge>
                      ) : (
                        <span className="small muted">
                          next <Time value={secret.rotation.nextRotationAt} />
                        </span>
                      )}
                    </span>
                  ) : (
                    <span key="r" className="muted">
                      {secret.kind === 'dynamic' ? 'per lease' : 'on demand'}
                    </span>
                  ),
                  <Time key="u" value={secret.lastAccessedAt} />,
                ])}
                empty={prefix ? 'No secrets under this path.' : 'No secrets yet.'}
              />
            ) : (
              <div className="empty">Could not list secrets.</div>
            )}
          </Card>
          {mine.length > 0 && (
            <Card title="Your check-outs and leases" flush>
              <Table
                head={['Secret', 'Kind', 'Until']}
                rows={mine.map((lease) => [
                  <Link key="n" href={secretHref(base, lease.name)}>
                    <code>{lease.name}</code>
                  </Link>,
                  <span key="k">{lease.kind === 'checkout' ? 'check-out' : 'dynamic lease'}</span>,
                  <Time key="u" value={lease.expiresAt} />,
                ])}
              />
            </Card>
          )}
        </div>
        <div className="stack">
          <Card
            title="Add a secret"
            description="Requires iam:vault:manage on iam/vault/secrets/{name}. Leave the value empty and tick Generate for a random one."
          >
            <ApiForm
              path="vault/create"
              tenantId={tenantId}
              submitLabel="Add secret"
              redirectTo={`${base}/vault/{name}`}
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'name',
                  label: 'Name',
                  required: true,
                  placeholder: 'prod/payments/db-password',
                  help: 'Path segments separated by /. Policies grant by path: iam/vault/secrets/prod/*.',
                },
                { name: 'description', label: 'Description' },
                {
                  name: 'format',
                  label: 'Format',
                  type: 'select',
                  required: true,
                  defaultValue: 'text',
                  options: [
                    { value: 'text', label: 'Text' },
                    { value: 'json', label: 'JSON object (fields)' },
                  ],
                },
                {
                  name: 'value',
                  label: 'Value',
                  type: 'password',
                  help: 'For JSON secrets, a JSON object such as {"username":"app","password":"…"}.',
                },
                { name: 'generate', label: 'Generate a random value (32 characters)', type: 'checkbox' },
                {
                  name: 'tags',
                  label: 'Tags',
                  type: 'json',
                  rows: 3,
                  placeholder: '{ "environment": "prod", "team": "payments" }',
                  help: 'Policies read them as resource.tag.{name}.',
                },
                {
                  name: 'rotation',
                  label: 'Rotation',
                  type: 'json',
                  rows: 3,
                  placeholder: '{ "intervalDays": 30, "generator": { "length": 32, "charset": "ascii" } }',
                  help: 'Add "rotator": "<name>" to apply new values through a configured rotator; json secrets name the "field" to replace.',
                },
                {
                  name: 'checkout',
                  label: 'Check-out policy',
                  type: 'json',
                  rows: 3,
                  placeholder: '{ "exclusive": true, "rotateOnCheckin": true, "requireReason": true }',
                  help: 'For shared credentials: values are then handed out only through check-outs.',
                },
                {
                  name: 'kmsKey',
                  label: 'Customer-managed key',
                  placeholder: 'alias/vault',
                  help: 'Encrypt values under one of your KMS keys (needs iam:kms:encrypt on it).',
                },
              ]}
            />
          </Card>
          <Alert tone="info">
            Grant access with policies on <code>iam/vault/secrets/&#123;name&#125;</code>:{' '}
            <code>iam:vault:read</code> for metadata, <code>iam:vault:reveal</code> for values,{' '}
            <code>iam:vault:lease</code> for check-outs and dynamic credentials, and{' '}
            <code>iam:vault:write</code> / <code>iam:vault:manage</code> to change them. Conditions can
            use <code>resource.tag.environment</code> and friends.
          </Alert>
          <Alert tone="warning">
            Dynamic secrets and rotators are configured on the deployment (<code>vault.engines</code>,{' '}
            <code>vault.rotators</code>); create dynamic secrets through the API.
          </Alert>
        </div>
      </div>
    </>
  );
}
