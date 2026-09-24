import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const stateTone: Record<string, Tone> = {
  enabled: 'success',
  disabled: 'warning',
  'pending-deletion': 'danger',
};

const usageLabel: Record<string, string> = {
  encrypt: 'Encrypt / decrypt',
  sign: 'Sign / verify',
  mac: 'MAC',
};

export default async function Keys({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const listed = await tryRead(() => iam.api.keys.list(auth, { tenantId, limit: 500 }));
  const keys = listed?.keys ?? [];
  const count = (state: string) => keys.filter((key) => key.state === state).length;
  const rotating = keys.filter((key) => key.rotationPeriodDays !== undefined).length;
  return (
    <>
      <PageHeader
        title="Keys"
        description="Encryption, signing, and MAC keys for this organization. Key material never leaves the server: applications call encrypt, decrypt, sign, and verify with a key, and every call is authorized and audited."
      />
      <div className="tiles">
        <Stat label="Keys" value={listed ? listed.total : '—'} hint="that you may read" />
        <Stat label="Enabled" value={count('enabled')} />
        <Stat
          label="Disabled or deleting"
          value={count('disabled') + count('pending-deletion')}
          hint="cryptographic calls refused"
        />
        <Stat label="Rotating automatically" value={rotating} />
      </div>
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Keys" flush>
          {listed ? (
            <Table
              head={['Key', 'Kind', 'State', 'Version', 'Rotation', 'Created']}
              rows={keys.map((key) => [
                <span key="n" className="stack">
                  <Link href={`${base}/keys/${key.id}`}>
                    {key.description ?? key.aliases[0] ?? key.id}
                  </Link>
                  {key.aliases.length > 0 && (
                    <code className="small truncate">{key.aliases.join(', ')}</code>
                  )}
                  {Object.keys(key.tags).length > 0 && (
                    <span className="small muted">
                      {Object.entries(key.tags)
                        .map(([name, value]) => `${name}=${value}`)
                        .join(' · ')}
                    </span>
                  )}
                </span>,
                <span key="k" className="stack">
                  <code className="small" style={{ whiteSpace: 'nowrap' }}>
                    {key.keySpec}
                  </code>
                  <span className="small muted">{usageLabel[key.keyUsage] ?? key.keyUsage}</span>
                </span>,
                <Badge key="s" tone={stateTone[key.state] ?? 'neutral'}>
                  {key.state.replace('-', ' ')}
                </Badge>,
                <span key="v">v{key.currentVersion}</span>,
                key.rotationPeriodDays ? (
                  <span key="r" className="stack">
                    <span>every {key.rotationPeriodDays} days</span>
                    <span className="small muted">
                      next <Time value={key.nextRotationAt} />
                    </span>
                  </span>
                ) : (
                  <span key="r" className="muted">
                    on demand
                  </span>
                ),
                <Time key="c" value={key.createdAt} />,
              ])}
              empty="No keys yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:kms:read</code>.
            </div>
          )}
        </Card>
        <div className="stack">
          <Card
            title="Create a key"
            description="Requires iam:kms:create on iam/kms. RSA keys need a usage; every other kind has one."
          >
            <ApiForm
              path="keys/create"
              tenantId={tenantId}
              submitLabel="Create key"
              redirectTo={`${base}/keys/{id}`}
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'keySpec',
                  label: 'Kind',
                  type: 'select',
                  required: true,
                  defaultValue: 'aes-256-gcm',
                  options: [
                    { value: 'aes-256-gcm', label: 'AES-256-GCM (encrypt and decrypt, data keys)' },
                    { value: 'hmac-sha256', label: 'HMAC-SHA256 (MACs, HS256 tokens)' },
                    { value: 'hmac-sha512', label: 'HMAC-SHA512 (MACs, HS512 tokens)' },
                    { value: 'ecc-p256', label: 'ECDSA P-256 (ES256 signatures and tokens)' },
                    { value: 'ecc-p384', label: 'ECDSA P-384 (ES384)' },
                    { value: 'ed25519', label: 'Ed25519 (EdDSA)' },
                    { value: 'rsa-2048', label: 'RSA 2048' },
                    { value: 'rsa-3072', label: 'RSA 3072' },
                    { value: 'rsa-4096', label: 'RSA 4096' },
                  ],
                },
                {
                  name: 'keyUsage',
                  label: 'Usage (RSA only)',
                  type: 'select',
                  options: [
                    { value: 'sign', label: 'Sign and verify' },
                    { value: 'encrypt', label: 'Encrypt and decrypt (RSA-OAEP)' },
                  ],
                },
                {
                  name: 'alias',
                  label: 'Alias',
                  placeholder: 'alias/customer-records',
                  help: 'Applications can name the key by its alias; move the alias to switch keys.',
                },
                { name: 'description', label: 'Description' },
                {
                  name: 'tags',
                  label: 'Tags',
                  type: 'json',
                  rows: 3,
                  placeholder: '{ "team": "payments" }',
                  help: 'Policies read them as resource.tags.{name}.',
                },
                {
                  name: 'rotationPeriodDays',
                  label: 'Rotate automatically every (days)',
                  type: 'number',
                  placeholder: '365',
                },
              ]}
            />
          </Card>
          <Alert tone="info">
            Grant use with policies on <code>iam/kms/&#123;keyId&#125;</code>, for example{' '}
            <code>iam:kms:decrypt</code> where <code>resource.tags.team</code> is your team and{' '}
            <code>resource.encryptionContext.app</code> names the application, or hand one workload
            a key grant from the key&apos;s page.
          </Alert>
          <Alert tone="warning">
            Key material is sealed under the deployment secret. Deleting a key destroys it after a
            waiting period, and nothing encrypted under it can be decrypted again.
          </Alert>
        </div>
      </div>
    </>
  );
}
