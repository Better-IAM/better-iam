import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const stateTone: Record<string, Tone> = {
  enabled: 'success',
  disabled: 'warning',
  'pending-deletion': 'danger',
};

const grantOperations: Record<string, string[]> = {
  encrypt: ['read', 'encrypt', 'decrypt', 'generate-data-key'],
  sign: ['read', 'sign', 'verify'],
  mac: ['read', 'generate-mac', 'verify-mac'],
};

export default async function KeyDetail({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const key = await tryRead(() => iam.api.keys.get(auth, { tenantId, keyId: id }));
  if (!key) notFound();
  const asymmetric =
    key.keySpec.startsWith('ecc') || key.keySpec === 'ed25519' || key.keySpec.startsWith('rsa');
  const [versions, grants, activity, published, members] = await Promise.all([
    tryRead(() => iam.api.keys.listVersions(auth, { tenantId, keyId: key.id })),
    tryRead(() => iam.api.keys.listGrants(auth, { tenantId, keyId: key.id })),
    tryRead(() => iam.api.audit.list(auth, { tenantId, resourceId: `kms/${key.id}`, limit: 25 })),
    asymmetric
      ? tryRead(() => iam.api.keys.publicKey(auth, { tenantId, keyId: key.id }))
      : Promise.resolve(undefined),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 200 })),
  ]);
  const people = new Map(
    (members ?? [])
      .filter((person) => person.status !== 'deleted')
      .map((person) => [person.id, person.name || person.email || person.id]),
  );
  const granteeName = (identityId: string) => people.get(identityId) ?? identityId;
  const usable = key.state === 'enabled';
  const title = key.description ?? key.aliases[0] ?? key.id;
  return (
    <>
      <PageHeader
        title={title}
        description={
          <>
            <Link href={`${base}/keys`}>Keys</Link> · <code>{key.id}</code>
          </>
        }
        actions={
          <>
            {key.state !== 'pending-deletion' && (
              <ApiButton
                path={key.state === 'enabled' ? 'keys/disable' : 'keys/enable'}
                body={{ tenantId, keyId: key.id }}
                label={key.state === 'enabled' ? 'Disable' : 'Enable'}
                confirm={
                  key.state === 'enabled'
                    ? 'Disable this key? Every call with it is refused until you enable it again, so data encrypted under it cannot be read meanwhile.'
                    : undefined
                }
                tenantId={tenantId}
              />
            )}
            {usable && (
              <ApiButton
                path="keys/rotate"
                body={{ tenantId, keyId: key.id }}
                label="Rotate now"
                tenantId={tenantId}
              />
            )}
            {key.state === 'pending-deletion' && (
              <ApiButton
                path="keys/cancelDeletion"
                body={{ tenantId, keyId: key.id }}
                label="Cancel deletion"
                tenantId={tenantId}
              />
            )}
          </>
        }
      />
      {key.state === 'pending-deletion' && (
        <Alert tone="danger">
          This key will be destroyed on <Time value={key.deletionDate} />. After that, nothing
          encrypted under it can be decrypted. Cancel the deletion to keep it (it comes back
          disabled).
        </Alert>
      )}
      <div className="grid cols-2">
        <Card title="Key">
          <KeyValues
            items={[
              [
                'State',
                <Badge key="s" tone={stateTone[key.state] ?? 'neutral'}>
                  {key.state.replace('-', ' ')}
                </Badge>,
              ],
              ['Kind', <code key="k">{key.keySpec}</code>],
              ['Usage', key.keyUsage],
              ['Algorithms', key.algorithms.length ? key.algorithms.join(', ') : 'AES-256-GCM'],
              ['Current version', `v${key.currentVersion}`],
              [
                'Rotation',
                key.rotationPeriodDays ? (
                  <span key="r">
                    every {key.rotationPeriodDays} days, next <Time value={key.nextRotationAt} />
                  </span>
                ) : (
                  'on demand'
                ),
              ],
              ['Last rotated', <Time key="l" value={key.lastRotatedAt} />],
              [
                'Tags',
                Object.keys(key.tags).length ? (
                  <code key="t" className="small">
                    {Object.entries(key.tags)
                      .map(([name, value]) => `${name}=${value}`)
                      .join(', ')}
                  </code>
                ) : (
                  <span key="t" className="muted">
                    none
                  </span>
                ),
              ],
              ['Created', <Time key="c" value={key.createdAt} />],
            ]}
          />
        </Card>
        <Card
          title="Settings"
          description="Requires iam:kms:update. New tags must still let you manage the key."
        >
          <ApiForm
            path="keys/update"
            tenantId={tenantId}
            submitLabel="Save"
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
              {
                name: 'description',
                label: 'Description',
                defaultValue: key.description ?? '',
                emptyAsNull: true,
              },
              {
                name: 'tags',
                label: 'Tags',
                type: 'json',
                rows: 3,
                defaultValue: JSON.stringify(key.tags),
              },
              {
                name: 'rotationPeriodDays',
                label: 'Rotate automatically every (days)',
                type: 'number',
                defaultValue: key.rotationPeriodDays ?? '',
                emptyAsNull: true,
                help: 'Leave empty to rotate only on demand.',
              },
            ]}
          />
        </Card>
      </div>

      <div className="grid cols-2">
        <Card
          title="Versions"
          description="New calls use the current version; older versions keep decrypting and verifying."
          flush
        >
          <Table
            head={['Version', 'Origin', 'Created', asymmetric ? 'Public key' : '']}
            rows={(versions ?? []).map((version) => [
              <span key="v">
                v{version.version} {version.current && <Badge tone="accent">current</Badge>}
              </span>,
              version.origin,
              <Time key="c" value={version.createdAt} />,
              version.publicKeyFingerprint ? (
                <code key="f" className="small">
                  {version.publicKeyFingerprint}
                </code>
              ) : (
                ''
              ),
            ])}
          />
        </Card>
        <Card title="Aliases" description="Applications can name the key by any of its aliases.">
          <Table
            head={['Alias', '']}
            rows={key.aliases.map((alias) => [
              <code key="a">{alias}</code>,
              <ApiButton
                key="d"
                path="keys/deleteAlias"
                body={{ tenantId, alias }}
                label="Remove"
                tone="danger"
                confirm={`Remove ${alias}? Applications that name it will get NOT_FOUND.`}
                tenantId={tenantId}
              />,
            ])}
            empty="No aliases."
          />
          <ApiForm
            path="keys/createAlias"
            tenantId={tenantId}
            submitLabel="Add alias"
            resetOnSuccess
            compact
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
              {
                name: 'alias',
                label: 'Alias',
                required: true,
                placeholder: 'alias/app-data',
              },
            ]}
          />
        </Card>
      </div>

      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card
          title="Grants"
          description="Named operations on this key for one person, service account or agent, without a policy. A grant works only while its creator still holds what it passes on."
          flush
        >
          {grants ? (
            <Table
              head={['Grantee', 'Operations', 'Constraint', 'Until', '']}
              rows={grants.map((grant) => [
                <span key="g" className="stack">
                  <span>{grant.name ?? granteeName(grant.granteeId)}</span>
                  <span className="small muted">
                    for {granteeName(grant.granteeId)}, by {granteeName(grant.createdBy)}
                  </span>
                </span>,
                <code key="o" className="small">
                  {grant.operations.join(', ')}
                </code>,
                grant.constraints ? (
                  <code key="c" className="small">
                    {JSON.stringify(grant.constraints)}
                  </code>
                ) : (
                  <span key="c" className="muted">
                    any context
                  </span>
                ),
                grant.expiresAt ? (
                  <span key="u">
                    <Time value={grant.expiresAt} />{' '}
                    {!grant.active && <Badge tone="warning">lapsed</Badge>}
                  </span>
                ) : (
                  <span key="u" className="muted">
                    no end
                  </span>
                ),
                <ApiButton
                  key="r"
                  path="keys/revokeGrant"
                  body={{ tenantId, grantId: grant.id }}
                  label="Revoke"
                  tone="danger"
                  tenantId={tenantId}
                />,
              ])}
              empty="No grants."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:kms:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Grant use of this key"
          description="Requires iam:kms:grant. You can only grant operations you hold yourself."
        >
          <ApiForm
            path="keys/createGrant"
            tenantId={tenantId}
            submitLabel="Create grant"
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
              {
                name: 'granteeId',
                label: 'Grantee',
                type: 'select',
                required: true,
                help: 'A person, service account or agent. For a group, bind a role instead.',
                options: [...people].map(([value, label]) => ({ value, label })),
              },
              {
                name: 'operations',
                label: 'Operations',
                type: 'multiselect',
                required: true,
                options: (grantOperations[key.keyUsage] ?? []).map((operation) => ({
                  value: operation,
                  label: operation,
                })),
              },
              {
                name: 'constraints',
                label: 'Encryption context constraint',
                type: 'json',
                rows: 3,
                placeholder: '{ "encryptionContextSubset": { "app": "billing" } }',
                help: 'Only for encrypt, decrypt and data key grants.',
              },
              { name: 'expiresAt', label: 'Until', type: 'datetime' },
              { name: 'name', label: 'Name', placeholder: 'billing worker' },
            ]}
          />
        </Card>
      </div>

      {usable && (
        <div className="grid cols-2">
          {key.keyUsage === 'encrypt' && (
            <>
              <Card
                title="Encrypt"
                description="Requires iam:kms:encrypt. Up to 4 KiB; the context must be presented again to decrypt."
              >
                <ApiForm
                  path="keys/encrypt"
                  tenantId={tenantId}
                  submitLabel="Encrypt"
                  showResult
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
                    { name: 'plaintext', label: 'Plaintext', type: 'textarea', required: true },
                    {
                      name: 'encryptionContext',
                      label: 'Encryption context',
                      type: 'json',
                      rows: 3,
                      placeholder: '{ "app": "billing" }',
                    },
                  ]}
                />
              </Card>
              <Card
                title="Decrypt"
                description="Requires iam:kms:decrypt. Failed attempts are audited."
              >
                <ApiForm
                  path="keys/decrypt"
                  tenantId={tenantId}
                  submitLabel="Decrypt"
                  showResult
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'ciphertext', label: 'Ciphertext', type: 'textarea', required: true },
                    {
                      name: 'encryptionContext',
                      label: 'Encryption context',
                      type: 'json',
                      rows: 3,
                    },
                  ]}
                />
              </Card>
            </>
          )}
          {key.keyUsage === 'sign' && (
            <Card title="Sign" description="Requires iam:kms:sign.">
              <ApiForm
                path="keys/sign"
                tenantId={tenantId}
                submitLabel="Sign"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
                  { name: 'message', label: 'Message', type: 'textarea', required: true },
                  {
                    name: 'algorithm',
                    label: 'Algorithm',
                    type: 'select',
                    options: key.algorithms.map((algorithm) => ({
                      value: algorithm,
                      label: algorithm,
                    })),
                  },
                ]}
              />
            </Card>
          )}
          {key.keyUsage !== 'encrypt' && (
            <Card
              title="Sign a JWT"
              description={`Requires iam:kms:${key.keyUsage === 'mac' ? 'generate-mac' : 'sign'}. The kid names this key's version.`}
            >
              <ApiForm
                path="keys/signJwt"
                tenantId={tenantId}
                submitLabel="Sign token"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
                  {
                    name: 'claims',
                    label: 'Claims',
                    type: 'json',
                    required: true,
                    rows: 4,
                    defaultValue: '{ "sub": "service-1", "aud": "api" }',
                  },
                  {
                    name: 'expiresInSeconds',
                    label: 'Expires in (seconds)',
                    type: 'number',
                    defaultValue: 300,
                  },
                ]}
              />
            </Card>
          )}
          {key.keyUsage === 'mac' && (
            <Card title="Compute a MAC" description="Requires iam:kms:generate-mac.">
              <ApiForm
                path="keys/generateMac"
                tenantId={tenantId}
                submitLabel="Compute"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
                  { name: 'message', label: 'Message', type: 'textarea', required: true },
                ]}
              />
            </Card>
          )}
        </div>
      )}

      {published && (
        <Card
          title="Public key"
          description="Verify signatures (or encrypt for an RSA encryption key) offline; the JWKS carries every version."
        >
          <pre className="result">{published.publicKeyPem}</pre>
        </Card>
      )}

      <Card title="Recent activity" description="Every call with this key, newest first." flush>
        {activity ? (
          <Table
            head={['When', 'Action', 'Who', 'Outcome', 'Details']}
            rows={activity.map((event) => [
              <Time key="t" value={event.timestamp} />,
              <code key="a" className="small">
                {event.action}
              </code>,
              <span key="w">{people.get(event.actorId) ?? event.actorId}</span>,
              <Badge key="o" tone={event.outcome === 'allow' ? 'success' : 'danger'}>
                {event.outcome}
              </Badge>,
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

      {key.state !== 'pending-deletion' && (
        <Card
          title="Delete this key"
          description="Requires iam:kms:delete and a recent sign-in. The key is unusable during the waiting period and destroyed afterwards."
        >
          <ApiForm
            path="keys/scheduleDeletion"
            tenantId={tenantId}
            submitLabel="Schedule deletion"
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'keyId', label: 'Key', type: 'hidden', defaultValue: key.id },
              {
                name: 'waitingDays',
                label: 'Waiting period (days, 7-30)',
                type: 'number',
                required: true,
                defaultValue: 30,
              },
            ]}
          />
        </Card>
      )}
    </>
  );
}
