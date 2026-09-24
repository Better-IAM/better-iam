import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const stateTone: Record<string, Tone> = {
  valid: 'success',
  suspended: 'warning',
  revoked: 'danger',
  expired: 'neutral',
};
const days = (ms: number) => Math.round(ms / 86_400_000);

export default async function VerifiableCredentials({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const status = await tryRead(() => iam.api.verifiableCredentials.status(auth, { tenantId }));
  const types = await tryRead(() => iam.api.verifiableCredentials.listTypes(auth, { tenantId }));
  const issued = await tryRead(() => iam.api.verifiableCredentials.listIssued(auth, { tenantId, limit: 50 }));
  const available = await tryRead(() => iam.api.verifiableCredentials.available(auth, { tenantId }));
  const mine = await tryRead(() => iam.api.verifiableCredentials.mine(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Credentials"
        description="Verifiable credentials this organization issues: digital badges people keep in their wallets and show with only the claims a verifier needs. Revoked and suspended credentials fail verification through the issuer's status list."
      />
      {status && (
        <div className="tiles">
          <Stat label="Credential types" value={status.types} />
          <Stat label="Valid" value={status.credentials.valid} />
          <Stat label="Suspended" value={status.credentials.suspended} />
          <Stat label="Revoked" value={status.credentials.revoked} hint="not yet expired" />
        </div>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          {available && available.length > 0 && (
            <Card
              title="Add to your wallet"
              description="Scan the offer link with an OpenID4VCI wallet. The code works once and expires in minutes; enter the PIN when the wallet asks."
            >
              <div className="stack">
                {available.map((type) => (
                  <div key={type.id} className="stack">
                    <strong>{type.displayName}</strong>
                    {type.description && <span className="small muted">{type.description}</span>}
                    <ApiButton
                      path="verifiableCredentials/createOffer"
                      body={{ tenantId, type: type.name, txCode: true }}
                      label="Create wallet offer"
                      tenantId={tenantId}
                      showResult
                    />
                  </div>
                ))}
              </div>
            </Card>
          )}
          {mine && mine.length > 0 && (
            <Card title="Your credentials" flush>
              <Table
                head={['Type', 'State', 'Issued', 'Valid until', '']}
                rows={mine.map((credential) => [
                  credential.typeName,
                  <Badge key="s" tone={stateTone[credential.state] ?? 'neutral'}>
                    {credential.state}
                  </Badge>,
                  <Time key="i" value={credential.issuedAt} />,
                  <Time key="v" value={credential.validUntil} />,
                  credential.state === 'valid' || credential.state === 'suspended' ? (
                    <ApiButton
                      key="r"
                      path="verifiableCredentials/revoke"
                      body={{ tenantId, credentialId: credential.id }}
                      label="Revoke"
                      tone="danger"
                      confirm="Revoke this credential? Verifiers refuse it from now on."
                      tenantId={tenantId}
                    />
                  ) : (
                    ''
                  ),
                ])}
              />
            </Card>
          )}
          <Card title="Credential types" flush>
            {types ? (
              <Table
                head={['Type', 'Claims', 'Lifetime', 'State', '']}
                rows={types.map((type) => [
                  <span key="n" className="stack">
                    <strong>{type.displayName}</strong>
                    <code className="small truncate">{type.vct}</code>
                  </span>,
                  <span key="c" className="small">
                    {type.claims
                      .map((claim) => `${claim.name}${claim.selective === false ? '' : '*'}`)
                      .join(', ')}
                  </span>,
                  `${days(type.lifetimeMs)} days`,
                  <span key="s" className="stack">
                    <Badge tone={type.enabled ? 'success' : 'neutral'}>{type.enabled ? 'enabled' : 'disabled'}</Badge>
                    {type.requireMfa && <span className="small muted">MFA required</span>}
                  </span>,
                  <ApiButton
                    key="t"
                    path="verifiableCredentials/updateType"
                    body={{ tenantId, name: type.name, enabled: !type.enabled }}
                    label={type.enabled ? 'Disable' : 'Enable'}
                    tenantId={tenantId}
                  />,
                ])}
                empty="No credential types yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:vc:read</code>.
              </div>
            )}
          </Card>
          <Card title="Issued credentials" flush>
            {issued ? (
              <Table
                head={['Type', 'Holder', 'State', 'Valid until', '']}
                rows={issued.credentials.map((credential) => [
                  credential.typeName,
                  <span key="h" className="stack">
                    <code className="small">{credential.identityId}</code>
                    <span className="small muted">via {credential.via}</span>
                  </span>,
                  <Badge key="s" tone={stateTone[credential.state] ?? 'neutral'}>
                    {credential.reason ? `${credential.state}: ${credential.reason}` : credential.state}
                  </Badge>,
                  <Time key="v" value={credential.validUntil} />,
                  <span key="a" className="actions">
                    {credential.state === 'valid' && (
                      <ApiButton
                        path="verifiableCredentials/suspend"
                        body={{ tenantId, credentialId: credential.id }}
                        label="Suspend"
                        tenantId={tenantId}
                      />
                    )}
                    {credential.state === 'suspended' && (
                      <ApiButton
                        path="verifiableCredentials/reinstate"
                        body={{ tenantId, credentialId: credential.id }}
                        label="Reinstate"
                        tenantId={tenantId}
                      />
                    )}
                    {(credential.state === 'valid' || credential.state === 'suspended') && (
                      <ApiButton
                        path="verifiableCredentials/revoke"
                        body={{ tenantId, credentialId: credential.id }}
                        label="Revoke"
                        tone="danger"
                        confirm="Revoke this credential for good?"
                        tenantId={tenantId}
                      />
                    )}
                  </span>,
                ])}
                empty="No credentials issued yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:vc:read</code>.
              </div>
            )}
          </Card>
        </div>
        <div className="stack">
          <Card
            title="New credential type"
            description="Requires iam:vc:manage. Claims are a JSON list of { name, source, selective?, required?, label? }; sources: email, emailVerified, name, identityId, kind, tenantId, tenantName, teams, department, attribute:{name}, static (with value)."
          >
            <ApiForm
              path="verifiableCredentials/createType"
              tenantId={tenantId}
              submitLabel="Create type"
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'employee' },
                { name: 'displayName', label: 'Display name', required: true, placeholder: 'Acme employee' },
                { name: 'description', label: 'Description' },
                {
                  name: 'claims',
                  label: 'Claims',
                  type: 'json',
                  required: true,
                  rows: 6,
                  defaultValue: JSON.stringify(
                    [
                      { name: 'email', source: 'email', label: 'Email' },
                      { name: 'name', source: 'name', selective: false },
                      { name: 'organization', source: 'tenantName', selective: false },
                    ],
                    null,
                    2,
                  ),
                },
                {
                  name: 'lifetimeMs',
                  label: 'Lifetime (days)',
                  type: 'number',
                  multiplier: 86_400_000,
                  placeholder: '30',
                },
                { name: 'requireMfa', label: 'People need an MFA session to get one', type: 'checkbox' },
                { name: 'backgroundColor', label: 'Card color', placeholder: '#0b2545' },
              ]}
            />
          </Card>
          {status && (
            <Card title="Issuer" description="Wallets and verifiers find the issuer here.">
              <div className="stack small">
                <span>
                  Issuer <code className="truncate">{status.issuer}</code>
                </span>
                <span>
                  Metadata <code className="truncate">{status.metadataUrl}</code>
                </span>
                {status.keys.map((key) => (
                  <span key={key.kid}>
                    <Badge tone={key.status === 'active' ? 'success' : 'warning'}>{key.status}</Badge>{' '}
                    <code className="truncate">{key.kid}</code>
                  </span>
                ))}
                <ApiButton
                  path="verifiableCredentials/rotateKey"
                  body={{ tenantId }}
                  label="Rotate signing key"
                  confirm="Sign new credentials with a new key? The current key stays published, so existing credentials keep verifying."
                  tenantId={tenantId}
                />
              </div>
            </Card>
          )}
          <Alert tone="info">
            Verifiers check presentations offline with the issuer&apos;s keys and status list, or call{' '}
            <code>verifiableCredentials/verify</code>. Claims marked * are selectively disclosable.
          </Alert>
        </div>
      </div>
    </>
  );
}
