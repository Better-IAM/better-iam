import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const stateTone: Record<string, Tone> = {
  active: 'success',
  disabled: 'warning',
  revoked: 'danger',
  valid: 'success',
  expired: 'neutral',
};

const namesOf = (names: {
  dnsNames: string[];
  uris: string[];
  ipAddresses: string[];
  emails: string[];
}) => [...names.dnsNames, ...names.uris, ...names.ipAddresses, ...names.emails];

export default async function Certificates({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [authorities, listed] = await Promise.all([
    tryRead(() => iam.api.pki.listAuthorities(auth, { tenantId })),
    tryRead(() => iam.api.pki.listCertificates(auth, { tenantId, limit: 100 })),
  ]);
  const byId = new Map((authorities ?? []).map((authority) => [authority.id, authority]));
  const certificates = listed?.certificates ?? [];
  const active = (authorities ?? []).filter((authority) => authority.state === 'active');
  const authorityOptions = active.map((authority) => ({
    value: authority.id,
    label: `${authority.name} (${authority.type})`,
  }));
  return (
    <>
      <PageHeader
        title="Certificates"
        description="A private certificate authority for mutual TLS, internal HTTPS and workload identity. Authorities sign with KMS keys; every name on a certificate is decided by policy."
      />
      <div className="tiles">
        <Stat
          label="Authorities"
          value={authorities ? authorities.length : '—'}
          hint={`${active.length} active`}
        />
        <Stat
          label="Valid certificates"
          value={
            certificates.filter((item) => item.status === 'valid' && item.usage !== 'ca').length
          }
        />
        <Stat
          label="Workload identities"
          value={certificates.filter((item) => item.spiffeId && item.status === 'valid').length}
          hint="SPIFFE certificates"
        />
        <Stat
          label="Revoked"
          value={certificates.filter((item) => item.status === 'revoked').length}
        />
      </div>

      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Authorities" flush>
          {authorities ? (
            <Table
              head={['Authority', 'Kind', 'State', 'Valid until', '']}
              rows={authorities.map((authority) => [
                <span key="n" className="stack">
                  <strong>{authority.name}</strong>
                  <span className="small muted">{authority.subject.commonName}</span>
                  {authority.trustDomain && (
                    <code className="small">spiffe://{authority.trustDomain}</code>
                  )}
                </span>,
                <span key="k" className="stack">
                  <span>
                    {authority.type}
                    {authority.parentId && byId.get(authority.parentId)
                      ? ` under ${byId.get(authority.parentId)!.name}`
                      : ''}
                  </span>
                  <Link className="small" href={`${base}/keys/${authority.keyId}`}>
                    KMS key v{authority.keyVersion} · {authority.algorithm}
                  </Link>
                </span>,
                <Badge key="s" tone={stateTone[authority.state] ?? 'neutral'}>
                  {authority.state}
                </Badge>,
                <Time key="t" value={authority.notAfter} />,
                authority.state === 'revoked' ? (
                  ''
                ) : (
                  <ApiButton
                    key="a"
                    path="pki/updateAuthority"
                    body={{
                      tenantId,
                      authorityId: authority.id,
                      state: authority.state === 'active' ? 'disabled' : 'active',
                    }}
                    label={authority.state === 'active' ? 'Disable' : 'Enable'}
                    tenantId={tenantId}
                  />
                ),
              ])}
              empty="No certificate authorities yet. Create a root, then an intermediate to issue from."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:pki:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Create an authority"
          description="Requires iam:pki:create and a recent sign-in. Leave the parent empty for a root."
        >
          <ApiForm
            path="pki/createAuthority"
            tenantId={tenantId}
            submitLabel="Create authority"
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'name', label: 'Name', required: true, placeholder: 'Acme Workloads' },
              {
                name: 'commonName',
                label: 'Common name',
                required: true,
                group: 'subject',
                placeholder: 'Acme Workload CA',
              },
              { name: 'organization', label: 'Organization', group: 'subject' },
              {
                name: 'parentId',
                label: 'Parent authority',
                type: 'select',
                options: authorityOptions,
              },
              {
                name: 'keySpec',
                label: 'Signing key',
                type: 'select',
                defaultValue: 'ecc-p256',
                options: [
                  { value: 'ecc-p256', label: 'ECDSA P-256' },
                  { value: 'ecc-p384', label: 'ECDSA P-384' },
                  { value: 'ed25519', label: 'Ed25519' },
                  { value: 'rsa-3072', label: 'RSA 3072' },
                ],
              },
              {
                name: 'trustDomain',
                label: 'SPIFFE trust domain',
                placeholder: 'acme.internal',
                help: 'Needed for workload certificates.',
              },
              {
                name: 'permitted',
                label: 'Name constraints',
                type: 'json',
                rows: 3,
                placeholder: '{ "dnsNames": ["internal"], "uriHosts": ["acme.internal"] }',
              },
              {
                name: 'pathLength',
                label: 'Path length',
                type: 'number',
                help: 'How many levels of authorities may sit below this one.',
              },
            ]}
          />
        </Card>
      </div>

      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card
          title="Certificates"
          description="Newest first, including subordinate authorities' own certificates."
          flush
        >
          {listed ? (
            <Table
              head={['Names', 'Issued by', 'State', 'Expires', '']}
              rows={certificates.map((certificate) => [
                <span key="n" className="stack">
                  <span>
                    {certificate.usage === 'ca'
                      ? `CA: ${certificate.commonName ?? ''}`
                      : (certificate.commonName ?? namesOf(certificate.names)[0] ?? '—')}
                  </span>
                  <code className="small truncate">
                    {namesOf(certificate.names).join(', ') || certificate.serialNumber}
                  </code>
                </span>,
                <span key="a" className="stack">
                  <span>{byId.get(certificate.authorityId)?.name ?? certificate.authorityId}</span>
                  <span className="small muted">{certificate.usage}</span>
                </span>,
                <Badge key="s" tone={stateTone[certificate.status] ?? 'neutral'}>
                  {certificate.status}
                  {certificate.revocationReason ? ` (${certificate.revocationReason})` : ''}
                </Badge>,
                <Time key="t" value={certificate.notAfter} />,
                certificate.status === 'valid' ? (
                  <ApiButton
                    key="r"
                    path="pki/revokeCertificate"
                    body={{
                      tenantId,
                      serialNumber: certificate.serialNumber,
                      reason: 'superseded',
                    }}
                    label="Revoke"
                    tone="danger"
                    confirm={
                      certificate.usage === 'ca'
                        ? 'Revoke this authority certificate? The authority and everything it issued stop working.'
                        : 'Revoke this certificate? It stops verifying at once.'
                    }
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
              Requires <code>iam:pki:read</code>.
            </div>
          )}
        </Card>
        <div className="stack">
          <Card
            title="Issue a certificate"
            description="Paste a PKCS#10 request (openssl req -new, or createCertificateRequest). Every name is checked against iam:pki:issue."
          >
            <ApiForm
              path="pki/issueCertificate"
              tenantId={tenantId}
              submitLabel="Issue"
              showResult
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'authorityId',
                  label: 'Authority',
                  type: 'select',
                  required: true,
                  options: authorityOptions,
                },
                {
                  name: 'csr',
                  label: 'Certificate request (PEM)',
                  type: 'textarea',
                  required: true,
                  rows: 6,
                  placeholder: '-----BEGIN CERTIFICATE REQUEST-----',
                },
                {
                  name: 'usage',
                  label: 'Usage',
                  type: 'select',
                  defaultValue: 'both',
                  options: [
                    { value: 'both', label: 'Server and client' },
                    { value: 'server', label: 'Server' },
                    { value: 'client', label: 'Client' },
                  ],
                },
                {
                  name: 'validitySeconds',
                  label: 'Valid for (hours)',
                  type: 'number',
                  multiplier: 3600,
                  placeholder: '24',
                },
              ]}
            />
          </Card>
          <Alert tone="info">
            Services get SPIFFE workload certificates for their own identity with{' '}
            <code>pki.requestCertificate</code> and an API key that holds{' '}
            <code>iam:pki:request</code>. Servers verify peers with <code>iam.pki.verify</code>, and
            relying parties fetch revocation lists from <code>iam.pki.crlResponse</code>.
          </Alert>
        </div>
      </div>
    </>
  );
}
