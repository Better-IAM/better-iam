import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Domains({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const domains = await tryRead(() => iam.api.domains.list(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Domains"
        description="Verify the email domains your organization owns. People who type an address at a verified domain on the sign-in page are routed straight to this organization."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Claimed domains" flush>
          {domains ? (
            <Table
              head={['Domain', 'Status', 'DNS record', 'Checked', '']}
              rows={domains.map((domain) => [
                <code key="d">{domain.domain}</code>,
                domain.status === 'verified' ? (
                  <Badge key="s" tone="success">
                    verified
                  </Badge>
                ) : (
                  <Badge key="s" tone="warning">
                    pending
                  </Badge>
                ),
                domain.status === 'verified' ? (
                  <span key="r" className="muted small">
                    verified <Time value={domain.verifiedAt} />
                  </span>
                ) : (
                  <span key="r" className="stack">
                    <span className="small muted">
                      TXT <code>{domain.dnsRecord.name}</code>
                    </span>
                    <code className="small truncate">{domain.dnsRecord.value}</code>
                  </span>
                ),
                domain.lastCheckedAt ? <Time key="c" value={domain.lastCheckedAt} /> : '—',
                <span key="a" className="actions">
                  {domain.status !== 'verified' && (
                    <ApiButton
                      path="domains/verify"
                      body={{ tenantId, domainId: domain.id }}
                      label="Verify"
                      tenantId={tenantId}
                      showResult
                    />
                  )}
                  <ApiButton
                    path="domains/delete"
                    body={{ tenantId, domainId: domain.id }}
                    label="Remove"
                    tone="danger"
                    confirm={`Release ${domain.domain}? Sign-in discovery stops routing it here immediately.`}
                    tenantId={tenantId}
                  />
                </span>,
              ])}
              empty="No domains claimed yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:domains:read</code>.
            </div>
          )}
        </Card>
        <div className="stack">
          <Card
            title="Claim a domain"
            description="Requires iam:domains:create. You receive a TXT record to publish at your DNS provider."
          >
            <ApiForm
              path="domains/add"
              tenantId={tenantId}
              submitLabel="Claim domain"
              resetOnSuccess
              successMessage="Claimed. Publish the TXT record shown in the table, then choose Verify."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'domain',
                  label: 'Domain',
                  required: true,
                  placeholder: 'example.com',
                },
              ]}
            />
          </Card>
          <Alert tone="info">
            A domain is verified by exactly one organization. Shared mailbox providers such as
            gmail.com cannot be claimed, and DNS changes can take a few minutes to become visible.
          </Alert>
        </div>
      </div>
    </>
  );
}
