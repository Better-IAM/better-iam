import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/**
 * The organization's own sign-in address: its subdomain (from the deployment's `hosts.patterns`), its home region,
 * and the custom hostnames it verified (`hostnames` API group), with the DNS records each one needs.
 */
export default async function SignInAddress({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, tenant } = await orgPage(org);
  const signInUrl = await iam.hosts.signInUrl(tenantId).catch(() => undefined);
  const hostnames = iam.hosts.customHostnames
    ? await tryRead(() => iam.api.hostnames.list(auth, { tenantId }))
    : undefined;
  return (
    <>
      <PageHeader
        title="Sign-in address"
        description="Where your people sign in. An address of your own shows your organization's name before anyone types and keeps its sessions apart from other organizations'."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Your address">
            {signInUrl ? (
              <p>
                People sign in at <code>{signInUrl}</code>. Requests there are pinned to this
                organization: sign-in pages need no organization name, and sessions of other
                organizations are refused.
              </p>
            ) : (
              <p className="muted">
                This deployment has no organization addresses configured, so people sign in at the
                main address
                {tenant.slug ? (
                  <>
                    {' '}
                    with your alias <code>{tenant.slug}</code>
                  </>
                ) : null}
                .
              </p>
            )}
            {iam.hosts.region ? (
              <p className="small muted">
                This deployment serves the <code>{iam.hosts.region}</code> region
                {tenant.region ? (
                  <>
                    ; your organization is homed in <code>{tenant.region}</code>
                  </>
                ) : null}
                .
              </p>
            ) : null}
          </Card>
          {iam.hosts.customHostnames ? (
            <Card title="Custom hostnames" flush>
              {hostnames ? (
                <Table
                  head={['Hostname', 'Status', 'DNS records', 'Checked', '']}
                  rows={hostnames.map((hostname) => [
                    <code key="h">{hostname.hostname}</code>,
                    <span key="s" className="actions">
                      {hostname.status === 'verified' ? (
                        <Badge tone="success">verified</Badge>
                      ) : (
                        <Badge tone="warning">pending</Badge>
                      )}
                      {hostname.primary ? <Badge tone="accent">primary</Badge> : null}
                    </span>,
                    hostname.status === 'verified' ? (
                      <span key="r" className="muted small">
                        verified <Time value={hostname.verifiedAt} />
                      </span>
                    ) : (
                      <span key="r" className="stack">
                        <span className="small muted">
                          TXT <code>{hostname.dnsRecords.verification.name}</code>
                        </span>
                        <code className="small truncate">
                          {hostname.dnsRecords.verification.value}
                        </code>
                        {hostname.dnsRecords.routing ? (
                          <span className="small muted">
                            CNAME <code>{hostname.dnsRecords.routing.name}</code> →{' '}
                            <code>{hostname.dnsRecords.routing.value}</code>
                          </span>
                        ) : null}
                      </span>
                    ),
                    hostname.lastCheckedAt ? <Time key="c" value={hostname.lastCheckedAt} /> : '—',
                    <span key="a" className="actions">
                      {hostname.status !== 'verified' && (
                        <ApiButton
                          path="hostnames/verify"
                          body={{ tenantId, hostnameId: hostname.id }}
                          label="Verify"
                          tenantId={tenantId}
                          showResult
                        />
                      )}
                      {hostname.status === 'verified' && !hostname.primary && (
                        <ApiButton
                          path="hostnames/setPrimary"
                          body={{ tenantId, hostnameId: hostname.id }}
                          label="Make primary"
                          tone="secondary"
                          tenantId={tenantId}
                        />
                      )}
                      {hostname.primary && (
                        <ApiButton
                          path="hostnames/setPrimary"
                          body={{ tenantId, hostnameId: null }}
                          label="Use subdomain"
                          tone="secondary"
                          tenantId={tenantId}
                        />
                      )}
                      <ApiButton
                        path="hostnames/delete"
                        body={{ tenantId, hostnameId: hostname.id }}
                        label="Remove"
                        tone="danger"
                        confirm={`Release ${hostname.hostname}? It stops working as your sign-in address immediately.`}
                        tenantId={tenantId}
                      />
                    </span>,
                  ])}
                  empty="No custom hostnames yet."
                />
              ) : (
                <div className="empty">
                  Requires <code>iam:hostnames:read</code>.
                </div>
              )}
            </Card>
          ) : null}
        </div>
        <div className="stack">
          {iam.hosts.customHostnames ? (
            <>
              <Card
                title="Use your own domain"
                description="Requires iam:hostnames:create. You receive a TXT record that proves you control the hostname and a CNAME that sends it here."
              >
                <ApiForm
                  path="hostnames/add"
                  tenantId={tenantId}
                  submitLabel="Claim hostname"
                  resetOnSuccess
                  successMessage="Claimed. Publish both DNS records shown in the table, then choose Verify."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'hostname',
                      label: 'Hostname',
                      required: true,
                      placeholder: 'login.example.com',
                    },
                  ]}
                />
              </Card>
              <Alert tone="info">
                A hostname is verified by exactly one organization, and DNS changes can take a few
                minutes to become visible. Passkeys are tied to the deployment&apos;s domain, so on
                your own hostname people sign in with a password, a sign-in link, or single sign-on.
              </Alert>
            </>
          ) : (
            <Alert tone="info">
              Custom hostnames are not enabled on this deployment. An operator can turn them on with
              the <code>hosts.customHostnames</code> option.
            </Alert>
          )}
        </div>
      </div>
    </>
  );
}
