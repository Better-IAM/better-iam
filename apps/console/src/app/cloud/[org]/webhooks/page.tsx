import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Webhooks({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const webhooks = await tryRead(() => iam.api.webhooks.list(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Webhooks"
        description="Signed HTTPS deliveries for this organization's audit events. Secrets are shown once; verify X-Better-IAM-Signature before trusting a delivery."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Subscriptions" flush>
          {webhooks ? (
            <Table
              head={['Endpoint', 'Events', 'State', 'Updated', '']}
              rows={webhooks.map((hook) => [
                <span key="u" className="stack">
                  <Link href={`${base}/webhooks/${hook.id}`}>{hook.description ?? hook.url}</Link>
                  <code className="small truncate">{hook.url}</code>
                </span>,
                <code key="e" className="small">
                  {hook.events.join(', ')}
                </code>,
                hook.active ? (
                  <Badge key="s" tone="success">
                    active
                  </Badge>
                ) : (
                  <Badge key="s" tone="warning">
                    paused
                  </Badge>
                ),
                <Time key="t" value={hook.updatedAt} />,
                <span key="a" className="actions">
                  <ApiButton
                    path="webhooks/ping"
                    body={{ tenantId, webhookId: hook.id }}
                    label="Ping"
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="webhooks/update"
                    body={{ tenantId, webhookId: hook.id, active: !hook.active }}
                    label={hook.active ? 'Pause' : 'Resume'}
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="webhooks/delete"
                    body={{ tenantId, webhookId: hook.id }}
                    label="Delete"
                    tone="danger"
                    confirm="Delete this webhook and its pending deliveries?"
                    tenantId={tenantId}
                  />
                </span>,
              ])}
              empty="No webhooks yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:webhooks:read</code>.
            </div>
          )}
        </Card>
        <div className="stack">
          <Card
            title="Add a webhook"
            description="Requires iam:webhooks:create and recent authentication. The response contains the signing secret exactly once."
          >
            <ApiForm
              path="webhooks/create"
              tenantId={tenantId}
              submitLabel="Create webhook"
              showResult
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'url',
                  label: 'Endpoint URL',
                  required: true,
                  placeholder: 'https://hooks.example.com/iam',
                },
                {
                  name: 'events',
                  label: 'Event patterns',
                  type: 'list',
                  required: true,
                  defaultValue: 'iam:identities:*, iam:bindings:*, auth:session:create',
                  help: 'Comma separated; * and ? are wildcards. Use * for everything.',
                },
                { name: 'description', label: 'Description' },
              ]}
            />
          </Card>
          <Alert tone="info">
            Deliveries are queued in the same transaction as the audit record, retried with backoff,
            and listed per webhook with their attempt history.
          </Alert>
        </div>
      </div>
    </>
  );
}
