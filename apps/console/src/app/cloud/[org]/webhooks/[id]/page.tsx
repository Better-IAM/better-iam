import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Webhook({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const hook = await tryRead(() => iam.api.webhooks.get(auth, { tenantId, webhookId: id }));
  if (!hook) notFound();
  const deliveries = await tryRead(() =>
    iam.api.webhooks.listDeliveries(auth, { tenantId, webhookId: id, limit: 100 }),
  );
  return (
    <>
      <PageHeader
        title={
          <>
            {hook.description ?? 'Webhook'}{' '}
            {hook.active ? (
              <Badge tone="success">active</Badge>
            ) : (
              <Badge tone="warning">paused</Badge>
            )}
          </>
        }
        description={
          <>
            <code className="small">{hook.url}</code> ·{' '}
            <Link href={`${base}/webhooks`}>all webhooks</Link>
          </>
        }
        actions={
          <>
            <ApiButton
              path="webhooks/ping"
              body={{ tenantId, webhookId: id }}
              label="Send ping"
              tenantId={tenantId}
            />
            <ApiButton
              path="webhooks/rotateSecret"
              body={{ tenantId, webhookId: id }}
              label="Rotate secret"
              confirm="Rotate the signing secret? Update the endpoint before pending deliveries are sent."
              showResult
              tenantId={tenantId}
            />
          </>
        }
      />
      <div className="stack">
        <div className="grid cols-2">
          <Card title="Subscription">
            <KeyValues
              items={[
                [
                  'ID',
                  <code key="i" className="small">
                    {hook.id}
                  </code>,
                ],
                ['Scope', hook.scope],
                [
                  'Events',
                  <code key="e" className="small">
                    {hook.events.join(', ')}
                  </code>,
                ],
                ['Created', <Time key="c" value={hook.createdAt} />],
                ['Updated', <Time key="u" value={hook.updatedAt} />],
              ]}
            />
          </Card>
          <Card title="Edit" description="Requires iam:webhooks:update and recent authentication.">
            <ApiForm
              path="webhooks/update"
              tenantId={tenantId}
              submitLabel="Save"
              compact
              successMessage="Saved."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'webhookId', label: 'Webhook', type: 'hidden', defaultValue: id },
                { name: 'url', label: 'Endpoint URL', required: true, defaultValue: hook.url },
                {
                  name: 'events',
                  label: 'Event patterns',
                  type: 'list',
                  required: true,
                  defaultValue: hook.events.join(', '),
                },
                { name: 'description', label: 'Description', defaultValue: hook.description ?? '' },
              ]}
            />
          </Card>
        </div>
        <Card
          title="Deliveries"
          description="Newest first. Payloads are never stored after delivery."
          flush
        >
          {deliveries ? (
            <Table
              head={['Event', 'Status', 'Attempts', 'Queued', 'Delivered', 'Last error', '']}
              rows={deliveries.map((delivery) => [
                <code key="e">{delivery.event}</code>,
                <Badge
                  key="s"
                  tone={
                    delivery.status === 'delivered'
                      ? 'success'
                      : delivery.status === 'failed'
                        ? 'danger'
                        : 'warning'
                  }
                >
                  {delivery.status}
                </Badge>,
                delivery.attempts,
                <Time key="q" value={delivery.createdAt} />,
                <Time key="d" value={delivery.deliveredAt} />,
                delivery.lastError ? (
                  <code key="x" className="small truncate">
                    {delivery.lastError}
                  </code>
                ) : (
                  ''
                ),
                delivery.eventId && delivery.status !== 'pending' ? (
                  <ApiButton
                    key="r"
                    path="webhooks/redeliver"
                    body={{ tenantId, webhookId: id, deliveryId: delivery.id }}
                    label="Redeliver"
                    tenantId={tenantId}
                  />
                ) : (
                  ''
                ),
              ])}
              empty="No deliveries yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:webhooks:read</code>.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
