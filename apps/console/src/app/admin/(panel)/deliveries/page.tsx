import { headers } from 'next/headers';
import { renderDeliveryMessage } from 'better-iam/auth/templates';
import { Alert, Card, PageHeader, Table, Time } from '@/components/ui';
import type { Tenant } from 'better-iam';
import { joinLink } from '@/lib/admin';
import { getDeliveries, getIam } from '@/lib/iam';
import { requireRootSession } from '@/lib/session';

export default async function Deliveries() {
  await requireRootSession();
  const { messages, webhook } = await getDeliveries();
  const origin =
    process.env.BETTER_IAM_BASE_URL ??
    `http://${(await headers()).get('host') ?? 'localhost:3000'}`;
  // Security notices link to the organization's account page, addressed by alias when it has one.
  const slugById = new Map(
    (await (await getIam()).store.find<Tenant>('tenants')).map((tenant) => [
      tenant.id,
      tenant.slug ?? tenant.id,
    ]),
  );
  // The same renderer a production delivery callback would use, pointed at this console's own pages.
  const render = (message: (typeof messages)[number]) =>
    renderDeliveryMessage(message, {
      appName: 'Better IAM Console',
      links: {
        invitation: ({ kind, tenantId, token }) =>
          joinLink(origin, `${kind}-invitation`, tenantId, token) ?? '',
        passwordReset: ({ tenantId, token }) =>
          joinLink(origin, 'password-reset', tenantId, token) ?? '',
        emailChange: ({ tenantId, token }) =>
          joinLink(origin, 'email-change', tenantId, token) ?? '',
        verifyEmail: ({ tenantId, token }) =>
          joinLink(origin, 'verify-email', tenantId, token) ?? '',
        magicLink: ({ tenantId, token, destination }) =>
          joinLink(origin, 'magic-link', tenantId, token, destination) ?? '',
        account: ({ tenantId }) =>
          `${origin}/cloud/${encodeURIComponent(slugById.get(tenantId) ?? tenantId)}/account`,
        certification: ({ tenantId, campaignId }) =>
          `${origin}/cloud/${encodeURIComponent(slugById.get(tenantId) ?? tenantId)}/certifications/${encodeURIComponent(campaignId)}`,
      },
    });
  return (
    <>
      <PageHeader
        title="Deliveries"
        description="Invitations, verification links, and codes leave Better IAM through a transactional outbox and your delivery callback."
      />
      <div className="stack">
        {webhook ? (
          <Alert tone="info">
            Messages are posted to <code>DELIVERY_WEBHOOK_URL</code>; nothing is retained in this
            process.
          </Alert>
        ) : (
          <Alert tone="warning">
            No <code>DELIVERY_WEBHOOK_URL</code> is configured, so messages are kept in memory for
            this development process and shown here to root administrators. In production they are
            refused (and retried) instead: configure a webhook before exposing the console publicly.
          </Alert>
        )}
        <Card title="Recent messages" flush>
          <Table
            head={['Received', 'Template', 'Subject', 'To', 'Tenant', 'Payload', 'Action']}
            rows={messages.map((message) => {
              const link = message.payload.token
                ? joinLink(
                    origin,
                    message.template,
                    message.tenantId,
                    message.payload.token,
                    message.to,
                  )
                : undefined;
              const rendered = render(message);
              return [
                <Time key="r" value={message.receivedAt} />,
                <code key="t">{message.template}</code>,
                rendered ? (
                  <span key="s" title={rendered.text}>
                    {rendered.subject}
                  </span>
                ) : (
                  <span key="s" className="muted">
                    —
                  </span>
                ),
                message.to,
                <code key="tn" className="small">
                  {message.tenantId}
                </code>,
                <code key="p" className="small" style={{ wordBreak: 'break-all' }}>
                  {JSON.stringify(
                    Object.fromEntries(
                      Object.entries(message.payload).filter(([key]) => key !== 'token'),
                    ),
                  )}
                </code>,
                link ? (
                  <a key="l" className="btn small" href={link}>
                    Open link
                  </a>
                ) : message.payload.token ? (
                  <code key="l" className="small">
                    {message.payload.token}
                  </code>
                ) : (
                  ''
                ),
              ];
            })}
            empty="No messages delivered yet."
          />
        </Card>
      </div>
    </>
  );
}
