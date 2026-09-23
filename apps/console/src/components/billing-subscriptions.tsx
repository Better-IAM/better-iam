import type { DiscountView, InvoiceItemView, PlanView, SubscriptionView } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Badge, Card, Table, Time } from '@/components/ui';
import { money, periodLabel, planSummary } from '@/lib/billing';

/**
 * The organization's side of plans and invoicing on its Billing page: its subscriptions (seats, cancel, resume), the
 * plans it can subscribe to itself, promotion codes, and charges waiting for the next invoice.
 */
export function SubscriptionCards({
  tenantId,
  currency,
  subscriptions,
  plans,
  discounts,
  pendingItems,
}: {
  tenantId: string;
  currency: string;
  subscriptions: SubscriptionView[] | undefined;
  plans: PlanView[] | undefined;
  discounts: DiscountView[] | undefined;
  pendingItems: InvoiceItemView[] | undefined;
}) {
  const own = (subscriptions ?? []).filter((subscription) => subscription.accountId === tenantId);
  const selfServe = (plans ?? []).filter(
    (plan) => plan.selfServe && !own.some((subscription) => subscription.planId === plan.id),
  );
  const planById = new Map((plans ?? []).map((plan) => [plan.id, plan]));
  return (
    <>
      <Card
        title="Subscription"
        description="Plan fees and seats are billed a month ahead, prorated when the subscription starts or changes mid-month; plan prices replace the rate card for the meters they cover."
        flush
      >
        {subscriptions ? (
          <Table
            head={['Plan', 'Status', 'Seats', '']}
            rows={own.map((subscription) => {
              const plan = planById.get(subscription.planId);
              return [
                <span key="p" className="stack" style={{ gap: 2 }}>
                  <strong>{subscription.planName}</strong>
                  {plan && <span className="small muted">{planSummary(plan, currency)}</span>}
                </span>,
                <span key="s" className="stack" style={{ gap: 2 }}>
                  <span className="row">
                    <Badge tone={subscription.status === 'trialing' ? 'accent' : 'success'}>
                      {subscription.status}
                    </Badge>
                    {subscription.cancelAtPeriodEnd && <Badge tone="warning">cancels</Badge>}
                  </span>
                  <span className="small muted">
                    {subscription.trialEndsAt && subscription.status === 'trialing' ? (
                      <>
                        Trial until <Time value={subscription.trialEndsAt} />
                      </>
                    ) : subscription.endsAt ? (
                      <>
                        Ends <Time value={subscription.endsAt} />
                      </>
                    ) : (
                      <>
                        Since <Time value={subscription.startedAt} />
                      </>
                    )}
                  </span>
                </span>,
                String(subscription.seats),
                subscription.cancelAtPeriodEnd ? (
                  <ApiButton
                    key="a"
                    path="billing/resumeSubscription"
                    body={{ tenantId, subscriptionId: subscription.id }}
                    label="Keep it"
                    tenantId={tenantId}
                  />
                ) : (
                  <ApiButton
                    key="a"
                    path="billing/cancelSubscription"
                    body={{ tenantId, subscriptionId: subscription.id }}
                    label="Cancel"
                    tone="danger"
                    confirm={`Cancel ${subscription.planName} at the end of this month? It keeps running until then and can be kept.`}
                    tenantId={tenantId}
                  />
                ),
              ];
            })}
            empty="No subscription: usage is billed at the platform's list prices."
          />
        ) : (
          <div className="empty">
            Requires <code>iam:billing:read</code>.
          </div>
        )}
        {own.length > 0 && (
          <div style={{ padding: '12px 16px' }}>
            <ApiForm
              path="billing/updateSubscription"
              tenantId={tenantId}
              submitLabel="Change seats"
              successMessage="Seats changed. The difference for this month is on the next invoice."
              compact
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'subscriptionId',
                  label: 'Subscription',
                  type: 'select',
                  required: true,
                  options: own.map((subscription) => ({
                    value: subscription.id,
                    label: `${subscription.planName} (${subscription.seats} seats)`,
                  })),
                },
                { name: 'seats', label: 'Seats', type: 'number', required: true },
              ]}
            />
          </div>
        )}
      </Card>
      {selfServe.length > 0 && (
        <Card
          title="Plans"
          description="Plans this organization can subscribe to itself. The rest of this month is invoiced at once, unless the plan starts with a trial."
          flush
        >
          <Table
            head={['Plan', 'Price', '']}
            rows={selfServe.map((plan) => [
              <span key="n" className="stack" style={{ gap: 2 }}>
                <strong>{plan.name}</strong>
                {plan.description && <span className="small muted">{plan.description}</span>}
                {plan.trialDays && <Badge tone="accent">{`${plan.trialDays}-day trial`}</Badge>}
              </span>,
              <span key="p" className="small">
                {planSummary(plan, currency)}
              </span>,
              <ApiButton
                key="s"
                path="billing/subscribe"
                body={{ tenantId, plan: plan.key }}
                label="Subscribe"
                confirm={`Subscribe to ${plan.name}?`}
                tenantId={tenantId}
              />,
            ])}
          />
        </Card>
      )}
      <Card
        title="Promotion codes"
        description="A redeemed code discounts invoices after any contract discount, for the code's duration."
        flush
      >
        {discounts && discounts.length > 0 && (
          <Table
            head={['Code', 'Discount', 'Invoices', 'Status']}
            rows={discounts.map((discount) => [
              <span key="c" className="stack" style={{ gap: 2 }}>
                <code>{discount.code}</code>
                <span className="small muted">{discount.name}</span>
              </span>,
              `${discount.percentOff !== undefined ? `${discount.percentOff}%` : money(discount.amountOffMicros ?? 0, currency)} off ${
                discount.duration === 'once'
                  ? 'one invoice'
                  : discount.duration === 'forever'
                    ? 'every invoice'
                    : `for ${discount.durationInMonths} months`
              }`,
              String(discount.appliedInvoices),
              <Badge key="s" tone={discount.active ? 'success' : 'neutral'}>
                {discount.active ? 'active' : 'ended'}
              </Badge>,
            ])}
          />
        )}
        <div style={{ padding: '12px 16px' }}>
          <ApiForm
            path="billing/redeemCoupon"
            tenantId={tenantId}
            submitLabel="Redeem"
            successMessage="Code redeemed."
            resetOnSuccess
            compact
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'code', label: 'Code', required: true, placeholder: 'LAUNCH50' },
            ]}
          />
        </div>
      </Card>
      {pendingItems && pendingItems.length > 0 && (
        <Card
          title="Next invoice"
          description="One-off charges and credits, including prorations from subscription changes, waiting for the next invoice."
          flush
        >
          <Table
            head={['Item', 'Invoice', 'Amount']}
            rows={pendingItems.map((item) => [
              <span key="d" className="row">
                {item.description}
                {item.source === 'proration' && <Badge tone="info">proration</Badge>}
              </span>,
              item.period ? periodLabel(item.period) : 'next',
              money(item.amountMicros, currency),
            ])}
          />
        </Card>
      )}
    </>
  );
}
