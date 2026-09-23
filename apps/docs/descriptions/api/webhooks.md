# webhooks

Webhooks push a tenant's audit events to an HTTPS endpoint you run, signed so the endpoint can tell they came from
Better IAM. Every change, sign-in, and denial already produces an audit event; a subscription picks the ones you care
about by event name, outcome, and resource, and delivers them through the transactional outbox with retries. Use them
to feed a SIEM, alert on privilege elevation (`binding:*`), or keep another system in sync without polling
[`audit.list`](/docs/reference/api/audit#list). The [webhooks guide](/docs/guides/events/webhooks) walks through a
full setup, and [lifecycle events](/docs/guides/events/lifecycle-events) lists the event names beyond `iam:*`.

## Delivery and signing

A delivery is queued in the same transaction as the event it carries, so a change that rolls back sends nothing and a
committed change is never lost. The outbox worker (`iam.auth.dispatchOutbox()`, see
[scheduled jobs](/docs/operations/jobs)) sends it as a `POST` with a JSON body and these headers:
`X-Better-IAM-Event` (the event name), `X-Better-IAM-Delivery` (the delivery id), `X-Better-IAM-Webhook` (the
subscription id), `X-Better-IAM-Timestamp` (Unix seconds), and `X-Better-IAM-Signature` (`v1=` followed by the hex
HMAC-SHA256 of `${timestamp}.${body}` under the subscription's secret).

The body carries `id` (the audit event id), `type`, `tenantId`, `actorId`, `resourceId`, `outcome`, and `timestamp`,
plus optional fields such as `metadata`, `impersonatorId`, and the event's `sequence` and `hash` in the
[audit chain](/docs/guides/events/audit-chain). It never contains tokens, secrets, or passwords. Verify every request
before trusting it:

```ts
import { verifyWebhookSignature } from 'better-iam';

const body = await request.text(); // the raw body, before JSON parsing
const valid = verifyWebhookSignature({
  secret: process.env.IAM_WEBHOOK_SECRET!,
  timestamp: request.headers.get('x-better-iam-timestamp')!,
  body,
  signature: request.headers.get('x-better-iam-signature')!,
}); // constant-time; rejects timestamps more than 300 seconds off (toleranceSeconds)
```

Any non-2xx response, a timeout (`events.webhookTimeoutMs`, ten seconds by default), or a redirect counts as a
failed attempt; redirects are never followed. Failed deliveries retry with exponential backoff from 30 seconds up to
one hour, and after `authentication.maxDeliveryAttempts` (25 by default) they are abandoned with `failedAt` and
`lastError`. Delivery is at least once, so deduplicate on the body's `id`, which stays the same across retries and
redeliveries. To hand deliveries to your own queue instead of HTTP, set `events.deliverWebhook`; it receives the
already signed request.

## Filters and scope

A subscription receives an event only when all of its filters match:

- `events`: 1 to 50 name patterns with `*` and `?` wildcards, such as `iam:identities:*`, `binding:*`, or
  `auth:signin:fail`. `['*']` means every event.
- `outcomes` (optional): `['allow']`, `['deny']`, or both. `['deny']` turns a subscription into a feed of refused
  operations.
- `resources` (optional): 1 to 20 glob patterns of up to 256 characters, matched against the event's `resourceId`,
  such as `project/*` for events about registered projects.

A subscription belongs to one tenant and receives that tenant's events. With `scope: 'subtree'` it also receives the
events of every descendant tenant; only the platform root may create one, because membership in a parent tenant
grants nothing in its children. A tenant holds at most 50 subscriptions, and its plan limit for webhooks may be
lower.

## create

Subscribes an HTTPS endpoint to the tenant's audit events and returns the signing secret, which is shown only once.

- **Permission:** `iam:webhooks:create` on the tenant, with recent authentication.
- **Audited as:** `iam:webhooks:create`.
- **Errors:** `INVALID_INPUT` for a URL that is not absolute HTTPS, carries credentials or a fragment, or for invalid
  `events`, `outcomes`, or `resources`; `LIMIT_EXCEEDED` at 50 subscriptions or the tenant's plan limit;
  `ACCESS_DENIED` for `scope: 'subtree'` unless the caller is the platform root; `RECENT_AUTH_REQUIRED` when the
  caller has not authenticated recently or uses a temporary credential; `IMPERSONATION_RESTRICTED` in a "view as"
  session.

Store the returned `secret` (it starts with `whsec_`) in your endpoint's configuration right away: only a sealed copy
is kept, and no call returns it again. Plain HTTP is accepted only for `localhost`, `127.0.0.1`, or `[::1]` while the
deployment itself does not run on HTTPS, which is enough for local development. The subscription starts active.

```ts
const { webhook, secret } = await iam.api.webhooks.create(credential, {
  tenantId,
  url: 'https://siem.example.com/hooks/iam',
  events: ['iam:*', 'binding:*', 'auth:signin:fail'],
  outcomes: ['deny'],
  description: 'Security feed',
});
```

## delete

Deletes a subscription and discards the deliveries still waiting to be sent.

- **Permission:** `iam:webhooks:delete` on the webhook, with recent authentication.
- **Audited as:** `iam:webhooks:delete`.
- **Errors:** `NOT_FOUND` when the webhook is not in this tenant.

Delivered and abandoned deliveries stay in storage until the retention sweep removes them. To stop deliveries
temporarily and keep the secret, pause the subscription with [`update`](#update) instead.

## get

Returns one subscription without its secret.

- **Permission:** `iam:webhooks:read` on the webhook.
- **Audited as:** `iam:webhooks:read`.
- **Errors:** `NOT_FOUND` when the webhook is not in this tenant.

## list

Lists every subscription of the tenant, without secrets.

- **Permission:** `iam:webhooks:read` on the tenant.
- **Audited as:** `iam:webhooks:read`.

## listDeliveries

Returns the delivery history of one subscription, newest first, with status, attempt count, and the last error.

- **Permission:** `iam:webhooks:read` on the webhook.
- **Audited as:** `iam:webhooks:read`.
- **Errors:** `NOT_FOUND` when the webhook is not in this tenant; `INVALID_INPUT` when `limit` is outside 1 to 1000.

Each entry has the delivery `id`, the `event` name, the audit `eventId` it carried, `createdAt`, `attempts`,
`deliveredAt`, `failedAt`, `lastError`, and a `status` of `pending`, `delivered`, or `failed`. `limit` defaults to 100.
Payloads are never returned. Use it to diagnose a failing endpoint (`lastError` holds the HTTP status or network
error) and to find the deliveries to [`redeliver`](#redeliver) after an outage. Finished deliveries stay listed until
`iam.sweepExpired()` removes them after its delivery retention period (30 days by default).

## ping

Queues a synthetic `webhook:ping` delivery so you can check an endpoint and its signature verification end to end.

- **Permission:** `iam:webhooks:update` on the webhook.
- **Audited as:** `iam:webhooks:update`.
- **Errors:** `INVALID_TRANSITION` when the subscription is paused; `NOT_FOUND` when the webhook is not in this
  tenant.

The ping is sent whatever the subscription's event patterns are. Its body has `type: 'webhook:ping'`, the caller as
`actorId`, and the webhook id as `resourceId`. It is not an audit event, so it cannot be redelivered. The call returns
the `deliveryId`; follow it with [`listDeliveries`](#listdeliveries) once the outbox worker has run.

## redeliver

Queues the event behind an earlier delivery again, rebuilt from the audit log and signed with the current secret.

- **Permission:** `iam:webhooks:update` on the webhook.
- **Audited as:** `iam:webhooks:update`.
- **Errors:** `NOT_FOUND` when the delivery does not belong to this webhook, or when its audit event no longer exists
  (for example after `pruneAudit`); `INVALID_TRANSITION` when the subscription is paused or the delivery was a ping.

Use it after an endpoint outage outlasted the retries, or to replay an event your consumer lost. It works on any
delivery, whatever its status, and creates a new delivery id, so your endpoint must deduplicate on the body's `id`
(the audit event id, returned here as `eventId`).

```ts
const failed = (await iam.api.webhooks.listDeliveries(credential, { tenantId, webhookId }))
  .filter((delivery) => delivery.status === 'failed');
for (const delivery of failed)
  await iam.api.webhooks.redeliver(credential, { tenantId, webhookId, deliveryId: delivery.id });
```

## rotateSecret

Replaces a subscription's signing secret and returns the new one, which is shown only once.

- **Permission:** `iam:webhooks:update` on the webhook, with recent authentication.
- **Audited as:** `iam:webhooks:update`.
- **Errors:** `NOT_FOUND` when the webhook is not in this tenant; `RECENT_AUTH_REQUIRED`;
  `IMPERSONATION_RESTRICTED`.

Deliveries are signed when they are sent, not when they are queued, so every delivery sent after this call, including
retries of older events, uses the new secret. There is no overlap period: update your endpoint right away, or let it
accept either secret while you switch. Rotate when a secret may have leaked or when the person who configured the
endpoint leaves.

## update

Changes a subscription's URL, event patterns, filters, description, or active flag.

- **Permission:** `iam:webhooks:update` on the webhook, with recent authentication.
- **Audited as:** `iam:webhooks:update`.
- **Errors:** `INVALID_INPUT` when nothing is given to change or a value is invalid (the same rules as
  [`create`](#create)); `NOT_FOUND`; `RECENT_AUTH_REQUIRED`; `IMPERSONATION_RESTRICTED`.

Pass `null` for `description`, `outcomes`, or `resources` to clear it. The `scope` cannot change after creation.
`active: false` pauses the subscription: new events are not queued for it, and deliveries already queued are dropped
rather than sent. Setting `active: true` resumes it for new events only; use [`redeliver`](#redeliver) for anything
you still need from the paused period's queued deliveries.
