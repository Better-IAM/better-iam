# Events and webhooks

Every audit event is an event. Provisioning operations, authentication events (`auth:session:create`, `auth:mfa:enable`, and so on), denials, root overrides, invitation redemptions, access-request decisions, and deployment operations all produce one audit record inside the transaction that made the change. The event service fans each record out in that same transaction, so nothing is emitted for a mutation that rolled back and nothing committed is lost. The one deliberate exception is `auth:signin:fail`, a wrong password, factor, or recovery code presented for a real account: the refused sign-in rolled back, so the event is appended in a transaction of its own (with `metadata.reason`, `metadata.ip`, and `metadata.userAgent`), which makes it a good subscription for brute-force alerting.

## In-process subscribers

```ts
const stop = iam.events.subscribe(['iam:identities:*', 'access-request:*'], async (event) => {
  await metrics.count(event.action, { tenant: event.tenantId, outcome: event.outcome });
});
// Later
stop();
```

Patterns use the policy glob syntax (`*` and `?`). `events.onEvent` in the options receives every event. Handlers run from the dispatcher, not from the request: call `iam.events.dispatch()` (the same function as `iam.dispatchAuditHooks()`) from the worker schedule that also drives `iam.auth.dispatchOutbox()`. Dispatch is at-least-once. A handler that throws leaves its row queued for the next run, so handlers must be idempotent by `event.id`. Plugin `afterAudit` hooks share this queue.

## Webhook subscriptions

```ts
const { webhook, secret } = await iam.api.webhooks.create(credential, {
  tenantId,
  url: 'https://hooks.example.com/iam',
  events: ['iam:identities:*', 'iam:bindings:*', 'auth:session:create'],
  description: 'SIEM feed',
});
```

- `iam:webhooks:create`, `read`, `update`, and `delete` gate the API group. Creating, updating, rotating, and deleting require recent authentication.
- `outcomes` (`['deny']`, for example) and `resources` (glob patterns over the event's `resourceId`) narrow a subscription beyond its action patterns; `update` changes them and `null` clears them.
- A subscription belongs to one tenant and receives that tenant's events. Root administrators may create a subscription with `scope: 'subtree'` on any tenant to receive its descendants' events as well; ordinary administrators cannot, because parent membership grants nothing in child tenants.
- URLs must use HTTPS (HTTP is accepted only for loopback development installations), carry no credentials or fragment, and are stored as given. At most 50 subscriptions per tenant.
- The signing secret is returned once by `create` and `rotateSecret`; only its sealed form is stored. Pending deliveries are signed with the secret current at delivery time.
- `update` changes the URL, event patterns, description, or `active` flag. A paused subscription drops its pending deliveries rather than accumulating them.
- `ping` queues a synthetic `webhook:ping` event. `listDeliveries` returns the newest deliveries with attempt counts, timestamps, the last error, the audit `eventId` they carried, and a `pending`, `delivered`, or `failed` status; payloads are never returned.
- `redeliver({ webhookId, deliveryId })` (`iam:webhooks:update`) queues the event behind an earlier delivery again, rebuilt from the audit record and signed with the subscription's current secret at delivery time. Use it after an endpoint outage abandoned deliveries, or to replay an event; endpoints must still deduplicate by event `id`.

## Delivery

Deliveries travel through the encrypted transactional outbox as `kind: 'webhook'` messages and are sent by `iam.auth.dispatchOutbox()`. The built-in transport POSTs the JSON body with these headers:

| Header                   | Value                                                          |
| ------------------------ | -------------------------------------------------------------- |
| `Content-Type`           | `application/json`                                             |
| `X-Better-IAM-Event`     | The event type (audit action), for example `iam:groups:create` |
| `X-Better-IAM-Delivery`  | The outbox message ID; deduplicate on it                       |
| `X-Better-IAM-Webhook`   | The subscription ID                                            |
| `X-Better-IAM-Timestamp` | Unix seconds at signing time                                   |
| `X-Better-IAM-Signature` | `v1=` followed by hex HMAC-SHA256 of `${timestamp}.${body}`    |

The body is `{ id, type, tenantId, actorId, originalActorId?, impersonatorId?, resourceId, outcome, rootOverride?, timestamp, metadata?, sequence?, hash? }`; `impersonatorId` names the administrator behind a "view as" session while `actorId` stays the member; `sequence` and `hash` locate the event in the tenant's audit chain (below). Events recorded for a credential also carry `sessionContext` (see [session context](#session-context)). Verify the delivery with:

```ts
import { verifyWebhookSignature } from 'better-iam';

const valid = verifyWebhookSignature({
  secret,
  timestamp: request.headers.get('x-better-iam-timestamp')!,
  body: await request.text(),
  signature: request.headers.get('x-better-iam-signature')!,
});
```

Verification uses a constant-time comparison and rejects timestamps more than five minutes from the current time by default (`toleranceSeconds`). A non-2xx response or a timeout (`events.webhookTimeoutMs`, default ten seconds) counts as a failed attempt. Failed messages retry with exponential backoff starting at thirty seconds and capped at one hour; after `authentication.maxDeliveryAttempts` (default 25) the message is abandoned with `failedAt` and `lastError` set. Redirects are never followed.

Supply `events.deliverWebhook` to replace the HTTP transport, for example to hand deliveries to a queue. It receives `{ id, tenantId, webhookId, url, event, body, headers }` with the signature already computed and must throw to signal failure.

Webhook endpoints receive audit metadata only: identifiers, action names, outcomes, and the metadata a mutation recorded. Tokens, secrets, and passwords never appear in audit records and therefore never reach a webhook.

## Access lifecycle events

Beyond the `iam:*` operation names, the access lifecycle features record their own events, all subscribable by pattern (`binding:*`, `identity:*`):

| Event                              | Recorded when                                                                                                                  | Metadata                                                                                                                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `binding:activate`                 | A member activates an eligible binding                                                                                         | `activationId`, `roleId`, `expiresAt`, `justification`                                                                                                                      |
| `binding:activation-requested`     | Activation needs approval and a request was recorded                                                                           | `activationId`, `roleId`, `expiresAt` (lapse), `requestedDurationMs`, `justification`                                                                                       |
| `binding:activation-approved`      | An approver granted a request                                                                                                  | `activationId`, `roleId`, `identityId`, `expiresAt`, `note`                                                                                                                 |
| `binding:activation-denied`        | An approver refused a request                                                                                                  | `activationId`, `roleId`, `identityId`, `note`                                                                                                                              |
| `binding:deactivate`               | The holder ended an activation, withdrew a request (`cancelled`), or an administrator ended it (`revoked`)                     | `activationId`, `roleId`, `identityId`, `cancelled`, `revoked`                                                                                                              |
| `identity:expire`                  | The purge worker disabled an identity past its `expiresAt` (actor `deployment-operator`)                                       | `kind`, `expiresAt`                                                                                                                                                         |
| `identity:offboard`                | `identities.offboard` ran                                                                                                      | `reason`, `kind`, `successorId`, and the counts of everything removed                                                                                                       |
| `identity:export`                  | A data-subject export was produced                                                                                             | `kind`, `auditIncluded`                                                                                                                                                     |
| `tenant:access-policy`             | `tenants.setAccessPolicy` changed the activation floors                                                                        | `accessPolicy`                                                                                                                                                              |
| `tenant:access-digest`             | `sendAccessDigest` emailed the owners an access digest (actor `deployment-operator`)                                           | `recipients` and the finding counts                                                                                                                                         |
| `package:assign`                   | `packages.assign` granted an access package                                                                                    | `packageId`, `packageName`, `identityId`, `bindings`, `memberships`, `skipped`, `expiresAt`, `justification`, `replacedAutomatic`                                           |
| `package:revoke`                   | `packages.revoke` removed an assignment                                                                                        | `packageId`, `packageName`, `identityId`, `bindings`, `memberships`                                                                                                         |
| `package:request`                  | A member asked for a requestable package                                                                                       | `requestId`, `packageId`, `packageName`, `lapsesAt`, `desiredExpiresAt`, `justification`                                                                                    |
| `package:request-approved`         | An approver granted a request (the package was assigned)                                                                       | `requestId`, `packageId`, `identityId`, `assignmentId`, `bindings`, `memberships`, `skipped`, `expiresAt`, `note`                                                           |
| `package:request-denied`           | An approver refused a request                                                                                                  | `requestId`, `packageId`, `identityId`, `note`                                                                                                                              |
| `package:request-cancelled`        | The requester withdrew a pending request                                                                                       | `requestId`, `packageId`                                                                                                                                                    |
| `package:extend`                   | `packages.extend` moved the end of an assignment and everything it created                                                     | `packageId`, `packageName`, `identityId`, `previousExpiresAt`, `expiresAt`                                                                                                  |
| `identity:expiry-reminder`         | `sendExpiryReminders` emailed a person about access of theirs ending soon (actor `deployment-operator`)                        | `count`, `earliest`, `items` (item keys, so nothing is reminded twice)                                                                                                      |
| `invariant:broken`                 | `checkInvariants` found an access invariant newly failing or with new violators (actor `deployment-operator`, outcome `deny`)  | `name`, `mode`, `violations` (identity IDs), `error` when it could not be evaluated                                                                                         |
| `invariant:restored`               | `checkInvariants` found a previously failing invariant passing again (actor `deployment-operator`)                             | `name`, `mode`                                                                                                                                                              |
| `agreement:accept`                 | A member accepted a version of a terms-of-use agreement (`agreements.accept`)                                                  | `name`, `version`                                                                                                                                                           |
| `onboarding:step`                  | A person (or a tenant's administrator, for setup) completed an onboarding step or submitted a task for review                  | `flowId`, `flow`, `stepId`, `kind`, `awaitingVerification`, `attributes` (identity attributes the answers filled)                                                           |
| `onboarding:complete`              | An onboarding flow was first seen complete in its current version (resource: the person or tenant)                             | `flowId`, `flow`, `version`, `subjectType`                                                                                                                                  |
| `onboarding:verify`                | An administrator approved a verified onboarding task (`onboarding.verifyStep`)                                                 | `flowId`, `flow`, `stepId`, `subjectType`, `note`                                                                                                                           |
| `onboarding:reject`                | An administrator sent a verified onboarding task back                                                                          | `flowId`, `flow`, `stepId`, `subjectType`, `note`                                                                                                                           |
| `onboarding:reset`                 | `onboarding.resetProgress` cleared progress through a flow                                                                     | `flowId`, `flow`, `reset`, `subjectId`, `stepId`                                                                                                                            |
| `onboarding:groups`                | A finished flow's completion groups were applied (actor: the person)                                                           | `flowId`, `flow`, `groupIds`                                                                                                                                                |
| `feature:create`                   | `features.create` defined a feature flag (in the root tenant: a platform flag)                                                 | `key`, `defaultValue`, `rolloutPercentage`, `tenantOverridable`, `killSwitch`, `internal`                                                                                   |
| `feature:update`                   | `features.update` changed a flag's settings, including the kill switch                                                         | `before`, `after` (the settings)                                                                                                                                            |
| `feature:delete`                   | `features.delete` removed a flag with its targets and overrides                                                                | `key`, `removedTargets`                                                                                                                                                     |
| `feature:target`                   | `features.setTarget` pinned or removed a flag's value for a tenant below the defining one (recorded in the defining tenant)    | `key`, `targetTenantId`, `value` (`null` when removed), `locked`, `expiresAt`                                                                                               |
| `feature:override`                 | `features.setOverride` recorded or withdrew a tenant's own choice                                                              | `key`, `value` (`null` when withdrawn), `definedBy`                                                                                                                         |
| `package:auto-rule`                | A package rule was set, changed, taken over (`owner`), re-authored by a contents change, or cleared (actor: the administrator) | `packageId`, `packageName`, `change`, `revision`, `ownerId`, `previousOwnerId`, `authorityId`, `include`, `exclude`, `graceMs`, `maxGrants`, `maxRemovals`, `kept`          |
| `package:auto-confirm`             | Held-back rule changes were approved for a day (actor: the confirmer or `deployment-operator`)                                 | `packageId`, `packageName`, `grants`, `removals`, `until`                                                                                                                   |
| `package:auto-assign`              | The reconciler assigned, refreshed, or restored an automatic assignment (actor `deployment-operator`)                          | `trigger`, `revision`, `ownerId`, `requestedBy`, `identityId`, `mode`, `reason`, `bindings`, `memberships`, `removedBindings`, `removedMemberships`, `skipped`, `matchedBy` |
| `package:auto-ending`              | An automatic holder stopped matching and the grace period started                                                              | `trigger`, `identityId`, `endsAt`, `graceMs`                                                                                                                                |
| `package:auto-revoke`              | The reconciler removed an automatic assignment                                                                                 | `trigger`, `identityId`, `reason` (`no-longer-matches` or `rule-cleared`), `bindings`, `memberships`                                                                        |
| `package:auto-failed`              | A change could not be applied (for example a separation-of-duties conflict); once per new problem (outcome `deny`)             | `identityId`, `change`, `code`, `message`                                                                                                                                   |
| `package:auto-suspended`           | A rule stopped adding access: invalid rule, owner inactive, authority revoked, or owner lacking rights (outcome `deny`)        | `reason`, `detail`                                                                                                                                                          |
| `package:auto-resumed`             | A suspended rule runs again                                                                                                    | `previousReason`                                                                                                                                                            |
| `package:auto-braked`              | An unattended run held back more grants or removals than the rule allows (outcome `deny`)                                      | `direction`, `planned`, `threshold`                                                                                                                                         |
| `config:apply`                     | A configuration document was applied                                                                                           | `prune`, the change summary, `changed`                                                                                                                                      |
| `team:create`                      | `teams.create` created a team with its backing group                                                                           | `name`, `parentId`, `team` (slug)                                                                                                                                           |
| `team:update`                      | `teams.update` changed a team (moving it recomputes the old and new parents)                                                   | `fields`, `parentId`, `previousParentId`, `team`                                                                                                                            |
| `team:delete`                      | `teams.delete` removed a team, its memberships, join requests, and backing group                                               | `name`, `members`, `team`                                                                                                                                                   |
| `team:member:add`                  | Someone joined a team: added, approved, or named a maintainer at creation                                                      | `identityId`, `role`, `source` (`add`, `approve`, `create`), `expiresAt`, `via` (`maintainer`), `team`                                                                      |
| `team:member:update`               | A member's role or expiry changed                                                                                              | `identityId`, `role`, `expiresAt`, `via`, `team`                                                                                                                            |
| `team:member:remove`               | A member was removed from a team (also by a completed membership review: `source: review`, `reviewId`)                         | `identityId`, `role`, `via`, `team`                                                                                                                                         |
| `team:join:request`                | A person asked to join a team (`teams.requestToJoin`)                                                                          | `requestId`, `justification`, `team`                                                                                                                                        |
| `team:join:approve`                | A maintainer or administrator approved a join request                                                                          | `requestId`, `identityId`, `via`, `team`                                                                                                                                    |
| `team:join:deny`                   | A maintainer or administrator denied a join request                                                                            | `requestId`, `identityId`, `via`, `team`                                                                                                                                    |
| `team:join:cancel`                 | The requester withdrew a pending join request                                                                                  | `requestId`, `team`                                                                                                                                                         |
| `team:leave`                       | A person left a team (`teams.leave`)                                                                                           | `identityId`, `role`, `team`                                                                                                                                                |
| `team:review:start`                | An administrator opened a membership review of a team (`teams.startReview`)                                                    | `reviewId`, `members`, `dueAt`, `onUndecided`, `team`                                                                                                                       |
| `team:review:decide`               | A maintainer or administrator decided keep or remove for people under review                                                   | `reviewId`, `keep`, `remove`, `via`, `team`                                                                                                                                 |
| `team:review:complete`             | A review completed (by a person, or by `closeOverdueTeamReviews` as `deployment-operator`) and its removals applied            | `reviewId`, `kept`, `removed`, `undecided`, `gone`                                                                                                                          |
| `team:review:cancel`               | An administrator cancelled an open review without changing the team                                                            | `reviewId`, `team`                                                                                                                                                          |
| `department:create`                | A department was created (also by `departments.importFromAttribute`)                                                           | `name`, `parentId`, `source`                                                                                                                                                |
| `department:update`                | `departments.update` changed a department                                                                                      | `fields`                                                                                                                                                                    |
| `department:delete`                | `departments.delete` removed a department                                                                                      | `name`, `unassigned`, `teams`                                                                                                                                               |
| `department:assign`                | A person was placed in (or moved to) a department                                                                              | `identityId`, `previousDepartmentId`, `title`                                                                                                                               |
| `department:unassign`              | A person was taken out of their department                                                                                     | `identityId`                                                                                                                                                                |
| `department:sync-managers`         | `departments.syncManagers` set managers from department heads                                                                  | `updated`, `departmentId`                                                                                                                                                   |
| `billing:meter-create`             | `billing.createMeter` defined a usage meter (in the root tenant: a platform meter)                                             | `key`, `name`, `unit`, `aggregation`, `pricing`                                                                                                                             |
| `billing:meter-update`             | `billing.updateMeter` renamed or archived a meter                                                                              | `key`, `name`, `unit`, `archived`                                                                                                                                           |
| `billing:meter-delete`             | `billing.deleteMeter` removed a meter that never recorded usage                                                                | `key`, `removedPrices`                                                                                                                                                      |
| `billing:price`                    | `billing.setPrice` set or removed a rate-card price                                                                            | `meter`, `targetTenantId`, `effectiveFrom`, `model` (or `price: null`)                                                                                                      |
| `billing:budget-create`            | `billing.createBudget` created a spend budget                                                                                  | `budgetId`, `name`, `subjectType`, `subjectId`, `amountMicros`, `period`, `enforce`                                                                                         |
| `billing:budget-update`            | `billing.updateBudget` changed a budget                                                                                        | `budgetId`, `name`, `amountMicros`, `period`, `enforce`                                                                                                                     |
| `billing:budget-delete`            | `billing.deleteBudget` removed a budget                                                                                        | `budgetId`, `name`                                                                                                                                                          |
| `billing:budget-alert`             | `iam.billing.checkBudgets` found a threshold reached or a projection past the budget (actor `deployment-operator`)             | `budgetId`, `name`, `kind` (`actual`/`forecast`), `threshold`, `spentMicros`, `amountMicros`, `window`, `recipients`                                                        |
| `billing:anomaly`                  | `iam.billing.detectAnomalies` found a spend spike for a person, team or meter (actor `deployment-operator`)                    | `dimension`, `key`, `label`, `day`, `costMicros`, `baselineMicros`, `factor`                                                                                                |
| `billing:credit-grant`             | A root administrator granted credit to a billing account                                                                       | `creditId`, `amountMicros`, `reason`, `expiresAt`                                                                                                                           |
| `billing:terms`                    | A root administrator set a billing account's contract terms (discount, commitment, tax)                                        | `discountPercent`, `minimumCommitmentMicros`, `taxRatePercent`                                                                                                              |
| `billing:credit-revoke`            | A root administrator withdrew what was left of a credit                                                                        | `creditId`, `forfeitedMicros`                                                                                                                                               |
| `billing:profile`                  | `billing.setProfile` created or changed a billing profile                                                                      | `targetTenantId`, `created`, `billingEmails`, `companyName`                                                                                                                 |
| `billing:profile-delete`           | `billing.deleteProfile` removed a profile (the tenant rolls into its parent's account)                                         | `targetTenantId`                                                                                                                                                            |
| `billing:statement`                | An invoice was finalized: by `closePeriod` (actor `deployment-operator`), `finalizeInvoice`, or a new subscription             | `number`, `period`, `billingReason`, `subtotalMicros`, `creditsMicros`, `totalMicros`, `invoiceItems`, `recipients`                                                         |
| `billing:statement-paid`           | A root administrator marked a statement paid (a payment of the amount due)                                                     | `number`, `totalMicros`, `reference`                                                                                                                                        |
| `billing:statement-void`           | A root administrator voided a statement (credit, items, coupons and advance months come back; the month reopens)               | `number`, `reason`, `restoredCreditMicros`                                                                                                                                  |
| `billing:statement-finalize`       | A root administrator finalized a draft invoice                                                                                 | `number`, `period`, `totalMicros`, `recipients`                                                                                                                             |
| `billing:statement-uncollectible`  | A root administrator wrote an invoice off                                                                                      | `number`, `amountDueMicros`                                                                                                                                                 |
| `billing:payment`                  | A payment was recorded against an invoice (by a root administrator, or `iam.billing.recordPayment` as `deployment-operator`)   | `number`, `amountMicros`, `method`, `reference`, `overpaymentMicros`, `status`                                                                                              |
| `billing:credit-note`              | A root administrator issued a credit note                                                                                      | `number`, `statementNumber`, `amountMicros`, `reason`, `dueMicros`, `creditMicros`, `refundMicros`                                                                          |
| `billing:payment-reminder`         | `iam.billing.sendPaymentReminders` reminded billing contacts of an unpaid invoice (actor `deployment-operator`)                | `number`, `step`, `amountDueMicros`, `recipients`                                                                                                                           |
| `billing:invoice-item`             | A root administrator added an invoice item                                                                                     | `description`, `amountMicros`, `period`                                                                                                                                     |
| `billing:invoice-item-delete`      | A root administrator deleted a pending invoice item                                                                            | `description`, `amountMicros`                                                                                                                                               |
| `billing:plan`                     | A root administrator created a plan                                                                                            | `key`, `name`, `items`, `selfServe`                                                                                                                                         |
| `billing:plan-update`              | A root administrator changed a plan                                                                                            | `key`, `fields`                                                                                                                                                             |
| `billing:subscription`             | A billing account subscribed to a plan                                                                                         | `plan`, `seats`, `trialEndsAt`, `invoice`, `totalMicros`                                                                                                                    |
| `billing:subscription-update`      | A subscription's seats changed                                                                                                 | `plan`, `seats`, `prorationMicros`                                                                                                                                          |
| `billing:subscription-cancel`      | A subscription was cancelled at the month's end or ended now                                                                   | `plan`, `atPeriodEnd`, `endsAt`, `prorationMicros`                                                                                                                          |
| `billing:subscription-resume`      | A cancellation at the month's end was undone                                                                                   | `plan`                                                                                                                                                                      |
| `billing:subscription-plan-change` | A subscription moved to another plan                                                                                           | `from`, `to`, `previousSubscriptionId`, `prorationMicros`                                                                                                                   |
| `billing:coupon`                   | A root administrator created a coupon                                                                                          | `code`, `percentOff`, `amountOffMicros`, `duration`                                                                                                                         |
| `billing:coupon-deactivate`        | A root administrator stopped a coupon's redemptions                                                                            | `code`                                                                                                                                                                      |
| `billing:coupon-redeem`            | A billing account redeemed a coupon code                                                                                       | `code`, `couponId`                                                                                                                                                          |
| `billing:discount-remove`          | A root administrator ended an account's discount                                                                               | `code`                                                                                                                                                                      |

## Key management events

Every `keys` call records its own action (`iam:kms:create`, `iam:kms:encrypt`, `iam:kms:decrypt`, `iam:kms:sign` and
so on) on resource `kms/{keyId}` (`kms` for tenant-wide calls), with `keyVersion`, `encryptionContext`, `algorithm`
and `grantId` in its metadata where they apply. It never records plaintexts, key material or signatures. A decryption
that fails after the call was authorized is recorded as `deny` with `reason: 'invalid-ciphertext'`. The scheduler job
and grantees record these as well:

| Action             | When                                                                                                 | Metadata                  |
| ------------------ | ---------------------------------------------------------------------------------------------------- | ------------------------- |
| `kms:key-rotate`   | `iam.kms.maintain()` rotated a key whose rotation period came due (actor `deployment-operator`)      | `keyVersion`, `automatic` |
| `kms:key-destroy`  | `iam.kms.maintain()` destroyed a key after its deletion waiting period (actor `deployment-operator`) | `keySpec`, `versions`     |
| `kms:grant-retire` | A grantee gave up a key grant made to it                                                             | `grantId`                 |

See [Key management](key-management.md).

## Certificate authority events

Every `pki` call records its own action (`iam:pki:create`, `iam:pki:issue`, `iam:pki:request`, `iam:pki:revoke` and
so on) on resource `pki/{authorityId}` (`pki` for tenant-wide calls). Issuing records `serialNumber`, every name as
`{nameType}:{name}`, `usage` and `notAfter`; workload certificates record the `spiffeId`; revocations record the
`serialNumber` and `reason`. Signatures made with an authority's KMS key are also recorded on the key as
`iam:kms:sign` with `via: 'pki'`. See [Private certificate authority](private-ca.md).

## Data protection events

Every `protection` call records its own action (`iam:protection:tokenize`, `iam:protection:detokenize`,
`iam:protection:mask`, `iam:protection:delete`, `iam:protection:manage`, `iam:protection:read`) on resource
`protection/{profile}`, with the `profile` and counts (`count`, `created`, `found`, `deleted`), the `purpose` of a
detokenization and the `style` of a mask. Refusals carry the `profile` and `purpose` too. Values and tokens are never
recorded. The KMS data keys behind them are audited on the key with `via: 'protection'`. See
[Data protection](data-protection.md).

| Action                        | When                                                                                             | Metadata                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------- |
| `protection:retention-sweep`  | `iam.protection.sweep()` deleted tokens past a profile's retention (actor `deployment-operator`) | `deleted`, `retentionDays` |

## Secrets vault events

Every `vault` call records its operation event (`iam:vault:read`, `iam:vault:reveal`, `iam:vault:manage` and so on) on
resource `vault/secrets/{name}`, and calls that change a secret or hand out a value also record one of these, on the
same resource. None carries a value. Jobs record them with actor `deployment-operator`.

| Action                   | When                                                                              | Metadata                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `vault:create`           | `vault.create` created a secret                                                   | `name`, `kind`, `format`, `tags`, `version`, `engine`, `kmsKeyId`                           |
| `vault:update`           | `vault.update` changed its settings                                               | `name`, `tags`, `maxVersions`, `rotation`, `rotator`, `checkout`, `kmsKeyId`, `reencrypted` |
| `vault:delete`           | `vault.delete` scheduled (or, with `recoveryDays: 0`, started) a deletion         | `name`, `recoveryDays`, `deletionAt`                                                        |
| `vault:restore`          | `vault.restore` cancelled a scheduled deletion                                    | `name`                                                                                      |
| `vault:purge`            | The secret was deleted for good with its versions, leases and access records      | `name`, `versions`                                                                          |
| `vault:reveal`           | `vault.reveal` returned a value                                                   | `name`, `version`                                                                           |
| `vault:put`              | `vault.put` stored a new version                                                  | `name`, `version`, `stage`                                                                  |
| `vault:promote`          | `vault.promote` made a version current                                            | `name`, `version`, `previous`                                                               |
| `vault:stage`            | `vault.setStage` moved or removed a stage label                                   | `name`, `stage`, `version`                                                                  |
| `vault:version-state`    | `vault.setVersionState` disabled or enabled a version                             | `name`, `version`, `state`                                                                  |
| `vault:destroy-version`  | `vault.destroyVersion` erased a version's value                                   | `name`, `version`                                                                           |
| `vault:rotate`           | A rotation promoted its pending version (`allow`) or its rotator failed (`deny`)  | `name`, `version`, `rotator`, `error` (redacted)                                            |
| `vault:rotation-due`     | `iam.vault.rotateDue` found a scheduled rotation due with no generator or rotator | `name`, `dueAt`                                                                             |
| `vault:checkout`         | `vault.checkout` handed out a check-out                                           | `name`, `version`, `leaseId`, `expiresAt`, `reason`                                         |
| `vault:checkin`          | The holder (or an administrator) returned a check-out                             | `leaseId`, `kind`, `holderId`                                                               |
| `vault:checkout-expired` | `iam.vault.expireLeases` ended an expired check-out                               | `name`, `leaseId`, `holderId`                                                               |
| `vault:lease`            | `vault.lease` issued a dynamic credential (`allow`) or the engine failed (`deny`) | `name`, `leaseId`, `expiresAt`, `error`                                                     |
| `vault:renew`            | `vault.renewLease` extended a lease                                               | `leaseId`, `kind`                                                                           |
| `vault:revoke`           | `vault.revokeLease` ended a lease                                                 | `leaseId`, `kind`, `holderId`                                                               |
| `vault:lease-expired`    | `iam.vault.expireLeases` revoked an expired lease at its engine                   | `name`, `leaseId`, `holderId`                                                               |
| `vault:revoke-failed`    | The engine kept refusing a revocation for seven days; the lease is given up       | `name`, `leaseId`, `error`                                                                  |

Values under a customer-managed key also show on the key's trail as `iam:kms:encrypt` / `iam:kms:decrypt` with
`metadata.via: 'vault'`. See [Secrets vault](secrets-vault.md).

## Privacy events

Every `privacy` call made with a permission records its operation event (`iam:privacy:read`, `iam:privacy:manage`,
`iam:privacy:record`, `iam:privacy:check` or `iam:privacy:handle`). These record what happened, subscribable as
`privacy:*`. Consent, erasure, hold and restriction events name the account (or a subject key such as
`external:cus_100`) as their resource; request events name the request. Public intake records them with actor
`public-intake`, the deadline job with actor `deployment-operator`, and `iam.privacy.record` with actor `application`.

| Action                            | When                                                                                                  | Metadata                                                                       |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `privacy:consent`                 | A consent decision was recorded (`privacy.decide`, `privacy.record`, `iam.privacy.record`)            | `purposeKey`, `granted`, `purposeVersion`, `source`, `receiptId`, `externalId` |
| `privacy:consent-import`          | `privacy.importDecisions` imported decisions from another system                                      | `count`, `current`, `purposes`                                                 |
| `privacy:request:submit`          | A data-subject request was filed by the person, by staff, or through public intake                    | `number`, `type`, `regulation`, `channel`                                      |
| `privacy:request:email-confirmed` | A public request naming an `externalId` had its address confirmed; a handler must still verify it     | `number`                                                                       |
| `privacy:request:verify`          | A request was verified (`privacy.verifyRequest`, or `privacy.confirmPublic` through the emailed link) | `number`, `method`, `linked`                                                   |
| `privacy:request:link`            | `privacy.linkRequest` linked a request known only by email to an account or application subject       | `number`, `subjectKind`                                                        |
| `privacy:request:cancel`          | The person withdrew their own request                                                                 | `number`, `type`                                                               |
| `privacy:request:extend`          | `privacy.extendRequest` extended the deadline                                                         | `number`, `dueAt`                                                              |
| `privacy:request:complete`        | `privacy.fulfilRequest` completed a request                                                           | `number`, `type`, `actions`                                                    |
| `privacy:request:reject`          | `privacy.rejectRequest` declined a request                                                            | `number`, `type`, `reason`                                                     |
| `privacy:request:due-soon`        | `iam.privacy.sendDeadlineReminders` found an open request due soon                                    | `number`, `type`, `dueAt`                                                      |
| `privacy:request:overdue`         | `iam.privacy.sendDeadlineReminders` found an open request past its deadline                           | `number`, `type`, `dueAt`                                                      |
| `privacy:erasure`                 | An erasure request was fulfilled; erase the person's data downstream                                  | `requestId`, `subjectKind`, `externalId`                                       |
| `privacy:export:download`         | An access or portability export was downloaded                                                        | `number`, `by` (`subject` or `handler`)                                        |
| `privacy:hold:place`              | A legal hold was placed                                                                               | `holdId`, `expiresAt`                                                          |
| `privacy:hold:release`            | A legal hold was released                                                                             | `holdId`                                                                       |
| `privacy:restriction:lift`        | A restriction of processing was lifted                                                                |                                                                                |

An erasure that deletes an account also records `identity:delete` with `{ kind, erasure: true }` and no email
address. See [Privacy and consent](privacy.md).

## Workflow events

Every `workflows` call records its operation event (`iam:workflows:manage`, `iam:workflows:read` or
`iam:workflows:run`). [Lifecycle workflow](workflows.md) runs record these, subscribable as `workflow:*`. Run events
name the run as their resource, `workflow:brake` the workflow, and `workflow:event` the person.

| Action                  | When                                                                                               | Metadata                                               |
| ----------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `workflow:run:start`    | A trigger started a run (actor `deployment-operator`), or someone started one with `workflows.run` | `workflowId`, `identityId`, `occurrence`               |
| `workflow:step`         | A step other than a wait was done or skipped (actor `deployment-operator`)                         | `workflowId`, `identityId`, `index`, `kind`, `outcome` |
| `workflow:run:complete` | A run finished its last step (actor `deployment-operator`)                                         | `workflowId`, `identityId`                             |
| `workflow:run:fail`     | A step failed and stopped the run (actor `deployment-operator`, outcome `deny`)                    | `workflowId`, `identityId`, `index`, `code`            |
| `workflow:brake`        | The daily brake held runs back, once a day (actor `deployment-operator`, outcome `deny`)           | `held`, `startedToday`, `maxRunsPerDay`                |
| `workflow:event`        | An `emit-event` step ran (actor: the run's owner)                                                  | `name`, `via`, `workflowId`, `runId`                   |

The changes steps make are recorded as their ordinary events (`iam:groups:update`, `package:assign`,
`package:revoke`, `identity:revoke-sessions`, `iam:identities:update`, `identity:delete`), with the run's owner (the
workflow's owner when the run started, or whoever retried it) as the actor and `via: 'workflow'`, `workflowId` and
`runId` in the metadata.

## Compliance events

Every `compliance` call records its operation event (`iam:compliance:read`, `iam:compliance:evaluate` or
`iam:compliance:manage`). The [compliance center](compliance.md) also records these, subscribable as `compliance:*`.
Evaluations record them with the caller as the actor, or `deployment-operator` for `iam.compliance.evaluateAll()`.

| Action                       | When                                                                               | Metadata                                           |
| ---------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------- |
| `compliance:evaluate`        | An evaluation ran (resource: the run); `digest` is the SHA-256 of its results      | `pass`, `fail`, `warn`, `not-applicable`, `digest` |
| `compliance:control:fail`    | A control failed after another status in its previous evaluation (outcome `deny`)  | `key`, `checkId`, `status`, `previous`, `summary`  |
| `compliance:control:recover` | A control that failed has another status now (resource: the control)               | `key`, `checkId`, `status`, `previous`, `summary`  |
| `compliance:exception`       | `compliance.createException` accepted a finding until `expiresAt`                  | `controlKey`, `subject`, `expiresAt`               |
| `compliance:evidence-export` | `compliance.exportEvidence` produced a signed evidence pack (resource: the tenant) | `framework`, `controls`                            |

## Threat detection events

Every `threats` call made with a permission records its operation event (`iam:threats:read`, `iam:threats:manage` or
`iam:threats:respond`). [Threat detection](threat-detection.md) records these as well, subscribable as `threat:*`.
Detections, incidents, and everything playbooks do are recorded by the actor `threat-detection`; changes and
responses made through the API by the person who made them. Responses name the identity as their resource (so
receivers can match them to the account), network blocks `threats/networks/{network}`, and the rest the record they
concern (`threats/detections/{id}`, `threats/incidents/{id}`, `threats/playbooks/{id}`, `threats/settings`). Every
event is `allow`. `incidentId`, `detectionId` and `playbookId` appear on responses when they were taken for one.

| Action                     | When                                                                                                                    | Metadata                                                                                   |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `threat:detection`         | A rule fired, `threats.configure` turned a rule off, or a person reported suspicious activity                           | `ruleId`, `severity`, `subjectType`, `subjectId`, `identityId`, `network`, `incidentId`    |
| `threat:incident-open`     | A detection opened a new incident about its subject                                                                     | `ruleId`, `severity`, `subjectType`, `subjectId`, `identityId`                             |
| `threat:risk-change`       | An identity's risk level changed (resource: the identity; actor `threat-detection` or the person whose action moved it) | `from`, `to`, `score`                                                                      |
| `threat:settings`          | `threats.configure` saved the tenant's settings                                                                         | `changed` (setting names), `changedRules`, `disabledRules`                                 |
| `threat:detection-dismiss` | `threats.dismissDetection` marked a detection a false alarm                                                             | `ruleId`, `severity`, `reason`, `identityId`, `incidentId`                                 |
| `threat:incident-update`   | `threats.updateIncident` changed status, assignee or severity                                                           | `changes`, `status`, `severity`, `assigneeId` (`null` when unassigned)                     |
| `threat:note`              | `threats.addNote` added a note (without its text)                                                                       | `noteId`, `length`                                                                         |
| `threat:incident-resolve`  | `threats.resolveIncident` closed an incident                                                                            | `resolution`, `severity`, `subjectType`, `subjectId`, `detectionsResolved`, `identityId`   |
| `threat:risk-override`     | `threats.setRisk` set or cleared an identity's risk level (resource: the identity)                                      | `level`, `reason`, `expiresAt`, `clearedContributions` (for `none`)                        |
| `threat:revoke-sessions`   | A `revoke-sessions` response ended the identity's sessions (resource: the identity)                                     | `revoked`, `keptApiKeys`, `reason`, `incidentId`, `detectionId`, `playbookId`              |
| `threat:forget-devices`    | A `forget-devices` response removed remembered devices (resource: the identity)                                         | `removed`, `reason`, `incidentId`, `detectionId`, `playbookId`                             |
| `threat:contain`           | A `contain` response disabled the identity (resource: the identity)                                                     | `reason`, `sessionsEnded`, `incidentId`, `detectionId`, `playbookId`                       |
| `threat:release`           | `threats.release` lifted a containment (resource: the identity)                                                         | `note`, `containedAt`, `incidentId`                                                        |
| `threat:block-network`     | A `block-network` response blocked a network (resource `threats/networks/{network}`)                                    | `network`, `expiresAt`, `renewed`, `reason`, `incidentId`, `detectionId`, `playbookId`     |
| `threat:notify`            | A `notify` response queued `threat-alert` emails (resource: the incident)                                               | `recipients` (count), `severity`, `incidentId`                                             |
| `threat:response-braked`   | Playbooks reached `maxAutomaticContainments` in a run and held further containments back, once per run                  | `threshold`, `identityId` (the first held back), `incidentId`, `detectionId`, `playbookId` |
| `threat:playbook-create`   | `threats.createPlaybook` defined a playbook                                                                             | `name`, `enabled`, `trigger`, `actions`                                                    |
| `threat:playbook-update`   | `threats.updatePlaybook` changed one                                                                                    | `before`, `after` (the settings)                                                           |
| `threat:playbook-delete`   | `threats.deletePlaybook` removed one                                                                                    | `name`                                                                                     |
| `threat:user-report`       | A person reported suspicious activity on their own account (`threats.reportSuspicious`; resource: the person)           | `detectionId`, `incidentId`, `sessionsEnded`, `devicesForgotten`, `withNote`, `sessionId`  |

With the Shared Signals transmitter, `threat:revoke-sessions` is sent as CAEP `session-revoked` and `threat:contain`
as RISC `account-disabled` ([protocols](protocols.md#shared-signals-caep-and-risc)). The detection engine never reads
these events back as input for its rules, but it verifies them as part of the chain.

## Shared Signals receiver events

Every `signals` call records its operation event (`iam:signals:read` or `iam:signals:manage`). The
[Shared Signals receiver](shared-signals-receiver.md) also records these, subscribable as `signal:*`. Events about
received security events are recorded by the actor `signal:{sourceId}`, changes to sources by the administrator who
made them. Sources are named `signals/sources/{sourceId}` and received events `signals/events/{eventId}`. Every event
is `allow`, and none carries a token or a SET.

| Action                   | When                                                                                                                    | Metadata                                                                                                |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `signal:received`        | A security event was recorded, or reprocessed and now matches someone (resource: the matched identity, else the source) | `sourceId`, `eventType`, `jti`, `status`, `identityId`, `reasonAdmin`, `currentLevel`, `credentialType` |
| `signal:revoke-sessions` | A source's `revoke-sessions` action ended the matched person's sessions except API keys (resource: the identity)        | `sourceId`, `eventType`, `jti`, `revoked`                                                               |
| `signal:source-create`   | `signals.createSource` registered a transmitter                                                                         | `name`, `issuer`, `delivery`                                                                            |
| `signal:source-update`   | `signals.updateSource` changed one                                                                                      | `changed` (field names)                                                                                 |
| `signal:source-delete`   | `signals.deleteSource` removed one                                                                                      | `name`, `issuer`                                                                                        |
| `signal:source-rotate`   | `signals.rotatePushToken` replaced a push source's bearer token (or gave it its first one)                              | `replaced`                                                                                              |
| `signal:reprocess`       | `signals.reprocess` mapped an unmatched or failed event again (resource: the event)                                     | `sourceId`, `eventType`, `jti`, `previousStatus`, `status`, `identityId`                                |

`reasonAdmin` (the event's `reason_admin`, at most 256 characters), `currentLevel` (the upper-cased `current_level` of a
`risk-level-change`) and `credentialType` appear only when the event carries them, and `identityId` only for a match.
Threat detection reads `signal:received`. The Shared Signals transmitter maps none of these actions, so what the
receiver does is never sent back upstream.

## Device posture events

Every administrative `devices` call records its operation event (`iam:devices:read`, `iam:devices:manage` or
`iam:devices:report`). [Device posture](device-posture.md) changes also record one of these, subscribable as
`device:*`. The resource is the device (`devices/{deviceId}`), `devices/enrollments`, `devices/settings`, or the
integration (`devices/integrations/{integrationId}`). The actor is the person, administrator or reporting service
account that made the call, and every event is `allow`. `devices.mine` and `devices.check` record nothing. No event
carries a key, a proof or an enrollment code; `keyId` is the public key's thumbprint. These are separate from
`auth:device:*`, which records remembered devices.

| Action                      | When                                                                                                   | Metadata                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `device:enroll`             | A person enrolled a key (`devices.enroll`), creating a device or binding the key to one with a code    | `deviceId`, `keyId`, `platform`, `created`, `managed`, `enrollmentId` (with a code) |
| `device:retire`             | The owner (`devices.retireMine`, `self: true`) or an administrator (`devices.retire`) retired a device | `deviceId`, `keysRemoved`, `self`                                                   |
| `device:update`             | `devices.update` renamed a device, changed its owner, or marked it lost or active                      | `deviceId`, `before`, `after` (`name`, `status`, `ownerIdentityId`), `keysRemoved`  |
| `device:delete`             | `devices.delete` removed a device with its keys and enrollment codes                                   | `deviceId`, `name`, `managed`, `keysRemoved`, `enrollmentsRemoved`                  |
| `device:key-remove`         | `devices.removeKey` removed one key                                                                    | `deviceId`, `keyId`                                                                 |
| `device:enrollment-create`  | `devices.createEnrollment` issued an enrollment code                                                   | `enrollmentId`, `deviceId`, `ownerIdentityId`, `expiresAt`                          |
| `device:enrollment-revoke`  | `devices.revokeEnrollment` withdrew one                                                                | `enrollmentId`, `deviceId`, `used`                                                  |
| `device:settings`           | `devices.configure` changed the compliance requirements                                                | `before`, `after` (the requirements)                                                |
| `device:integration-create` | `devices.createIntegration` added an MDM or EDR integration                                            | `integrationId`, `name`, `vendor`, `status`, `trustVendorCompliance`                |
| `device:integration-update` | `devices.updateIntegration` renamed, disabled or enabled one, or changed `trustVendorCompliance`       | `integrationId`, `before`, `after`                                                  |
| `device:integration-delete` | `devices.deleteIntegration` removed one                                                                | `integrationId`, `name`, `detached` (devices left unmanaged)                        |
| `device:report`             | An integration reported devices (`devices.report`); once per call                                      | `integrationId`, `received`, `created`, `updated`, `unchanged`, `complianceChanged` |
| `device:compliance-change`  | A report made an existing device compliant or took it out of compliance (resource: the device)         | `deviceId`, `integrationId`, `from`, `to`, `reasons`                                |

`device:compliance-change` comes from reports only. Compliance that changes because the requirements changed, an
integration was disabled, or a device stopped checking in shows up in decisions and in `devices.list` but records no
event.

## Temporary credential events

Issuing and revoking [temporary credentials](temporary-credentials.md) records these events besides the operation events (`iam:roles:assume`, `iam:session-tokens:create`, `iam:roles:revoke-sessions`, `iam:trust:*`, `iam:oidc-providers:*`), subscribable as `role:*`, `session-token:*` and `auth:mfa:*`:

| Event                            | Recorded when                                                                                                                                                     | Metadata                                                                                                                                                                                                                                                             |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `role:assumed`                   | `roles.assume` issued a role session; recorded in the **target** tenant (the operation event stays in the source tenant), resource the role                       | `trustId`, `sourceTenantId`, `sourceSessionKind`, `durationSeconds`, `format`, `tagKeys` (names only, never values), `passSourceAttributes`                                                                                                                          |
| `role:assumed-with-web-identity` | The public web-identity exchange issued a session (`allow`, actor the trust's service account), or refused a token once the trust resolved in its tenant (`deny`) | `trustId`, `providerId`, and for `allow` `issuer`, `subject`, `durationSeconds`, `format`, `tagKeys`; for `deny` `reason` (such as `signature`, `audience`, `conditions`, `replay`, `service-account`), plus `issuer` and `subject` only when the signature verified |
| `session-token:issued`           | `sts.getSessionToken` issued a token, resource the identity                                                                                                       | `sessionId`, `sourceSessionKind`, `durationSeconds`, `format`, `mfaStepUp`                                                                                                                                                                                           |
| `role:sessions-revoked`          | `roles.revokeSessions`, `trust.revokeSessions` or `oidcProviders.revokeSessions` moved a watermark; resource the role, trust or provider                          | `sessionsRevokedBefore`, `revoked` (rows deleted)                                                                                                                                                                                                                    |
| `auth:mfa:step-up`               | A TOTP code was verified for an MFA step-up on an existing credential (`sts.getSessionToken` with `mfaCode`)                                                      | none                                                                                                                                                                                                                                                                 |

Denied web-identity exchanges are recorded best-effort in a transaction of their own, never for an unknown trust (so the log cannot be flooded with attacker-chosen ids), and never with unverified claims. The raw external token and every issued token are never recorded.

## Session context

Every audit event the server records for an authenticated principal (each operation, and the events above except denials) carries `sessionContext`: `{ sessionId, kind, roleId?, trustId?, sourceTenantId?, sessionName?, sourceIdentity?, webIdentityProviderId?, webIdentitySubject?, format? }`. `kind` is `user`, `api-key`, `role` or `session-token`; the optional fields describe role sessions and session tokens (the subject is truncated to 256 characters, and `format` is present only for session JWTs). Events recorded without a principal (deployment operations, denied web-identity exchanges), the authentication service's own `auth:*` events, and simulated principals have none. It is part of the hashed event, so `audit.verify` and `verifyAuditChain` cover it, and webhook bodies copy it. Session ids are identifiers, not credentials; hashes, policies, tag values and authority ids never appear. Filter on it to answer "what did this CI run do" (`sessionContext.sessionName`) or "who acted through this trust" (`sessionContext.trustId`).

## Audit chain

Every tenant's audit log is a hash chain. Each event carries `sequence` (its position, from 1), `previousHash` (the hash of the previous event, or sixty-four zeros for the first), and `hash`: SHA-256 over the canonical JSON of the event without `hash` (keys sorted recursively, `undefined` omitted; see `canonicalJson`). The chain head per tenant is stored in `auditChains` and advanced inside the transaction that records the event. Every writer goes through the same append: provisioning operations, denials, authentication events, SCIM provisioning, the OAuth provider, and deployment operations. Events recorded by versions without the chain are chained once, in timestamp order per tenant, the next time `initialize()` runs.

- `audit.verify({ tenantId, fromSequence?, toSequence? })` (`iam:audit:read`) walks the stored events: contiguous sequences, linked hashes, recomputable hashes, and, for a full verification, a chain head equal to the last event. It returns `{ valid, checked, unchained, first, last, lastHash, head, failure? }` where `failure` names the sequence, event ID, and reason (`sequence-gap`, `previous-hash-mismatch`, `hash-mismatch`, `head-mismatch`, `missing-prefix`, `unchained`). A full verification also shows deletions at either end: the chain must start at sequence 1 or right after an `audit:prune` checkpoint recorded inside it (`missing-prefix` otherwise), deleting every event fails the head check, and an event without chain fields fails as `unchained` (every writer chains, so it was inserted around them). `initialize()` chains legacy unchained events only for tenants that have no chain yet.
- `audit.export({ tenantId, fromSequence?, limit? })` returns chained events in sequence order as JSON Lines (`body`), with `firstSequence`, `lastSequence`, `nextSequence` for the following page, and the current `head`. Archive pages as they are.
- `verifyAuditChain(events, { previousHash?, head? })`, exported by `better-iam` and `@better-iam/core`, verifies an archive anywhere: pass the last hash of the previous page as `previousHash` so pages link. It uses Web Crypto and runs in browsers and workers.

A chain proves that stored events were not altered, reordered, or removed after the fact by anyone without write access to both the events and the chain head; it does not stop someone with full database access from rewriting both. Export regularly to independent storage and compare heads.

Retention: `iam.pruneAudit({ tenantId, retentionMs })` (CLI `audit-prune`) deletes the longest prefix of a tenant's chain older than the cutoff and appends an `audit:prune` checkpoint whose metadata records the deleted count and the sequence and hash the chain now starts after. Verification keeps working from the checkpoint because a run may start mid-chain; the archive you exported before pruning still links to it through `previousHash`.
