# Recipes

Short, copy-ready examples for the capabilities that go beyond roles and bindings. Every call below runs through the same transactional authorization envelope as the rest of the API; `credential` is a session token or the request headers.

## Share a resource with relationships

Declare the relations a type supports, let a role read them, then hand out relations instead of editing policies.

```ts
// Configuration
permissions: {
  resourceTypes: {
    folder: { managed: true, actions: ['folders:read', 'folders:share'], relations: ['viewer', 'editor', 'owner'] },
    file: { managed: true, parent: 'folder', actions: ['files:read'], relations: ['viewer'] },
  },
}

// A role that turns relations into permissions (bind it to everyone)
await iam.api.roles.create(credential, {
  tenantId,
  name: 'Sharing',
  document: {
    version: 1,
    statements: [
      { effect: 'allow', actions: ['folders:read'], resources: ['folder/*'],
        conditions: { ArrayContains: { 'resource.relations': ['viewer', 'editor', 'owner'] } } },
      { effect: 'allow', actions: ['files:read'], resources: ['file/*'],
        conditions: { ArrayContains: { 'resource.parentRelations': ['viewer', 'editor', 'owner'] } } },
      { effect: 'allow', actions: ['iam:relationships:create'], resources: ['iam/folder/*'],
        conditions: { ArrayContains: { 'resource.relations': ['owner'] } } },
    ],
  },
});

// Owners share their own folders; the server checks their `owner` relation on iam/folder/{id}.
await iam.api.relationships.create(ownerCredential, {
  tenantId, type: 'folder', id: 'plans', relation: 'viewer', subjectType: 'group', subjectId: designTeam.id,
});
```

## Answer "who can?" and "what can they do?"

```ts
const { identities } = await iam.api.policies.whoCan(credential, {
  tenantId,
  action: 'folders:read',
  resource: { type: 'folder', id: 'plans' },
  assumeMfa: true,
});
const { allowed } = await iam.api.policies.effectiveActions(credential, {
  tenantId,
  identityId: alice.id,
  resource: { type: 'folder', id: 'plans' },
});
```

## Test a policy before saving it, and roll back a bad one

```ts
const decision = await iam.api.policies.test(credential, {
  tenantId,
  document: candidate,
  action: 'documents:write',
  resource: 'document/alice-notes',
  context: { 'principal.id': 'alice', 'principal.mfa': true },
});
await iam.api.policies.restoreVersion(credential, { tenantId, policyId, version: 3 });
```

## Require MFA or restrict sign-in methods for one organization

```ts
await iam.api.tenants.setAuthPolicy(credential, {
  tenantId,
  authPolicy: {
    requireMfa: true,
    allowedMethods: ['passkey', 'federated'],
    sessionIdleTimeoutMs: 30 * 60_000,
  },
});
```

Policies only tighten the deployment's configuration. Existing sessions are re-checked on their next request.

## Verify and archive the audit chain

```ts
const status = await iam.api.audit.verify(credential, { tenantId }); // { valid, checked, head, failure? }
let from = 1;
for (;;) {
  const page = await iam.api.audit.export(credential, {
    tenantId,
    fromSequence: from,
    limit: 5000,
  });
  await archive.append(page.body); // JSON Lines
  if (!page.nextSequence) break;
  from = page.nextSequence;
}
```

```sh
better-iam audit-verify --config better-iam.config.mjs --tenant TENANT_ID
better-iam audit-export --config better-iam.config.mjs --tenant TENANT_ID --output audit.jsonl
```

Archives verify anywhere with `verifyAuditChain(events, { previousHash })` from `better-iam`.

## Call a downstream service with a stateless assertion

```ts
// Issuer: the caller needs iam:assertions:create on iam/reports
const { token } = await iam.api.assertions.issue(credential, {
  tenantId,
  audience: 'reports',
  ttlSeconds: 120,
});

// Downstream service: holds only the derived key (iam.assertionKey()), never the secret
import { verifyAssertion } from 'better-iam';
const claims = verifyAssertion(token, { key: process.env.IAM_ASSERTION_KEY!, audience: 'reports' });
// claims.sub, claims.tid, claims.roles, claims.groups, claims.mfa
```

From a Next.js server component: `await iamNext.assertion({ tenantId, audience: 'reports' })`.

## Observe latency and outcomes

```ts
observability: {
  onSpan(span) {
    histogram.observe({ kind: span.kind, name: span.name, outcome: span.outcome }, span.durationMs);
    if (span.outcome === 'denied') counter.inc({ code: span.code ?? '' });
  },
}
```

## Devices, sign-out everywhere, and incident response

```ts
const sessions = await iam.api.auth.listSessions(credential); // each with client.userAgent / ip / label
await iam.api.auth.revokeOtherSessions(credential); // the caller keeps this session
await iam.api.identities.revokeSessions(adminCredential, { tenantId, identityId }); // one member
await iam.api.tenants.revokeSessions(adminCredential, { tenantId }); // everyone else
await iam.api.identities.unlock(adminCredential, { tenantId, identityId }); // clear rate-limit lockouts
```

Record real client IPs behind your proxy with `http.clientInfo(request)`.

## Render the outbox's emails

```ts
import { renderDeliveryMessage } from 'better-iam/auth/templates';

authentication: {
  sendEmail: async (message) => {
    const rendered = renderDeliveryMessage(message, {
      appName: 'Acme Cloud',
      links: {
        invitation: ({ kind, tenantId, token }) => `https://acme.example/join?kind=${kind}&tenant=${tenantId}&token=${token}`,
        passwordReset: ({ tenantId, token }) => `https://acme.example/reset?tenant=${tenantId}&token=${token}`,
        verifyEmail: ({ tenantId, token }) => `https://acme.example/verify?tenant=${tenantId}&token=${token}`,
      },
    });
    if (!rendered) throw new Error(`Unknown template ${message.template}`); // retried by the outbox
    await mailer.send({ to: message.to, subject: rendered.subject, text: rendered.text, html: rendered.html });
  },
},
```

## Remember this device after MFA

```ts
const outcome = await client.auth.signIn({ tenantId, email, password });
if ('mfaRequired' in outcome) {
  // The device cookie is set by the server; API clients receive deviceToken in the body instead.
  await client.auth.verifyMfa({
    tenantId,
    challenge: outcome.challenge,
    code,
    rememberDevice: true,
  });
}
// Later sign-ins from this browser skip the code until the device expires or is forgotten:
await client.auth.listTrustedDevices();
await client.auth.revokeTrustedDevice({ deviceId });
await client.auth.revokeTrustedDevices();
```

Tenants set `authPolicy.trustedDeviceDays` (0 disables); the deployment caps it with `authentication.trustedDeviceLifetimeMs`. A password, email, or factor change forgets every device.

## Support: see the product as a member sees it

```ts
// Once per organization, by an owner:
await iam.api.tenants.setAuthPolicy(ownerCredential, {
  tenantId,
  authPolicy: { allowImpersonation: true },
});
// Support staff hold a role with iam:identities:read and iam:identities:impersonate.
const viewAs = await iam.api.identities.impersonate(supportCredential, {
  tenantId,
  identityId,
  reason: 'Ticket 1234: cannot open the Q3 report',
  durationMs: 30 * 60_000,
});
// viewAs.token authenticates as the member; viewAs.session.impersonatorId names the agent.
await iam.api.auth.signOut({ token: viewAs.token }); // or wait for it to expire
```

The session can read and act as the member within their permissions, but nothing that needs recent authentication, no role assumption, no OAuth consent, and no further impersonation. Deny sensitive product actions to support sessions with `{ "Bool": { "principal.impersonated": true } }` in a deny statement. Every audit record and webhook body carries `impersonatorId`, the member sees the session in their own session list, and the token is returned in the body only (never as a cookie). The console's member page offers "View as" with a banner and a stop button when the policy is on.

## Export everything stored about a person

```ts
const bundle = await iam.api.identities.export(adminCredential, { tenantId, identityId });
// identity, sessions, mfa, passkeys, externalIdentities, bindings, groups, relationships,
// accessRequests, boundaries, grantAuthorities, links, scim, and audit (when the caller may read it)
```

## Plan limits and usage

```ts
await iam.api.tenants.setLimits(rootCredential, {
  tenantId,
  limits: { identities: 25, webhooks: 5 },
});
const usage = await iam.api.tenants.usage(credential, { tenantId }); // counts, activeSessions, limits
```

Creation past a limit fails with `LIMIT_EXCEEDED` on every path, including invitation acceptance, SCIM, and bulk creation.

## Webhooks: only denials, only some resources, and redelivery

```ts
const { webhook, secret } = await iam.api.webhooks.create(credential, {
  tenantId,
  url: 'https://siem.example.com/iam',
  events: ['*'],
  outcomes: ['deny'],
  resources: ['iam/*'],
});
const history = await iam.api.webhooks.listDeliveries(credential, {
  tenantId,
  webhookId: webhook.id,
});
await iam.api.webhooks.redeliver(credential, {
  tenantId,
  webhookId: webhook.id,
  deliveryId: history[0].id,
});
```

## Bulk onboarding and directory attributes

```ts
await iam.api.identities.createMany(credential, {
  tenantId,
  identities: rows.map((row) => ({
    email: row.email,
    name: row.name,
    attributes: { department: row.department },
    roleIds: [editor.id],
  })),
});

// SCIM: map the enterprise extension to declared identity attributes
createScimService({
  ...iam.protocolHost,
  mapAttributes: (user) => ({ department: user.enterprise?.department, title: user.title }),
});
```

## Store data in libSQL or Turso

```ts
import { libsqlAdapter } from 'better-iam/adapter-libsql';
const database = libsqlAdapter({
  url: 'libsql://name-org.turso.io',
  authToken: process.env.TURSO_AUTH_TOKEN,
});
```

## Just-in-time elevation instead of standing admin roles

```ts
// Everyone may activate roles they are eligible for.
const member = await iam.api.roles.create(credential, {
  tenantId,
  name: 'Member',
  permissions: ['iam:bindings:activate'],
});
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: member.id,
  subjectType: 'group',
  subjectId: everyone.id,
});
// The on-call group is eligible for incident response: two hours, with a reason and MFA.
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: responder.id,
  subjectType: 'group',
  subjectId: onCall.id,
  eligible: true,
  maxActivationMs: 2 * 3_600_000,
  requireJustification: true,
  requireMfa: true,
});
// Production administration additionally needs a second person: the platform team approves.
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: productionAdmin.id,
  subjectType: 'group',
  subjectId: engineers.id,
  eligible: true,
  requireApproval: true,
  approverGroupId: platformTeam.id, // members hold iam:bindings:approve and receive activation-request emails
});
const pending = await iam.api.bindings.activate(engineerCredential, {
  tenantId,
  bindingId,
  justification: 'CHG-88',
});
await iam.api.bindings.approveActivation(platformCredential, {
  tenantId,
  activationId: pending.id,
  durationMs: 45 * 60_000,
});

// A member elevates, works, and (optionally) steps down early.
const activation = await iam.api.bindings.activate(memberCredential, {
  tenantId,
  bindingId: eligibleBinding.id,
  justification: 'INC-4211',
  durationMs: 30 * 60_000,
});
await iam.api.bindings.deactivate(memberCredential, { tenantId, activationId: activation.id });

// Alert on every elevation.
await iam.api.webhooks.create(credential, {
  tenantId,
  url: 'https://ops.example.com/hooks/iam',
  events: ['binding:*'],
});
```

## Contractors: schedule deactivation

```ts
await iam.api.identities.create(credential, {
  tenantId,
  email: 'contractor@example.com',
  name: 'Contractor',
  expiresAt: Date.parse('2027-03-31T00:00:00Z'),
});
// Who deactivates in the next 30 days?
const expiring = await iam.api.identities.list(credential, {
  tenantId,
  expiresBefore: Date.now() + 30 * 86400_000,
});
// Extend, or clear the deadline.
await iam.api.identities.update(credential, { tenantId, identityId, expiresAt: null });
// Run the retention worker on a schedule: it disables expired identities and records identity:expire.
await iam.purgeDeleted();
```

## API key hygiene

```ts
const key = await iam.api.credentials.create(credential, {
  tenantId,
  identityId: deployer.id,
  name: 'github-actions',
  description: 'Deploys from the release workflow',
  expiresInSeconds: 90 * 86400,
});
// Keys nobody has used for 30 days, including keys never used since they were issued.
const unused = await iam.api.credentials.list(credential, {
  tenantId,
  unusedForMs: 30 * 86400_000,
});
for (const item of unused)
  await iam.api.credentials.revoke(credential, { tenantId, credentialId: item.id });
```

## Configuration as code

```ts
// Export from staging, keep the file in version control, apply to production.
const document = await staging.api.config.export(credential, { tenantId: stagingTenant });
const plan = await production.api.config.plan(credential, {
  tenantId: productionTenant,
  config: document,
  prune: true,
});
console.log(
  plan.summary,
  plan.changes.filter((change) => change.action !== 'unchanged'),
);
await production.api.config.apply(credential, {
  tenantId: productionTenant,
  config: document,
  prune: true,
});
```

```bash
BETTER_IAM_TOKEN=... better-iam config-export --tenant TENANT_ID --output tenant.json
BETTER_IAM_TOKEN=... better-iam config-plan --tenant TENANT_ID --input tenant.json --prune
BETTER_IAM_TOKEN=... better-iam config-apply --tenant TENANT_ID --input tenant.json --prune
# In CI: fail the pipeline when production drifted from the reviewed file.
BETTER_IAM_TOKEN=... better-iam config-plan --tenant TENANT_ID --input tenant.json --fail-on-drift
```

## Role hierarchy and business-hours access

```ts
const viewer = await iam.api.roles.create(credential, {
  tenantId,
  name: 'Viewer',
  permissions: ['documents:read'],
});
const editor = await iam.api.roles.create(credential, {
  tenantId,
  name: 'Editor',
  permissions: ['documents:write'],
  inherits: [viewer.id], // editors read too
});
// Support staff hold their role on weekdays, office hours, Berlin time.
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: support.id,
  subjectType: 'group',
  subjectId: supportTeam.id,
  window: { from: '08:00', to: '18:00', timeZone: 'Europe/Berlin', days: [1, 2, 3, 4, 5] },
});
```

## Project teams and start dates

```ts
// A three-month project membership that ends by itself.
await iam.api.groups.addMember(credential, {
  tenantId,
  groupId: projectTeam.id,
  identityId: alice.id,
  expiresAt: Date.now() + 90 * 86400_000,
});
// Access that begins on the contract's first day and ends on its last.
await iam.api.bindings.create(credential, {
  tenantId,
  roleId: contractor.id,
  subjectType: 'identity',
  subjectId: bob.id,
  startsAt: Date.parse('2027-01-04T08:00:00Z'),
  expiresAt: Date.parse('2027-06-30T18:00:00Z'),
});
```

## Offboard a person

```ts
const summary = await iam.api.identities.offboard(credential, {
  tenantId,
  identityId: leaver.id,
  reason: 'Left the company (HR-1234)',
  successorId: manager.id, // takes over the workspaces the leaver owned
});
// summary: { sessions, bindings, memberships, activations, relationships, accessRequests, authorities, resourcesReassigned, ... }
// Later, after the retention period:
await iam.api.identities.delete(credential, { tenantId, identityId: leaver.id });
```

## Tell people how to get access instead of just "denied"

When a check fails, ask what the person could do about it themselves. Every option is verified by simulating it (in a transaction that is rolled back), so the list never promises access that would still be refused:

```ts
const check = await iam.authorize({ token, tenantId, action: 'documents:delete', resource });
if (!check.allowed) {
  const { paths } = await iam.api.accessPaths.find(
    { token },
    { tenantId, action: 'documents:delete', resource },
  );
  for (const path of paths) {
    if (path.kind === 'mfa') showStepUp();
    if (path.kind === 'accept-agreements') showTerms(path.agreements); // then agreements.accept
    if (path.kind === 'activate')
      offerActivation(path.bindingId, path.role, path.requireJustification); // bindings.activate
    if (path.kind === 'request-package') offerRequest(path.package); // packages.request
  }
  if (!paths.length) showAskAnAdministrator();
}
```

The call needs only the person's own ordinary session. Activation and package options appear only when the person holds `iam:bindings:activate` / `iam:packages:request` for them, and approval requirements are reported so the UI can say "your request goes to an approver". Like `authorize`, a denial's `reason` is always `ACCESS_DENIED`, so the call does not reveal which rule refused.

## Guardrails, terms of use, and change previews

```ts
// Nobody outside finance may ever approve payments, whatever roles say; refuse changes that would break it.
await iam.api.invariants.create(credential, {
  tenantId,
  name: 'Only finance approves payments',
  subject: { attribute: { name: 'department', value: 'Sales' } },
  action: 'payments:approve',
  resource: { type: 'ledger', id: 'main' },
  expect: 'deny',
  mode: 'enforce',
});
// Before editing a role: who gains or loses what, and which invariants would break?
const preview = await iam.api.impact.preview(credential, {
  tenantId,
  change: { role: { roleId, permissions: ['payments:read', 'payments:approve'] } },
  resources: [{ type: 'ledger', id: 'main' }],
});
// Terms of use that policies can require (deny while principal.pendingAgreements > 0).
await iam.api.agreements.create(credential, { tenantId, name: 'Acceptable use', content: '...' });
```
