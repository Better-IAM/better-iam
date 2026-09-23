# Enterprise onboarding

This guide takes one customer organization from "we use Okta or Entra ID" to fully managed access: its people sign in with the company's identity provider, are created and removed by the company's directory, and flow on to the SaaS applications you connect for them. Each step links to the reference section with every option. The same steps work from your own admin UI, the console, or a script.

The examples assume a server instance `iam`, an organization `tenantId`, and `credential` for an administrator of that organization (a cookie session or an API key with the listed permissions).

## 1. Prove the email domain

```ts
const claimed = await iam.api.domains.add(credential, { tenantId, domain: 'acme.com' });
// Publish claimed.dnsRecord (a TXT record), then:
await iam.api.domains.verify(credential, { tenantId, domainId: claimed.id });
```

A verified domain belongs to exactly one organization. Your sign-in page can then route people by email: `iam.api.domains.discover({ email })` answers with the organization, its alias, the sign-in methods it accepts, and whether it requires MFA. Pass the email on as a sign-in hint (step 2) so people do not type it twice. See the `domains` group in the [API reference](api-reference.md).

## 2. Connect the identity provider

**SAML (Okta, Entra ID, ADFS, Google Workspace, …).** With one deployment-wide service-provider key pair configured (`serviceProvider` in `createSamlService`), organization administrators upload their IdP's metadata themselves:

```ts
const sso = await saml.createConnection(credential, {
  tenantId,
  id: 'acme-okta',
  name: 'Acme Okta',
  metadataXml,
  trustedEmailDomains: ['acme.com'],
  attributeMapping: { department: 'department', title: 'title' },
});
// Give the IdP administrator: sso.entityId (audience) and sso.acsUrl (ACS, HTTP-POST).
```

Sign-in starts at `sso.loginUrl`. Enable `allowIdpInitiated` only if people launch the app from their IdP portal. Certificate rollover means listing old and new certificates with `updateConnection`, and summaries warn before a certificate expires. Details are in [Tenant-managed connections](protocols.md#tenant-managed-connections).

**OpenID Connect.** Use `createOAuthLogin` with `kind: 'microsoft'` for Entra ID. Pin `allowedMicrosoftTenants` to the customer's directory, or use `microsoftTenant` with their tenant ID. For any other OIDC provider use `kind: 'oidc'`. Forward the discovered email as a hint: `login.begin(connectionId, undefined, { loginHint: email, domainHint: 'acme.com' })`. Details are in [OAuth and OpenID Connect sign-in](protocols.md#oauth-and-openid-connect-sign-in).

`trustedEmailDomains` (SAML) or a verified-email claim (OIDC) lets the first sign-in create the account. Without them, people link the provider to an existing account explicitly. Federation never merges accounts on a matching email alone.

## 3. Require it

```ts
await iam.api.tenants.setAuthPolicy(credential, {
  tenantId,
  authPolicy: {
    allowedMethods: ['federated'],
    requireMfa: true,
    allowedIpRanges: ['203.0.113.0/24'],
  },
});
```

Password and email-link sign-in are then refused for the organization before any credential is checked. `requireMfa` adds the product's own second factor on top of the IdP's. `allowedIpRanges` limits where sessions may be used from. See [Authentication](authentication.md) for every policy field.

## 4. Let their directory provision people (SCIM in)

```ts
const connection = await scim.createConnection(credential, { tenantId, name: 'Okta provisioning' });
// Give the IdP: connection base path + connection.token (shown once).
await scim.setRoleMappings(credential, {
  tenantId,
  connectionId: connection.id,
  groupId,
  roleIds: [viewerRoleId],
});
```

The directory then creates, updates, deactivates, and deletes accounts and groups. Deactivation revokes sessions immediately. Mapped groups carry their roles, so joining "Engineering" in Okta grants the engineering role here. `scim.rotateToken` replaces the token without losing provisioned state. See [SCIM 2.0](protocols.md#scim-20).

## 5. Provision their applications (SCIM out)

Customers often want the people you manage to appear in their other SaaS tools, or your platform launches downstream services per organization:

```ts
await provisioner.createTarget(credential, {
  tenantId,
  name: 'Slack',
  baseUrl: 'https://api.slack.com/scim/v2',
  token: slackScimToken,
  groupIds: [engineeringGroupId],
  pushGroups: true,
});
```

`previewTarget` shows what a sync would change before anything is written. `subscribe(iam.events)` and a periodic `syncAll()` keep the application current. The console's App provisioning page does all of this without code. See [Outbound provisioning](protocols.md#outbound-provisioning).

## 6. Offboarding end to end

When the company removes someone in its directory:

1. SCIM deactivates the identity here, and its sessions and API keys stop working.
2. The provisioner deactivates or deletes the person in every connected application at its next run, which the event subscription triggers within seconds.
3. OAuth grants bound to the ended sessions are revoked by `logoutEndedSessions()`, and clients registered with a `backchannelLogoutUri` receive an OpenID back-channel logout ([Back-channel logout](protocols.md#back-channel-logout)).
4. Receivers registered as Shared Signals streams (the customer's SIEM, or applications that keep their own sessions) get a signed `session-revoked` or `account-disabled` event within seconds, so they can end their own sessions too ([Shared Signals](protocols.md#shared-signals-caep-and-risc)).
5. An administrator can also call `identities.offboard` to remove role bindings and group memberships and to hand owned resources to a successor in one audited step.

## 7. Watch it

Every step above is audited: `iam:saml:*Connection`, `iam:scim:*` (inbound users and groups, outbound targets and syncs), `iam:oauth:*`, `tenant:auth-policy`, and the domain operations. Route them to your SIEM with [webhooks](events.md), verify the tamper-evident chain with `audit.verify`, and run `analysis.findings` for risky configuration such as administrators without MFA or unused API keys.
