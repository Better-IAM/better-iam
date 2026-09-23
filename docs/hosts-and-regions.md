# Sign-in addresses and regions

Every AWS account has its own sign-in URL and every Slack workspace its own address. Better IAM gives organizations
the same: an address of their own, where requests are pinned to them, and, in a multi-region deployment, a home region
that serves their sign-in. The full guide, with setup steps and examples, is on the documentation site under
Deployment → Sign-in addresses and regions (`apps/docs/content/docs/operations/deployment/hosts-and-regions.mdx`).

## Organization addresses

```ts
betterIam({
  baseURL: 'https://signin.example.com',
  hosts: {
    patterns: ['{tenant}.signin.example.com'], // '{tenant}.localhost:3000' in development
    signInPath: '/login',
  },
});
```

`{tenant}` is an organization's alias (`tenants.setSlug`); `{region}` may name a configured region. Serve the IAM
handler on every host (wildcard DNS and certificate). On `acme.signin.example.com`:

- public sign-in calls act in Acme; `tenantId` may be omitted, and any other tenant ID is refused (`HOST_MISMATCH`);
- sessions, API keys, and role sessions of other organizations are refused (`HOST_MISMATCH`);
- the address's origin is trusted, and cookies stay host-only;
- an alias no active organization holds answers `NOT_FOUND`.

The deployment's own `baseURL` host is not pinned and serves every organization, as before.

## Custom hostnames

With `hosts.customHostnames: true` (and optionally `hosts.cnameTarget`), the `hostnames` API group lets an
organization claim `login.acme.com`, publish the TXT record `_better-iam-challenge.login.acme.com` =
`better-iam-hostname=<token>` plus the CNAME, verify it, and make it primary. Verified hostnames resolve like the
subdomain. Use `iam.hosts.allowed(hostname)` for on-demand TLS certificate checks. Passkeys are not offered on a
hostname outside the passkey RP ID.

## Regions

```ts
regions: {
  current: 'eu-west-1',
  regions: {
    'us-east-1': { baseURL: 'https://signin.us-east-1.example.com' },
    'eu-west-1': { baseURL: 'https://signin.eu-west-1.example.com' },
  },
  locate: async (alias) => directory.get(alias), // only when regions keep separate databases
},
```

A tenant's home region is its own `region` or its nearest ancestor's (`tenants.create({ region })`, root-only
`tenants.setRegion`). Sign-in entry points (`tenants.lookup`, `domains.discover`, public sign-in calls, organization
addresses) answer `WRONG_REGION` (421) with `region` and `location` everywhere but the home region. Authenticated
calls are not refused by region.

## Sign-in URLs

`iam.hosts.signInUrl(tenantId)`, `signInUrl` in lookup and discovery results, and `DeliveryMessage.signInUrl` on every
message give the organization's canonical address: its primary custom hostname, else its subdomain, else its region's
base URL, plus `hosts.signInPath`.
