# @better-iam/ldap

A read-only LDAPv3 directory gateway over [Better IAM](https://github.com/Better-IAM/better-iam), so applications that
only speak LDAP (VPNs, NAS devices, CI servers, wikis, printers) can look up people and groups and check passwords.

```ts
import { createLdapServer } from '@better-iam/ldap';

const ldap = createLdapServer({ iam, tls: { key, cert } });
await ldap.listen(636, '0.0.0.0');
```

Each organization turns it on with `iam.api.ldap.updateSettings` and publishes its directory under its own base DN.
People bind with their password (plus their one-time code when they use MFA) as a Better IAM sign-in; service accounts
bind with an API key. Searches are authorized as the bound account.

The BER codec, DN and filter helpers, and client-side message encoders are exported for tools and tests.

Guide: [docs/ldap.md](https://github.com/Better-IAM/better-iam/blob/main/docs/ldap.md). License: Apache-2.0.
