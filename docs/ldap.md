# LDAP directory gateway

Plenty of software only speaks LDAP: VPN concentrators, NAS devices, CI servers, wikis, printers, older line-of-business
apps. The LDAP gateway lets them look up people and groups and check passwords against Better IAM, without a second
directory to keep in sync. It is a read-only LDAPv3 server (`@better-iam/ldap`) that you run next to your deployment.
Each organization publishes its directory under a base DN of its own.

## Running the gateway

```ts
import { readFileSync } from 'node:fs';
import { createLdapServer } from '@better-iam/ldap';
import { iam } from './iam';

const ldap = createLdapServer({
  iam,
  tls: { key: readFileSync('ldap.key'), cert: readFileSync('ldap.crt') }, // LDAPS; leave out for plain LDAP
});
await ldap.listen(636, '0.0.0.0');
```

| Option            | Default   | Meaning                                                        |
| ----------------- | --------- | -------------------------------------------------------------- |
| `tls`             | none      | Serve LDAPS (TLS from the first byte) with these options        |
| `maxResults`      | 1000      | The most entries one search returns, and the largest page       |
| `idleTimeoutMs`   | 5 minutes | Idle connections are closed                                     |
| `maxRequestBytes` | 64 KiB    | The largest request accepted                                    |
| `cacheMs`         | 5 seconds | How long a connection reuses a directory snapshot              |
| `maxConnections`  | 1000      | The most simultaneous connections                               |
| `onError`         | none      | Called with errors the gateway could not answer (logging)       |

`ldap.close()` tells connected clients and signs out the sessions the gateway created.

## Publishing an organization's directory

Administrators with `iam:ldap:manage` turn the gateway on for their organization:

```ts
await iam.api.ldap.updateSettings(admin, {
  tenantId,
  enabled: true,
  baseDn: 'dc=acme,dc=com',
  uid: 'localPart', // 'email' (default), 'localPart' or 'id'
  attributes: ['title', 'costCenter'], // declared identity attributes to publish; none by default
  groups: 'selected',
  groupIds: [vpnUsers.id, engineering.id],
});
```

| Setting                  | Default  | Meaning                                                                        |
| ------------------------ | -------- | ------------------------------------------------------------------------------ |
| `baseDn`                 | `o={slug}` | Where the tree starts; one organization per base DN (`LDAP_BASE_TAKEN`)       |
| `uid`                    | `email`  | What `uid` holds: the email, its local part (the email where they collide), or the ID |
| `peopleBind`             | `true`   | People may bind with their password                                           |
| `serviceBind`            | `true`   | Service accounts and agents may bind with an API key                          |
| `requireTls`             | `true`   | Binds without TLS are refused (`confidentialityRequired`), except from loopback |
| `mfaSuffix`              | `auto`   | People who use MFA append their current code to the password; `never` refuses their binds |
| `includeServiceAccounts` | `false`  | List service accounts and agents under `ou=services`                          |
| `attributes`             | none     | Declared identity attributes published on people's entries                    |
| `groups`, `groupIds`     | `all`    | Publish every group, or only the selected ones                                |

The tree looks like this:

```
dc=acme,dc=com                          (organization)
├─ ou=people
│  └─ uid=alice@acme.com                (inetOrgPerson: uid, cn, sn, givenName, displayName, mail, memberOf)
├─ ou=groups
│  └─ cn=Engineering                    (groupOfNames: cn, description, member)
└─ ou=services
   └─ cn=vpn                            (account: cn, uid, description, memberOf)
```

Every entry carries its Better IAM ID as the operational attribute `entryUUID`. Only active, unexpired accounts and
live group memberships appear. Two service accounts or groups with the same name are told apart by ID: the later one
is named `cn={id}`.

## Binding

Applications bind in one of two ways:

- **As a person:** `uid={uid},ou=people,{baseDn}` with their password. The bind is a Better IAM sign-in, so rate
  limits, lockouts, allowed sign-in methods, IP rules and sign-in alerts apply, and the client's address is recorded.
  People who use MFA append the current six-digit authenticator code to the password (`hunter2` + `123456`). People
  whose MFA is required but who have no authenticator enrolled cannot bind, since LDAP has no way to ask for a passkey.
  The gateway makes exactly one sign-in attempt per bind, and signs the session out when the connection ends or binds
  again.
- **As a service account or agent:** `cn={name},ou=services,{baseDn}` with one of its API keys as the password.

Anonymous binds read only the root DSE. A name with an empty password is refused (`unwillingToPerform`) rather than
treated as an anonymous bind, a common source of LDAP login bypasses. SASL binds are not supported.

## What a bound account sees

Searches are authorized as the bound account. With `iam:ldap:read` on `iam/ldap/directory`, it reads the whole
published directory, audited as `ldap:directory:read`. This is the permission for the VPN's or wiki's service account:

```json
{ "effect": "allow", "actions": ["iam:ldap:read"], "resources": ["iam/ldap/directory"] }
```

Without it, an account sees only its own entry and its own groups, with only itself as a member. That is enough for
applications that bind as the person and then read their groups. The platform root override and "view as" sessions
read nothing.

Supported: search (base, one level and subtree scopes, every RFC 4515 filter, attribute selection with `*`, `+` and
`1.1`, size limits, and the paged results control of RFC 2696), compare, the WhoAmI extended operation (RFC 4532) and
unbind. Add, modify, delete and rename are refused (`unwillingToPerform`): the directory is managed in Better IAM.

## Testing a setup

With OpenLDAP's command-line tools:

```bash
ldapsearch -H ldaps://ldap.example.com -D "cn=vpn,ou=services,dc=acme,dc=com" -w "$VPN_API_KEY" -b "ou=people,dc=acme,dc=com" "(memberOf=cn=VPN users,ou=groups,dc=acme,dc=com)" mail
```

## API

| Method                      | Access                                                          |
| --------------------------- | --------------------------------------------------------------- |
| `getSettings`               | `iam:ldap:read`                                                 |
| `updateSettings`            | `iam:ldap:manage`                                               |
| `directory`                 | a credential of the organization; `iam:ldap:read` for everyone, otherwise only yourself |

`iam.ldap.tenantForBase` and `iam.ldap.resolveBindName` are what the gateway uses before anyone is bound. They return
no secrets.
