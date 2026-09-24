# ldap

Each organization can publish its directory over LDAP, so applications that only speak LDAP (VPNs, NAS devices, CI
servers, wikis, printers) look up people and groups and check passwords against Better IAM. The gateway itself is the
`@better-iam/ldap` package (`createLdapServer({ iam })`); this group holds each organization's settings and the
directory view the gateway serves searches from. The directory is read-only. The guide is
[LDAP directory gateway](https://github.com/Better-IAM/better-iam/blob/main/docs/ldap.md).

## getSettings

The organization's gateway settings: whether it is on, its base DN, how `uid` is formed (`email`, `localPart` or
`id`), who may bind (`peopleBind`, `serviceBind`), `requireTls`, `mfaSuffix`, whether service accounts are listed, the
published identity `attributes`, and which groups are published.

- **Permission:** `iam:ldap:read` on `iam/ldap/settings`.

## updateSettings

Changes the gateway settings; fields left out keep their values. A base DN is `attr=value` components (letters,
digits, spaces, `.`, `_` or `-`), at most 10, compared without regard to case. It belongs to one organization of the
deployment. `attributes` lists declared identity attributes to publish on people's entries (none by default, since
attributes may be sensitive). `groups: 'selected'` publishes only `groupIds`.

- **Permission:** `iam:ldap:manage` on `iam/ldap/settings`.
- **Errors:** `LDAP_BASE_TAKEN` when another organization publishes under the base DN; `INVALID_INPUT` for a malformed
  base DN, an undeclared attribute, or an unknown option value; `NOT_FOUND` for a group of another organization.

## directory

The directory as the caller may read it: active people, published groups with their members and, when listed,
service accounts and agents. With `iam:ldap:read` on `iam/ldap/directory` the caller reads everything published
(audited as `ldap:directory:read`). Otherwise the caller reads only their own entry, and their own groups with only
themselves as a member. The platform root override and "view as" sessions read nothing. The gateway calls this as the
account that bound.

- **Errors:** `FEATURE_DISABLED` while the gateway is off for the organization; `ACCESS_DENIED` for a session of
  another organization or a "view as" session.
