/**
 * `@better-iam/ldap`: a read-only LDAPv3 directory gateway over Better IAM, so applications that only speak LDAP
 * (VPNs, NAS devices, CI servers, wikis, printers) can look up people and groups and check passwords. Start it with
 * `createLdapServer({ iam })`; each organization publishes its directory under its own base DN (`ldap.updateSettings`).
 * The BER codec, DN and filter helpers and message encoders are exported for tools and tests.
 */
export { createLdapServer } from './server.js';
export type { LdapIam, LdapServerOptions } from './server.js';
export { buildEntries, selectAttributes } from './directory.js';
export type { DirectoryData, DirectoryEntry } from './directory.js';
export { DnError, depthBelow, escapeDnValue, formatDn, isUnder, normalizeDn, parentDn, parseDn } from './dn.js';
export type { Rdn } from './dn.js';
export { decodeFilter, encodeFilter, matchFilter, parseFilter } from './filter.js';
export type { EntryAttributes, Filter } from './filter.js';
export { BerError, readElement } from './ber.js';
export {
  OID,
  ResultCode,
  decodeMessage,
  decodeResponse,
  encodeBind,
  encodeCompare,
  encodeExtended,
  encodeSearch,
  encodeUnbind,
  pagedResultsRequest,
} from './protocol.js';
export type { LdapControl, LdapMessage, LdapRequest, LdapResponse, SearchScope } from './protocol.js';
