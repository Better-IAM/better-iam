import {
  ENTERPRISE_SCHEMA,
  GROUP_SCHEMA,
  USER_SCHEMA,
  type ObjectValue,
  type ResourceType,
} from './types.js';

/** Read-only attributes (RFC 7643 §3.1, §4): a client may send them back, and RFC 7644 §3.3/§3.5.1 says to ignore them. */
const READ_ONLY: Record<ResourceType, Set<string>> = {
  Users: new Set(['id', 'meta', 'groups']),
  Groups: new Set(['id', 'meta']),
};
/**
 * Core User attributes RFC 7643 §4.1 defines that this service provider does not store. Identity providers send
 * several of them by default (Entra ID: `addresses`, `phoneNumbers`, `preferredLanguage`; Okta: `locale`, `nickName`,
 * `password` with password sync), so with `unsupportedAttributes: 'ignore'` they are accepted and dropped.
 */
const UNSUPPORTED_USER = new Set([
  'nickname',
  'profileurl',
  'usertype',
  'preferredlanguage',
  'locale',
  'timezone',
  'password',
  'phonenumbers',
  'ims',
  'photos',
  'addresses',
  'entitlements',
  'roles',
  'x509certificates',
]);
const CORE_PREFIXES = [USER_SCHEMA, GROUP_SCHEMA].map((schema) => `${schema.toLowerCase()}:`);
const ENTERPRISE = ENTERPRISE_SCHEMA.toLowerCase();

/**
 * Whether an attribute (a top-level name such as `addresses`, or a PATCH path such as
 * `phoneNumbers[type eq "work"].value` or `urn:…:core:2.0:User:preferredLanguage`) is dropped instead of applied:
 * read-only attributes are (unless `readOnly` is false: a PATCH path that targets one is a `mutability` error, RFC 7644
 * §3.5.2, while a POST/PUT body or a pathless PATCH value that carries one is not, §3.5.1); with `lenient`, so are core attributes this service does not store and anything in
 * an extension schema other than the enterprise User extension. Everything else is validated as before, so a typo in a
 * supported attribute (or an attribute no schema defines, such as `badge` in the enterprise extension) is still an error.
 */
export function ignoredAttribute(
  path: string,
  type: ResourceType,
  lenient: boolean,
  readOnly = true,
): boolean {
  let lower = path.split('[')[0]!.toLowerCase();
  const core = CORE_PREFIXES.find((prefix) => lower.startsWith(prefix));
  if (core) lower = lower.slice(core.length);
  if (lower === ENTERPRISE || lower.startsWith(`${ENTERPRISE}:`)) return false;
  if (lower.startsWith('urn:')) return lenient;
  const name = lower.split('.')[0]!;
  if (READ_ONLY[type].has(name)) return readOnly;
  return lenient && type === 'Users' && UNSUPPORTED_USER.has(name);
}

/** A copy of a POST/PUT body without the attributes `ignoredAttribute` drops (and, when lenient, foreign schema URNs). */
export function withoutIgnored(
  data: ObjectValue,
  type: ResourceType,
  lenient: boolean,
): ObjectValue {
  const kept: ObjectValue = {};
  for (const [key, value] of Object.entries(data))
    if (key === 'schemas' || !ignoredAttribute(key, type, lenient)) kept[key] = value;
  if (lenient && Array.isArray(kept.schemas)) {
    const known = type === 'Users' ? [USER_SCHEMA, ENTERPRISE_SCHEMA] : [GROUP_SCHEMA];
    // Extension schemas this service does not implement are listed by the IdP but their attributes were dropped above.
    kept.schemas = kept.schemas.filter(
      (schema) =>
        !(typeof schema === 'string' && schema.startsWith('urn:') && !known.includes(schema)),
    );
  }
  return kept;
}
