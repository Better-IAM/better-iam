import { escapeDnValue, normalizeDn, parseDn } from './dn.js';
import type { EntryAttributes } from './filter.js';

/** The directory data the server's `ldap.directory` returns (see `@better-iam/server` `LdapDirectory`). */
export interface DirectoryData {
  tenantId: string;
  tenantName: string;
  baseDn: string;
  scope: 'full' | 'self';
  people: {
    id: string;
    uid: string;
    email?: string;
    name?: string;
    emailVerified: boolean;
    attributes: Record<string, unknown>;
    groupIds: string[];
  }[];
  groups: { id: string; name: string; description?: string; memberIds: string[] }[];
  services: { id: string; name: string; kind: string; groupIds: string[] }[];
}

/** One entry of the tree: its DN, the normalized DN, and attributes (user and operational, in output order). */
export interface DirectoryEntry {
  dn: string;
  normalizedDn: string;
  attributes: [string, string[]][];
  operational: [string, string[]][];
  /** Lowercased attribute names → values, for filters (user and operational attributes). */
  index: EntryAttributes;
}

const standard = new Set(
  [
    'objectClass',
    'uid',
    'cn',
    'sn',
    'givenName',
    'displayName',
    'mail',
    'memberOf',
    'member',
    'ou',
    'o',
    'dc',
    'description',
    'entryUUID',
    'entryDN',
  ].map((name) => name.toLowerCase()),
);

function entry(dn: string, attributes: [string, string[]][], operational: [string, string[]][] = []): DirectoryEntry {
  const kept = attributes.filter(([, values]) => values.length > 0);
  const extra: [string, string[]][] = [...operational, ['entryDN', [dn]]];
  const index: EntryAttributes = new Map();
  for (const [name, values] of [...kept, ...extra]) index.set(name.toLowerCase(), values);
  return { dn, normalizedDn: normalizeDn(dn), attributes: kept, operational: extra, index };
}

const words = (name: string | undefined) => (name ?? '').trim().split(/\s+/).filter(Boolean);
const text = (value: unknown) => (typeof value === 'string' ? value : JSON.stringify(value));

/**
 * The tree under the tenant's base DN: the base entry, `ou=people` (inetOrgPerson entries named `uid={uid}`),
 * `ou=groups` (groupOfNames named `cn={name}`, with `member` DNs) and `ou=services` (service accounts and agents,
 * named `cn={name}`). People and services carry `memberOf`; `entryUUID` is the Better IAM identity or group ID.
 */
export function buildEntries(data: DirectoryData): DirectoryEntry[] {
  const base = data.baseDn;
  const [top] = parseDn(base);
  const naming = top?.[0];
  const baseClasses =
    naming?.type.toLowerCase() === 'dc'
      ? ['top', 'dcObject', 'organization']
      : naming?.type.toLowerCase() === 'ou'
        ? ['top', 'organizationalUnit']
        : ['top', 'organization'];
  const entries: DirectoryEntry[] = [
    entry(base, [
      ['objectClass', baseClasses],
      ...(naming ? ([[naming.type, [naming.value]]] as [string, string[]][]) : []),
      ...(naming?.type.toLowerCase() === 'o' ? [] : ([['o', [data.tenantName]]] as [string, string[]][])),
    ]),
  ];
  const container = (ou: string) => entry(`ou=${ou},${base}`, [['objectClass', ['top', 'organizationalUnit']], ['ou', [ou]]]);
  entries.push(container('people'), container('groups'));
  if (data.services.length || data.scope === 'full') entries.push(container('services'));
  const personDn = new Map(data.people.map((person) => [person.id, `uid=${escapeDnValue(person.uid)},ou=people,${base}`]));
  // Names can collide (two service accounts called "ci"): the first keeps its name, later ones are named by their ID.
  const named = (items: { id: string; name: string }[], ou: string) => {
    const taken = new Set<string>();
    return new Map(
      items.map((item) => {
        const rdn = taken.has(item.name.toLowerCase()) ? item.id : item.name;
        taken.add(rdn.toLowerCase());
        return [item.id, `cn=${escapeDnValue(rdn)},ou=${ou},${base}`];
      }),
    );
  };
  const serviceDn = named(data.services, 'services');
  const groupDn = named(data.groups, 'groups');
  for (const person of data.people) {
    const parts = words(person.name);
    const extra: [string, string[]][] = [];
    for (const [name, value] of Object.entries(person.attributes))
      if (/^[a-zA-Z][a-zA-Z0-9-]{0,63}$/.test(name) && !standard.has(name.toLowerCase()) && value !== null && value !== undefined)
        extra.push([name, (Array.isArray(value) ? value : [value]).map(text)]);
    entries.push(
      entry(
        personDn.get(person.id)!,
        [
          ['objectClass', ['top', 'person', 'organizationalPerson', 'inetOrgPerson']],
          ['uid', [person.uid]],
          ['cn', [person.name ?? person.email ?? person.uid]],
          ['sn', [parts.at(-1) ?? person.uid]],
          ['givenName', parts.length > 1 ? [parts[0]!] : []],
          ['displayName', person.name ? [person.name] : []],
          ['mail', person.email ? [person.email] : []],
          ['memberOf', person.groupIds.flatMap((groupId) => (groupDn.has(groupId) ? [groupDn.get(groupId)!] : []))],
          ...extra,
        ],
        [['entryUUID', [person.id]]],
      ),
    );
  }
  for (const service of data.services)
    entries.push(
      entry(
        serviceDn.get(service.id)!,
        [
          ['objectClass', ['top', 'account', 'applicationProcess']],
          ['cn', [service.name]],
          ['uid', [parseDn(serviceDn.get(service.id)!)[0]![0]!.value]],
          ['description', [service.kind === 'agent' ? 'AI agent' : 'Service account']],
          ['memberOf', service.groupIds.flatMap((groupId) => (groupDn.has(groupId) ? [groupDn.get(groupId)!] : []))],
        ],
        [['entryUUID', [service.id]]],
      ),
    );
  for (const group of data.groups)
    entries.push(
      entry(
        groupDn.get(group.id)!,
        [
          ['objectClass', ['top', 'groupOfNames']],
          ['cn', [group.name]],
          ['description', group.description ? [group.description] : []],
          [
            'member',
            group.memberIds.flatMap((memberId) => {
              const dn = personDn.get(memberId) ?? serviceDn.get(memberId);
              return dn ? [dn] : [];
            }),
          ],
        ],
        [['entryUUID', [group.id]]],
      ),
    );
  return entries;
}

/**
 * The attributes a search returns for an entry: all user attributes for none or `*`, operational ones for `+` or by
 * name, only the named ones otherwise, nothing for `1.1`.
 */
export function selectAttributes(target: DirectoryEntry, requested: string[]): [string, string[]][] {
  const wanted = requested.map((name) => name.toLowerCase());
  if (wanted.length === 1 && wanted[0] === '1.1') return [];
  const all = wanted.length === 0 || wanted.includes('*');
  const operational = wanted.includes('+');
  return [
    ...target.attributes.filter(([name]) => all || wanted.includes(name.toLowerCase())),
    ...target.operational.filter(([name]) => operational || wanted.includes(name.toLowerCase())),
  ];
}
