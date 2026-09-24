/**
 * Distinguished names (RFC 4514): parsing with escapes (`\,`, `\2C`), quoting of values, and a normalized form for
 * comparisons (attribute types and values lowercased, insignificant spaces trimmed). Multi-valued RDNs (`+`) are
 * kept in order.
 */

export class DnError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DnError';
  }
}

export interface Rdn {
  type: string;
  value: string;
}

const special = new Set([',', '+', '"', '\\', '<', '>', ';', '=']);

/** Escapes an attribute value for use in a DN. */
export function escapeDnValue(value: string): string {
  let out = '';
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    const code = char.charCodeAt(0);
    if (special.has(char)) out += `\\${char}`;
    else if (code < 0x20 || code === 0x7f) out += `\\${code.toString(16).padStart(2, '0')}`;
    else if ((index === 0 && (char === ' ' || char === '#')) || (index === value.length - 1 && char === ' '))
      out += `\\${char}`;
    else out += char;
  }
  return out;
}

/** Parses a DN into RDNs (each a list of type/value pairs; most have one). The empty DN is the root. */
export function parseDn(dn: string): Rdn[][] {
  if (typeof dn !== 'string' || dn.length > 4096) throw new DnError('Invalid DN');
  const rdns: Rdn[][] = [];
  if (!dn.trim()) return rdns;
  let index = 0;
  let current: Rdn[] = [];
  const bytes: number[] = [];
  const flushBytes = () => {
    if (!bytes.length) return '';
    const text = Buffer.from(bytes).toString('utf8');
    bytes.length = 0;
    return text;
  };
  while (index <= dn.length) {
    // Attribute type.
    while (dn[index] === ' ') index++;
    const equals = dn.indexOf('=', index);
    if (equals < 0) throw new DnError('Missing = in DN');
    const type = dn.slice(index, equals).trim();
    if (!/^(?:[a-zA-Z][a-zA-Z0-9-]*|\d+(?:\.\d+)*)$/.test(type)) throw new DnError('Invalid attribute type in DN');
    index = equals + 1;
    while (dn[index] === ' ') index++;
    // Attribute value.
    let value = '';
    if (dn[index] === '"') {
      index++;
      while (index < dn.length && dn[index] !== '"') {
        if (dn[index] === '\\') index++;
        value += dn[index] ?? '';
        index++;
      }
      if (dn[index] !== '"') throw new DnError('Unterminated quoted value');
      index++;
      while (dn[index] === ' ') index++;
    } else {
      let trailingSpaces = 0;
      while (index < dn.length && dn[index] !== ',' && dn[index] !== '+' && dn[index] !== ';') {
        const char = dn[index]!;
        if (char === '\\') {
          const hex = dn.slice(index + 1, index + 3);
          if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            bytes.push(Number.parseInt(hex, 16));
            index += 3;
          } else if (index + 1 < dn.length) {
            value += flushBytes() + dn[index + 1];
            index += 2;
          } else throw new DnError('Dangling escape in DN');
          trailingSpaces = 0;
          continue;
        }
        value += flushBytes() + char;
        trailingSpaces = char === ' ' ? trailingSpaces + 1 : 0;
        index++;
      }
      value = value + flushBytes();
      if (trailingSpaces) value = value.slice(0, value.length - trailingSpaces);
    }
    current.push({ type, value });
    const separator = dn[index];
    index++;
    if (separator === '+') continue;
    rdns.push(current);
    current = [];
    if (separator === undefined) break;
  }
  return rdns;
}

/** Formats RDNs as a DN string. */
export function formatDn(rdns: Rdn[][]): string {
  return rdns.map((rdn) => rdn.map((part) => `${part.type}=${escapeDnValue(part.value)}`).join('+')).join(',');
}

/** The comparison form of a DN: lowercased, re-escaped, spaces normalized. Throws on malformed DNs. */
export function normalizeDn(dn: string): string {
  return parseDn(dn)
    .map((rdn) =>
      rdn
        .map((part) => `${part.type.toLowerCase()}=${escapeDnValue(part.value.trim().replace(/\s+/g, ' ').toLowerCase())}`)
        .sort()
        .join('+'),
    )
    .join(',');
}

/** The normalized RDN strings of a DN, leaf first. */
function normalizedRdns(dn: string): string[] {
  const normalized = normalizeDn(dn);
  return normalized ? parseDn(normalized).map((rdn) => formatDn([rdn])) : [];
}

/**
 * Whether `dn` equals `base` or lies below it. Compared RDN by RDN, never as strings: `cn=a\,ou=people,dc=x` is not
 * under `ou=people,dc=x`.
 */
export function isUnder(dn: string, base: string): boolean {
  const child = normalizedRdns(dn);
  const parent = normalizedRdns(base);
  if (parent.length > child.length) return false;
  const offset = child.length - parent.length;
  return parent.every((rdn, index) => child[offset + index] === rdn);
}

/** How many RDNs `dn` has below `base` (-1 when it is not under it). */
export function depthBelow(dn: string, base: string): number {
  return isUnder(dn, base) ? normalizedRdns(dn).length - normalizedRdns(base).length : -1;
}

/** The normalized parent of a normalized DN ('' for a single RDN). */
export function parentDn(dn: string): string {
  const rdns = parseDn(dn);
  return rdns.length <= 1 ? '' : normalizeDn(formatDn(rdns.slice(1)));
}
