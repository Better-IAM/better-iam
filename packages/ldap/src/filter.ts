import {
  BerError,
  children,
  octets,
  readBoolean,
  readString,
  sequence,
  set,
  boolean,
  type BerElement,
} from './ber.js';

/**
 * LDAP search filters (RFC 4511 §4.5.1): the BER form a search carries, the string form of RFC 4515 (for clients and
 * tests), and evaluation against an entry. Attribute names compare case-insensitively; values compare as caseIgnore
 * strings, except that `entryUUID` and DN-valued attributes are normalized first by the caller's entry data.
 */
export type Filter =
  | { type: 'and'; filters: Filter[] }
  | { type: 'or'; filters: Filter[] }
  | { type: 'not'; filter: Filter }
  | { type: 'equal' | 'greater' | 'less' | 'approx'; attribute: string; value: string }
  | { type: 'substrings'; attribute: string; initial?: string; any: string[]; final?: string }
  | { type: 'present'; attribute: string }
  | { type: 'extensible'; attribute?: string; rule?: string; value: string; dnAttributes: boolean };

const MAX_DEPTH = 32;
const MAX_TERMS = 256;

/** Decodes a BER filter. Deep or huge filters are refused (a search is evaluated against every entry). */
export function decodeFilter(item: BerElement, depth = 0, budget = { terms: 0 }): Filter {
  if (depth > MAX_DEPTH || ++budget.terms > MAX_TERMS) throw new BerError('Filter too complex');
  const parts = () => children(item.value);
  switch (item.tag) {
    case 0xa0:
    case 0xa1: {
      const filters = parts().map((part) => decodeFilter(part, depth + 1, budget));
      return { type: item.tag === 0xa0 ? 'and' : 'or', filters };
    }
    case 0xa2: {
      const [inner] = parts();
      if (!inner) throw new BerError('Empty not filter');
      return { type: 'not', filter: decodeFilter(inner, depth + 1, budget) };
    }
    case 0xa3:
    case 0xa5:
    case 0xa6:
    case 0xa8: {
      const [attribute, value] = parts();
      const kind = item.tag === 0xa3 ? 'equal' : item.tag === 0xa5 ? 'greater' : item.tag === 0xa6 ? 'less' : 'approx';
      return { type: kind, attribute: readString(attribute), value: readString(value) };
    }
    case 0xa4: {
      const [attribute, substrings] = parts();
      const filter: Filter = { type: 'substrings', attribute: readString(attribute), any: [] };
      if (!substrings || substrings.tag !== 0x30) throw new BerError('Invalid substrings filter');
      for (const part of children(substrings.value)) {
        const text = part.value.toString('utf8');
        if (part.tag === 0x80) filter.initial = text;
        else if (part.tag === 0x81) filter.any.push(text);
        else if (part.tag === 0x82) filter.final = text;
        else throw new BerError('Invalid substring');
      }
      return filter;
    }
    case 0x87:
      return { type: 'present', attribute: item.value.toString('utf8') };
    case 0xa9: {
      const filter: Extract<Filter, { type: 'extensible' }> = { type: 'extensible', value: '', dnAttributes: false };
      for (const part of parts()) {
        if (part.tag === 0x81) filter.rule = part.value.toString('utf8');
        else if (part.tag === 0x82) filter.attribute = part.value.toString('utf8');
        else if (part.tag === 0x83) filter.value = part.value.toString('utf8');
        else if (part.tag === 0x84) filter.dnAttributes = readBoolean(part, 0x84);
      }
      return filter;
    }
    default:
      throw new BerError(`Unknown filter choice 0x${item.tag.toString(16)}`);
  }
}

export function encodeFilter(filter: Filter): Buffer {
  switch (filter.type) {
    case 'and':
    case 'or':
      return set(filter.filters.map(encodeFilter), filter.type === 'and' ? 0xa0 : 0xa1);
    case 'not':
      return sequence([encodeFilter(filter.filter)], 0xa2);
    case 'equal':
    case 'greater':
    case 'less':
    case 'approx': {
      const tag = { equal: 0xa3, greater: 0xa5, less: 0xa6, approx: 0xa8 }[filter.type];
      return sequence([octets(filter.attribute), octets(filter.value)], tag);
    }
    case 'substrings':
      return sequence(
        [
          octets(filter.attribute),
          sequence([
            ...(filter.initial !== undefined ? [octets(filter.initial, 0x80)] : []),
            ...filter.any.map((part) => octets(part, 0x81)),
            ...(filter.final !== undefined ? [octets(filter.final, 0x82)] : []),
          ]),
        ],
        0xa4,
      );
    case 'present':
      return octets(filter.attribute, 0x87);
    case 'extensible':
      return sequence(
        [
          ...(filter.rule ? [octets(filter.rule, 0x81)] : []),
          ...(filter.attribute ? [octets(filter.attribute, 0x82)] : []),
          octets(filter.value, 0x83),
          ...(filter.dnAttributes ? [boolean(true, 0x84)] : []),
        ],
        0xa9,
      );
  }
}

/** Parses the RFC 4515 string form, e.g. `(&(objectClass=person)(|(uid=alice)(mail=*@acme.test)))`. */
export function parseFilter(text: string): Filter {
  let index = 0;
  // `\2a` escapes are bytes (possibly parts of one UTF-8 character); everything else is text.
  const unescape = (value: string) =>
    Buffer.concat(
      value
        .split(/(\\[0-9a-fA-F]{2})/)
        .map((part) =>
          /^\\[0-9a-fA-F]{2}$/.test(part) ? Buffer.from([Number.parseInt(part.slice(1), 16)]) : Buffer.from(part, 'utf8'),
        ),
    ).toString('utf8');
  const parse = (): Filter => {
    if (text[index] !== '(') throw new BerError('Expected (');
    index++;
    const head = text[index];
    let filter: Filter;
    if (head === '&' || head === '|') {
      index++;
      const filters: Filter[] = [];
      while (text[index] === '(') filters.push(parse());
      filter = { type: head === '&' ? 'and' : 'or', filters };
    } else if (head === '!') {
      index++;
      filter = { type: 'not', filter: parse() };
    } else {
      const end = text.indexOf(')', index);
      if (end < 0) throw new BerError('Expected )');
      const item = text.slice(index, end);
      index = end;
      const match = /^([^=~<>:]+)(=|~=|>=|<=)(.*)$/s.exec(item);
      if (!match) throw new BerError('Invalid filter item');
      const [, attribute, operator, raw] = match as unknown as [string, string, string, string];
      if (operator === '=' && raw === '*') filter = { type: 'present', attribute };
      else if (operator === '=' && raw.includes('*')) {
        const pieces = raw.split('*').map(unescape);
        filter = {
          type: 'substrings',
          attribute,
          ...(pieces[0] ? { initial: pieces[0] } : {}),
          any: pieces.slice(1, -1).filter(Boolean),
          ...(pieces.at(-1) ? { final: pieces.at(-1) } : {}),
        };
      } else
        filter = {
          type: operator === '=' ? 'equal' : operator === '~=' ? 'approx' : operator === '>=' ? 'greater' : 'less',
          attribute,
          value: unescape(raw),
        };
    }
    if (text[index] !== ')') throw new BerError('Expected )');
    index++;
    return filter;
  };
  const trimmed = text.trim();
  text = trimmed.startsWith('(') ? trimmed : `(${trimmed})`;
  const result = parse();
  if (index !== text.length) throw new BerError('Trailing characters after the filter');
  return result;
}

/** An entry's attributes, keyed by lowercased attribute name. */
export type EntryAttributes = Map<string, string[]>;

const fold = (value: string) => value.trim().replace(/\s+/g, ' ').toLowerCase();

/** Evaluates a filter (RFC 4511 three-valued logic collapsed: Undefined counts as false). */
export function matchFilter(filter: Filter, attributes: EntryAttributes): boolean {
  const values = (name: string) => attributes.get(name.toLowerCase()) ?? [];
  switch (filter.type) {
    case 'and':
      return filter.filters.every((item) => matchFilter(item, attributes));
    case 'or':
      return filter.filters.some((item) => matchFilter(item, attributes));
    case 'not':
      return !matchFilter(filter.filter, attributes);
    case 'present':
      return filter.attribute.toLowerCase() === 'objectclass' || values(filter.attribute).length > 0;
    case 'equal':
    case 'approx':
      return values(filter.attribute).some((value) => fold(value) === fold(filter.value));
    case 'greater':
      return values(filter.attribute).some((value) => fold(value) >= fold(filter.value));
    case 'less':
      return values(filter.attribute).some((value) => fold(value) <= fold(filter.value));
    case 'substrings':
      return values(filter.attribute).some((raw) => {
        const value = fold(raw);
        let position = 0;
        if (filter.initial !== undefined) {
          if (!value.startsWith(fold(filter.initial))) return false;
          position = fold(filter.initial).length;
        }
        for (const part of filter.any) {
          const found = value.indexOf(fold(part), position);
          if (found < 0) return false;
          position = found + fold(part).length;
        }
        return filter.final === undefined || (value.length - fold(filter.final).length >= position && value.endsWith(fold(filter.final)));
      });
    case 'extensible':
      // Only the default equality rule on a named attribute is supported; other rules match nothing.
      return (
        !filter.rule &&
        filter.attribute !== undefined &&
        values(filter.attribute).some((value) => fold(value) === fold(filter.value))
      );
  }
}
