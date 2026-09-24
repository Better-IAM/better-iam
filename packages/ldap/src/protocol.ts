import {
  BerError,
  children,
  enumerated,
  integer,
  octets,
  readBoolean,
  readInteger,
  readOctets,
  readString,
  sequence,
  set,
  Tag,
  type BerElement,
} from './ber.js';
import { decodeFilter, encodeFilter, type Filter } from './filter.js';

/** LDAPv3 messages (RFC 4511) as the gateway reads and writes them. */

export const ResultCode = {
  success: 0,
  operationsError: 1,
  protocolError: 2,
  timeLimitExceeded: 3,
  sizeLimitExceeded: 4,
  compareFalse: 5,
  compareTrue: 6,
  authMethodNotSupported: 7,
  noSuchAttribute: 16,
  noSuchObject: 32,
  invalidDNSyntax: 34,
  inappropriateAuthentication: 48,
  invalidCredentials: 49,
  insufficientAccessRights: 50,
  busy: 51,
  unavailable: 52,
  unwillingToPerform: 53,
  confidentialityRequired: 13,
  other: 80,
} as const;

export const OID = {
  whoAmI: '1.3.6.1.4.1.4203.1.11.3',
  startTls: '1.3.6.1.4.1.1466.20037',
  noticeOfDisconnection: '1.3.6.1.4.1.1466.20036',
  pagedResults: '1.2.840.113556.1.4.319',
} as const;

export type SearchScope = 'base' | 'one' | 'sub';

export type LdapRequest =
  | { op: 'bind'; version: number; name: string; password?: Buffer; sasl?: string }
  | { op: 'unbind' }
  | {
      op: 'search';
      base: string;
      scope: SearchScope;
      sizeLimit: number;
      timeLimit: number;
      typesOnly: boolean;
      filter: Filter;
      attributes: string[];
    }
  | { op: 'compare'; entry: string; attribute: string; value: string }
  | { op: 'extended'; name: string; value?: Buffer }
  | { op: 'abandon'; id: number }
  /** A write or other operation the gateway refuses; `responseTag` is the tag its answer needs. */
  | { op: 'unsupported'; name: string; responseTag: number };

export interface LdapControl {
  type: string;
  critical: boolean;
  value?: Buffer;
}

export interface LdapMessage {
  id: number;
  request: LdapRequest;
  controls: LdapControl[];
}

const scopes: SearchScope[] = ['base', 'one', 'sub'];
const unsupported: Record<number, [string, number]> = {
  0x66: ['modify', 0x67],
  0x68: ['add', 0x69],
  0x4a: ['delete', 0x6b],
  0x6c: ['modifyDN', 0x6d],
};

/** Decodes one LDAPMessage element. */
export function decodeMessage(message: BerElement): LdapMessage {
  if (message.tag !== Tag.SEQUENCE) throw new BerError('Expected an LDAPMessage');
  const [idElement, op, controlsElement] = children(message.value);
  const id = readInteger(idElement);
  if (id < 0 || id > 2147483647) throw new BerError('Invalid message ID');
  if (!op) throw new BerError('Missing protocol operation');
  const controls: LdapControl[] = [];
  if (controlsElement?.tag === 0xa0)
    for (const control of children(controlsElement.value)) {
      const [type, second, third] = children(control.value);
      const critical = second?.tag === Tag.BOOLEAN ? readBoolean(second) : false;
      const valueItem = second?.tag === Tag.OCTET_STRING ? second : third;
      controls.push({
        type: readString(type),
        critical,
        ...(valueItem?.tag === Tag.OCTET_STRING ? { value: valueItem.value } : {}),
      });
    }
  return { id, request: decodeRequest(op), controls };
}

function decodeRequest(op: BerElement): LdapRequest {
  switch (op.tag) {
    case 0x60: {
      const [version, name, auth] = children(op.value);
      if (!auth) throw new BerError('Missing authentication');
      if (auth.tag === 0x80)
        return { op: 'bind', version: readInteger(version), name: readString(name), password: auth.value };
      if (auth.tag === 0xa3) {
        const [mechanism] = children(auth.value);
        return { op: 'bind', version: readInteger(version), name: readString(name), sasl: readString(mechanism) };
      }
      throw new BerError('Unknown authentication choice');
    }
    case 0x42:
      return { op: 'unbind' };
    case 0x63: {
      const [base, scope, , sizeLimit, timeLimit, typesOnly, filter, attributes] = children(op.value);
      const scopeValue = readInteger(scope, Tag.ENUMERATED);
      if (!scopes[scopeValue]) throw new BerError('Invalid search scope');
      if (!filter) throw new BerError('Missing filter');
      return {
        op: 'search',
        base: readString(base),
        scope: scopes[scopeValue]!,
        sizeLimit: readInteger(sizeLimit),
        timeLimit: readInteger(timeLimit),
        typesOnly: readBoolean(typesOnly),
        filter: decodeFilter(filter),
        attributes: attributes ? children(attributes.value).map((item) => readString(item)) : [],
      };
    }
    case 0x6e: {
      const [entry, assertion] = children(op.value);
      const [attribute, value] = children(assertion!.value);
      return { op: 'compare', entry: readString(entry), attribute: readString(attribute), value: readString(value) };
    }
    case 0x77: {
      const parts = children(op.value);
      const name = parts.find((part) => part.tag === 0x80);
      const value = parts.find((part) => part.tag === 0x81);
      if (!name) throw new BerError('Missing extended request name');
      return { op: 'extended', name: name.value.toString('utf8'), ...(value ? { value: value.value } : {}) };
    }
    case 0x50:
      return { op: 'abandon', id: readInteger({ ...op, tag: Tag.INTEGER }) };
    default: {
      const known = unsupported[op.tag];
      if (known) return { op: 'unsupported', name: known[0], responseTag: known[1] };
      throw new BerError(`Unknown protocol operation 0x${op.tag.toString(16)}`);
    }
  }
}

const envelope = (id: number, op: Buffer, controls?: Buffer) =>
  sequence([integer(id), op, ...(controls ? [controls] : [])]);

function result(tag: number, code: number, matchedDn = '', message = '', extra: Buffer[] = []): Buffer {
  return sequence([enumerated(code), octets(matchedDn), octets(message), ...extra], tag);
}

export const bindResponse = (id: number, code: number, message = '') => envelope(id, result(0x61, code, '', message));
export const searchDone = (id: number, code: number, message = '', matchedDn = '', controls?: Buffer) =>
  envelope(id, result(0x65, code, matchedDn, message), controls);
export const compareResponse = (id: number, code: number, message = '') => envelope(id, result(0x6f, code, '', message));
export const genericResponse = (id: number, tag: number, code: number, message = '') =>
  envelope(id, result(tag, code, '', message));
export const extendedResponse = (id: number, code: number, message = '', name?: string, value?: Buffer | string) =>
  envelope(
    id,
    result(0x78, code, '', message, [
      ...(name ? [octets(name, 0x8a)] : []),
      ...(value !== undefined ? [octets(value, 0x8b)] : []),
    ]),
  );
/** The unsolicited notice sent before the server closes a connection (message ID 0). */
export const noticeOfDisconnection = (code: number, message: string) =>
  extendedResponse(0, code, message, OID.noticeOfDisconnection);

/** One SearchResultEntry: attribute order kept, values as given (or types only). */
export function searchEntry(id: number, dn: string, attributes: [string, string[]][], typesOnly = false): Buffer {
  return envelope(
    id,
    sequence(
      [
        octets(dn),
        sequence(
          attributes.map(([name, values]) =>
            sequence([octets(name), set(typesOnly ? [] : values.map((value) => octets(value)))]),
          ),
        ),
      ],
      0x64,
    ),
  );
}

/** The paged-results response control (RFC 2696): estimated size and the cookie for the next page. */
export function pagedResultsControl(size: number, cookie: Buffer): Buffer {
  return sequence(
    [sequence([octets(OID.pagedResults), octets(sequence([integer(size), octets(cookie)]))])],
    0xa0,
  );
}

/** Reads a paged-results request control value: page size and cookie. */
export function readPagedResults(value: Buffer | undefined): { size: number; cookie: Buffer } | undefined {
  if (!value) return undefined;
  const [outer] = children(value);
  if (!outer) return undefined;
  const [size, cookie] = children(outer.value);
  return { size: readInteger(size), cookie: readOctets(cookie) };
}

// Client-side encoders, for tests and for programs that talk to an LDAP server.
export const encodeBind = (id: number, name: string, password: string) =>
  envelope(id, sequence([integer(3), octets(name), octets(password, 0x80)], 0x60));
export const encodeUnbind = (id: number) => envelope(id, Buffer.from([0x42, 0x00]));
export function encodeSearch(
  id: number,
  search: {
    base: string;
    scope?: SearchScope;
    filter: Filter;
    attributes?: string[];
    sizeLimit?: number;
    typesOnly?: boolean;
  },
  controls?: Buffer,
): Buffer {
  return envelope(
    id,
    sequence(
      [
        octets(search.base),
        enumerated(scopes.indexOf(search.scope ?? 'sub')),
        enumerated(0),
        integer(search.sizeLimit ?? 0),
        integer(0),
        Buffer.from([Tag.BOOLEAN, 1, search.typesOnly ? 0xff : 0]),
        encodeFilter(search.filter),
        sequence((search.attributes ?? []).map((name) => octets(name))),
      ],
      0x63,
    ),
    controls,
  );
}
export const encodeExtended = (id: number, name: string, value?: Buffer) =>
  envelope(id, sequence([octets(name, 0x80), ...(value ? [octets(value, 0x81)] : [])], 0x77));
export const encodeCompare = (id: number, entry: string, attribute: string, value: string) =>
  envelope(id, sequence([octets(entry), sequence([octets(attribute), octets(value)])], 0x6e));
export const pagedResultsRequest = (size: number, cookie: Buffer = Buffer.alloc(0)) =>
  sequence(
    [sequence([octets(OID.pagedResults), octets(sequence([integer(size), octets(cookie)]))])],
    0xa0,
  );

/** A decoded server answer (client side). */
export interface LdapResponse {
  id: number;
  tag: number;
  code?: number;
  message?: string;
  dn?: string;
  attributes?: Record<string, string[]>;
  responseName?: string;
  responseValue?: Buffer;
  controls?: LdapControl[];
}

export function decodeResponse(message: BerElement): LdapResponse {
  const [idElement, op, controlsElement] = children(message.value);
  const id = readInteger(idElement);
  const response: LdapResponse = { id, tag: op!.tag };
  const parts = children(op!.value);
  if (op!.tag === 0x64) {
    response.dn = readString(parts[0]);
    response.attributes = {};
    for (const attribute of children(parts[1]!.value)) {
      const [name, values] = children(attribute.value);
      response.attributes[readString(name)] = children(values!.value).map((value) => value.value.toString('utf8'));
    }
  } else {
    response.code = readInteger(parts[0], Tag.ENUMERATED);
    response.message = readString(parts[2]);
    const name = parts.find((part) => part.tag === 0x8a);
    const value = parts.find((part) => part.tag === 0x8b);
    if (name) response.responseName = name.value.toString('utf8');
    if (value) response.responseValue = value.value;
  }
  if (controlsElement?.tag === 0xa0)
    response.controls = children(controlsElement.value).map((control) => {
      const [type, second, third] = children(control.value);
      const valueItem = second?.tag === Tag.OCTET_STRING ? second : third;
      return {
        type: readString(type),
        critical: second?.tag === Tag.BOOLEAN ? readBoolean(second) : false,
        ...(valueItem?.tag === Tag.OCTET_STRING ? { value: valueItem.value } : {}),
      };
    });
  return response;
}
