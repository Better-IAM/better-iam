/**
 * The subset of ASN.1 BER (X.690) that LDAPv3 (RFC 4511) uses: definite lengths, INTEGER/ENUMERATED, BOOLEAN,
 * OCTET STRING, NULL, SEQUENCE/SET and context/application tags. Decoding is strict (no indefinite lengths, lengths at
 * most four bytes) and bounds-checked; anything malformed throws `BerError`.
 */

export class BerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BerError';
  }
}

export const Tag = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  ENUMERATED: 0x0a,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

/** A decoded element: its tag byte and raw content. */
export interface BerElement {
  tag: number;
  /** The content octets. */
  value: Buffer;
  /** Total encoded size (tag + length + content). */
  size: number;
}

function lengthBytes(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest & 0xff);
  if (bytes.length > 4) throw new BerError('Element too long');
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** One TLV. */
export function element(tag: number, value: Buffer | Buffer[]): Buffer {
  const content = Array.isArray(value) ? Buffer.concat(value) : value;
  return Buffer.concat([Buffer.from([tag]), lengthBytes(content.length), content]);
}

export function integerBytes(value: number): Buffer {
  if (!Number.isSafeInteger(value)) throw new BerError('Integer out of range');
  const bytes: number[] = [];
  let rest = BigInt(value);
  do {
    bytes.unshift(Number(rest & 0xffn));
    rest >>= 8n;
  } while (rest !== 0n && rest !== -1n);
  // Keep the sign bit right: a positive value whose top bit is set needs a leading 0x00, a negative one 0xff.
  if (value >= 0 && bytes[0]! & 0x80) bytes.unshift(0);
  if (value < 0 && !(bytes[0]! & 0x80)) bytes.unshift(0xff);
  return Buffer.from(bytes);
}

export const integer = (value: number, tag: number = Tag.INTEGER) => element(tag, integerBytes(value));
export const enumerated = (value: number) => element(Tag.ENUMERATED, integerBytes(value));
export const octets = (value: string | Buffer, tag: number = Tag.OCTET_STRING) =>
  element(tag, typeof value === 'string' ? Buffer.from(value, 'utf8') : value);
export const boolean = (value: boolean, tag: number = Tag.BOOLEAN) => element(tag, Buffer.from([value ? 0xff : 0]));
export const sequence = (items: Buffer[], tag: number = Tag.SEQUENCE) => element(tag, items);
export const set = (items: Buffer[], tag: number = Tag.SET) => element(tag, items);

/**
 * Reads one element at `offset`, or undefined when `buffer` does not yet hold all of it (stream framing).
 * `maxSize` bounds the content length a peer may announce.
 */
export function readElement(buffer: Buffer, offset = 0, maxSize = 1 << 20): BerElement | undefined {
  if (offset >= buffer.length) return undefined;
  const tag = buffer[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new BerError('Multi-byte tags are not supported');
  if (offset + 1 >= buffer.length) return undefined;
  let length = buffer[offset + 1]!;
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0) throw new BerError('Indefinite lengths are not allowed');
    if (count > 4) throw new BerError('Length too long');
    if (offset + 2 + count > buffer.length) return undefined;
    length = 0;
    for (let index = 0; index < count; index++) length = length * 256 + buffer[offset + 2 + index]!;
    header += count;
  }
  if (length > maxSize) throw new BerError('Element exceeds the size limit');
  if (offset + header + length > buffer.length) return undefined;
  return {
    tag,
    value: buffer.subarray(offset + header, offset + header + length),
    size: header + length,
  };
}

/** The elements inside a constructed value. */
export function children(value: Buffer): BerElement[] {
  const result: BerElement[] = [];
  let offset = 0;
  while (offset < value.length) {
    const item = readElement(value, offset);
    if (!item) throw new BerError('Truncated element');
    result.push(item);
    offset += item.size;
  }
  return result;
}

export function readInteger(item: BerElement | undefined, tag: number = Tag.INTEGER): number {
  if (!item || item.tag !== tag || item.value.length === 0 || item.value.length > 6)
    throw new BerError('Expected an integer');
  let value = BigInt(item.value[0]! & 0x80 ? -1 : 0);
  for (const byte of item.value) value = (value << 8n) | BigInt(byte);
  return Number(BigInt.asIntN(48, value));
}

export function readOctets(item: BerElement | undefined, tag: number = Tag.OCTET_STRING): Buffer {
  if (!item || item.tag !== tag) throw new BerError('Expected an octet string');
  return item.value;
}

export const readString = (item: BerElement | undefined, tag: number = Tag.OCTET_STRING) =>
  readOctets(item, tag).toString('utf8');

export function readBoolean(item: BerElement | undefined, tag: number = Tag.BOOLEAN): boolean {
  if (!item || item.tag !== tag || item.value.length !== 1) throw new BerError('Expected a boolean');
  return item.value[0] !== 0;
}
