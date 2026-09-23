/**
 * The JSON Canonicalization Scheme (RFC 8785): the single serialization of a JSON value that signers and verifiers
 * agree on. Object members are sorted by the UTF-16 code units of their names at every depth, numbers use the
 * ECMAScript shortest form and strings the escaping of `JSON.stringify`, and there is no whitespace. Unlike
 * `canonicalJson`, member order does not depend on how a JavaScript engine orders integer-like keys.
 *
 * Members whose value is `undefined`, a function or a symbol are left out and such array entries become `null`, as
 * `JSON.stringify` does; `toJSON` is honoured. Throws a `TypeError` for values JSON cannot represent: non-finite
 * numbers, bigints, cycles, and a top-level value without a JSON form.
 */
export function canonicalizeJson(value: unknown): string {
  const path = new Set<object>();
  const write = (item: unknown): string | undefined => {
    if (item === null) return 'null';
    switch (typeof item) {
      case 'boolean':
        return item ? 'true' : 'false';
      case 'string':
        return JSON.stringify(item);
      case 'number':
        if (!Number.isFinite(item))
          throw new TypeError('JSON cannot represent a non-finite number');
        return JSON.stringify(item);
      case 'bigint':
        throw new TypeError('JSON cannot represent a bigint');
      case 'object': {
        const convert = (item as { toJSON?: unknown }).toJSON;
        if (typeof convert === 'function') return write(convert.call(item));
        if (path.has(item)) throw new TypeError('Cannot canonicalize a cyclic value');
        path.add(item);
        try {
          if (Array.isArray(item))
            return `[${item.map((entry: unknown) => write(entry) ?? 'null').join(',')}]`;
          const record = item as Record<string, unknown>;
          const members: string[] = [];
          for (const key of Object.keys(record).sort()) {
            const entry = write(record[key]);
            if (entry !== undefined) members.push(`${JSON.stringify(key)}:${entry}`);
          }
          return `{${members.join(',')}}`;
        } finally {
          path.delete(item);
        }
      }
      default:
        return undefined;
    }
  };
  const result = write(value);
  if (result === undefined) throw new TypeError('The value has no JSON representation');
  return result;
}
