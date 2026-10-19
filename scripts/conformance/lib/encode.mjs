// Value encoding shared by the trace recorder (tests/conformance) and the TypeScript conformance server.
//
// Two encodings exist, and spec/conformance/FORMAT.md describes both:
//
// - `httpJson(value)` is exactly what the HTTP router sends: `JSON.parse(JSON.stringify(value))`, with a top-level
//   `session` object losing `tokenHash` and `uniqueKey` (packages/server/src/http.ts `publicResult`). Used for every
//   step that the replay sends over the public HTTP surface.
// - `encodeValue(value)` is the tagged encoding of control-plane values (`call` and `store` steps, outbox messages):
//   plain JSON where possible, with `{"$bytes": base64}`, `{"$date": iso}`, `{"$bigint": "123"}`, `{"$map": [[k, v]]}`,
//   `{"$set": [..]}`, `{"$undefined": true}` (array holes and explicit undefined in arrays only), `{"$function": name}`
//   and `{"$error": {...}}` for values JSON cannot carry. `decodeValue` reverses it (functions stay markers).

/** The router's success body (`{ data: publicResult(result) }`) without the envelope. */
export function publicResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result) || !('session' in result))
    return result;
  const session = result.session;
  if (
    !session ||
    typeof session !== 'object' ||
    Array.isArray(session) ||
    !('tokenHash' in session || 'uniqueKey' in session)
  )
    return result;
  const { tokenHash: _tokenHash, uniqueKey: _uniqueKey, ...rest } = session;
  return { ...result, session: rest };
}

/** What a JSON body round trip makes of a value (undefined stays undefined: no body member). */
export function httpJson(value) {
  if (value === undefined) return undefined;
  const text = JSON.stringify(value);
  return text === undefined ? undefined : JSON.parse(text);
}

const isPlainObject = (value) => {
  if (!value || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

/** Tagged JSON encoding for control-plane values; never throws (cycles become `{"$cycle": true}`). */
export function encodeValue(value, seen = new WeakSet()) {
  if (value === null) return null;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : { $number: String(value) };
    case 'bigint':
      return { $bigint: value.toString() };
    case 'undefined':
      return { $undefined: true };
    case 'function':
      return { $function: value.name || 'anonymous' };
    case 'symbol':
      return { $symbol: value.description ?? '' };
  }
  if (seen.has(value)) return { $cycle: true };
  if (value instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)))
    return {
      $bytes: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64'),
    };
  if (value instanceof ArrayBuffer) return { $bytes: Buffer.from(value).toString('base64') };
  if (value instanceof Date)
    return { $date: Number.isNaN(value.getTime()) ? 'Invalid Date' : value.toISOString() };
  if (value instanceof URL) return value.href;
  if (typeof Headers !== 'undefined' && value instanceof Headers) {
    const out = {};
    value.forEach((item, key) => (out[key] = item));
    return { $headers: out };
  }
  if (value instanceof Error) {
    const error = { name: value.name, message: value.message };
    if (typeof value.code === 'string') error.code = value.code;
    if (typeof value.status === 'number') error.status = value.status;
    return { $error: error };
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const out = [];
      for (let index = 0; index < value.length; index++) out.push(encodeValue(value[index], seen));
      return out;
    }
    if (value instanceof Map)
      return {
        $map: [...value.entries()].map(([k, v]) => [encodeValue(k, seen), encodeValue(v, seen)]),
      };
    if (value instanceof Set) return { $set: [...value].map((item) => encodeValue(item, seen)) };
    if (typeof value.then === 'function') return { $promise: true };
    const out = {};
    for (const key of Object.keys(value)) {
      const item = value[key];
      // Object members that are undefined disappear, as in JSON.
      if (item === undefined) continue;
      out[key] = encodeValue(item, seen);
    }
    if (!isPlainObject(value) && value.constructor && value.constructor.name !== 'Object')
      return Object.keys(out).length ? out : { $object: value.constructor.name };
    return out;
  } finally {
    seen.delete(value);
  }
}

/** Reverses `encodeValue` (functions, symbols, promises and cycles stay as their markers). */
export function decodeValue(value) {
  if (Array.isArray(value)) return value.map(decodeValue);
  if (!value || typeof value !== 'object') return value;
  const keys = Object.keys(value);
  if (keys.length === 1) {
    const [key] = keys;
    const inner = value[key];
    switch (key) {
      case '$bytes':
        return new Uint8Array(Buffer.from(inner, 'base64'));
      case '$date':
        return new Date(inner);
      case '$bigint':
        return BigInt(inner);
      case '$undefined':
        return undefined;
      case '$number':
        return Number(inner);
      case '$map':
        return new Map(inner.map(([k, v]) => [decodeValue(k), decodeValue(v)]));
      case '$set':
        return new Set(inner.map(decodeValue));
      case '$headers':
        return new Headers(inner);
    }
  }
  const out = {};
  for (const key of keys) out[key] = decodeValue(value[key]);
  return out;
}

/** True when the value holds something only `encodeValue` can carry, or a function (`$function`). */
export function containsFunction(value, seen = new WeakSet()) {
  if (typeof value === 'function') return true;
  if (!value || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  const items = Array.isArray(value) ? value : Object.values(value);
  return items.some((item) => containsFunction(item, seen));
}

/**
 * The error shape a step records: IamError code/status/message, anything else INTERNAL_ERROR 500 (what the router
 * answers). `isIamError` is the `instanceof IamError` check of the caller's module graph; without it an error with a
 * string `code` and numeric `status` counts as one.
 */
export function errorShape(error, isIamError) {
  const known = isIamError
    ? isIamError(error)
    : Boolean(
        error &&
          typeof error === 'object' &&
          typeof error.code === 'string' &&
          typeof error.status === 'number',
      );
  if (known) {
    const shape = { code: error.code, status: error.status, message: String(error.message ?? '') };
    if (typeof error.retryAfterMs === 'number' && error.retryAfterMs > 0)
      shape.retryAfterMs = error.retryAfterMs;
    return shape;
  }
  return {
    code: 'INTERNAL_ERROR',
    status: 500,
    message: 'Internal server error',
    thrown: { name: error?.name ?? typeof error, message: String(error?.message ?? error) },
  };
}
