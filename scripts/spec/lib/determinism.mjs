// Deterministic randomness for vector generation. Imported before any package code: node:crypto's randomBytes,
// randomUUID, randomInt and getRandomValues (and Web Crypto's getRandomValues) draw from a SHA-256 counter stream
// that `reseed(label)` resets, so every case that needs random bytes (IVs, salts, tokens, ids) produces the same
// output on every run. Signatures computed inside OpenSSL (ECDSA nonces) are not covered; vectors that need them
// reuse the previously checked-in value after verifying it (see vectors/context.mjs).
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';

let seed = Buffer.alloc(32);
let counter = 0;
let pool = Buffer.alloc(0);

function next(length) {
  const chunks = [pool];
  let size = pool.length;
  while (size < length) {
    const block = crypto.createHash('sha256').update(seed).update(String(counter++)).digest();
    chunks.push(block);
    size += block.length;
  }
  const all = Buffer.concat(chunks);
  pool = all.subarray(length);
  return Buffer.from(all.subarray(0, length));
}

/** Resets the stream to the one named by `label`. */
export function reseed(label) {
  seed = crypto.createHash('sha256').update(`better-iam-spec:${label}`).digest();
  counter = 0;
  pool = Buffer.alloc(0);
}
reseed('initial');

/** `length` bytes from the current stream (for generator-side fixtures). */
export const deterministicBytes = (length) => next(length);

const original = {
  randomBytes: crypto.randomBytes,
  randomUUID: crypto.randomUUID,
  randomInt: crypto.randomInt,
  getRandomValues: crypto.getRandomValues,
};

function fill(view) {
  const bytes = next(view.byteLength);
  new Uint8Array(view.buffer, view.byteOffset, view.byteLength).set(bytes);
  return view;
}

crypto.randomBytes = (size, callback) => {
  const bytes = next(size);
  if (typeof callback === 'function') {
    queueMicrotask(() => callback(null, bytes));
    return undefined;
  }
  return bytes;
};
crypto.randomUUID = () => {
  const bytes = next(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};
crypto.randomInt = (min, max, callback) => {
  if (max === undefined || typeof max === 'function') {
    callback = max;
    max = min;
    min = 0;
  }
  const range = max - min;
  const value = min + (next(6).readUIntBE(0, 6) % range);
  if (typeof callback === 'function') {
    queueMicrotask(() => callback(null, value));
    return undefined;
  }
  return value;
};
crypto.randomFillSync = (buffer, offset = 0, size) => {
  const view = new Uint8Array(buffer.buffer ?? buffer, buffer.byteOffset ?? 0, buffer.byteLength);
  const length = size ?? view.length - offset;
  view.set(next(length), offset);
  return buffer;
};
/** Replaces a method, defining it as an own property where the original is a getter-only accessor. */
function replace(target, name, value) {
  if (!target) return;
  try {
    Object.defineProperty(target, name, { value, writable: true, configurable: true });
  } catch {
    try {
      target[name] = value;
    } catch {
      /* Not replaceable in this runtime. */
    }
  }
}
replace(crypto, 'getRandomValues', (view) => fill(view));
replace(crypto.webcrypto, 'getRandomValues', (view) => fill(view));
replace(globalThis.crypto, 'getRandomValues', (view) => fill(view));
replace(globalThis.crypto, 'randomUUID', () => crypto.randomUUID());
syncBuiltinESMExports();

export { original as originalRandom };
