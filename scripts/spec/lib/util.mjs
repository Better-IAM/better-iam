// Shared helpers for the spec generators: repository paths, deterministic JSON, dist imports, and the tagged encoding
// of values JSON cannot hold (used by test vectors).
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
/** The checked-in spec directory (the reference for `--check` and for reused nondeterministic values). */
export const specDir = join(root, 'spec');

/** Imports a built module of a workspace package: `dist('server', 'http.js')`. Run `pnpm build` first. */
export async function dist(pkg, file = 'index.js') {
  return import(pathToFileURL(join(root, 'packages', pkg, 'dist', file)).href);
}

/** Imports a dependency as a workspace package resolves it (`fromPackage('auth', 'otplib')`). */
export async function fromPackage(pkg, specifier) {
  const { createRequire } = await import('node:module');
  const require = createRequire(join(root, 'packages', pkg, 'package.json'));
  const resolved = require.resolve(specifier);
  return import(pathToFileURL(resolved).href);
}

/** Repository-relative POSIX path. */
export const repoPath = (path) => relative(root, path).split(sep).join('/');

/** Recursively sorts object keys (arrays keep their order). */
export function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort(codePointCompare)) out[key] = sortKeys(value[key]);
    return out;
  }
  return value;
}

/** Code-point order for strings (the order Rust and Go sort strings in). */
export function codePointCompare(a, b) {
  const left = [...a];
  const right = [...b];
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const x = left[i].codePointAt(0);
    const y = right[i].codePointAt(0);
    if (x !== y) return x - y;
  }
  return left.length - right.length;
}

/** Pretty JSON with a trailing LF; `sorted` sorts keys recursively first. */
export function json(value, { sorted = true } = {}) {
  return `${JSON.stringify(sorted ? sortKeys(value) : value, null, 2)}\n`;
}

/** Collects the files one generator run writes, relative to the output directory. */
export class Output {
  constructor(dir) {
    this.dir = dir;
    this.files = new Map();
  }
  add(path, content) {
    if (this.files.has(path)) throw new Error(`spec output ${path} written twice`);
    if (content.includes('\r')) throw new Error(`spec output ${path} contains CR`);
    this.files.set(path, content);
  }
  async flush() {
    for (const [path, content] of this.files) {
      const target = join(this.dir, ...path.split('/'));
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, content);
    }
  }
}

export async function* walkFiles(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  for (const entry of entries.sort((a, b) => codePointCompare(a.name, b.name))) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walkFiles(path);
    else yield path;
  }
}

export async function readText(path) {
  return readFile(path, 'utf8');
}

export const sha256Hex = (value) => createHash('sha256').update(value).digest('hex');

// --- tagged values ---------------------------------------------------------------------------------------------------
//
// Test vectors are JSON, but some inputs and outputs are not JSON values. They are written as one-key objects:
//   {"$undefined": true}            JavaScript undefined (an absent argument, a field set to undefined)
//   {"$number": "NaN" | "Infinity" | "-Infinity" | "-0"}
//   {"$utf16": [0xd800, ...]}       a string with an unpaired surrogate (or U+0000 where noted), as UTF-16 code units
//   {"$bigint": "123"}              a bigint
//   {"$bytes": "<base64url>"}       a Uint8Array / Buffer
//   {"$set": [...]}                 a Set (members in insertion order)
//   {"$error": {...}}               (outputs only) the call threw: name, code, status, reason when present, message
// Plain JSON objects never use these keys.

const lone = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function encode(value) {
  if (value === undefined) return { $undefined: true };
  if (typeof value === 'number') {
    if (Number.isNaN(value)) return { $number: 'NaN' };
    if (value === Infinity) return { $number: 'Infinity' };
    if (value === -Infinity) return { $number: '-Infinity' };
    if (Object.is(value, -0)) return { $number: '-0' };
    return value;
  }
  if (typeof value === 'bigint') return { $bigint: String(value) };
  if (typeof value === 'string') {
    if (lone.test(value))
      return { $utf16: [...Array(value.length).keys()].map((i) => value.charCodeAt(i)) };
    return value;
  }
  if (value instanceof Uint8Array) return { $bytes: Buffer.from(value).toString('base64url') };
  if (value instanceof Set) return { $set: [...value].map(encode) };
  if (Array.isArray(value)) return value.map(encode);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = encode(item);
    return out;
  }
  return value;
}

export function decode(value) {
  if (Array.isArray(value)) return value.map(decode);
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 1) {
      const [key] = keys;
      const item = value[key];
      if (key === '$undefined') return undefined;
      if (key === '$number') return item === '-0' ? -0 : Number(item);
      if (key === '$bigint') return BigInt(item);
      if (key === '$utf16') return String.fromCharCode(...item);
      if (key === '$bytes') return new Uint8Array(Buffer.from(item, 'base64url'));
      if (key === '$set') return new Set(item.map(decode));
    }
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = decode(item);
    return out;
  }
  return value;
}

/** An error as vectors report it: name, code and status when present, and the message. */
export function errorOf(error) {
  if (!error || typeof error !== 'object') return { name: 'Thrown', message: String(error) };
  const out = { name: error.name ?? 'Error' };
  if (typeof error.code === 'string') out.code = error.code;
  if (typeof error.status === 'number') out.status = error.status;
  if (typeof error.reason === 'string') out.reason = error.reason;
  out.message = String(error.message ?? '');
  return out;
}

/**
 * Runs `fn` and returns its tagged-encoded result, or `{"$error": {name, code?, status?, reason?, message}}` when it
 * throws (or rejects).
 */
export async function outcome(fn) {
  try {
    return encode(await fn());
  } catch (error) {
    return { $error: errorOf(error) };
  }
}
