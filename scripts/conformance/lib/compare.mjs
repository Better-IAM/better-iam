// Binding and normalized comparison for trace replay (spec/conformance/FORMAT.md, "Binding" and "Normalization").
//
// A recorded value the server generated (IDs, tokens, secrets, codes, hashes, signatures, wall-clock times) is bound,
// by position, to the value the server under test returned in the same place. Bindings are then substituted into every
// later input, and every later occurrence of a bound value must match its binding.

/** Generated-looking runs inside strings, most specific first. */
const tokenPattern = new RegExp(
  [
    // A PEM block (keys, certificates, CRLs).
    /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/,
    // A PHC password hash ($argon2id$v=19$m=…,t=…,p=…$salt$hash).
    /\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+/,
    // A compact JWS/JWT (also SD-JWT presentations, which append ~disclosures).
    /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*(?:~[A-Za-z0-9_-]*)*/,
    // A UUID.
    /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/,
    // Prefixed credential tokens and identifiers: biam_ses_… (58 characters), usr_/ses_/out_… + 22 base64url.
    /biam_(?:ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}(?![A-Za-z0-9_-])/,
    /(?<![A-Za-z0-9_-])[a-z][a-z0-9]{1,15}_[A-Za-z0-9_-]{22}(?![A-Za-z0-9_-])/,
    // Standard base64 with + or / (keys, certificates, salts, MACs): at least 20 characters, not part of a
    // base64url run.
    /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9]*[+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9_-])/,
    // Base64url, hex, base32 runs.
    /[A-Za-z0-9_-]{16,}={0,2}/,
  ]
    .map((pattern) => pattern.source)
    .join('|'),
  'g',
);

/** Whether a run matched by `tokenPattern` looks random rather than like a stable word or path. */
export function looksGenerated(run) {
  if (run.startsWith('-----BEGIN ') || run.startsWith('$argon2')) return true;
  if (/^eyJ/.test(run) && run.includes('.')) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(run)) return true;
  if (/^biam_(ses|key|rol|sts|dlg)_/.test(run) && run.length === 58) return true;
  if (/^[a-z][a-z0-9]{1,15}_[A-Za-z0-9_-]{22}$/.test(run)) return true;
  if (run.length < 16) return false;
  const digits = /[0-9]/.test(run);
  const lower = /[a-z]/.test(run);
  const upper = /[A-Z]/.test(run);
  // Base64 with + or /: random when it mixes cases (paths are lower case).
  if (/[+/]/.test(run)) return lower && upper && (digits || run.length >= 24);
  if (digits && (lower || upper)) return true;
  // Base32 (TOTP secrets, short codes): upper case letters and 2-7 only.
  if (/^[A-Z2-7]{16,}=*$/.test(run)) return true;
  // Mixed case without digits is base64 unless it reads as words: random text switches case between about every
  // other pair of letters, camelCase names rarely (organizationAdministratorRole: 4 switches in 29 characters).
  if (!lower || !upper) return false;
  const letters = run.replace(/[^A-Za-z]/g, '');
  let switches = 0;
  for (let index = 1; index < letters.length; index++)
    if (letters[index] < 'a' !== letters[index - 1] < 'a') switches++;
  // Random base64 is also about half upper case; names are mostly lower case.
  const upperShare = letters.replace(/[a-z]/g, '').length / letters.length;
  if (switches / run.length >= 0.3 || (upperShare >= 0.35 && switches / run.length >= 0.2))
    return true;
  // Names split into syllables: a camel or kebab segment of three or more letters without a vowel is not a word.
  const segments = run.split(/[-_]|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/).filter(Boolean);
  const voweless = segments.filter(
    (segment) => segment.length >= 3 && !/[aeiouyAEIOUY]/.test(segment),
  );
  return voweless.length > 0 && switches / run.length >= 0.12;
}

/** Splits a string into its stable skeleton and its generated tokens. */
export function shape(text) {
  const tokens = [];
  const skeleton = text.replace(tokenPattern, (run) => {
    if (!looksGenerated(run)) return run;
    tokens.push(run);
    return '\u0000';
  });
  return { skeleton, tokens };
}

/** Epoch milliseconds and ISO-8601 instants inside a string (`denial-burst:<id>:1792400810045`). */
const timePattern =
  /(?<![0-9])1[0-9]{12}(?![0-9])|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z/g;
const isoInstant = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const timeValue = (text) => (/^\d+$/.test(text) ? Number(text) : Date.parse(text));
function timeShape(text) {
  const times = [];
  const skeleton = text.replace(timePattern, (run) => {
    times.push(run);
    return '\u0001';
  });
  return { skeleton, times };
}

/** Members whose string values are generated even when short (one-time codes, short tokens). */
const volatileKeyPattern =
  /(^|[a-z_])(id|Id|token|Token|secret|Secret|challenge|Challenge|code|Code|nonce|Nonce|hash|Hash|salt|Salt|signature|Signature|jti|kid|serial|Serial|fingerprint|Fingerprint|sealed|Sealed|ciphertext|Ciphertext|password|Password|otp|Otp|lease|Lease)s?$/;
export const isVolatileKey = (key) => typeof key === 'string' && volatileKeyPattern.test(key);
/** A random code inside a reference number (DSR-AXGF0YR8): a 6+ character run mixing letters and digits. */
const randomCode = (value) =>
  /[A-Za-z0-9]{6,}/.test(value) &&
  (value.match(/[A-Za-z0-9]{6,}/g) ?? []).some((run) => /[A-Za-z]/.test(run) && /[0-9]/.test(run));
const referenceKeyPattern = /(^|[a-z_])(number|Number|reference|Reference)$/;
/** A short value under a volatile member that still looks generated: digits (one-time codes) or a code-like run. */
const codeLike = (value) =>
  /^\d{4,10}$/.test(value) ||
  (/^[A-Za-z0-9_\-+/=.~]{8,}$/.test(value) && (/\d/.test(value) || value.length >= 16));

/**
 * A format-preserving token (`902-26-6789` for `123-45-6789`, `Atzz Vxfrdb ZLCU-6178-4345`): the same length, an
 * upper-case letter, lower-case letter, digit or the very same other character at every position, and at least four
 * letters or digits that differ.
 */
const charClass = (char) =>
  /[A-Z]/.test(char) ? 'A' : /[a-z]/.test(char) ? 'a' : /[0-9]/.test(char) ? '9' : char;
function sameLayout(recorded, actual) {
  if (recorded.length !== actual.length || recorded.length < 6) return false;
  let differing = 0;
  for (let index = 0; index < recorded.length; index++) {
    if (charClass(recorded[index]) !== charClass(actual[index])) return false;
    if (recorded[index] !== actual[index]) differing++;
  }
  return differing >= 4;
}

/**
 * A generated password or secret value (`lh]rswfE|7_wWyh(jL>~-ITx`): no whitespace or URL syntax, 16+ characters
 * mixing at least three character classes, two or more of them punctuation outside the base64url alphabet.
 */
const generatedPassword = (value) =>
  value.length >= 16 &&
  value.length <= 256 &&
  !/\s|:\/\//.test(value) &&
  (value.match(/[^A-Za-z0-9_-]/g) ?? []).length >= 2 &&
  [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value)).length >= 3;

/** Numeric members that measure elapsed time and are never stable. */
const durationKeys = new Set(['latencyMs', 'durationMs', 'elapsedMs', 'tookMs', 'sumSeconds']);

const msRange = (value) => Number.isFinite(value) && value >= 1e12 && value < 1e13;
const secondsRange = (value) => Number.isFinite(value) && value >= 1e9 && value < 1e10;

/** CONFORMANCE_DEBUG_BIND=<text> logs every binding whose recorded value contains <text>. */
const debugBinding =
  typeof process !== 'undefined' ? process.env.CONFORMANCE_DEBUG_BIND : undefined;

/** A binding table with child tables for trial comparisons (arrays matched out of order). */
export class Bindings {
  constructor(parent) {
    this.parent = parent;
    this.forward = new Map();
    this.backward = new Map();
    /** Records seen in outputs, by recorded `id`: kept with the table, so a failed trial pairing leaves none behind. */
    this.records = new Map();
    this.extraInstants = new Map();
    /** Instants that agreed only within the time tolerance (a cost when pairing list elements). */
    this.inexact = 0;
    this.version = 0;
  }
  /** Further replayed instants a recorded instant stood for (beyond its binding). */
  instants(recorded) {
    return [
      ...(this.parent?.instants(recorded) ?? []),
      ...(this.extraInstants.get(recorded) ?? []),
    ];
  }
  addInstant(recorded, actual) {
    const list = this.extraInstants.get(recorded) ?? [];
    if (!list.includes(actual)) list.push(actual);
    this.extraInstants.set(recorded, list);
  }
  getRecord(id) {
    if (this.records.has(id)) return this.records.get(id);
    return this.parent?.getRecord(id);
  }
  setRecord(id, pair) {
    this.records.set(id, pair);
  }
  get(recorded) {
    if (this.forward.has(recorded)) return this.forward.get(recorded);
    return this.parent?.get(recorded);
  }
  recordedFor(actual) {
    if (this.backward.has(actual)) return this.backward.get(actual);
    return this.parent?.recordedFor(actual);
  }
  set(recorded, actual) {
    if (debugBinding && String(recorded).includes(debugBinding))
      console.error(`[bind] ${recorded} -> ${actual}${this.parent ? ' (trial)' : ''}`);
    this.forward.set(recorded, actual);
    this.backward.set(actual, recorded);
    this.version++;
  }
  child() {
    return new Bindings(this);
  }
  commit() {
    for (const [recorded, actual] of this.forward) this.parent.set(recorded, actual);
    for (const [id, pair] of this.records) this.parent.setRecord(id, pair);
    this.parent.inexact += this.inexact;
    for (const [recorded, list] of this.extraInstants)
      for (const actual of list) this.parent.addInstant(recorded, actual);
  }
  get size() {
    return this.forward.size + (this.parent?.size ?? 0);
  }
  *entries() {
    if (this.parent) yield* this.parent.entries();
    yield* this.forward.entries();
  }
}

/**
 * Tries to bind a recorded string to an actual one. Returns true when they agree: equal, equal after substitution, or
 * the same skeleton with generated tokens that can be bound consistently.
 */
function bindString(recorded, actual, key, bindings, context) {
  if (bindStringOnce(recorded, actual, key, bindings, context)) return true;
  // A generated document (an invoice page, a CSV export, a list of keys) lists its rows in the order of generated IDs
  // when they tie otherwise: two multi-line texts agree when their lines do, in any order (compared as a list).
  if (context.lineMode || !recorded.includes('\n') || !actual.includes('\n')) return false;
  const recordedLines = recorded.split('\n');
  const actualLines = actual.split('\n');
  if (recordedLines.length !== actualLines.length || recordedLines.length < 3) return false;
  const child = bindings.child();
  const lineDiffs = compareValues(
    recordedLines,
    actualLines,
    child,
    { ...context, maxDiffs: 1, lineMode: true },
    '$',
    key,
    [],
  );
  if (lineDiffs.length) return false;
  child.commit();
  return true;
}

function bindStringOnce(recorded, actual, key, bindings, context) {
  const bound = bindings.get(recorded);
  if (bound !== undefined) return bound === actual;
  if (recorded === actual) {
    // Generated-looking values both runs agree on (the test's own IDs, deterministic hashes) stand for themselves.
    if (recorded.length >= 16)
      for (const token of shape(recorded).tokens)
        if (bindings.get(token) === undefined && bindings.recordedFor(token) === undefined)
          bindings.set(token, token);
    return true;
  }
  const substituted = substituteString(recorded, bindings, context);
  if (substituted === actual) return true;
  // An instant on its own (`2026-10-19T09:06:41.583Z`) follows the time rules.
  if (isoInstant.test(substituted) && isoInstant.test(actual)) {
    const agrees = timeAgrees(Date.parse(substituted), Date.parse(actual), key, context, true);
    if (agrees && substituted !== actual) bindings.inexact++;
    return agrees;
  }
  // Epoch seconds as text under a time member (a webhook's `x-better-iam-timestamp` header).
  if (
    /^1\d{9}$/.test(substituted) &&
    /^1\d{9}$/.test(actual) &&
    /time|Time|stamp|Stamp/.test(String(key))
  )
    return timeAgrees(Number(substituted) * 1000, Number(actual) * 1000, key, context, true);
  let left = shape(substituted);
  let right = shape(actual);
  if (left.skeleton !== right.skeleton) {
    // Instants embedded in the string are compared by the time rules, the rest as usual.
    const leftTimes = timeShape(left.skeleton);
    const rightTimes = timeShape(right.skeleton);
    if (
      !leftTimes.times.length ||
      leftTimes.skeleton !== rightTimes.skeleton ||
      leftTimes.times.length !== rightTimes.times.length ||
      !leftTimes.times.every((time, index) =>
        timeAgrees(timeValue(time), timeValue(rightTimes.times[index]), key, context, true),
      )
    )
      return bindByKey(recorded, actual, key, bindings);
    leftTimes.times.forEach((time, index) => {
      if (/^\d+$/.test(time))
        bindTime(Number(time), Number(rightTimes.times[index]), key, bindings);
    });
    left = { skeleton: leftTimes.skeleton, tokens: left.tokens };
    right = { skeleton: rightTimes.skeleton, tokens: right.tokens };
    if (!left.tokens.length) return left.tokens.length === right.tokens.length;
  }
  if (
    left.tokens.length &&
    left.skeleton === right.skeleton &&
    left.tokens.length === right.tokens.length
  ) {
    const pending = [];
    for (let index = 0; index < left.tokens.length; index++) {
      const r = left.tokens[index];
      const a = right.tokens[index];
      if (r === a) {
        // A value both runs agree on (one the test made up, a deterministic hash) stands for itself from now on.
        if (bindings.get(r) === undefined && bindings.recordedFor(r) === undefined)
          pending.push([r, r]);
        continue;
      }
      const existing = bindings.get(r);
      if (existing !== undefined) {
        if (existing !== a) return false;
        continue;
      }
      const owner = bindings.recordedFor(a);
      if (owner !== undefined && owner !== r) return false;
      pending.push([r, a]);
    }
    for (const [r, a] of pending) bindings.set(r, a);
    return true;
  }
  return bindByKey(recorded, actual, key, bindings);
}

/**
 * A wall-clock instant that agreed within the tolerance is bound too, so a test that passes it back (`until: event
 * .timestamp`, a record it read and writes back) sends the instant the server under test produced.
 */
function bindTime(recorded, actual, key, bindings) {
  if (durationKeys.has(key) || !msRange(recorded) || !msRange(actual)) return;
  const bound = bindings.get(recorded);
  if (bound === undefined) bindings.set(recorded, actual);
  // Several events of one recorded millisecond took different instants in the replay.
  else if (bound !== actual) bindings.addInstant(recorded, actual);
}

/** Short generated values recognized by their member name (one-time codes, reference numbers). */
function bindByKey(recorded, actual, key, bindings) {
  if (
    (isVolatileKey(key) && codeLike(recorded) && codeLike(actual)) ||
    (isVolatileKey(key) && sameLayout(recorded, actual)) ||
    (typeof key === 'string' &&
      /(^|[a-z_])(value|Value|password|Password|secret|Secret)$/.test(key) &&
      recorded.length === actual.length &&
      generatedPassword(recorded) &&
      generatedPassword(actual)) ||
    (typeof key === 'string' &&
      referenceKeyPattern.test(key) &&
      (randomCode(recorded) || randomCode(actual)) &&
      recorded.length === actual.length &&
      // The same layout: separators and the letters around the random run stay put (`DSR-` + 8 characters).
      recorded.replace(/[A-Za-z0-9]/g, '') === actual.replace(/[A-Za-z0-9]/g, '') &&
      recorded.split(/[^A-Za-z0-9]/)[0].length === actual.split(/[^A-Za-z0-9]/)[0].length)
  ) {
    const owner = bindings.recordedFor(actual);
    if (owner !== undefined && owner !== recorded) return false;
    bindings.set(recorded, actual);
    return true;
  }
  return false;
}

/**
 * Time values. Without a controlled clock every instant is wall-clock time, which the replay drives too (`wall`), so
 * two agree within the tolerance (any two, for traces recorded without wall times). With one, an instant the
 * server derived from the injected clock (a whole number of seconds away from the step's clock value) must be exact;
 * one it read from the wall clock (`Date.now()`) may differ by a little (the conformance wall clock moves on from the
 * set time) or by the time between recording and replay.
 */
function timeAgrees(recorded, actual, key, context, instant = false) {
  if (durationKeys.has(key)) return true;
  if (!Number.isFinite(recorded) || !Number.isFinite(actual)) return false;
  const drift = context.wallDriftMs ?? 0;
  const tolerance = context.timeToleranceMs ?? 30_000;
  const wall = (delta) => Math.abs(delta) <= tolerance || Math.abs(delta - drift) <= tolerance;
  const clockDerived = (value) =>
    context.stepAt !== undefined && (value - context.stepAt) % 1000 === 0;
  if ((msRange(recorded) && msRange(actual)) || instant) {
    if (!context.clockControlled) return context.wallReplayed ? wall(actual - recorded) : true;
    if (recorded === actual) return true;
    if (clockDerived(recorded)) return false;
    return wall(actual - recorded);
  }
  if (
    secondsRange(recorded) &&
    secondsRange(actual) &&
    /^(exp|iat|nbf|auth_time|iat_.*|validAfter|validBefore)$/.test(String(key))
  ) {
    if (!context.clockControlled)
      return context.wallReplayed ? wall((actual - recorded) * 1000) : true;
    if (recorded === actual) return true;
    return wall((actual - recorded) * 1000);
  }
  return false;
}

const preview = (value) => {
  let text;
  try {
    text = typeof value === 'string' ? JSON.stringify(value) : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text === undefined) text = 'undefined';
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
};

const typeOf = (value) => (value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value);

/**
 * Compares a recorded value with the actual one, binding generated values. Appends `{ path, problem, recorded,
 * actual }` entries to `diffs`; an empty list means they agree.
 */
export function compareValues(
  recorded,
  actual,
  bindings,
  context,
  path = '$',
  key = '',
  diffs = [],
) {
  const limit = context.maxDiffs ?? 20;
  if (diffs.length >= limit) return diffs;
  // Tolerated paths (tolerances.json) are not compared at all, so they cannot block matching either.
  if (context.ignore?.length) {
    const normalized = path.replace(/\[\d+\]/g, '[*]');
    if (context.ignore.some((pattern) => pattern.test(normalized))) {
      context.tolerated = (context.tolerated ?? 0) + 1;
      return diffs;
    }
  }
  const fail = (problem) =>
    diffs.push({ path, problem, recorded: preview(recorded), actual: preview(actual) });
  const rt = typeOf(recorded);
  const at = typeOf(actual);
  if (rt !== at) {
    // A bound numeric string vs number is never equal; report the type change.
    fail(`type ${rt} != ${at}`);
    return diffs;
  }
  switch (rt) {
    case 'string':
      if (!bindString(recorded, actual, key, bindings, context)) fail('value differs');
      return diffs;
    case 'number':
      if (recorded !== actual) {
        if (!timeAgrees(recorded, actual, key, context)) fail('value differs');
        else {
          // Agreeing only within the tolerance makes a pairing less likely than an exact one.
          if (!durationKeys.has(key)) bindings.inexact++;
          bindTime(recorded, actual, key, bindings);
        }
      }
      return diffs;
    case 'boolean':
    case 'null':
    case 'undefined':
      if (recorded !== actual) fail('value differs');
      return diffs;
    case 'array':
      compareArrays(recorded, actual, bindings, context, path, key, diffs);
      return diffs;
    case 'object':
      compareObjects(recorded, actual, bindings, context, path, diffs);
      return diffs;
    default:
      if (recorded !== actual) fail('value differs');
      return diffs;
  }
}

function trial(recorded, actual, bindings, context, path, key) {
  const child = bindings.child();
  const diffs = compareValues(recorded, actual, child, { ...context, maxDiffs: 1 }, path, key, []);
  return diffs.length ? undefined : child;
}

/** Bindings a trial table adds that are not identities. */
const newBindings = (table) => {
  let count = table.inexact;
  for (const [recorded, actual] of table.forward) if (recorded !== actual) count++;
  return count;
};

const chainKeys = new Set(['sequence', 'hash', 'previousHash']);

function compareArrays(recorded, actual, bindings, context, path, key, diffs) {
  if (recorded.length !== actual.length) {
    diffs.push({
      path,
      problem: `length ${recorded.length} != ${actual.length}`,
      recorded: preview(recorded),
      actual: preview(actual),
    });
    return;
  }
  // In order first: the common case, and the only one for arrays of scalars that repeat.
  const whole = bindings.child();
  const quiet = { ...context, maxDiffs: 1 };
  const inOrder = recorded.every(
    (item, index) =>
      !compareValues(item, actual[index], whole, quiet, `${path}[${index}]`, key, []).length,
  );
  // Out of order: lists sorted by generated IDs (or delivered in parallel) come back in another order. Each recorded
  // element takes the first unused actual element it agrees with, trying its own position first.
  // For lists of a manageable size every candidate is tried and the one that needs the fewest new bindings wins: the
  // right partner shares the values both runs agree on (a test's own IDs, deterministic hashes), where a wrong one of
  // the same shape would bind them to something else.
  const exhaustive = recorded.length <= 200;
  const greedy = (ctx) => {
    const table = bindings.child();
    const taken = new Set();
    for (let index = 0; index < recorded.length; index++) {
      let best;
      let bestCandidate = -1;
      for (const candidate of [index, ...actual.keys()]) {
        if (taken.has(candidate)) continue;
        const child = trial(
          recorded[index],
          actual[candidate],
          table,
          ctx,
          `${path}[${index}]`,
          key,
        );
        if (!child) continue;
        const cost = newBindings(child);
        if (!best || cost < best.cost) {
          best = { child, cost };
          bestCandidate = candidate;
        }
        if (!exhaustive || best.cost === 0) break;
      }
      if (!best) return undefined;
      best.child.commit();
      taken.add(bestCandidate);
    }
    return table;
  };
  if (inOrder) {
    // In order agrees, but maybe only by binding values both runs share to each other (two records of the same shape
    // in swapped order): a short list of records is also paired by fewest new bindings, and the cheaper pairing wins.
    const records =
      recorded.length <= 50 && recorded.some((item) => item && typeof item === 'object');
    const cost = newBindings(whole);
    const alternative = records && cost > 0 ? greedy(context) : undefined;
    if (alternative && newBindings(alternative) < cost) alternative.commit();
    else whole.commit();
    return;
  }
  const matched = greedy(context);
  if (matched) {
    matched.commit();
    return;
  }
  // Audit events appended in an order that follows generated IDs (or concurrent writers): the same events at other
  // positions of the hash chain. Their chain members are then not compared; `audit/verify` steps check the chain.
  const chained = (list) =>
    list.every(
      (item) =>
        item &&
        typeof item === 'object' &&
        typeof item.sequence === 'number' &&
        typeof item.hash === 'string',
    );
  if (chained(recorded) && chained(actual)) {
    const relaxed = greedy({ ...context, ignoreKeys: chainKeys });
    if (relaxed) {
      relaxed.commit();
      return;
    }
  }
  const used = new Set();
  const order = [];
  for (let index = 0; index < recorded.length; index++) {
    let matched = -1;
    const candidates = [index, ...actual.keys()].filter(
      (candidate, at, all) => all.indexOf(candidate) === at,
    );
    for (const candidate of candidates) {
      if (used.has(candidate)) continue;
      const child = trial(
        recorded[index],
        actual[candidate],
        bindings,
        context,
        `${path}[${index}]`,
        key,
      );
      if (child) {
        child.commit();
        matched = candidate;
        break;
      }
    }
    if (matched < 0) {
      // Report the difference against the closest unused element (fewest differences), for a readable diff.
      let fallback = used.has(index) ? actual.findIndex((_, at) => !used.has(at)) : index;
      let fewest = Infinity;
      for (const candidate of candidates) {
        if (used.has(candidate)) continue;
        const count = compareValues(
          recorded[index],
          actual[candidate],
          bindings.child(),
          { ...context, maxDiffs: 50 },
          `${path}[${index}]`,
          key,
          [],
        ).length;
        if (count < fewest) {
          fewest = count;
          fallback = candidate;
        }
      }
      compareValues(
        recorded[index],
        actual[fallback],
        bindings,
        context,
        `${path}[${index}]`,
        key,
        diffs,
      );
      used.add(fallback);
      order.push(fallback);
      if (diffs.length >= (context.maxDiffs ?? 20)) return;
      continue;
    }
    used.add(matched);
    order.push(matched);
  }
}

function compareObjects(recorded, actual, bindings, context, path, diffs) {
  // Records (objects with an `id`) seen in outputs: a test that writes one back sends the actual record's values.
  if (
    typeof recorded.id === 'string' &&
    typeof actual.id === 'string' &&
    shape(recorded.id).tokens.length
  )
    bindings.setRecord(recorded.id, { recorded, actual });
  const actualKeys = new Set(Object.keys(actual));
  const unmatched = [];
  for (const key of Object.keys(recorded)) {
    if (context.ignoreKeys?.has(key)) {
      actualKeys.delete(key);
      continue;
    }
    const mapped = actualKeys.has(key)
      ? key
      : (bindings.get(key) ?? substituteString(key, bindings, context));
    if (actualKeys.has(mapped)) {
      actualKeys.delete(mapped);
      compareValues(recorded[key], actual[mapped], bindings, context, `${path}.${key}`, key, diffs);
    } else unmatched.push(key);
  }
  if (!unmatched.length && !actualKeys.size) return;
  // Maps keyed by generated values: pair the remaining keys by their values.
  const extra = [...actualKeys];
  if (unmatched.length === extra.length && unmatched.every((key) => shape(key).tokens.length)) {
    const left = [...unmatched];
    for (const key of left) {
      const index = extra.findIndex((candidate) => {
        const child = bindings.child();
        if (!bindString(key, candidate, key, child, context)) return false;
        const inner = compareValues(
          recorded[key],
          actual[candidate],
          child,
          { ...context, maxDiffs: 1 },
          `${path}.${key}`,
          key,
          [],
        );
        if (inner.length) return false;
        child.commit();
        return true;
      });
      if (index >= 0) {
        extra.splice(index, 1);
        unmatched.splice(unmatched.indexOf(key), 1);
      }
    }
  }
  for (const key of unmatched)
    diffs.push({
      path: `${path}.${key}`,
      problem: 'missing',
      recorded: preview(recorded[key]),
      actual: 'absent',
    });
  for (const key of extra)
    diffs.push({
      path: `${path}.${key}`,
      problem: 'unexpected member',
      recorded: 'absent',
      actual: preview(actual[key]),
    });
}

// --- Substitution -------------------------------------------------------------------------------------------------------

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Replaces bound values inside a string: the whole string when bound, else every bound run of 12+ characters. */
export function substituteString(text, bindings, context = {}) {
  const whole = bindings.get(text);
  if (whole !== undefined && typeof whole === 'string') return whole;
  if (text.length < 12) return text;
  const layers = [];
  let root = bindings;
  while (root.parent) {
    layers.push(root);
    root = root.parent;
  }
  // One compiled pattern for the trace's table; trial tables (a few entries) are applied directly.
  const cache = (context.substitutionCache ??= {});
  if (cache.root !== root || cache.version !== root.version) {
    const map = new Map();
    for (const [recorded, actual] of root.forward)
      if (
        typeof recorded === 'string' &&
        typeof actual === 'string' &&
        recorded.length >= 12 &&
        recorded !== actual
      )
        map.set(recorded, actual);
    const keys = [...map.keys()].sort((a, b) => b.length - a.length);
    cache.pattern = keys.length ? new RegExp(keys.map(escape).join('|'), 'g') : undefined;
    cache.map = map;
    cache.root = root;
    cache.version = root.version;
  }
  let out = cache.pattern
    ? text.replace(cache.pattern, (match) => cache.map.get(match) ?? match)
    : text;
  for (const layer of layers.reverse())
    for (const [recorded, actual] of layer.forward)
      if (
        typeof recorded === 'string' &&
        typeof actual === 'string' &&
        recorded.length >= 12 &&
        out.includes(recorded)
      )
        out = out.split(recorded).join(actual);
  return out;
}

/** Substitutes bindings throughout an input value (strings, object keys, nested values). */
export function substitute(value, bindings, context = {}, key = '') {
  if (typeof value === 'string') return substituteString(value, bindings, context);
  if (typeof value === 'number' && msRange(value)) {
    const bound = bindings.get(value);
    if (typeof bound !== 'number') return value;
    // A recorded instant that several replayed instants stand for: an upper bound (`until`) takes the latest, a
    // lower bound (`since`) the earliest, so a range keeps covering the same events.
    const all = [bound, ...bindings.instants(value)];
    if (all.length > 1 && /^(until|to|before|end)/i.test(String(key))) return Math.max(...all);
    if (all.length > 1 && /^(since|from|after|start)/i.test(String(key))) return Math.min(...all);
    return bound;
  }
  if (Array.isArray(value)) return value.map((item) => substitute(item, bindings, context, key));
  if (value && typeof value === 'object') {
    // A record the test read and passes back: members it left as they were take the actual record's values.
    const seen = typeof value.id === 'string' ? bindings.getRecord(value.id) : undefined;
    // A range whose bounds are the same recorded instant (`{ since: t, until: t }`) keeps them equal.
    const bounds = Object.entries(value).filter(
      ([key, item]) =>
        typeof item === 'number' && /^(until|to|before|end|since|from|after|start)/i.test(key),
    );
    const sameBounds = bounds.length > 1 && bounds.every(([, item]) => item === bounds[0][1]);
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      const name = substituteString(key, bindings, context);
      const role = sameBounds && bounds.some(([bound]) => bound === key) ? '' : key;
      out[name] =
        seen &&
        Object.hasOwn(seen.recorded, key) &&
        Object.hasOwn(seen.actual, key) &&
        sameJson(item, seen.recorded[key])
          ? structuredClone(seen.actual[key])
          : substitute(item, bindings, context, role);
    }
    return out;
  }
  return value;
}

const sameJson = (left, right) => {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
};

/** Sets `value` at `path` inside `target` (paths come from the recorder's `derive` entries). */
export function setPath(target, path, value) {
  if (!path.length) return value;
  let node = target;
  for (const part of path.slice(0, -1)) {
    if (!node || typeof node !== 'object') return target;
    node = node[part];
  }
  if (node && typeof node === 'object') node[path[path.length - 1]] = value;
  return target;
}

export function getPath(target, path) {
  let node = target;
  for (const part of path) {
    if (!node || typeof node !== 'object') return undefined;
    node = node[part];
  }
  return node;
}
