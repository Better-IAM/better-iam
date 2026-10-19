// The standalone server configuration (`better-iam.json`, spec/conformance/CONFIG.md) in both directions:
//
// - `configFromOptions(options)` turns in-process `BetterIamOptions` (as a test passed them to `betterIam()`) into the
//   JSON configuration plus the reasons it cannot be expressed exactly. The trace recorder uses it.
// - `optionsFromConfig(config, runtime)` turns a JSON configuration back into `BetterIamOptions` for the TypeScript
//   server. scripts/conformance/serve.mjs uses it. Rust and Go implement the same mapping natively.

/** Top-level configuration members, in the order CONFIG.md documents them. */
export const configKeys = [
  '$schema',
  'store',
  'secret',
  'previousSecrets',
  'baseURL',
  'basePath',
  'trustedOrigins',
  'authentication',
  'delivery',
  'resolveResource',
  'resolveContext',
  'hierarchy',
  'permissions',
  'onboarding',
  'events',
  'accessRequests',
  'observability',
  'accessUsage',
  'inference',
  'a2a',
  'billing',
  'ssh',
  'verifiableCredentials',
  'clearances',
  'vault',
  'http',
  'tenantDefaults',
  'domains',
  'hosts',
  'regions',
  'sts',
  'signals',
  'auditArchive',
];

/** `BetterIamOptions` members whose value is copied as JSON (the function-valued parts are handled below). */
const jsonOptionKeys = [
  'secret',
  'previousSecrets',
  'baseURL',
  'basePath',
  'trustedOrigins',
  'hierarchy',
  'permissions',
  'onboarding',
  'accessRequests',
  'accessUsage',
  'inference',
  'a2a',
  'billing',
  'ssh',
  'verifiableCredentials',
  'clearances',
  'tenantDefaults',
  'hosts',
  'signals',
];

const isPlainObject = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

/** A function's source with all whitespace removed, for recognizing the few callbacks that have JSON equivalents. */
const compact = (fn) => {
  try {
    return Function.prototype.toString.call(fn).replace(/\s+/g, '');
  } catch {
    return '';
  }
};

/** `async (reference) => reference` and its spellings: the resolver that trusts the reference as given. */
export function isEchoResolver(fn) {
  const source = compact(fn);
  const match =
    /^(?:async)?\(?([A-Za-z_$][\w$]*)\)?=>\(?\1\)?;?$/.exec(source) ??
    /^(?:async)?\(?([A-Za-z_$][\w$]*)\)?=>\({\.\.\.\1}\)$/.exec(source) ??
    /^(?:async)?\(?([A-Za-z_$][\w$]*)\)?=>Promise\.resolve\(\1\)$/.exec(source) ??
    /^(?:async)?(?:function)?[\w$]*\(([A-Za-z_$][\w$]*)\){return\1;?}$/.exec(source);
  return Boolean(match);
}

/**
 * The application callbacks a conformance server answers from the recording (`{"$scripted": true}`, CONTROL.md
 * "Script"): each is called with JSON-representable arguments and returns JSON-representable values, so the replay can
 * hand the server the answers the recorded callback gave. Paths are option paths without the leading `options.`.
 */
export const scriptablePaths = [
  /^resolveResource$/,
  /^resolveContext$/,
  /^authentication\.requireMfa$/,
  /^authentication\.passwordPolicy\.(?:isBreached|check)$/,
  /^domains\.resolveTxt$/,
  /^regions\.locate$/,
  /^sts\.webIdentity\.fetchJson$/,
  /^vault\.rotators\.[^.]+\.rotate$/,
  /^vault\.engines\.[^.]+\.(?:issue|revoke|renew)$/,
  /^auditArchive\.write$/,
];
export const isScriptable = (path) => scriptablePaths.some((pattern) => pattern.test(path));
const optionPath = (path) => path.replace(/^options\./, '');

/**
 * Copies a JSON-representable value; functions and class instances are reported with their path and left out.
 * Returns undefined for a value that is entirely non-JSON. A function at a scriptable path becomes
 * `{"$scripted": true}` and its path is added to `scripted` (when given).
 */
function jsonCopy(value, path, problems, scripted) {
  if (value === undefined) return undefined;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) problems.push(`${path} is not a finite number`);
    return value;
  }
  if (typeof value === 'function') {
    if (scripted && isScriptable(optionPath(path))) {
      scripted.push(optionPath(path));
      return { $scripted: true };
    }
    problems.push(`${path} is a function`);
    return undefined;
  }
  if (typeof value !== 'object') {
    problems.push(`${path} is a ${typeof value}`);
    return undefined;
  }
  if (Array.isArray(value))
    return value.map((item, index) => {
      const copied = jsonCopy(item, `${path}[${index}]`, problems, scripted);
      return copied === undefined ? null : copied;
    });
  if (!isPlainObject(value)) {
    problems.push(`${path} is a ${value.constructor?.name ?? 'non-plain'} object`);
    return undefined;
  }
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    const copied = jsonCopy(item, `${path}.${key}`, problems, scripted);
    if (copied !== undefined) out[key] = copied;
  }
  return out;
}

/**
 * The JSON configuration equivalent to `options`.
 *
 * - `reasons`: members the JSON format cannot express (the trace is then not replayable).
 * - `dropped`: observational callbacks left out because they cannot change the server's behavior unless they throw
 *   (`observability.onSpan`); the recorder marks the trace if one ever throws. `events.onEvent` becomes the `events` channel.
 * - `clock`: true when `authentication.now` was injected (the replay drives the server clock).
 * - `scripted`: the option paths of callbacks written as `{"$scripted": true}` (the recorder records their calls).
 */
export function configFromOptions(options) {
  const reasons = [];
  const dropped = [];
  const scripted = [];
  const config = {
    store: { kind: 'sqlite', path: ':memory:' },
  };
  if (!isPlainObject(options))
    return { config, reasons: ['options is not an object'], dropped, clock: false, scripted };
  for (const key of Object.keys(options))
    if (
      ![
        ...jsonOptionKeys,
        'database',
        'authentication',
        'events',
        'observability',
        'vault',
        'http',
        'domains',
        'regions',
        'sts',
        'resolveResource',
        'resolveContext',
        'plugins',
        'protocols',
        'auditArchive',
      ].includes(key)
    )
      reasons.push(`options.${key} is not a known option`);
  for (const key of jsonOptionKeys) {
    if (options[key] === undefined) continue;
    const problems = [];
    const copied = jsonCopy(options[key], `options.${key}`, problems);
    reasons.push(...problems);
    if (copied !== undefined) config[key] = copied;
  }
  let clock = false;
  if (options.authentication !== undefined) {
    const { sendEmail, sendSms, deliverWebhook, now, ...rest } = options.authentication ?? {};
    if (typeof now === 'function') clock = true;
    else if (now !== undefined) reasons.push('options.authentication.now is not a function');
    if (deliverWebhook !== undefined) reasons.push('options.authentication.deliverWebhook is set');
    const problems = [];
    const copied = jsonCopy(rest, 'options.authentication', problems, scripted);
    reasons.push(...problems);
    if (copied && Object.keys(copied).length) config.authentication = copied;
    const delivery = {};
    if (typeof sendEmail === 'function') delivery.email = { kind: 'capture' };
    else if (sendEmail !== undefined)
      reasons.push('options.authentication.sendEmail is not a function');
    if (typeof sendSms === 'function') delivery.sms = { kind: 'capture' };
    else if (sendSms !== undefined)
      reasons.push('options.authentication.sendSms is not a function');
    if (Object.keys(delivery).length) config.delivery = delivery;
  }
  if (options.events !== undefined) {
    const { onEvent, deliverWebhook, ...rest } = options.events ?? {};
    if (typeof onEvent === 'function')
      config.delivery = { ...config.delivery, events: { kind: 'capture' } };
    if (typeof deliverWebhook === 'function')
      config.delivery = { ...config.delivery, webhook: { kind: 'capture' } };
    const problems = [];
    const copied = jsonCopy(rest, 'options.events', problems);
    reasons.push(...problems);
    if (copied && Object.keys(copied).length) config.events = copied;
  }
  if (options.observability !== undefined) {
    const { onSpan, ...rest } = options.observability ?? {};
    if (typeof onSpan === 'function') dropped.push('observability.onSpan');
    const problems = [];
    const copied = jsonCopy(rest, 'options.observability', problems);
    reasons.push(...problems);
    if (copied && Object.keys(copied).length) config.observability = copied;
  }
  for (const key of ['vault', 'http', 'domains', 'regions', 'sts', 'auditArchive']) {
    if (options[key] === undefined) continue;
    const problems = [];
    let value = options[key];
    // A clientInfo function that only copies request headers has a JSON form.
    if (key === 'http' && isPlainObject(value) && typeof value.clientInfo === 'function') {
      const inferred = inferClientInfo(value.clientInfo);
      if (inferred) value = { ...value, clientInfo: inferred };
    }
    const copied = jsonCopy(value, `options.${key}`, problems, scripted);
    reasons.push(...problems);
    if (copied !== undefined) config[key] = copied;
  }
  if (options.resolveResource !== undefined) {
    if (isEchoResolver(options.resolveResource)) config.resolveResource = { kind: 'echo' };
    else if (typeof options.resolveResource === 'function') {
      config.resolveResource = { $scripted: true };
      scripted.push('resolveResource');
    } else reasons.push('options.resolveResource is not a function');
  }
  if (options.resolveContext !== undefined) {
    if (typeof options.resolveContext === 'function') {
      config.resolveContext = { $scripted: true };
      scripted.push('resolveContext');
    } else reasons.push('options.resolveContext is not a function');
  }
  if (options.plugins !== undefined && (!Array.isArray(options.plugins) || options.plugins.length))
    reasons.push('options.plugins is set');
  if (
    options.protocols !== undefined &&
    (!Array.isArray(options.protocols) || options.protocols.length)
  )
    reasons.push('options.protocols is set');

  if (!options.database) reasons.push('options.database is missing');
  return { config, reasons, dropped, clock, scripted };
}

/**
 * The `http.clientInfo(request)` function of the JSON form `{ userAgent?, ipHeader?, labelHeader?, ipValue? }`: the
 * User-Agent (unless `userAgent` is false), the client IP from `ipHeader` (its first comma-separated entry, trimmed,
 * or with `ipValue: "whole"` the header as sent) and the device label from `labelHeader`; no client when none is
 * present.
 */
export function clientInfoFunction({ userAgent = true, ipHeader, labelHeader, ipValue = 'first' }) {
  return (request) => {
    const info = {};
    if (ipHeader) {
      const header = request.headers.get(ipHeader);
      const ip = ipValue === 'whole' ? header : header?.split(',')[0]?.trim();
      if (ip) info.ip = ip;
    }
    if (userAgent) {
      const agent = request.headers.get('user-agent');
      if (agent) info.userAgent = agent;
    }
    if (labelHeader) {
      const label = request.headers.get(labelHeader);
      if (label) info.label = label;
    }
    return Object.keys(info).length ? info : undefined;
  };
}

/**
 * The JSON form of a test's `http.clientInfo` function, when it only copies request headers into the client: the
 * headers are read from its source (`ip: request.headers.get('x-real-ip')`) and the result is checked against the
 * function on probe requests (every combination of those headers, with a comma-separated IP). An empty client and
 * none count as the same (the server treats them alike). Undefined when the function does anything else.
 */
export function inferClientInfo(fn) {
  const source = (() => {
    try {
      return Function.prototype.toString.call(fn);
    } catch {
      return '';
    }
  })();
  const read = {};
  for (const match of source.matchAll(
    /(ip|userAgent|label)\s*:\s*[A-Za-z_$][\w$]*\.headers\.get\(\s*['"]([^'"]+)['"]\s*\)/g,
  ))
    read[match[1]] = match[2].toLowerCase();
  for (const match of source.matchAll(
    /const\s+(ip|userAgent|label)\s*=\s*[A-Za-z_$][\w$]*\.headers\.get\(\s*['"]([^'"]+)['"]\s*\)/g,
  ))
    read[match[1]] ??= match[2].toLowerCase();
  if (read.userAgent !== undefined && read.userAgent !== 'user-agent') return undefined;
  const headers = [read.ip, read.userAgent, read.label].filter(Boolean);
  const normalize = (value) => {
    if (!value || typeof value !== 'object') return undefined;
    const out = {};
    for (const [key, item] of Object.entries(value)) if (item !== undefined) out[key] = item;
    return Object.keys(out).length ? JSON.stringify(out) : undefined;
  };
  for (const ipValue of ['first', 'whole']) {
    const spec = {
      userAgent: Boolean(read.userAgent),
      ...(read.ip ? { ipHeader: read.ip } : {}),
      ...(read.label ? { labelHeader: read.label } : {}),
      ...(ipValue === 'whole' ? { ipValue } : {}),
    };
    const expected = clientInfoFunction(spec);
    let agrees = true;
    for (let mask = 0; mask < 1 << (headers.length + 1) && agrees; mask++) {
      const probe = new Headers();
      // The last bit probes a request with every header the function does not read, which it must ignore.
      if (mask & (1 << headers.length)) {
        probe.set('user-agent', read.userAgent ? 'probe-agent' : 'ignored-agent');
        probe.set('x-forwarded-for', '192.0.2.250');
        probe.set('x-real-ip', read.ip === 'x-real-ip' ? '192.0.2.251' : '192.0.2.252');
      }
      headers.forEach((name, index) => {
        if (mask & (1 << index))
          probe.set(name, name === read.ip ? ' 192.0.2.1 , 198.51.100.2' : `probe-${name}`);
      });
      let actual;
      try {
        actual = fn(new Request('http://probe.invalid/', { headers: probe }));
      } catch {
        return undefined;
      }
      if (actual && typeof actual.then === 'function') return undefined;
      if (
        normalize(actual) !==
        normalize(expected(new Request('http://probe.invalid/', { headers: probe })))
      )
        agrees = false;
    }
    if (agrees) return spec;
  }
  return undefined;
}

const invalid = (message) => {
  const error = new Error(`Invalid better-iam.json: ${message}`);
  error.name = 'IamError';
  error.code = 'INVALID_CONFIG';
  error.status = 400;
  return error;
};

function secretValue(value, path, env) {
  if (typeof value === 'string') return value;
  if (isPlainObject(value) && typeof value.env === 'string') {
    const resolved = env[value.env];
    if (typeof resolved !== 'string' || !resolved)
      throw invalid(`${path} names environment variable ${value.env}, which is not set`);
    return resolved;
  }
  throw invalid(`${path} must be a string or { "env": "NAME" }`);
}

/**
 * `BetterIamOptions` for a JSON configuration.
 *
 * `runtime` supplies what JSON cannot: `adapters` ({ sqliteAdapter, postgresAdapter?, libsqlAdapter? }), `now` (the
 * server clock), `deliver(kind, message)` for `capture` deliveries, `log` for `log` deliveries, and `env`.
 */
export async function optionsFromConfig(config, runtime) {
  const env = runtime.env ?? process.env;
  if (!isPlainObject(config)) throw invalid('the configuration must be a JSON object');
  for (const key of Object.keys(config))
    if (!configKeys.includes(key)) throw invalid(`unknown member "${key}"`);
  const store = config.store ?? { kind: 'sqlite', path: ':memory:' };
  if (!isPlainObject(store)) throw invalid('store must be an object');
  let database;
  switch (store.kind) {
    case 'sqlite':
      database = runtime.adapters.sqliteAdapter({
        filename: store.path ?? ':memory:',
        ...(store.journalMode !== undefined ? { journalMode: store.journalMode } : {}),
        ...(store.durability !== undefined ? { durability: store.durability } : {}),
        ...(store.busyTimeoutMs !== undefined ? { busyTimeoutMs: store.busyTimeoutMs } : {}),
      });
      break;
    case 'postgres': {
      if (!runtime.adapters.postgresAdapter) throw invalid('the postgres adapter is not available');
      database = runtime.adapters.postgresAdapter({
        connectionString: secretValue(store.url, 'store.url', env),
        ...(store.poolSize !== undefined ? { poolSize: store.poolSize } : {}),
        ...(store.lockTimeoutMs !== undefined ? { lockTimeoutMs: store.lockTimeoutMs } : {}),
      });
      break;
    }
    case 'libsql': {
      if (!runtime.adapters.libsqlAdapter) throw invalid('the libsql adapter is not available');
      database = runtime.adapters.libsqlAdapter({
        url: secretValue(store.url, 'store.url', env),
        ...(store.authToken !== undefined
          ? { authToken: secretValue(store.authToken, 'store.authToken', env) }
          : {}),
        ...(store.encryptionKey !== undefined
          ? { encryptionKey: secretValue(store.encryptionKey, 'store.encryptionKey', env) }
          : {}),
        ...(store.syncUrl !== undefined ? { syncUrl: store.syncUrl } : {}),
        ...(store.syncInterval !== undefined ? { syncInterval: store.syncInterval } : {}),
      });
      break;
    }
    default:
      throw invalid('store.kind must be sqlite, postgres or libsql');
  }
  const options = { database };
  for (const key of jsonOptionKeys)
    if (config[key] !== undefined) options[key] = structuredClone(config[key]);
  if (config.secret === undefined) throw invalid('secret is required');
  options.secret = secretValue(config.secret, 'secret', env);
  if (config.previousSecrets !== undefined) {
    if (!Array.isArray(config.previousSecrets)) throw invalid('previousSecrets must be an array');
    options.previousSecrets = config.previousSecrets.map((item, index) =>
      secretValue(item, `previousSecrets[${index}]`, env),
    );
  }
  if (typeof config.baseURL !== 'string') throw invalid('baseURL is required');
  for (const key of ['vault', 'domains', 'regions', 'sts', 'auditArchive'])
    if (config[key] !== undefined) options[key] = structuredClone(config[key]);
  options.authentication = config.authentication ? structuredClone(config.authentication) : {};
  if (runtime.now) options.authentication.now = runtime.now;
  const delivery = config.delivery ?? {};
  if (!isPlainObject(delivery)) throw invalid('delivery must be an object');
  for (const key of Object.keys(delivery))
    if (!['email', 'sms', 'webhook', 'events'].includes(key))
      throw invalid(`delivery.${key} is not a channel`);
  const transport = (kind) => {
    const spec = delivery[kind];
    if (spec === undefined) return undefined;
    if (!isPlainObject(spec)) throw invalid(`delivery.${kind} must be an object`);
    switch (spec.kind) {
      case 'capture':
        if (!runtime.deliver)
          throw invalid(`delivery.${kind} "capture" needs the server's conformance mode`);
        return async (message) => runtime.deliver(kind, message);
      case 'log':
        return async (message) =>
          (runtime.log ?? console.log)(JSON.stringify({ delivery: kind, message }));
      case 'http': {
        if (typeof spec.url !== 'string') throw invalid(`delivery.${kind}.url is required`);
        const headers = { 'content-type': 'application/json', ...(spec.headers ?? {}) };
        return async (message) => {
          const response = await fetch(spec.url, {
            method: 'POST',
            headers,
            body: JSON.stringify({ kind, message }),
            signal: AbortSignal.timeout(spec.timeoutMs ?? 10_000),
          });
          if (!response.ok) throw new Error(`delivery endpoint answered ${response.status}`);
        };
      }
      default:
        throw invalid(`delivery.${kind}.kind must be capture, log or http`);
    }
  };
  const sendEmail = transport('email');
  const sendSms = transport('sms');
  const deliverWebhook = transport('webhook');
  const onEvent = transport('events');
  if (sendEmail) options.authentication.sendEmail = sendEmail;
  if (sendSms) options.authentication.sendSms = sendSms;
  if (config.events !== undefined || deliverWebhook || onEvent) {
    options.events = structuredClone(config.events ?? {});
    if (deliverWebhook) options.events.deliverWebhook = deliverWebhook;
    if (onEvent) options.events.onEvent = onEvent;
  }
  if (config.observability !== undefined)
    options.observability = structuredClone(config.observability);
  if (config.http !== undefined) {
    const { clientInfo, ...rest } = config.http;
    options.http = structuredClone(rest);
    if (clientInfo !== undefined) {
      if (!isPlainObject(clientInfo)) throw invalid('http.clientInfo must be an object');
      if (clientInfo.ipValue !== undefined && !['first', 'whole'].includes(clientInfo.ipValue))
        throw invalid('http.clientInfo.ipValue must be "first" or "whole"');
      options.http.clientInfo = clientInfoFunction(clientInfo);
    }
  }
  if (config.resolveResource !== undefined) {
    if (isScriptedMarker(config.resolveResource)) options.resolveResource = config.resolveResource;
    else if (!isPlainObject(config.resolveResource) || config.resolveResource.kind !== 'echo')
      throw invalid('resolveResource.kind must be "echo"');
    else options.resolveResource = async (reference) => reference;
  }
  if (config.resolveContext !== undefined) {
    if (!isScriptedMarker(config.resolveContext))
      throw invalid('resolveContext has no JSON form other than {"$scripted": true}');
    options.resolveContext = config.resolveContext;
  }
  const { database: _database, ...rest } = options;
  return { ...injectScripted(rest, '', runtime), database };
}

const isScriptedMarker = (value) =>
  isPlainObject(value) && value.$scripted === true && Object.keys(value).length === 1;

/** Replaces every `{"$scripted": true}` with the conformance server's scripted callback for that option path. */
function injectScripted(value, path, runtime) {
  if (isScriptedMarker(value)) {
    if (!isScriptable(path)) throw invalid(`${path} cannot be scripted`);
    if (!runtime.scripted)
      throw invalid(`${path} is scripted, which needs the server's conformance mode`);
    return runtime.scripted(path);
  }
  if (Array.isArray(value))
    return value.map((item, index) => injectScripted(item, `${path}[${index}]`, runtime));
  if (!isPlainObject(value)) return value;
  const out = {};
  for (const [key, item] of Object.entries(value))
    out[key] = injectScripted(item, path ? `${path}.${key}` : key, runtime);
  return out;
}
