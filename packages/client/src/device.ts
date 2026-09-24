import { IamClientError } from './index.js';

// Registered-device proofs: WebCrypto only (browsers in secure contexts, Node 22 or later), no dependencies.

/** The request header that carries a device proof. */
export const deviceProofHeader = 'x-better-iam-device';

/** Where a device keeps its signing key between page loads or process restarts. */
export interface DeviceKeyStore {
  load(): Promise<CryptoKeyPair | undefined>;
  save(pair: CryptoKeyPair): Promise<void>;
  clear(): Promise<void>;
}

/** The public half of a device key, as `devices.enroll` takes it. */
export interface DevicePublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

export interface DeviceProverOptions {
  /**
   * Where the key pair lives. Defaults to `indexedDbKeyStore()` where IndexedDB exists (browsers) and to
   * `memoryKeyStore()` elsewhere, where the key lasts only as long as the process.
   */
  store?: DeviceKeyStore;
  /**
   * Keeps a separate key pair per scope in the default store, such as the signed-in identity's id. The server holds
   * each key once across the whole deployment (one device of one person), so a browser used with several accounts,
   * including one person's accounts in several tenants, needs one key per account: create one prover per account, each
   * with its own `scope`. 1 to 64 printable characters without spaces; ignored when `store` is given.
   */
  scope?: string;
  /** The signature algorithm. Only `ES256` (ECDSA P-256 with SHA-256) is supported. */
  algorithm?: 'ES256';
  /**
   * The clock, in milliseconds, used for a proof's `iat`. Defaults to `Date.now`. The server accepts proofs issued
   * up to five minutes either side of its own clock; on devices whose clocks drift further, pass one corrected with
   * the server time that `auth.getSession()` returns as `limits.now`.
   */
  now?: () => number;
  /**
   * Called when `headers()` could not produce a proof (no WebCrypto outside a secure context, a key store that
   * failed, an invalid session id). `headers()` then sends no proof, which the server treats as "no device".
   */
  onError?: (error: unknown) => void;
}

export interface DeviceProver {
  /** Public JWK for devices.enroll (EC P-256). */
  publicJwk(): Promise<DevicePublicJwk>;
  /** RFC 7638 thumbprint (the key id). */
  keyId(): Promise<string>;
  /** A fresh compact JWS for the given session id (cached ~4 min per session id). */
  proof(sessionId: string, tenantId?: string): Promise<string>;
  /**
   * Headers for ClientOptions.headers: { 'x-better-iam-device': proof } once a session id is known. Resolves to no
   * headers while the session id is unknown, and when no proof can be made (reported to `onError`), so a device
   * problem never fails the request itself.
   */
  headers(sessionId: string | undefined, tenantId?: string): Promise<Record<string, string>>;
  /** Forgets the key pair (in memory and in the store) and every cached proof; the next proof uses a new key. */
  reset(): Promise<void>;
}

const defaultDatabase = 'better-iam-registered-device';
const objectStoreName = 'keys';
const recordKey = 'current';
/** Serializes first-time key creation across tabs, so two tabs opened together settle on one key. */
const creationLock = 'better-iam:registered-device-key';
const proofType = 'device-proof+jwt';
/** The server accepts `iat` within 300 seconds of its clock; reuse leaves a minute of that window. */
const proofReuseMs = 240_000;
const maxCachedProofs = 16;
/** Session and tenant ids are printable ASCII without spaces, which also bounds the proof well below 2048 chars. */
const idPattern = /^[!-~]{1,256}$/;
/** A prover's `scope`: printable ASCII without spaces, short enough for a database name. */
const scopePattern = /^[!-~]{1,64}$/;

const encoder = new TextEncoder();
const utf8 = (text: string) => encoder.encode(text);

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function webCrypto(): SubtleCrypto {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle)
    throw new IamClientError(
      'UNSUPPORTED_ENVIRONMENT',
      'Device proofs need WebCrypto (crypto.subtle): a secure context (HTTPS or localhost) in browsers, Node 22 or later on servers',
      0,
    );
  return subtle;
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return (
    typeof value === 'object' &&
    value !== null &&
    'type' in value &&
    'algorithm' in value &&
    'usages' in value &&
    'extractable' in value
  );
}

function isP256(key: CryptoKey): boolean {
  const algorithm = key.algorithm as Partial<EcKeyAlgorithm>;
  return algorithm.name === 'ECDSA' && algorithm.namedCurve === 'P-256';
}

/** A stored pair is used only when it can still sign ES256 proofs and publish its public key. */
function usableKeyPair(value: unknown): value is CryptoKeyPair {
  if (typeof value !== 'object' || value === null) return false;
  const { privateKey, publicKey } = value as Partial<Record<keyof CryptoKeyPair, unknown>>;
  return (
    isCryptoKey(privateKey) &&
    isCryptoKey(publicKey) &&
    isP256(privateKey) &&
    isP256(publicKey) &&
    privateKey.type === 'private' &&
    privateKey.usages.includes('sign') &&
    publicKey.type === 'public' &&
    publicKey.extractable
  );
}

function checkId(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !idPattern.test(value))
    throw new IamClientError(
      'INVALID_INPUT',
      `${name} must be 1 to 256 printable characters without spaces`,
      0,
    );
}

/** Keeps the key pair in memory only: for tests, scripts, and servers that re-enrol after a restart. */
export function memoryKeyStore(): DeviceKeyStore {
  let current: CryptoKeyPair | undefined;
  return {
    async load() {
      return current;
    },
    async save(pair) {
      current = pair;
    },
    async clear() {
      current = undefined;
    },
  };
}

/**
 * Keeps the key pair in the browser's IndexedDB (database `name`, one record). CryptoKey objects are stored as they
 * are, so the private key stays non-extractable: script on the page can sign with it but never read it. Saving an
 * extractable private key is refused. Every call rejects with `UNSUPPORTED_ENVIRONMENT` where IndexedDB is missing.
 */
export function indexedDbKeyStore(name: string = defaultDatabase): DeviceKeyStore {
  if (typeof name !== 'string' || name.length === 0 || name.length > 128)
    throw new IamClientError(
      'INVALID_CONFIG',
      'indexedDbKeyStore needs a database name of 1 to 128 characters',
      0,
    );
  const open = (): Promise<IDBDatabase> => {
    const factory = typeof indexedDB === 'undefined' ? undefined : indexedDB;
    if (!factory)
      return Promise.reject(
        new IamClientError(
          'UNSUPPORTED_ENVIRONMENT',
          'IndexedDB is not available here; use memoryKeyStore() or your own DeviceKeyStore outside browsers',
          0,
        ),
      );
    return new Promise((resolve, reject) => {
      const request = factory.open(name, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(objectStoreName);
      };
      request.onsuccess = () => {
        const database = request.result;
        // Never hold up another tab's upgrade of this database.
        database.onversionchange = () => database.close();
        resolve(database);
      };
      request.onerror = () =>
        reject(
          request.error ??
            new IamClientError(
              'UNSUPPORTED_ENVIRONMENT',
              'The device key database could not be opened',
              0,
            ),
        );
    });
  };
  const run = async <T>(
    mode: IDBTransactionMode,
    action: (objects: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> => {
    const database = await open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const transaction = database.transaction(objectStoreName, mode);
        const request = action(transaction.objectStore(objectStoreName));
        const failed = () =>
          reject(
            transaction.error ??
              new IamClientError(
                'UNSUPPORTED_ENVIRONMENT',
                'The device key database refused the change',
                0,
              ),
          );
        transaction.oncomplete = () => resolve(request.result);
        transaction.onerror = failed;
        transaction.onabort = failed;
      });
    } finally {
      database.close();
    }
  };
  return {
    async load() {
      const value: unknown = await run('readonly', (objects) => objects.get(recordKey));
      if (typeof value !== 'object' || value === null) return undefined;
      const { privateKey, publicKey } = value as Partial<Record<keyof CryptoKeyPair, unknown>>;
      return isCryptoKey(privateKey) && isCryptoKey(publicKey)
        ? { privateKey, publicKey }
        : undefined;
    },
    async save(pair) {
      if (!pair || !isCryptoKey(pair.privateKey) || !isCryptoKey(pair.publicKey))
        throw new IamClientError('INVALID_INPUT', 'save() takes a CryptoKeyPair', 0);
      if (pair.privateKey.extractable)
        throw new IamClientError(
          'INVALID_INPUT',
          'indexedDbKeyStore keeps only non-extractable private keys',
          0,
        );
      await run('readwrite', (objects) =>
        objects.put({ privateKey: pair.privateKey, publicKey: pair.publicKey }, recordKey),
      );
    },
    async clear() {
      await run('readwrite', (objects) => objects.delete(recordKey));
    },
  };
}

interface ActiveKey {
  pair: CryptoKeyPair;
  jwk: DevicePublicJwk;
  kid: string;
  /** The encoded protected header, the same for every proof of this key. */
  header: string;
}
interface CachedProof {
  issuedAt: number;
  token: Promise<string>;
}

async function loadOrCreate(subtle: SubtleCrypto, store: DeviceKeyStore): Promise<CryptoKeyPair> {
  const stored = await store.load();
  if (usableKeyPair(stored)) return stored;
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  await store.save(pair);
  return pair;
}

async function describe(subtle: SubtleCrypto, pair: CryptoKeyPair): Promise<ActiveKey> {
  const exported = await subtle.exportKey('jwk', pair.publicKey);
  if (
    exported.kty !== 'EC' ||
    exported.crv !== 'P-256' ||
    typeof exported.x !== 'string' ||
    typeof exported.y !== 'string'
  )
    throw new IamClientError('INVALID_CONFIG', 'The stored device key is not an EC P-256 key', 0);
  const jwk: DevicePublicJwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y };
  // RFC 7638: the required members only, in lexicographic order, without whitespace.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const kid = base64url(new Uint8Array(await subtle.digest('SHA-256', utf8(canonical))));
  const header = base64url(utf8(JSON.stringify({ alg: 'ES256', typ: proofType, kid })));
  return { pair, jwk, kid, header };
}

/**
 * Proves which registered device a request comes from. The device keeps an ECDSA P-256 key pair it creates on first
 * use (the private half never leaves WebCrypto), enrols the public half once with `devices.enroll`, and then signs a
 * short-lived proof bound to the session it presents. Proofs are compact JWS (`ES256`, `typ: device-proof+jwt`,
 * `kid` = the key's RFC 7638 thumbprint) over `{ iat, sid, tid? }`, reused for up to four minutes per session id and
 * tenant id. The server reads them from `x-better-iam-device`; a missing or invalid proof only means "no device".
 * The server keeps each key for one account only, so a browser used with several accounts needs a prover (and key)
 * per account: pass each its own `scope`, such as the identity id. `devices.enroll` needs the request to carry a proof
 * made with the key being enrolled, which `headers()` adds once the session id is known.
 *
 * const device = createDeviceProver();
 * let sessionId: string | undefined;
 * const client = createIamClient<typeof iam>({ headers: () => device.headers(sessionId) });
 * sessionId = (await client.auth.getSession()).session.id;
 * const publicKey = await device.publicJwk();
 * await client.devices.enroll({ tenantId, name: 'Work laptop', platform: 'macos', publicKey });
 */
export function createDeviceProver(options: DeviceProverOptions = {}): DeviceProver {
  if (options.algorithm !== undefined && options.algorithm !== 'ES256')
    throw new IamClientError('INVALID_CONFIG', 'Device proofs support only the ES256 algorithm', 0);
  const { scope } = options;
  if (scope !== undefined && (typeof scope !== 'string' || !scopePattern.test(scope)))
    throw new IamClientError(
      'INVALID_CONFIG',
      'scope must be 1 to 64 printable characters without spaces',
      0,
    );
  const store =
    options.store ??
    (typeof indexedDB === 'undefined'
      ? memoryKeyStore()
      : indexedDbKeyStore(scope === undefined ? defaultDatabase : `${defaultDatabase}:${scope}`));
  const lockName = scope === undefined ? creationLock : `${creationLock}:${scope}`;
  if (
    typeof store !== 'object' ||
    store === null ||
    typeof store.load !== 'function' ||
    typeof store.save !== 'function' ||
    typeof store.clear !== 'function'
  )
    throw new IamClientError('INVALID_CONFIG', 'store must implement load, save, and clear', 0);
  const clock = options.now ?? Date.now;
  let active: Promise<ActiveKey> | undefined;
  // Key creation and reset run one at a time, so a reset never races a key that is still being saved.
  let lane: Promise<unknown> = Promise.resolve();
  const serial = <T>(task: () => Promise<T>): Promise<T> => {
    const result = lane.then(task);
    lane = result.catch(() => undefined);
    return result;
  };
  const proofs = new Map<string, CachedProof>();

  const currentKey = (): Promise<ActiveKey> => {
    if (active) return active;
    const pending = serial(async () => {
      const subtle = webCrypto();
      const locks = (globalThis as { navigator?: { locks?: Pick<LockManager, 'request'> } })
        .navigator?.locks;
      const pair =
        typeof locks?.request === 'function'
          ? await locks.request(lockName, () => loadOrCreate(subtle, store))
          : await loadOrCreate(subtle, store);
      return describe(subtle, pair);
    });
    active = pending;
    // A failure is not remembered: the next call tries again.
    pending.catch(() => {
      if (active === pending) active = undefined;
    });
    return pending;
  };

  const sign = async (sessionId: string, tenantId: string | undefined, issuedAt: number) => {
    const key = await currentKey();
    const claims = {
      iat: Math.floor(issuedAt / 1000),
      sid: sessionId,
      ...(tenantId === undefined ? {} : { tid: tenantId }),
    };
    const signingInput = `${key.header}.${base64url(utf8(JSON.stringify(claims)))}`;
    // WebCrypto's ECDSA signature is already the JOSE form: r and s as two 32-byte big-endian integers.
    const signature = await webCrypto().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key.pair.privateKey,
      utf8(signingInput),
    );
    if (signature.byteLength !== 64)
      throw new IamClientError(
        'UNSUPPORTED_ENVIRONMENT',
        'WebCrypto returned an ECDSA signature that is not in the raw r||s form',
        0,
      );
    return `${signingInput}.${base64url(new Uint8Array(signature))}`;
  };

  const prover: DeviceProver = {
    async publicJwk() {
      return { ...(await currentKey()).jwk };
    },
    async keyId() {
      return (await currentKey()).kid;
    },
    async proof(sessionId, tenantId) {
      checkId(sessionId, 'sessionId');
      if (tenantId !== undefined) checkId(tenantId, 'tenantId');
      const now = clock();
      if (!Number.isFinite(now))
        throw new IamClientError('INVALID_CONFIG', 'now() must return milliseconds', 0);
      const fresh = (entry: CachedProof) =>
        entry.issuedAt <= now && now - entry.issuedAt < proofReuseMs;
      // Ids never contain spaces, so the pair maps to one cache key without ambiguity.
      const cacheKey = tenantId === undefined ? sessionId : `${sessionId} ${tenantId}`;
      const cached = proofs.get(cacheKey);
      if (cached && fresh(cached)) return cached.token;
      for (const [key, entry] of proofs) if (!fresh(entry)) proofs.delete(key);
      for (const oldest of proofs.keys()) {
        if (proofs.size < maxCachedProofs) break;
        proofs.delete(oldest);
      }
      const entry: CachedProof = { issuedAt: now, token: sign(sessionId, tenantId, now) };
      proofs.set(cacheKey, entry);
      entry.token.catch(() => {
        if (proofs.get(cacheKey) === entry) proofs.delete(cacheKey);
      });
      return entry.token;
    },
    async headers(sessionId, tenantId): Promise<Record<string, string>> {
      if (sessionId === undefined || sessionId === '') return {};
      try {
        return { [deviceProofHeader]: await prover.proof(sessionId, tenantId) };
      } catch (error) {
        try {
          options.onError?.(error);
        } catch {
          /* A hook that throws never fails the request that asked for headers. */
        }
        return {};
      }
    },
    async reset() {
      active = undefined;
      proofs.clear();
      await serial(() => store.clear());
    },
  };
  return prover;
}
