import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';

/**
 * The number of reverse proxies in front of the console, from `TRUSTED_PROXY_HOPS` (0 or unset: none, and no client
 * addresses are recorded). Only set it when every request reaches the console through proxies you run.
 */
export function trustedProxyHops(env = process.env) {
  const value = env.TRUSTED_PROXY_HOPS?.trim();
  if (!value) return 0;
  const hops = Number(value);
  if (!Number.isInteger(hops) || hops < 0 || hops > 10)
    throw new Error(
      'TRUSTED_PROXY_HOPS must be a whole number from 0 to 10: the reverse proxies in front of the console.',
    );
  return hops;
}

/** A bare IP address from one X-Forwarded-For entry (an optional port and IPv4-mapped IPv6 form removed). */
function forwardedAddress(entry) {
  let value = entry.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) value = bracketed[1];
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value))
    value = value.slice(0, value.lastIndexOf(':'));
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];
  return isIP(value) ? value : undefined;
}

/**
 * `http.clientInfo` for a console behind `hops` trusted reverse proxies: the client IP and the User-Agent.
 * X-Forwarded-For is client-controlled except for the entries our own proxies append on the right, so the address is
 * the entry `hops` places from the right; everything further left is ignored. A request that carries fewer entries
 * did not pass through every proxy and gets no address rather than a guessed one.
 */
export function trustedProxyClientInfo(hops) {
  return (request) => {
    const userAgent = request.headers.get('user-agent') ?? undefined;
    // Repeated X-Forwarded-For headers arrive joined with ", " in order.
    const entries = (request.headers.get('x-forwarded-for') ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    const ip =
      hops > 0 && entries.length >= hops
        ? forwardedAddress(entries[entries.length - hops])
        : undefined;
    if (ip) return userAgent ? { ip, userAgent } : { ip };
    return userAgent ? { userAgent } : undefined;
  };
}

let developmentCardKey;

/**
 * The key agents' A2A cards are signed with (`a2a`): a private Ed25519 or P-256 JWK in `BETTER_IAM_A2A_SIGNING_KEY`.
 * Outside production the console makes one per process when none is set, so cards signed in development stop verifying
 * after a restart. Production without the variable leaves card signing off.
 */
export function cardSigningKey(env = process.env) {
  const configured = env.BETTER_IAM_A2A_SIGNING_KEY?.trim();
  if (configured) return JSON.parse(configured);
  if (env.NODE_ENV === 'production') return undefined;
  developmentCardKey ??= {
    ...generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }),
    kid: `dev-${randomUUID().slice(0, 8)}`,
    alg: 'EdDSA',
    use: 'sig',
  };
  return developmentCardKey;
}

/**
 * Shared Better IAM configuration for the console and its CLI scripts (migrate, bootstrap, doctor).
 * The Next.js server adds its delivery callback; the CLI runs without one.
 */
export async function createOptions(overrides = {}) {
  const secret = process.env.BETTER_IAM_SECRET;
  if (!secret || secret.length < 32)
    throw new Error('Set BETTER_IAM_SECRET to a stable random secret of at least 32 characters.');
  // Secrets being rotated out, comma-separated (see the rotation steps in docs/deployment.md).
  const previousSecrets = (process.env.BETTER_IAM_PREVIOUS_SECRETS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const baseURL = process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000';
  let database;
  if (process.env.DATABASE_URL) {
    const { postgresAdapter } = await import('better-iam/adapter-postgres');
    database = postgresAdapter({ connectionString: process.env.DATABASE_URL });
  } else {
    const { sqliteAdapter } = await import('better-iam/adapter-sqlite');
    database = sqliteAdapter({ filename: process.env.BETTER_IAM_DATABASE ?? './console.db' });
  }
  // Allowed networks, session binding, network blocks, and per-address sign-in failures all need the client IP,
  // which is only trustworthy behind proxies the deployment controls (TRUSTED_PROXY_HOPS). Without it the
  // console records the User-Agent only and its settings pages say that those controls are not enforced.
  const hops = trustedProxyHops();
  const cardKey = cardSigningKey();
  const http = {
    ...(hops ? { clientInfo: trustedProxyClientInfo(hops) } : {}),
    ...overrides.http,
  };
  return {
    database,
    secret,
    ...(previousSecrets.length ? { previousSecrets } : {}),
    baseURL,
    trustedOrigins: [new URL(baseURL).origin],
    ...(Object.keys(http).length ? { http } : {}),
    authentication: {
      appName: 'Better IAM Console',
      passkeys: { rpID: new URL(baseURL).hostname, rpName: 'Better IAM Console' },
      // Sign-in links need a mail transport, which only the Next.js server supplies; CLI runs stay password-only.
      passwordlessEmail: Boolean(overrides.authentication?.sendEmail),
      // One alert after five failed attempts since the person's last sign-in, whenever mail can go out.
      failedSignInAlerts: overrides.authentication?.sendEmail ? 5 : 0,
      ...overrides.authentication,
    },
    onboarding: { mode: 'linked' },
    // Process-local counters and latency histograms for the admin Operations page and `GET /api/iam/metrics`.
    observability: {
      metrics: process.env.METRICS_TOKEN ? { bearerToken: process.env.METRICS_TOKEN } : true,
    },
    // Which actions people actually use, for the Role mining page's least-privilege card.
    accessUsage: true,
    // AI model access, budgets and metering for the Models & budgets page (and the /api/ai gateway).
    inference: true,
    // Attested A2A agent cards (Agents page); the public keys are served at /api/a2a/jwks.json.
    ...(cardKey
      ? {
          a2a: {
            signingKeys: [cardKey],
            jwksUrl: `${baseURL.replace(/\/$/, '')}/api/a2a/jwks.json`,
          },
        }
      : {}),
    permissions: {
      // Organizations may register their own resource types and {type}:{verb} actions.
      mode: 'tenant-defined',
      // Administrators set these on members; policies read them as principal.department / principal.title.
      identityAttributes: { department: 'string', title: 'string' },
      resourceTypes: {
        workspace: {
          description: 'A workspace registered with IAM by the cloud console',
          managed: true,
          actions: ['workspaces:read', 'workspaces:manage'],
          attributes: { environment: 'string', archived: 'boolean' },
          // Sharing: members and groups hold relations on a workspace; roles read them as resource.relations.
          relations: ['viewer', 'editor', 'owner'],
        },
      },
    },
  };
}

export default () => createOptions();
