import { IamError, type IamStore, type StoredRecord, type Tenant } from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { TenantAlias } from './models.js';

/**
 * Organization sign-in addresses. Like an AWS account's sign-in URL or a Slack workspace address, each organization
 * can be reached at its own host: a subdomain built from its alias (`acme.signin.example.com`), optionally with a
 * region in it (`acme.signin.eu-west-1.example.com`), or a custom hostname the organization proved it controls
 * (`login.acme.com`). A request that arrives on an organization's address is pinned to that organization.
 */
export interface HostOptions {
  /**
   * Hostname templates. `{tenant}` stands for an organization's alias (its slug) and `{region}` for one of the
   * configured `regions`. The first template is the canonical address used in sign-in URLs and email links.
   * Examples: `'{tenant}.signin.example.com'`, `'{tenant}.signin.{region}.example.com'`,
   * `'{tenant}-signin-{region}.example.com'`, and for development `'{tenant}.localhost:3000'`.
   */
  patterns?: string[];
  /** Lets organizations verify hostnames of their own with a DNS TXT record (`hostnames` API group). Default false. */
  customHostnames?: boolean;
  /**
   * The hostname organizations point their custom hostname at with a CNAME record, shown in the setup
   * instructions `hostnames.add` returns (for example `custom.signin.example.com`).
   */
  cnameTarget?: string;
  /** The path of your sign-in page on an organization's address, used in sign-in URLs (default `/`). */
  signInPath?: string;
  /**
   * Read the address from `X-Forwarded-Host` before `Host`. Enable it only behind a proxy you control that sets
   * the header, because the address decides which organization a request is pinned to.
   */
  forwardedHost?: boolean;
}

/**
 * Where organizations live when a deployment runs in several regions. Every organization has a home region
 * (inherited from its parent unless set); sign-in for an organization homed elsewhere is refused with
 * `WRONG_REGION`, whose `location` is the organization's sign-in URL in its own region.
 */
export interface RegionOptions {
  /** This deployment's region, for example `'us-east-1'`. */
  current: string;
  /** Every region organizations can live in, with the base URL of that region's deployment and a display label. */
  regions: Record<string, { baseURL?: string; label?: string }>;
  /**
   * For deployments whose regions keep separate databases: returns the region an organization alias lives in when
   * this region's database does not know it, so its sign-in can be sent there instead of failing.
   */
  locate?: (alias: string) => Promise<string | undefined>;
}

/** A hostname an organization claims as its own sign-in address; it resolves to the organization once verified. */
export interface TenantHostname extends StoredRecord {
  hostname: string;
  status: 'pending' | 'verified';
  verificationToken: string;
  /** The organization's canonical address: sign-in URLs and email links use it instead of the subdomain. */
  primary?: boolean;
  createdAt: number;
  createdBy: string;
  verifiedAt?: number;
  lastCheckedAt?: number;
}
/** Global ownership record (id = the hostname), so one hostname belongs to at most one organization. */
export interface HostnameOwner extends StoredRecord {
  hostnameId: string;
  verifiedAt: number;
}

/** The organization an address belongs to. */
export interface HostMatch {
  tenantId: string;
  name: string;
  slug?: string;
  /** The hostname the organization was found by, lowercase, with its port when it has one. */
  hostname: string;
  /** `pattern` for a subdomain built from the alias, `custom` for a verified custom hostname. */
  via: 'pattern' | 'custom';
  /** The region named by the address itself (`{region}` in the pattern), if any. */
  hostRegion?: string;
}

/**
 * The organization is served by another region's deployment. `location` is its sign-in URL there (when one can be
 * built), so a sign-in page can redirect instead of showing an error. Answered with HTTP 421 Misdirected Request.
 */
export class WrongRegionError extends IamError {
  constructor(
    readonly region: string,
    readonly location: string | undefined,
    organization = 'This organization',
  ) {
    super(
      'WRONG_REGION',
      location
        ? `${organization} signs in at ${location}`
        : `${organization} is served from the ${region} region`,
      421,
    );
    this.name = 'WrongRegionError';
  }
}

interface CompiledPattern {
  source: string;
  regex: RegExp;
  hasRegion: boolean;
  /** Everything after the last placeholder when it starts a new label (`.signin.example.com`), else ''. */
  suffix: string;
  fill(alias: string, region: string | undefined): string;
}

export interface ResolvedHostConfig {
  patterns: CompiledPattern[];
  customHostnames: boolean;
  cnameTarget?: string;
  signInPath: string;
  forwardedHost: boolean;
  /** True when any organization address can exist, so requests must be resolved. */
  enabled: boolean;
}

export interface ResolvedRegionConfig {
  current: string;
  regions: Map<string, { baseURL?: string; label?: string }>;
  locate?: (alias: string) => Promise<string | undefined>;
}

const aliasSource = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const regionName = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const hostnameLabel = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const loopbackHost = (hostname: string) =>
  hostname === 'localhost' ||
  hostname.endsWith('.localhost') ||
  hostname === '127.0.0.1' ||
  hostname === '[::1]';

/** A request's address, lowercase and without a trailing dot, or undefined when it is not a plain host[:port]. */
export function normalizeHost(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const host = value
    .trim()
    .toLowerCase()
    .replace(/\.(?=:\d+$|$)/, '');
  return /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:]+\])(?::\d{1,5})?$/.test(host) &&
    host.length <= 260
    ? host
    : undefined;
}

/** Validates `options.regions` and applies defaults; undefined when the deployment has a single region. */
export function resolveRegionConfig(
  options: RegionOptions | undefined,
): ResolvedRegionConfig | undefined {
  if (options === undefined) return undefined;
  const invalid = (detail: string): never => {
    throw new IamError('INVALID_CONFIG', `regions.${detail}`);
  };
  if (options === null || typeof options !== 'object') invalid('options must be an object');
  if (typeof options.current !== 'string' || !regionName.test(options.current))
    invalid('current must be a region name such as us-east-1');
  if (!options.regions || typeof options.regions !== 'object')
    invalid('regions must map each region name to its settings');
  const entries = Object.entries(options.regions);
  if (!entries.length || entries.length > 64) invalid('regions must list 1 to 64 regions');
  const regions = new Map<string, { baseURL?: string; label?: string }>();
  for (const [name, settings] of entries) {
    if (!regionName.test(name)) invalid(`regions has an invalid region name: ${name}`);
    const value = settings ?? {};
    if (typeof value !== 'object') invalid(`regions.${name} must be an object`);
    const entry: { baseURL?: string; label?: string } = {};
    if (value.baseURL !== undefined) {
      let url: URL;
      try {
        url = new URL(value.baseURL);
      } catch {
        return invalid(`regions.${name}.baseURL must be an absolute URL`);
      }
      if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopbackHost(url.hostname)))
        invalid(`regions.${name}.baseURL must use HTTPS outside localhost`);
      entry.baseURL = `${url.origin}${url.pathname.replace(/\/$/, '')}`;
    }
    if (value.label !== undefined) {
      if (typeof value.label !== 'string' || !value.label.trim() || value.label.length > 64)
        invalid(`regions.${name}.label must be 1 to 64 characters`);
      entry.label = value.label.trim();
    }
    regions.set(name, entry);
  }
  if (!regions.has(options.current)) invalid('current must be one of regions');
  if (options.locate !== undefined && typeof options.locate !== 'function')
    invalid('locate must be a function');
  return {
    current: options.current,
    regions,
    ...(options.locate ? { locate: options.locate } : {}),
  };
}

/** Validates `options.hosts` against the base URL, the regions, and the passkey RP ID, and compiles the patterns. */
export function resolveHostConfig(
  options: HostOptions | undefined,
  context: { baseURL: URL; regions?: ResolvedRegionConfig; passkeyRpId?: string },
): ResolvedHostConfig {
  const invalid = (detail: string): never => {
    throw new IamError('INVALID_CONFIG', `hosts.${detail}`);
  };
  if (options !== undefined && (options === null || typeof options !== 'object'))
    invalid('options must be an object');
  const settings = options ?? {};
  if (
    settings.patterns !== undefined &&
    (!Array.isArray(settings.patterns) || settings.patterns.length > 16)
  )
    invalid('patterns must be an array of at most 16 templates');
  const regionNames = [...(context.regions?.regions.keys() ?? [])].sort(
    (a, b) => b.length - a.length,
  );
  const patterns = (settings.patterns ?? []).map((raw): CompiledPattern => {
    if (typeof raw !== 'string') return invalid('patterns must be strings');
    const source = raw.trim().toLowerCase();
    const count = (placeholder: string) => source.split(placeholder).length - 1;
    if (count('{tenant}') !== 1)
      invalid(`patterns entry ${raw} must contain {tenant} exactly once`);
    if (count('{region}') > 1) invalid(`patterns entry ${raw} may contain {region} at most once`);
    const hasRegion = count('{region}') === 1;
    if (hasRegion && !context.regions)
      invalid(`patterns entry ${raw} uses {region}, which needs the regions option`);
    const sample = source
      .replace('{tenant}', 'tenant')
      .replace('{region}', context.regions?.current ?? 'region');
    const [hostname, port, ...rest] = sample.split(':');
    if (
      rest.length ||
      (port !== undefined && !/^\d{1,5}$/.test(port)) ||
      /[{}]/.test(sample) ||
      !hostname ||
      hostname.split('.').length < 2 ||
      !hostname.split('.').every((part) => hostnameLabel.test(part))
    )
      invalid(`patterns entry ${raw} is not a valid hostname template`);
    if (context.baseURL.protocol !== 'https:' && !loopbackHost(hostname!))
      invalid('patterns need an HTTPS baseURL outside localhost');
    const rpId = context.passkeyRpId;
    if (rpId && hostname !== rpId && !hostname!.endsWith(`.${rpId}`))
      invalid(`patterns entry ${raw} must be under the passkey RP ID ${rpId}`);
    const parts = source.split(/(\{tenant\}|\{region\})/);
    const regex = new RegExp(
      `^${parts
        .map((part) =>
          part === '{tenant}'
            ? `(?<tenant>${aliasSource})`
            : part === '{region}'
              ? `(?<region>${regionNames.map(escapeRegex).join('|')})`
              : escapeRegex(part),
        )
        .join('')}$`,
    );
    const last = parts.at(-1) ?? '';
    return {
      source,
      regex,
      hasRegion,
      suffix: last.startsWith('.') ? last.replace(/:\d+$/, '') : '',
      fill: (alias, region) =>
        source
          .replace('{tenant}', alias)
          .replace('{region}', region ?? context.regions?.current ?? ''),
    };
  });
  if (settings.customHostnames !== undefined && typeof settings.customHostnames !== 'boolean')
    invalid('customHostnames must be a boolean');
  let cnameTarget: string | undefined;
  if (settings.cnameTarget !== undefined) {
    cnameTarget = normalizeHost(settings.cnameTarget);
    if (!cnameTarget || cnameTarget.includes(':'))
      invalid('cnameTarget must be a hostname such as custom.signin.example.com');
  }
  const signInPath = settings.signInPath ?? '/';
  if (typeof signInPath !== 'string' || !/^\/[\w./~%-]*$/.test(signInPath))
    invalid('signInPath must be a path starting with /');
  if (settings.forwardedHost !== undefined && typeof settings.forwardedHost !== 'boolean')
    invalid('forwardedHost must be a boolean');
  const customHostnames = settings.customHostnames === true;
  return {
    patterns,
    customHostnames,
    ...(cnameTarget ? { cnameTarget } : {}),
    signInPath,
    forwardedHost: settings.forwardedHost === true,
    enabled: patterns.length > 0 || customHostnames,
  };
}

export interface HostService {
  /** True when organization addresses are configured, so requests are resolved and may be pinned. */
  readonly enabled: boolean;
  /**
   * The organization an address belongs to. Undefined for the deployment's own address and hosts it does not
   * recognize; `NOT_FOUND` for a sign-in address of an unknown or inactive organization; `WRONG_REGION` when the
   * alias lives in another region's database (`regions.locate`).
   */
  resolve(host: string, tx?: IamStore): Promise<HostMatch | undefined>;
  /**
   * The organization a request is pinned to, from its address (`Host`) and, for cross-origin calls, its `Origin`.
   * `HOST_MISMATCH` when the two name different organizations; `WRONG_REGION` when the organization is served by
   * another region or the address names the wrong one.
   */
  requestTenant(request: Request): Promise<HostMatch | undefined>;
  /** True for the origin of an active organization address, so pages served there may call the API. */
  trustsOrigin(origin: string): Promise<boolean>;
  /** An organization's canonical sign-in URL: its primary custom hostname, else its subdomain, else its region. */
  signInUrl(tenant: Tenant | string, tx?: IamStore): Promise<string | undefined>;
  /** The home region of a tenant: its own `region`, else its nearest ancestor's. */
  regionOf(tx: IamStore, tenant: Tenant): Promise<string | undefined>;
  /** Throws `WRONG_REGION` when the tenant is served by another region (or `hostRegion` names the wrong one). */
  assertServedHere(tx: IamStore, tenant: Tenant, hostRegion?: string): Promise<void>;
  /** `assertServedHere` for a tenant ID from a request body; unknown tenants are left to the operation to refuse. */
  assertTenantServedHere(tenantId: string): Promise<void>;
  /** For an alias this database does not know: the redirect to the region that has it, if `regions.locate` finds one. */
  remoteAlias(alias: string): Promise<WrongRegionError | undefined>;
  /** The region a new tenant under `parent` gets: the requested one (validated), else none when inherited. */
  regionForNew(
    tx: IamStore,
    parent: Tenant,
    requested: string | undefined,
  ): Promise<string | undefined>;
  /** Validates a region name for `tenants.setRegion` and `tenants.create`. */
  region(value: unknown): string;
  /** Throws `HOSTNAME_NOT_ALLOWED` for hostnames the deployment itself uses (its base URL and pattern space). */
  assertClaimable(hostname: string): void;
  /**
   * Whether a TLS certificate may be issued for `hostname` (an on-demand TLS "ask" check): true for addresses of
   * active organizations, their verified custom hostnames, and the deployment's own hosts.
   */
  allowed(hostname: string): Promise<boolean>;
}

/** The host and region service of one deployment. */
export function createHosts(ctx: ServerContext): HostService {
  const { config, store } = ctx;
  const { hosts, regions, baseURL } = config;
  const baseHost = baseURL.host;
  const scheme = baseURL.protocol;
  const ownHostnames = new Set(
    [baseURL.origin, ...config.trustedOrigins].map((origin) => {
      try {
        return new URL(origin).hostname;
      } catch {
        return '';
      }
    }),
  );

  async function active(tx: IamStore, realm: Tenant | undefined): Promise<Tenant | undefined> {
    if (!realm || realm.status !== 'active') return undefined;
    return (await ctx.ancestry(tx, realm)).every((item) => item.status === 'active')
      ? realm
      : undefined;
  }

  async function regionOf(tx: IamStore, tenant: Tenant): Promise<string | undefined> {
    if (!regions) return undefined;
    for (const item of await ctx.ancestry(tx, tenant)) if (item.region) return item.region;
    return undefined;
  }

  async function signInUrl(target: Tenant | string, tx: IamStore = store) {
    const realm = typeof target === 'string' ? await tx.get<Tenant>('tenants', target) : target;
    if (!realm) return undefined;
    const home = await regionOf(tx, realm);
    if (hosts.customHostnames) {
      const primary = (
        await tx.find<TenantHostname>('tenantHostnames', { tenantId: realm.id })
      ).find((record) => record.primary && record.status === 'verified');
      if (primary) return `${scheme}//${primary.hostname}${hosts.signInPath}`;
    }
    const pattern = hosts.patterns[0];
    if (realm.slug && pattern)
      return `${scheme}//${pattern.fill(realm.slug, home)}${hosts.signInPath}`;
    const base = home ? regions?.regions.get(home)?.baseURL : undefined;
    return base ? `${base}${hosts.signInPath === '/' ? '' : hosts.signInPath}` : undefined;
  }

  async function redirectFor(realm: Tenant, region: string, tx: IamStore) {
    return new WrongRegionError(region, await signInUrl(realm, tx), realm.name);
  }

  async function assertServedHere(tx: IamStore, tenant: Tenant, hostRegion?: string) {
    if (!regions) return;
    const home = (await regionOf(tx, tenant)) ?? regions.current;
    if (home !== regions.current || (hostRegion !== undefined && hostRegion !== home))
      throw await redirectFor(tenant, home, tx);
  }

  async function remoteAlias(alias: string) {
    if (!regions?.locate) return undefined;
    let region: string | undefined;
    try {
      region = await regions.locate(alias);
    } catch {
      return undefined;
    }
    if (!region || region === regions.current || !regions.regions.has(region)) return undefined;
    const pattern = hosts.patterns[0];
    const base = regions.regions.get(region)?.baseURL;
    const location = pattern
      ? `${scheme}//${pattern.fill(alias, region)}${hosts.signInPath}`
      : base
        ? `${base}${hosts.signInPath === '/' ? '' : hosts.signInPath}`
        : undefined;
    return new WrongRegionError(region, location);
  }

  async function resolve(rawHost: string, tx: IamStore = store): Promise<HostMatch | undefined> {
    if (!hosts.enabled) return undefined;
    const host = normalizeHost(rawHost);
    if (!host || host === baseHost) return undefined;
    for (const pattern of hosts.patterns) {
      const match = pattern.regex.exec(host);
      if (!match?.groups) continue;
      const alias = match.groups.tenant!;
      const record = await tx.get<TenantAlias>('tenantAliases', alias);
      const realm = await active(
        tx,
        record ? await tx.get<Tenant>('tenants', record.tenantId) : undefined,
      );
      if (!realm) {
        const elsewhere = record ? undefined : await remoteAlias(alias);
        if (elsewhere) throw elsewhere;
        throw new IamError('NOT_FOUND', 'No organization uses this address', 404);
      }
      return {
        tenantId: realm.id,
        name: realm.name,
        slug: alias,
        hostname: host,
        via: 'pattern',
        ...(match.groups.region ? { hostRegion: match.groups.region } : {}),
      };
    }
    if (hosts.customHostnames) {
      const hostname = host.replace(/:\d+$/, '');
      const owner = await tx.get<HostnameOwner>('hostnameOwners', hostname);
      if (owner) {
        const realm = await active(tx, await tx.get<Tenant>('tenants', owner.tenantId));
        if (!realm) throw new IamError('NOT_FOUND', 'No organization uses this address', 404);
        return {
          tenantId: realm.id,
          name: realm.name,
          ...(realm.slug ? { slug: realm.slug } : {}),
          hostname: host,
          via: 'custom',
        };
      }
    }
    return undefined;
  }

  function validRegion(value: unknown): string {
    if (!regions) throw new IamError('INVALID_INPUT', 'This deployment has no regions configured');
    if (typeof value !== 'string' || !regions.regions.has(value))
      throw new IamError(
        'INVALID_INPUT',
        `Region must be one of ${[...regions.regions.keys()].join(', ')}`,
      );
    return value;
  }

  const originHost = (origin: string): string | undefined => {
    try {
      const url = new URL(origin);
      return url.protocol === scheme && url.origin === origin ? url.host : undefined;
    } catch {
      return undefined;
    }
  };

  /** Whether an address could belong to an organization, decided without storage. */
  const candidate = (host: string | undefined): host is string => {
    const normalized = normalizeHost(host);
    return (
      normalized !== undefined &&
      normalized !== baseHost &&
      (hosts.customHostnames || hosts.patterns.some((pattern) => pattern.regex.test(normalized)))
    );
  };

  return {
    enabled: hosts.enabled,
    resolve,
    regionOf,
    signInUrl,
    assertServedHere,
    remoteAlias,
    async assertTenantServedHere(tenantId) {
      if (!regions) return;
      await store.transaction(async (tx) => {
        const realm = await tx.get<Tenant>('tenants', tenantId);
        if (realm) await assertServedHere(tx, realm);
      });
    },
    async requestTenant(request) {
      if (!hosts.enabled) return undefined;
      const forwarded = hosts.forwardedHost
        ? request.headers.get('x-forwarded-host')?.split(',')[0]
        : undefined;
      let address: string | undefined;
      try {
        address = forwarded?.trim() || new URL(request.url).host;
      } catch {
        address = undefined;
      }
      const origin = request.headers.get('origin');
      const fromOrigin = origin ? originHost(origin) : undefined;
      // Most requests arrive on the deployment's own address: no storage read for those.
      if (!candidate(address) && !candidate(fromOrigin)) return undefined;
      return store.transaction(async (tx) => {
        const byHost = address ? await resolve(address, tx) : undefined;
        const byOrigin =
          fromOrigin && fromOrigin !== address ? await resolve(fromOrigin, tx) : undefined;
        if (byHost && byOrigin && byHost.tenantId !== byOrigin.tenantId)
          throw new IamError(
            'HOST_MISMATCH',
            'This page and this address belong to different organizations',
            403,
          );
        const match = byHost ?? byOrigin;
        if (match)
          await assertServedHere(tx, await ctx.tenant(tx, match.tenantId), match.hostRegion);
        return match;
      });
    },
    async trustsOrigin(origin) {
      if (!hosts.enabled) return false;
      const host = originHost(origin);
      if (!host) return false;
      try {
        return Boolean(await resolve(host));
      } catch {
        return false;
      }
    },
    async regionForNew(tx, parent, requested) {
      if (requested === undefined || requested === null) {
        // The first organizations under the (region-less) root are homed where they are created.
        if (!regions || (await regionOf(tx, parent))) return undefined;
        return regions.current;
      }
      const region = validRegion(requested);
      if (regions!.locate && region !== regions!.current)
        throw new IamError(
          'INVALID_INPUT',
          'Regions keep separate databases here: create the organization on the deployment of its region',
        );
      return region;
    },
    region: validRegion,
    assertClaimable(hostname) {
      const refuse = () => {
        throw new IamError(
          'HOSTNAME_NOT_ALLOWED',
          'This hostname belongs to the deployment itself and cannot be claimed',
        );
      };
      if (ownHostnames.has(hostname)) refuse();
      for (const pattern of hosts.patterns) {
        if (pattern.regex.exec(hostname)) refuse();
        const suffix = pattern.suffix;
        if (suffix && (hostname.endsWith(suffix) || hostname === suffix.slice(1))) refuse();
      }
    },
    async allowed(hostname) {
      const host = normalizeHost(hostname);
      if (!host) return false;
      if (ownHostnames.has(host.replace(/:\d+$/, ''))) return true;
      try {
        return Boolean(await resolve(host));
      } catch {
        return false;
      }
    },
  };
}
