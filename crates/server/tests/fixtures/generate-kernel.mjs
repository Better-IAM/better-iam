// Writes kernel.json: what the TypeScript server kernel answers for a set of inputs (configuration validation, the
// catalog, tenant policies, access windows, hosts, issuers, metrics rendering and the standalone configuration
// reader), so the Rust port can check it gives the same answers, errors included.
// Usage (after `pnpm build`): node crates/server/tests/fixtures/generate-kernel.mjs > crates/server/tests/fixtures/kernel.json
import { pathToFileURL, fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const load = (path) => import(pathToFileURL(`${root}${path}`).href);
const { resolveConfig } = await load('packages/server/dist/options.js');
const { Catalog } = await load('packages/server/dist/catalog.js');
const { tenantAuthPolicy, tenantLimits } = await load('packages/server/dist/tenant-policy.js');
const { tenantAccessPolicy } = await load('packages/server/dist/access-policy.js');
const { createContext, insideWindow, slug } = await load('packages/server/dist/context.js');
const { normalizeHost } = await load('packages/server/dist/hosts.js');
const { webIdentityIssuer } = await load('packages/server/dist/web-identity.js');
const { createMetrics } = await load('packages/server/dist/metrics.js');
const { createEvents } = await load('packages/server/dist/events.js');
const { optionsFromConfig, clientInfoFunction } = await load('scripts/conformance/lib/config.mjs');
const { clientFromHeaders } = await load('packages/server/dist/client-info.js');

const error = (thrown) =>
  thrown && thrown.name === 'IamError'
    ? { code: thrown.code, status: thrown.status, message: thrown.message }
    : { code: 'INTERNAL_ERROR', status: 500, message: 'Internal server error', thrown: String(thrown?.message) };
const attempt = (fn) => {
  try {
    return { result: fn() };
  } catch (thrown) {
    return { error: error(thrown) };
  }
};

/** The ServerConfig as JSON (URL, Set and Map members spelled out). */
function project(config) {
  return {
    baseURL: config.baseURL.href,
    basePath: config.basePath,
    trustedOrigins: [...config.trustedOrigins],
    hierarchy: config.hierarchy,
    maxDepth: config.maxDepth,
    tenantDefined: config.tenantDefined,
    strictResourceTypes: config.strictResourceTypes,
    linkedOnboarding: config.linkedOnboarding,
    invitationLifetimeMs: typeof config.invitationLifetimeMs === 'number' ? config.invitationLifetimeMs : null,
    accessRequestLifetimeMs: config.accessRequestLifetimeMs,
    accessRequestMaxDurationSeconds: config.accessRequestMaxDurationSeconds,
    webhookTimeoutMs: config.webhookTimeoutMs,
    tenantDefaults: config.tenantDefaults,
    sts: { ...config.sts, webIdentity: { ...config.sts.webIdentity, allowedIssuers: config.sts.webIdentity.allowedIssuers ? [...config.sts.webIdentity.allowedIssuers] : null } },
    hosts: {
      patterns: config.hosts.patterns.map((pattern) => ({
        source: pattern.source,
        hasRegion: pattern.hasRegion,
        suffix: pattern.suffix,
        sample: pattern.fill('acme', undefined),
      })),
      customHostnames: config.hosts.customHostnames,
      cnameTarget: config.hosts.cnameTarget ?? null,
      signInPath: config.hosts.signInPath,
      forwardedHost: config.hosts.forwardedHost,
      enabled: config.hosts.enabled,
    },
    regions: config.regions
      ? { current: config.regions.current, regions: Object.fromEntries(config.regions.regions) }
      : null,
    signals: config.signals,
    clearances: config.clearances ?? null,
  };
}

const base = { database: {}, secret: 'kernel-fixture-secret-with-at-least-32-chars', baseURL: 'https://iam.example.com' };
const configInputs = [
  {},
  { baseURL: 'http://localhost:3000', basePath: '/iam', trustedOrigins: ['https://app.example.com'] },
  { baseURL: 'http://example.com' },
  { baseURL: 'not a url' },
  { baseURL: 'http://[::1]:8080' },
  { basePath: '/api/iam/' },
  { basePath: 'api' },
  { basePath: '' },
  { basePath: null },
  { basePath: ['/api'] },
  { hierarchy: { types: { root: { allowedChildren: ['team'] }, team: { allowedChildren: [] } }, maxDepth: 3 } },
  { hierarchy: { types: { organization: { allowedChildren: [] } } } },
  { hierarchy: { types: { root: { allowedChildren: ['root'] } } } },
  { hierarchy: { types: { root: { allowedChildren: ['missing'] } } } },
  { hierarchy: { types: { root: { allowedChildren: [] } }, maxDepth: 0 } },
  { hierarchy: { types: { root: { allowedChildren: [] } }, maxDepth: 1.5 } },
  { hierarchy: { types: { root: { allowedChildren: [] }, ' ': { allowedChildren: [] } } } },
  { hierarchy: { types: { root: { allowedChildren: [] }, team: 5 } } },
  { hierarchy: { types: 'root' } },
  { hierarchy: { maxDepth: 4 } },
  { hierarchy: 5 },
  { permissions: { mode: 'tenant-defined', resourceTypes: {} }, onboarding: { mode: 'linked', invitationLifetimeMs: 1000 } },
  { onboarding: { invitationLifetimeMs: 'soon' } },
  { accessRequests: { lifetimeMs: 59_999 } },
  { accessRequests: { lifetimeMs: 60_000, maxDurationSeconds: 60 } },
  { accessRequests: { maxDurationSeconds: 1e12 } },
  { events: { webhookTimeoutMs: 500 } },
  { events: { webhookTimeoutMs: 30_000 } },
  { tenantDefaults: { limits: { roles: 5 }, authPolicy: { requireMfa: true, maxSessions: 3 } } },
  { tenantDefaults: { limits: { seats: 5 } } },
  { tenantDefaults: { authPolicy: { requireMfa: 'yes' } } },
  { tenantDefaults: { limits: [] } },
  { clearances: {} },
  { clearances: { appliesToRoot: false } },
  { clearances: true },
  { clearances: [] },
  { clearances: { level: 1 } },
  { clearances: { appliesToRoot: 'no' } },
  { regions: { current: 'us-east-1', regions: { 'us-east-1': { baseURL: 'https://us.example.com/' }, 'eu-west-1': { label: 'Europe' } } } },
  { regions: { current: 'us-east-1', regions: {} } },
  { regions: { current: 'US', regions: { us: {} } } },
  { regions: 'eu' },
  { regions: { current: 'us', regions: { us: { label: '' } } } },
  { regions: { current: 'us', regions: { us: { baseURL: 'ftp://files.example.com' } } } },
  { hosts: { patterns: ['{tenant}.signin.example.com'], customHostnames: true, cnameTarget: 'custom.signin.example.com', signInPath: '/login' } },
  { hosts: { patterns: ['{tenant}.signin.{region}.example.com'] }, regions: { current: 'eu', regions: { eu: {}, 'us-east-1': {} } } },
  { hosts: { patterns: ['{tenant}.signin.{region}.example.com'] } },
  { hosts: { patterns: ['signin.example.com'] } },
  { hosts: { patterns: ['{tenant}{tenant}.example.com'] } },
  { hosts: { patterns: ['{tenant}.example.com:99999'] } },
  { hosts: { patterns: ['{tenant}.-bad.example.com'] } },
  { hosts: { patterns: [5] } },
  { hosts: { patterns: 'x' } },
  { hosts: { patterns: ['{tenant}.other.org'] }, authentication: { passkeys: { rpID: 'example.com' } } },
  { hosts: { cnameTarget: 'a:80' } },
  { hosts: { cnameTarget: 5 } },
  { hosts: { cnameTarget: '' } },
  { hosts: { signInPath: 'login' } },
  { hosts: { forwardedHost: 1 } },
  { hosts: null },
  { baseURL: 'http://localhost:3000', hosts: { patterns: ['{tenant}.localhost:3000'] } },
  { baseURL: 'http://localhost:3000', hosts: { patterns: ['{tenant}.example.com'] } },
  { sts: { maxRoleSessionSeconds: 7200, maxSessionTokenSeconds: 900, maxSessionTokensPerIdentity: 1000 } },
  { sts: { maxRoleSessionSeconds: 60 } },
  { sts: { maxSessionTokenSeconds: '3600' } },
  { sts: 5 },
  { sts: { webIdentity: { enabled: true, allowedIssuers: ['https://token.actions.githubusercontent.com', 'https://token.actions.githubusercontent.com'], jwksCacheSeconds: 60, fetchTimeoutMs: 10_000, maxJwksBytes: 1024, maxExchangesPerWindow: 1, maxSessionsPerTrust: 100_000 } } },
  { sts: { webIdentity: { enabled: 'yes' } } },
  { sts: { webIdentity: null } },
  { sts: { webIdentity: { allowedIssuers: 'https://a.example.com' } } },
  { sts: { webIdentity: { allowedIssuers: ['http://a.example.com'] } } },
  { sts: { webIdentity: { allowedIssuers: ['https://iam.example.com/api/iam/'] } } },
  { sts: { jwt: { issuer: 'https://issuer.example.com' }, webIdentity: { allowedIssuers: ['https://issuer.example.com'] } } },
  { sts: { webIdentity: { allowInsecureLocalhost: true, allowedIssuers: ['http://localhost:9000'] } } },
  { sts: { webIdentity: { jwksCacheSeconds: 59 } } },
  { sts: { webIdentity: { maxJwksBytes: 2_000_000 } } },
  { signals: { allowPrivateNetworks: true, allowInsecureLocalhost: true, pushPath: '/hooks/ssf' } },
  { signals: { pushPath: '/hooks//ssf' } },
  { signals: { pushPath: '/hooks/' } },
  { signals: { pushPath: 5 } },
  { signals: { allowPrivateNetworks: 'yes' } },
  { signals: null },
  { basePath: '/custom', signals: {} },
];
const resolveConfigCases = configInputs.map((input) => {
  const options = { ...base, ...input };
  const outcome = attempt(() => project(resolveConfig(options)));
  return { input, ...outcome };
});

const catalogInputs = [
  {},
  { permissions: { actions: ['documents:read', 'documents:write'] } },
  { permissions: { actions: ['iam:roles:create'] } },
  { permissions: { actions: ['tenant/x'] } },
  { permissions: { actions: ['documents:*'] } },
  { permissions: { actions: ['documents read'] } },
  { permissions: { actions: [''] } },
  { permissions: { actions: [5] } },
  { permissions: { actions: 'ab' } },
  { permissions: { identityAttributes: { department: 'string', level: 'number' } } },
  { permissions: { identityAttributes: { groups: 'string' } } },
  { permissions: { identityAttributes: { clearanceRank: 'number' } } },
  { permissions: { identityAttributes: { clearanceRank: 'number' } }, clearances: {} },
  { permissions: { identityAttributes: { level: 'date' } } },
  { permissions: { identityAttributes: { tenantId: 'string' } } },
  { permissions: { identityAttributes: [] } },
  {
    permissions: {
      resourceTypes: {
        project: { managed: true, actions: ['project:read', 'project:write'], attributes: { name: 'string' }, relations: ['owner', 'viewer', 'owner'], description: 'A project' },
        document: { managed: true, parent: 'project', actions: ['document:read'], attributes: { pages: 'number' } },
        report: { actions: ['report:read', 'project:read'] },
      },
    },
  },
  { permissions: { resourceTypes: { iam: {} } } },
  { permissions: { resourceTypes: { Bad: {} } } },
  { permissions: { resourceTypes: { doc: 'x' } } },
  { permissions: { resourceTypes: { doc: { attributes: { tenantId: 'string' } } } } },
  { permissions: { resourceTypes: { doc: { attributes: { classification: 'string' } } } } },
  { permissions: { resourceTypes: { doc: { attributes: { classification: 'string' } } } }, clearances: {} },
  { permissions: { resourceTypes: { doc: { relations: ['Owner'] } } } },
  { permissions: { resourceTypes: { doc: { actions: 'doc:read' } } } },
  { permissions: { resourceTypes: { doc: { description: '' } } } },
  { permissions: { resourceTypes: { doc: { parent: 'missing' } } } },
  { permissions: { resourceTypes: { doc: { parent: 'doc' } } } },
  { permissions: { resourceTypes: { a: { parent: 'b' }, b: { parent: 'a' } } } },
  { permissions: { resourceTypes: { folder: {}, doc: { managed: true, parent: 'folder' } } } },
  { permissions: { resourceTypes: { doc: { parent: null } } } },
  { permissions: { resourceTypes: { doc: { actions: ['doc:*'] } } } },
];
const catalogCases = catalogInputs.map((input) => {
  const options = { ...base, ...input };
  const outcome = attempt(() => {
    const config = resolveConfig(options);
    const catalog = new Catalog(options, [], config);
    return {
      actions: [...catalog.actions].slice(221),
      actionCount: catalog.actions.size,
      actionTypes: Object.fromEntries(catalog.actionTypes),
      resourceTypes: [...catalog.resourceTypes.values()].map((type) => ({
        ...type,
        description: type.description ?? null,
        parent: type.parent ?? null,
      })),
      namespaces: [...catalog.namespaces],
      identityAttributes: catalog.identityAttributes,
      reservedAttributes: catalog.reservedAttributes ? [...catalog.reservedAttributes] : null,
    };
  });
  return { input, ...outcome };
});

const policyInputs = [
  {},
  { requireMfa: true, allowedMethods: ['password', 'passkey', 'password'], sessionLifetimeMs: 3_600_000, sessionIdleTimeoutMs: 600_000 },
  { maxAttempts: 0 },
  { allowedMethods: ['impersonation'] },
  { allowedMethods: 'password' },
  { allowedIpRanges: ['10.0.0.0/8', '2001:db8::/32', '192.0.2.1'] },
  { allowedIpRanges: ['10.0.0.0/33'] },
  { trustedDeviceDays: 0, passwordHistory: 24, passwordMaxAgeDays: 3650, passwordMinClasses: 2 },
  { passwordMinClasses: 5 },
  { bindSessionsToIp: null },
  { unknown: true },
  null,
  'x',
];
const authPolicyCases = policyInputs.map((input) => ({ input, ...attempt(() => tenantAuthPolicy(input)) }));
const limitInputs = [{}, { identities: 10, webhooks: 0 }, { roles: 1e10 }, { roles: -1 }, { roles: '5' }, { seats: 1 }, []];
const limitCases = limitInputs.map((input) => ({ input, ...attempt(() => tenantLimits(input)) }));
const accessInputs = [
  {},
  { maxActivationMs: 60_000, approvalLifetimeMs: 300_000, requireJustification: true, requireMfa: false, requireApproval: true },
  { maxActivationMs: 59_999 },
  { approvalLifetimeMs: 31 * 86_400_000 },
  { requireMfa: 1 },
  { other: 1 },
  [],
];
const accessPolicyCases = accessInputs.map((input) => ({ input, ...attempt(() => tenantAccessPolicy(input)) }));

const NOW = 1_767_225_600_000;
const helpers = createContext({
  options: {},
  config: { maxDepth: 8 },
  store: {},
  auth: {},
  plugins: [],
  catalog: {},
  now: () => NOW,
  observe: {},
});
const windowInputs = [
  { from: '09:00', to: '17:00', timeZone: 'Europe/Berlin', days: [5, 1, 3, 1] },
  { from: '22:00', to: '06:00', timeZone: 'America/New_York' },
  { from: '09:00', to: '09:00', timeZone: 'UTC' },
  { from: '9:00', to: '17:00', timeZone: 'UTC' },
  { from: '09:00', to: '17:00', timeZone: 'Mars/Base' },
  { from: '09:00', to: '17:00', timeZone: 'utc' },
  { from: '09:00', to: '17:00', timeZone: 'PST' },
  { from: '09:00', to: '17:00', timeZone: '+05:30' },
  { from: '09:00', to: '17:00', timeZone: 'UTC', days: [] },
  { from: '09:00', to: '17:00', timeZone: 'UTC', days: [7] },
  { from: '09:00', to: '17:00', timeZone: 'UTC', days: 'mon' },
  { from: '09:00', to: '17:00' },
  { from: '23:60', to: '17:00', timeZone: 'UTC' },
];
const windowCases = windowInputs.map((input) => ({ input, ...attempt(() => helpers.accessWindow(input)) }));
const instants = [];
for (let hour = 0; hour < 24 * 8; hour += 5) instants.push(NOW + hour * 3_600_000 + 17 * 60_000);
const insideCases = [
  { from: '09:00', to: '17:00', timeZone: 'Europe/Berlin', days: [1, 2, 3, 4, 5] },
  { from: '22:00', to: '06:00', timeZone: 'America/New_York', days: [0, 6] },
  { from: '00:30', to: '23:30', timeZone: 'Asia/Kolkata' },
  { from: '18:00', to: '02:00', timeZone: 'Australia/Lord_Howe' },
].map((window) => ({ window, results: instants.map((at) => [at, insideWindow(window, at)]) }));
const startCases = [NOW, NOW - 60_001, NOW - 60_000, NOW + 1, NOW + 10 * 365 * 86_400_000 + 1, 1.5, '1', -1].map((input) => ({
  input,
  start: attempt(() => helpers.bindingStart(input)),
  expiry: attempt(() => helpers.bindingExpiry(input)),
}));
const slugCases = ['Acme-Corp', 'acme', '-acme', 'acme-', 'a'.repeat(63), 'a'.repeat(64), 'ac me', '', 5, 'ÄCME'].map((input) => ({
  input,
  ...attempt(() => slug(input)),
}));
const hostCases = [' Example.COM. ', 'a.b.:8080', '[::1]:3000', 'a b', '', 'host:123456', 'UPPER.example.com', 'x.:80', 'xn--bcher-kva.example', 'a..b', null].map((input) => ({
  input,
  result: normalizeHost(input) ?? null,
}));
const issuerInputs = [
  'https://token.actions.githubusercontent.com',
  'https://accounts.google.com/',
  '',
  'x'.repeat(513),
  'https://a.example.com/\u0007',
  'not a url',
  'http://idp.example.com',
  'http://localhost:9000',
  'https://user:pass@idp.example.com',
  'https://idp.example.com/?',
  'https://idp.example.com/#',
  'https://iam.example.com/api/iam/',
  5,
];
const issuerCases = issuerInputs.flatMap((input) =>
  [false, true].map((allowInsecureLocalhost) => ({
    input,
    allowInsecureLocalhost,
    ...attempt(() => webIdentityIssuer(input, { allowInsecureLocalhost, selfIssuer: 'https://iam.example.com/api/iam' })),
  })),
);

// Metrics: one deterministic sequence of spans, rendered and snapshotted.
const spans = [];
const kinds = ['operation', 'authorize', 'authorizeMany', 'listAccessible', 'auth', 'http'];
const names = ['iam:groups:create', 'iam:roles:read', 'documents:read', 'signIn', '/api/iam/groups/create', 'Zeta', 'alpha', 'beta-2', '(x)', 'x'.repeat(257)];
const outcomes = ['ok', 'denied', 'error'];
const codes = [undefined, 'ACCESS_DENIED', 'INVALID_INPUT', 'NOT_FOUND', 'UNAUTHENTICATED', 'RATE_LIMITED'];
let seed = 7;
const next = (n) => ((seed = (seed * 1103515245 + 12345) % 2147483648), seed % n);
for (let index = 0; index < 400; index++) {
  const kind = kinds[next(kinds.length)];
  const outcome = outcomes[next(outcomes.length)];
  const span = {
    kind,
    name: names[next(names.length)],
    outcome,
    ...(outcome === 'ok' ? {} : { code: codes[1 + next(codes.length - 1)] }),
    durationMs: [0.4, 3, 12.5, 80, 700, 4000, 20000, -1][next(8)],
    ...(kind === 'http' ? { status: [200, 201, 400, 401, 403, 404, 500][next(7)] } : {}),
  };
  spans.push(span);
}
const metricsCases = [{}, { maxSeries: 25, buckets: [1, 0.05, 0.25] }].map((options) => {
  const metrics = createMetrics(options);
  for (const span of spans) metrics.onSpan(span);
  return { options, render: metrics.render(), snapshot: metrics.snapshot() };
});

// Webhook endpoint validation (createEvents needs only options and config here).
const eventsFor = (baseURL, allowPrivateNetworks) =>
  createEvents({
    options: { events: { allowPrivateNetworks } },
    config: { baseURL: new URL(baseURL) },
    store: {},
    plugins: [],
    subscribers: new Set(),
  });
const webhookUrlInputs = [
  'https://hooks.example.com/iam',
  'https://hooks.example.com:8443/iam?x=1',
  'http://hooks.example.com/iam',
  'http://localhost:4000/hook',
  'https://user:pw@hooks.example.com/',
  'https://hooks.example.com/#',
  'https://hooks.example.com/#frag',
  'https://10.0.0.1/hook',
  'https://169.254.169.254/latest',
  'https://[::1]/x',
  'relative/path',
  '',
  5,
];
const webhookUrlCases = webhookUrlInputs.flatMap((input) =>
  [
    ['https://iam.example.com', false],
    ['http://localhost:3000', false],
    ['https://iam.example.com', true],
  ].map(([baseURL, allowPrivateNetworks]) => ({
    input,
    baseURL,
    allowPrivateNetworks,
    ...attempt(() => eventsFor(baseURL, allowPrivateNetworks).webhookUrl(input)),
  })),
);
const webhookEventsCases = [
  ['iam:groups:*', 'iam:groups:*', 'auth:sign-in'],
  [],
  ['bad pattern'],
  Array.from({ length: 51 }, (_, index) => `e${index}`),
  'iam:*',
].map((input) => ({ input, ...attempt(() => eventsFor('https://iam.example.com', false).webhookEvents(input)) }));

// The standalone configuration reader (scripts/conformance/lib/config.mjs) and resolveConfig on what it built.
const readerInputs = [
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com' }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', extra: 1 }, {}],
  [[], {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', store: 'x' }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', store: { kind: 'mysql' } }, {}],
  [{ baseURL: 'https://iam.example.com' }, {}],
  [{ secret: 5, baseURL: 'https://iam.example.com' }, {}],
  [{ secret: { env: 'KERNEL_SECRET' }, baseURL: 'https://iam.example.com' }, {}],
  [{ secret: { env: 'MISSING_SECRET' }, baseURL: 'https://iam.example.com' }, {}],
  [{ secret: 's'.repeat(32), previousSecrets: 'x', baseURL: 'https://iam.example.com' }, {}],
  [{ secret: 's'.repeat(32), previousSecrets: ['a', { env: 'MISSING' }], baseURL: 'https://iam.example.com' }, {}],
  [{ secret: 's'.repeat(32) }, {}],
  [{ secret: 's'.repeat(32), baseURL: 5 }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: [] }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { push: {} } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { email: 'x' } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { email: { kind: 'capture' } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { email: { kind: 'capture' } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { sms: { kind: 'http' } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { sms: { kind: 'smtp' } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', delivery: { webhook: { kind: 'log' }, events: { kind: 'log' } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', http: { clientInfo: 'x' } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', http: { clientInfo: { ipValue: 'last' } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', http: { clientInfo: { ipHeader: 'x-real-ip' }, cookieSameSite: 'strict' } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', resolveResource: { kind: 'echo' } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', resolveResource: { kind: 'db' } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', resolveResource: { $scripted: true } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', resolveResource: { $scripted: true } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', resolveContext: { kind: 'echo' } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', hosts: { patterns: { $scripted: true } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', authentication: { requireMfa: { $scripted: true } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', authentication: { requireMfa: { $scripted: true } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', vault: { rotators: { db: { rotate: { $scripted: true } } } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', vault: { engines: { pg: { issue: { $scripted: true }, other: { $scripted: true } } } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', sts: { webIdentity: { enabled: true, fetchJson: { $scripted: true } } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', sts: { webIdentity: { fetchJson: { $scripted: true } } } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'http://example.com', hosts: { patterns: ['{tenant}.example.com'] } }, {}],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', clearances: true, regions: { current: 'us', regions: { us: {} }, locate: { $scripted: true } } }, { conformance: true }],
  [{ secret: 's'.repeat(32), baseURL: 'https://iam.example.com', regions: { current: 'us', regions: { us: {} }, locate: { $scripted: true } } }, { conformance: true }],
  [{ $schema: './config.schema.json', secret: 's'.repeat(32), baseURL: 'https://iam.example.com', tenantDefaults: { limits: { roles: 'many' } } }, {}],
];
const readerCases = [];
for (const [config, mode] of readerInputs) {
  const runtime = {
    adapters: { sqliteAdapter: () => ({}) },
    env: { KERNEL_SECRET: 'from-the-environment-at-least-32-chars' },
    ...(mode.conformance
      ? { now: () => NOW, deliver: async () => undefined, scripted: (name) => Object.assign(() => undefined, { scriptedName: name }) }
      : {}),
  };
  let outcome;
  try {
    const options = await optionsFromConfig(config, runtime);
    outcome = attempt(() => {
      const resolved = project(resolveConfig(options));
      return { secret: options.secret, previousSecrets: options.previousSecrets ?? null, config: resolved };
    });
  } catch (thrown) {
    outcome = { error: error(thrown) };
  }
  readerCases.push({ config, conformance: Boolean(mode.conformance), ...outcome });
}

// The JSON form of http.clientInfo and the default (User-Agent only), on probe requests.
const headerSets = [
  [],
  [['user-agent', 'Probe/1']],
  [['user-agent', ''], ['x-real-ip', ' 192.0.2.1 , 198.51.100.2']],
  [['x-forwarded-for', '192.0.2.7'], ['x-device', 'Laptop']],
  [['User-Agent', 'Probe/2'], ['X-Forwarded-For', ',198.51.100.9'], ['x-device', '']],
];
const clientSpecs = [
  null,
  {},
  { ipHeader: 'x-real-ip' },
  { ipHeader: 'X-Forwarded-For', ipValue: 'whole', labelHeader: 'x-device' },
  { userAgent: false, ipHeader: 'x-forwarded-for', labelHeader: 'x-device' },
];
const clientCases = clientSpecs.flatMap((spec) =>
  headerSets.map((headers) => {
    const options = spec ? { http: { clientInfo: clientInfoFunction(spec) } } : {};
    return { spec, headers, result: clientFromHeaders(options, headers, 'https://iam.example.com') ?? null };
  }),
);

process.stdout.write(
  `${JSON.stringify(
    {
      node: process.version,
      icu: process.versions.icu,
      resolveConfig: resolveConfigCases,
      catalog: catalogCases,
      authPolicy: authPolicyCases,
      limits: limitCases,
      accessPolicy: accessPolicyCases,
      now: NOW,
      windows: windowCases,
      inside: insideCases,
      bindingTimes: startCases,
      slugs: slugCases,
      hosts: hostCases,
      issuers: issuerCases,
      metrics: { spans, cases: metricsCases },
      webhookUrls: webhookUrlCases,
      webhookEvents: webhookEventsCases,
      reader: readerCases,
      clientInfo: clientCases,
    },
    null,
    1,
  )}\n`,
);
