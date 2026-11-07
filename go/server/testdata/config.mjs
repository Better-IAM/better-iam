// Writes config.json: standalone configurations (spec/conformance/CONFIG.md) read by the TypeScript reader
// (scripts/conformance/lib/config.mjs optionsFromConfig) and validated by resolveConfig and the Catalog, with the
// error each one fails with or a summary of the resulting configuration, for the Go differential test
// (standalone_config_test.go). Each case runs both outside and inside conformance mode.
// Regenerate (after building the TypeScript packages): node go/server/testdata/config.mjs > go/server/testdata/config.json
import { optionsFromConfig } from '../../../scripts/conformance/lib/config.mjs';
import { resolveConfig } from '../../../packages/server/dist/options.js';
import { Catalog } from '../../../packages/server/dist/catalog.js';
import { sqliteAdapter } from '../../../packages/adapter-sqlite/dist/index.js';

const secret = 'standalone-config-secret-with-at-least-32-characters';
const base = { secret, baseURL: 'http://localhost:3000' };
const env = { IAM_SECRET: secret, EMPTY: '' };
const scripted = { $scripted: true };
const configs = [
  base,
  { ...base, $schema: './config.schema.json', store: { kind: 'sqlite', path: ':memory:' } },
  [],
  'text',
  { ...base, nope: 1 },
  { ...base, store: 'sqlite' },
  { ...base, store: { kind: 'mysql' } },
  { ...base, store: { kind: 'postgres', url: 'postgres://localhost/iam' } },
  { ...base, store: { kind: 'libsql', url: ':memory:' } },
  { baseURL: 'http://localhost:3000' },
  { ...base, secret: { env: 'IAM_SECRET' } },
  { ...base, secret: { env: 'MISSING' } },
  { ...base, secret: { env: 'EMPTY' } },
  { ...base, secret: 42 },
  { ...base, previousSecrets: 'old' },
  { ...base, previousSecrets: ['old-secret', { env: 'IAM_SECRET' }] },
  { ...base, previousSecrets: ['old-secret', { env: 'MISSING' }] },
  { secret },
  { secret, baseURL: 7 },
  { ...base, baseURL: 'http://iam.example.com' },
  { ...base, baseURL: 'https://iam.example.com', basePath: '/iam', trustedOrigins: ['https://app.example.com'] },
  { ...base, basePath: '/iam/' },
  { ...base, delivery: [] },
  { ...base, delivery: { pager: { kind: 'log' } } },
  { ...base, delivery: { email: 'log' } },
  { ...base, delivery: { email: { kind: 'capture' } } },
  { ...base, delivery: { email: { kind: 'log' }, sms: { kind: 'http' } } },
  { ...base, delivery: { webhook: { kind: 'carrier-pigeon' } } },
  { ...base, delivery: { email: { kind: 'log' }, events: { kind: 'http', url: 'http://localhost:9/events' } } },
  { ...base, http: { clientInfo: 'x-forwarded-for' } },
  { ...base, http: { clientInfo: { ipHeader: 'x-real-ip', ipValue: 'last' } } },
  { ...base, http: { cookieSameSite: 'strict', clientInfo: { ipHeader: 'x-real-ip' } } },
  { ...base, resolveResource: { kind: 'echo' } },
  { ...base, resolveResource: { kind: 'database' } },
  { ...base, resolveResource: scripted },
  { ...base, resolveContext: { kind: 'echo' } },
  { ...base, resolveContext: scripted },
  { ...base, authentication: { requireMfa: scripted, passwordPolicy: { check: scripted } } },
  { ...base, authentication: { sendEmail: scripted } },
  { ...base, hosts: { patterns: [scripted] } },
  { ...base, regions: { current: 'eu', regions: { eu: {} }, locate: scripted } },
  { ...base, regions: { current: 'eu', regions: { eu: {} }, locate: 'nope' } },
  {
    ...base,
    vault: { rotators: { db: { rotate: scripted } }, engines: { pg: { issue: scripted, renew: scripted } } },
  },
  { ...base, sts: { maxRoleSessionSeconds: '3600' } },
  {
    ...base,
    sts: {
      webIdentity: {
        enabled: true,
        fetchJson: scripted,
        allowedIssuers: ['https://token.actions.githubusercontent.com'],
      },
    },
  },
  { ...base, sts: { webIdentity: { fetchJson: 'https://proxy' } } },
  {
    ...base,
    hierarchy: { types: { root: { allowedChildren: ['team'] }, team: { allowedChildren: [] } }, maxDepth: 4 },
  },
  { ...base, hierarchy: { types: { root: { allowedChildren: ['team'] } } } },
  { ...base, permissions: { actions: ['documents:read', 'iam:own'] } },
  {
    ...base,
    permissions: {
      mode: 'tenant-defined',
      actions: ['documents:read'],
      resourceTypes: {
        folder: { managed: true, actions: ['folder:read'], attributes: { owner: 'string' }, relations: ['viewer'] },
      },
      identityAttributes: { level: 'number' },
    },
  },
  { ...base, permissions: { identityAttributes: { roles: 'string' } } },
  { ...base, tenantDefaults: { limits: { seats: 3 } } },
  {
    ...base,
    tenantDefaults: { limits: { identities: 3 }, authPolicy: { requireMfa: true, minPasswordLength: 16 } },
  },
  { ...base, clearances: { appliesToRoot: 'no' } },
  { ...base, clearances: {}, permissions: { identityAttributes: { clearanceRank: 'number' } } },
  { ...base, signals: { pushPath: '/ssf/push' } },
  { ...base, signals: { pushPath: 'ssf' } },
  { ...base, hosts: { patterns: ['{tenant}.localhost:3000'], customHostnames: true } },
  { ...base, hosts: { patterns: ['{tenant}.signin.example.com'] } },
  {
    ...base,
    onboarding: { mode: 'linked', invitationLifetimeMs: 3600000 },
    accessRequests: { lifetimeMs: 120000 },
  },
  { ...base, accessRequests: { maxDurationSeconds: 1.5 } },
  { ...base, events: { webhookTimeoutMs: 500 } },
  {
    ...base,
    observability: { metrics: { bearerToken: 'scrape', buckets: [0.1, 1] } },
    accessUsage: true,
    ssh: { maxHostsPerCertificate: 8 },
  },
  { ...base, auditArchive: { write: scripted, batchSize: 10 } },
  { ...base, domains: { resolveTxt: scripted, blockedDomains: ['gmail.com'] } },
];
const runtimes = [
  { name: 'standalone', runtime: { adapters: { sqliteAdapter }, env } },
  {
    name: 'conformance',
    runtime: {
      adapters: { sqliteAdapter },
      env,
      now: () => 0,
      deliver: async () => {},
      scripted: (path) => () => path,
    },
  },
];
const summary = (config) => ({
  basePath: config.basePath,
  trustedOrigins: [...config.trustedOrigins],
  maxDepth: config.maxDepth,
  hierarchy: Object.keys(config.hierarchy.types),
  tenantDefined: config.tenantDefined,
  strictResourceTypes: config.strictResourceTypes,
  linkedOnboarding: config.linkedOnboarding,
  invitationLifetimeMs: config.invitationLifetimeMs,
  accessRequestLifetimeMs: config.accessRequestLifetimeMs,
  webhookTimeoutMs: config.webhookTimeoutMs,
  tenantDefaults: config.tenantDefaults,
  sts: config.sts,
  signals: config.signals,
  hosts: config.hosts.patterns.map((pattern) => pattern.source),
  regions: config.regions ? [config.regions.current, [...config.regions.regions.keys()]] : null,
  clearances: config.clearances ?? null,
});
const errorOf = (error) => ({ name: error.name, code: error.code ?? null, message: error.message });
const cases = [];
for (const config of configs) {
  const results = {};
  for (const { name, runtime } of runtimes) {
    let options;
    try {
      options = await optionsFromConfig(structuredClone(config), runtime);
      const resolved = resolveConfig(options);
      const catalog = new Catalog(options, options.plugins ?? [], resolved);
      results[name] = {
        config: summary(resolved),
        actions: catalog.actions.size,
        resourceTypes: [...catalog.resourceTypes.keys()],
      };
    } catch (error) {
      results[name] = { error: errorOf(error) };
    } finally {
      await options?.database?.close?.();
    }
  }
  cases.push({ config, ...results });
}
process.stdout.write(JSON.stringify({ node: process.version, env, cases }) + '\n');
