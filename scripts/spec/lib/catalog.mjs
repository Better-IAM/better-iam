// spec/catalog/actions.json: the built-in actions and resource types, exactly as the server's Catalog exposes them
// (`actions.list` / `resourceTypes.list` platform entries, in catalog order), for a default deployment and with each
// optional module that extends the catalog.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { dist, json, root } from './util.mjs';

export async function generateCatalog(output) {
  // The patterns and limits written below by hand must still be the ones the catalog enforces.
  const source = await readFile(join(root, 'packages/server/src/catalog.ts'), 'utf8');
  for (const fragment of [
    '/^([a-z][a-z0-9-]{0,63}):([a-zA-Z][a-zA-Z0-9_-]{0,63})$/',
    '/^[a-z][a-z0-9_-]{0,63}$/',
    '/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/',
    'unique.length > 32',
    'Object.keys(schema).length > 64',
    '(item as string).length > 2048',
    "text(declared.description, 'description', 512)",
  ])
    if (!source.includes(fragment))
      throw new Error(
        `packages/server/src/catalog.ts no longer contains ${fragment}: update scripts/spec/lib/catalog.mjs`,
      );
  const catalogModule = await dist('server', 'catalog.js');
  const { resolveConfig } = await dist('server', 'options.js');
  const { inferencePlugins } = await dist('server', 'inference.js');
  const { sshPlugins } = await dist('server', 'ssh.js');
  const { vcPlugins } = await dist('server', 'vc.js');
  const { sqliteAdapter } = await dist('adapter-sqlite');
  const database = sqliteAdapter({ filename: ':memory:' });
  const base = {
    database,
    secret: 'spec-generator-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
  };
  /** The catalog as `actions.list` and `resourceTypes.list` report its platform entries. */
  const view = (options) => {
    const plugins = [...inferencePlugins(options), ...sshPlugins(options), ...vcPlugins(options)];
    const config = resolveConfig(options);
    const catalog = new catalogModule.Catalog(options, plugins, config);
    return {
      plugins: plugins.map((plugin) => plugin.id),
      actions: [...catalog.actions].map((name) => ({
        name,
        source: 'platform',
        ...(catalog.actionTypes.get(name) !== undefined
          ? { resourceType: catalog.actionTypes.get(name) }
          : {}),
      })),
      resourceTypes: [...catalog.resourceTypes.values()].map((type) =>
        JSON.parse(JSON.stringify(type)),
      ),
      namespaces: [...catalog.namespaces],
      reservedAttributes: catalog.reservedAttributes ? [...catalog.reservedAttributes] : null,
    };
  };
  const defaults = view(base);
  const modules = {};
  for (const [name, extra] of [
    ['inference', { inference: true }],
    ['ssh', { ssh: true }],
    ['verifiableCredentials', { verifiableCredentials: true }],
    ['clearances', { clearances: {} }],
  ]) {
    const extended = view({ ...base, ...extra });
    const known = new Set(defaults.actions.map((action) => action.name));
    modules[name] = {
      option: Object.keys(extra)[0],
      plugins: extended.plugins,
      addedActions: extended.actions.filter((action) => !known.has(action.name)),
      addedResourceTypes: extended.resourceTypes,
      reservedAttributes: extended.reservedAttributes,
    };
  }
  const all = view({ ...base, inference: true, ssh: true, verifiableCredentials: true });
  await database.close();
  const value = {
    source: 'packages/server/src/catalog.ts',
    description:
      'Platform actions and resource types as Catalog holds them. `actions` keeps catalog order (built-ins, then configured actions, then plugin actions in plugin order: application plugins, inference, ssh, verifiable credentials). Tenant-defined actions and types come from the actions/resourceTypes collections.',
    builtInActions: [...catalogModule.builtInActions],
    default: defaults,
    modules,
    allModules: all,
    internalResourceTypes: [...catalogModule.internalResourceTypes],
    reservedResourceTypes: [...catalogModule.reservedResourceTypes],
    reservedPrincipalKeys: [...catalogModule.reservedPrincipalKeys],
    clearancePrincipalNames: [...catalogModule.clearancePrincipalNames],
    classificationAttributeNames: [...catalogModule.classificationAttributeNames],
    patterns: {
      resourceTypeName: catalogModule.resourceTypeName.source,
      tenantAction: '^([a-z][a-z0-9-]{0,63}):([a-zA-Z][a-zA-Z0-9_-]{0,63})$',
      relationName: '^[a-z][a-z0-9_-]{0,63}$',
      attributeName: '^[a-zA-Z][a-zA-Z0-9_]{0,63}$',
    },
    limits: {
      maxRelationsPerType: 32,
      maxAttributesPerType: 64,
      maxAttributeStringLength: 2048,
      descriptionLength: 512,
    },
    rules: [
      'Configured and plugin actions may not start with iam: or tenant/ and may not contain *, ? or whitespace (INVALID_CONFIG "Reserved or invalid action").',
      'Attribute types are string, number or boolean; tenantId is never an attribute name.',
      'Tenant actions need permissions.mode tenant-defined (CATALOG_LOCKED 403) and an existing tenant resource type named by their prefix.',
    ],
  };
  output.add('catalog/actions.json', json(value, { sorted: false }));
  return `actions.json (${value.builtInActions.length} built-in actions, ${all.actions.length} with all modules, ${all.resourceTypes.length} module resource types)`;
}
