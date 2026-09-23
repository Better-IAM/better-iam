// Generates the data behind the reference section of the docs site from the repository itself:
//
//   generated/api.json       every `iam.api` group and method with its HTTP route, credential requirement,
//                            JSDoc, and input/result types (read from packages/server/dist/index.d.ts)
//   generated/errors.json    every IamError code thrown in packages/*/src with its statuses and messages
//   generated/cli.json       the `better-iam` CLI commands, usage lines, and descriptions
//   generated/packages.json  the publishable packages, their subpath exports, and dependencies
//   generated/exports.json   every runtime export of every entry point, with parameters and JSDoc
//   content/docs/reference/changelog.md   CHANGELOG.md with frontmatter
//
// Run `pnpm build` at the workspace root first (the API catalog is read from built declarations and a live
// in-memory instance), then `pnpm --filter @better-iam/docs generate`.
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const here = dirname(fileURLToPath(import.meta.url));
const app = resolve(here, '..');
const root = resolve(app, '..', '..');
const out = join(app, 'generated');
await mkdir(out, { recursive: true });
const siteUrl = (process.env.DOCS_SITE_URL ?? 'http://localhost:4000').replace(/\/$/, '');
const { version } = JSON.parse(
  await readFile(join(root, 'packages/better-iam/package.json'), 'utf8'),
);

const prettier = await import(
  pathToFileURL(join(root, 'node_modules', 'prettier', 'index.mjs')).href
).catch(() => undefined);

async function formatType(raw) {
  // Declarations reference sibling modules as import('./models.js').Group; readers only need the name.
  const text = raw.replace(/import\((['"])[^'"]+\1\)\./g, '');
  if (!prettier) return text;
  try {
    const formatted = await prettier.format(`type T = ${text};`, {
      parser: 'typescript',
      printWidth: 88,
      singleQuote: true,
    });
    return formatted
      .replace(/^type T =\s*/, '')
      .replace(/;\s*$/, '')
      .trim();
  } catch {
    return text;
  }
}

// ---------------------------------------------------------------------------------------------------------
// API catalog
// ---------------------------------------------------------------------------------------------------------

async function generateApi() {
  const server = await import(pathToFileURL(join(root, 'packages/server/dist/index.js')).href);
  const { sqliteAdapter } = await import(
    pathToFileURL(join(root, 'packages/adapter-sqlite/dist/index.js')).href
  );
  const database = sqliteAdapter({ filename: ':memory:' });
  const iam = server.betterIam({
    database,
    secret: 'docs-site-generator-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: { sendEmail: async () => {}, sendSms: async () => {}, passwordlessEmail: true },
  });
  const live = Object.fromEntries(
    Object.keys(iam.api)
      .sort()
      .map((group) => [group, Object.keys(iam.api[group]).sort()]),
  );
  const topLevel = Object.keys(iam)
    .filter((key) => typeof iam[key] === 'function')
    .sort();
  await database.close();

  const declarations = join(root, 'packages/server/dist/index.d.ts');
  const program = ts.createProgram([declarations], {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    strict: true,
    skipLibCheck: true,
    noEmit: true,
  });
  const checker = program.getTypeChecker();
  const sourceFile = program.getSourceFile(declarations);
  const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
  const exported = checker.getExportsOfModule(moduleSymbol);
  const factory = exported.find((symbol) => symbol.name === 'betterIam');
  const factoryType = checker.getTypeOfSymbolAtLocation(factory, sourceFile);
  const instanceType = checker
    .getSignaturesOfType(factoryType, ts.SignatureKind.Call)[0]
    .getReturnType();
  const apiType = checker.getTypeOfSymbolAtLocation(instanceType.getProperty('api'), sourceFile);

  const flags =
    ts.TypeFormatFlags.NoTruncation |
    ts.TypeFormatFlags.UseAliasDefinedOutsideCurrentScope |
    ts.TypeFormatFlags.UseSingleQuotesForStringLiteralType |
    ts.TypeFormatFlags.WriteArrowStyleSignature;
  const typeText = (type) => checker.typeToString(type, sourceFile, flags);

  const docsOf = (symbol) => ({
    description: ts.displayPartsToString(symbol.getDocumentationComment(checker)).trim(),
    tags: symbol.getJsDocTags(checker).map((tag) => ({
      name: tag.name,
      text: ts.displayPartsToString(tag.text ?? []).trim(),
    })),
  });

  // TypeScript types -> JSON Schema (2020-12, as used by OpenAPI 3.1). Named interfaces and aliases become shared
  // components referenced with $ref, which also terminates recursive types such as `Json`.
  const schemas = {};
  const componentNames = new Map();
  const generic = new Set([
    'Record',
    'Partial',
    'Required',
    'Readonly',
    'Pick',
    'Omit',
    'Promise',
    'Array',
    'NoInfer',
  ]);
  function componentName(type) {
    const symbol = type.aliasSymbol ?? type.getSymbol();
    if (!symbol) return undefined;
    const name = symbol.getName();
    if (!name || name.startsWith('__') || generic.has(name) || name === 'default') return undefined;
    if (type.aliasSymbol && type.aliasTypeArguments?.length) return undefined;
    if (!type.aliasSymbol && !(symbol.flags & (ts.SymbolFlags.Interface | ts.SymbolFlags.Class)))
      return undefined;
    if (checker.isArrayType(type)) return undefined;
    return name;
  }
  function schemaOf(type, depth = 0) {
    if (depth > 12) return {};
    const f = type.flags;
    if (f & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return {};
    if (f & ts.TypeFlags.StringLiteral) return { type: 'string', const: type.value };
    if (f & ts.TypeFlags.NumberLiteral) return { type: 'number', const: type.value };
    if (f & ts.TypeFlags.BooleanLiteral)
      return { type: 'boolean', const: type.intrinsicName === 'true' };
    if (f & ts.TypeFlags.String || f & ts.TypeFlags.TemplateLiteral) return { type: 'string' };
    if (f & ts.TypeFlags.Number) return { type: 'number' };
    if (f & ts.TypeFlags.Boolean) return { type: 'boolean' };
    if (f & ts.TypeFlags.Null) return { type: 'null' };
    if (f & (ts.TypeFlags.Undefined | ts.TypeFlags.Void | ts.TypeFlags.Never)) return {};
    const name = componentName(type);
    if (name === 'Json') return { description: 'Any JSON value' };
    if (name && depth > 0) {
      if (!componentNames.has(type)) {
        let unique = name;
        for (let i = 2; Object.hasOwn(schemas, unique); i++) unique = `${name}${i}`;
        componentNames.set(type, unique);
        schemas[unique] = {};
        schemas[unique] = describeObject(type, depth);
      }
      return { $ref: `#/components/schemas/${componentNames.get(type)}` };
    }
    return describeObject(type, depth);
  }
  function describeObject(type, depth) {
    if (type.isUnion()) {
      const members = type.types.filter(
        (member) => !(member.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void)),
      );
      const literals = members.every((member) => member.flags & ts.TypeFlags.StringLiteral);
      if (literals) return { type: 'string', enum: members.map((member) => member.value) };
      if (members.every((member) => member.flags & ts.TypeFlags.BooleanLiteral))
        return { type: 'boolean' };
      const variants = members.map((member) => schemaOf(member, depth + 1));
      return variants.length === 1 ? variants[0] : { anyOf: variants };
    }
    if (type.isIntersection())
      return { allOf: type.types.map((member) => schemaOf(member, depth + 1)) };
    if (checker.isArrayType(type))
      return { type: 'array', items: schemaOf(checker.getTypeArguments(type)[0], depth + 1) };
    if (checker.isTupleType(type))
      return {
        type: 'array',
        prefixItems: checker.getTypeArguments(type).map((item) => schemaOf(item, depth + 1)),
      };
    if (type.getCallSignatures().length) return { description: 'Function (not serializable)' };
    const properties = {};
    const required = [];
    for (const property of checker.getPropertiesOfType(type)) {
      const propertyType = checker.getTypeOfSymbolAtLocation(property, sourceFile);
      if (propertyType.getCallSignatures().length) continue;
      const schema = { ...schemaOf(propertyType, depth + 1) };
      const doc = ts.displayPartsToString(property.getDocumentationComment(checker)).trim();
      if (doc && !schema.$ref) schema.description = doc;
      properties[property.getName()] = schema;
      if (!(property.flags & ts.SymbolFlags.Optional)) required.push(property.getName());
    }
    const result = { type: 'object', properties };
    if (required.length) result.required = required;
    const index = checker.getIndexInfosOfType(type)[0];
    if (index) result.additionalProperties = schemaOf(index.type, depth + 1);
    else if (Object.keys(properties).length) result.additionalProperties = false;
    return result;
  }

  async function describeFunction(symbol) {
    const type = checker.getTypeOfSymbolAtLocation(symbol, sourceFile);
    const signature = checker.getSignaturesOfType(type, ts.SignatureKind.Call)[0];
    if (!signature) return { ...docsOf(symbol), params: [], result: typeText(type) };
    const params = [];
    for (const parameter of signature.getParameters()) {
      const declaration = parameter.valueDeclaration;
      const parameterType = checker.getTypeOfSymbolAtLocation(parameter, sourceFile);
      params.push({
        name: parameter.name,
        optional: Boolean(
          declaration &&
            ts.isParameter(declaration) &&
            (declaration.questionToken || declaration.initializer),
        ),
        type: await formatType(typeText(parameterType)),
        schema: schemaOf(parameterType, 1),
      });
    }
    const returned = signature.getReturnType();
    const awaited = checker.getAwaitedType(returned) ?? returned;
    return {
      ...docsOf(symbol),
      params,
      async: awaited !== returned,
      result: await formatType(typeText(awaited)),
      resultSchema: schemaOf(awaited, 1),
    };
  }

  const groups = [];
  let methods = 0;
  for (const [group, names] of Object.entries(live)) {
    const groupSymbol = apiType.getProperty(group);
    const groupType = groupSymbol
      ? checker.getTypeOfSymbolAtLocation(groupSymbol, sourceFile)
      : undefined;
    const routed = group === 'auth' || server.routeGroups.has(group);
    const entries = [];
    for (const method of names) {
      const symbol = groupType?.getProperty(method);
      let credential = 'required';
      if (group === 'auth')
        credential = server.publicAuthMethods.has(method)
          ? 'none'
          : server.authenticatedAuthMethods.has(method)
            ? 'required'
            : 'not routed';
      else if (server.publicApiMethods.has(`${group}/${method}`)) credential = 'none';
      entries.push({
        name: method,
        http: routed && credential !== 'not routed' ? `POST /${group}/${method}` : null,
        credential,
        ...(symbol
          ? await describeFunction(symbol)
          : { description: '', tags: [], params: [], result: 'unknown' }),
      });
    }
    methods += entries.length;
    groups.push({ name: group, routed, methods: entries });
  }

  const top = [];
  for (const name of topLevel) {
    const symbol = instanceType.getProperty(name);
    if (symbol) top.push({ name, ...(await describeFunction(symbol)) });
  }

  const data = {
    generatedAt: new Date().toISOString(),
    basePath: '/api/iam',
    groups,
    topLevel: top,
    schemas,
  };
  await writeFile(join(out, 'api.json'), JSON.stringify(data, null, 1));
  await writeStats({
    groups: groups.filter((group) => group.methods.length).length,
    methods,
    functions: top.length,
  });
  return `${groups.length} groups, ${methods} methods, ${top.length} top-level functions`;
}

/** Small counts for the landing page, merged into generated/stats.json so pages never import the big catalogs. */
async function writeStats(patch) {
  const file = join(out, 'stats.json');
  let stats = {};
  try {
    stats = JSON.parse(await readFile(file, 'utf8'));
  } catch {
    // First run.
  }
  await writeFile(file, JSON.stringify({ ...stats, ...patch }, null, 2) + '\n');
}

// ---------------------------------------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------------------------------------

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'dist') yield* walk(path);
    } else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) yield path;
  }
}

async function generateErrors() {
  const codes = new Map();
  const pattern =
    /new IamError\(\s*'([A-Z][A-Z0-9_]+)'\s*,\s*(`(?:[^`\\]|\\.)*`|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[^,)]+)\s*(?:,\s*(\d{3}))?/g;
  // Codes raised through subclasses: `class SessionNetworkMismatch extends IamError { constructor() { super('CODE', …, 401) } }`.
  const subclass =
    /class\s+\w+\s+extends\s+IamError[\s\S]{0,600}?super\(\s*'([A-Z][A-Z0-9_]+)'\s*,\s*(`(?:[^`\\]|\\.)*`|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[^,)]+)\s*(?:,\s*(\d{3}))?/g;
  for (const pkg of await readdir(join(root, 'packages'))) {
    const src = join(root, 'packages', pkg, 'src');
    try {
      for await (const file of walk(src)) {
        const text = await readFile(file, 'utf8');
        for (const match of [...text.matchAll(pattern), ...text.matchAll(subclass)]) {
          const [, code, rawMessage, status] = match;
          const entry = codes.get(code) ?? {
            code,
            statuses: new Set(),
            messages: new Set(),
            packages: new Set(),
            count: 0,
          };
          entry.count++;
          entry.statuses.add(Number(status ?? 400));
          entry.packages.add(`@better-iam/${pkg}`.replace('@better-iam/better-iam', 'better-iam'));
          const literal = rawMessage.trim();
          if (/^['"`]/.test(literal)) {
            const message = literal
              .slice(1, -1)
              .replace(/\$\{[^}]+\}/g, '…')
              .replace(/\\(['"`])/g, '$1');
            if (message.length < 160 && entry.messages.size < 6) entry.messages.add(message);
          }
          codes.set(code, entry);
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  const list = [...codes.values()]
    .map((entry) => ({
      code: entry.code,
      statuses: [...entry.statuses].sort(),
      messages: [...entry.messages],
      packages: [...entry.packages].sort(),
      occurrences: entry.count,
    }))
    .sort((a, b) => a.code.localeCompare(b.code));
  await writeFile(join(out, 'errors.json'), JSON.stringify(list, null, 1));
  await writeStats({ errorCodes: list.length });
  return `${list.length} error codes`;
}

// ---------------------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------------------

/** Descriptions for commands whose help notes do not describe them in a sentence of their own. */
const cliFallback = {
  init: 'Writes a starter `better-iam.config.mjs` for SQLite, PostgreSQL, or libSQL.',
  migrate:
    'Creates or upgrades the database schema. Run it on every deploy before the application starts.',
  bootstrap:
    'Creates the root administrator from BETTER_IAM_ROOT_EMAIL, BETTER_IAM_ROOT_NAME, and BETTER_IAM_ROOT_PASSWORD. The root must enroll MFA before use.',
  'recover-root':
    'Creates a new root administrator from the same environment variables as bootstrap, for when every root credential is lost; the action is audited as `root:recover`.',
  outbox: 'Delivers pending transactional messages from the encrypted delivery outbox.',
  purge:
    'Removes tenants deleted more than --retention-days (default 30) ago, including their data, and records the action in the audit log. Audit records remain.',
};

/** Flags every configuration or token command takes; the CLI page explains them once instead of per command. */
const commonCliFlags = new Set(['--config', '--url', '--profile', '--format', '--query']);

async function generateCli() {
  // The CLI describes itself: `cliManifest()` (also `better-iam help --json`) lists every command with its usage,
  // flags (value, default, environment variable), examples, and description. Build packages/cli first.
  const { cliManifest } = await import(
    pathToFileURL(join(root, 'packages/cli/dist/index.js')).href
  );
  const manifest = cliManifest();
  const commands = manifest.commands.map((command) => ({
    name: command.name,
    group: command.group,
    summary: command.summary,
    usage: command.usage,
    target: command.target,
    args: command.args,
    flags: command.flags.map((flag) => ({
      flag: flag.flag,
      value: flag.value,
      optional: flag.optional,
      description: flag.description,
      ...(flag.env ? { env: flag.env } : {}),
      ...(flag.default !== undefined ? { default: flag.default } : {}),
      ...(flag.choices ? { choices: flag.choices } : {}),
    })),
    examples: command.examples,
    description: command.description || cliFallback[command.name] || '',
  }));
  // `env` stays a list of names (older readers filter it); `environment` adds what each variable does.
  const env = manifest.env.map((entry) => entry.name);
  const notes = commands.map((command) => command.description).join(' ');
  await writeFile(
    join(out, 'cli.json'),
    JSON.stringify(
      { version: manifest.version, commands, env, environment: manifest.env, notes },
      null,
      1,
    ),
  );
  await writeStats({ cliCommands: commands.length });
  return `${commands.length} CLI commands`;
}

// ---------------------------------------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------------------------------------

const descriptions = {
  'better-iam': 'Umbrella package: installs every package and exposes them as subpath imports.',
  '@better-iam/core':
    'Models, the policy engine, the storage contract, the audit chain, and shared errors.',
  '@better-iam/auth':
    'Passwords, sessions, MFA, passkeys, magic links, recovery, and delivery templates.',
  '@better-iam/server':
    'The `betterIam()` factory: tenants, identities, authorization, governance, HTTP API.',
  '@better-iam/client': 'Typed browser client with session store and passkey helpers.',
  '@better-iam/oauth':
    'OAuth/OIDC authorization server, resource-server helpers, and Shared Signals.',
  '@better-iam/saml': 'SAML 2.0 service provider with tenant-managed connections.',
  '@better-iam/scim': 'SCIM 2.0 inbound provisioning and outbound provisioning to applications.',
  '@better-iam/adapter-postgres': 'PostgreSQL storage adapter.',
  '@better-iam/adapter-sqlite': 'SQLite storage adapter (better-sqlite3).',
  '@better-iam/adapter-libsql': 'libSQL / Turso storage adapter.',
  '@better-iam/cli':
    'The `better-iam` command line: migrations, bootstrap, audits, config as code, jobs.',
  '@better-iam/projects': 'Reference tenant-scoped Projects plugin.',
  '@better-iam/react': 'React provider, hooks, and permission-gated components.',
  '@better-iam/next':
    'Next.js App Router helpers: guarded pages, routes, actions, and edge checks.',
  '@better-iam/nestjs': 'NestJS module, guard, decorators, and testing utilities.',
  '@better-iam/vue': 'Vue plugin, composables, and the `IamCan` component.',
  '@better-iam/nuxt': 'Nuxt module and h3 helpers.',
  '@better-iam/svelte': 'Svelte stores and SvelteKit hooks, guards, and actions.',
  '@better-iam/middleware':
    'Framework-neutral middleware core with Express, Hono, and Fastify adapters.',
  '@better-iam/react-router':
    'React Router (framework mode) middleware, guarded loaders, and actions.',
};

async function generatePackages() {
  const list = [];
  for (const dir of (await readdir(join(root, 'packages'))).sort()) {
    const manifest = JSON.parse(
      await readFile(join(root, 'packages', dir, 'package.json'), 'utf8'),
    );
    const internal = (deps) =>
      Object.keys(deps ?? {}).filter(
        (name) => name === 'better-iam' || name.startsWith('@better-iam/'),
      );
    const external = (deps) =>
      Object.keys(deps ?? {}).filter(
        (name) => !(name === 'better-iam' || name.startsWith('@better-iam/')),
      );
    list.push({
      name: manifest.name,
      directory: `packages/${dir}`,
      version: manifest.version,
      description: descriptions[manifest.name] ?? manifest.description,
      exports: Object.keys(manifest.exports ?? { '.': null }).map((key) =>
        key === '.' ? manifest.name : `${manifest.name}/${key.slice(2)}`,
      ),
      internalDependencies: internal(manifest.dependencies),
      dependencies: external(manifest.dependencies),
      peerDependencies: Object.keys(manifest.peerDependencies ?? {}),
    });
  }
  list.sort((a, b) =>
    a.name === 'better-iam' ? -1 : b.name === 'better-iam' ? 1 : a.name.localeCompare(b.name),
  );
  await writeFile(join(out, 'packages.json'), JSON.stringify(list, null, 1));
  await writeStats({ packages: list.length });
  return `${list.length} packages`;
}

// ---------------------------------------------------------------------------------------------------------
// Package exports
// ---------------------------------------------------------------------------------------------------------

/** The runtime kind of an exported symbol, or null for types and interfaces (documented on the Types page). */
function exportKind(symbol) {
  if (symbol.flags & ts.SymbolFlags.Function) return 'function';
  if (symbol.flags & ts.SymbolFlags.Class) return 'class';
  if (symbol.flags & ts.SymbolFlags.Enum) return 'enum';
  if (symbol.flags & ts.SymbolFlags.Variable) return 'const';
  return null;
}

/**
 * Every runtime export (function, class, constant) of every `@better-iam/*` entry point, read from the built
 * declarations: its parameter names, JSDoc, and the package it is originally declared in.
 */
async function generateExports() {
  const entries = [];
  for (const dir of (await readdir(join(root, 'packages'))).sort()) {
    let manifest;
    try {
      manifest = JSON.parse(await readFile(join(root, 'packages', dir, 'package.json'), 'utf8'));
    } catch {
      continue;
    }
    // The umbrella package only re-exports the others.
    if (manifest.name === 'better-iam' || manifest.private) continue;
    for (const [key, value] of Object.entries(manifest.exports ?? {})) {
      const types =
        value && typeof value === 'object' ? (value.types ?? value.import?.types) : undefined;
      if (!types?.endsWith('.d.ts')) continue;
      entries.push({
        specifier: key === '.' ? manifest.name : `${manifest.name}/${key.slice(2)}`,
        package: manifest.name,
        file: join(root, 'packages', dir, types),
      });
    }
  }
  const packageOfDirectory = new Map();
  for (const entry of entries)
    packageOfDirectory.set(relative(root, entry.file).split(/[\\/]/)[1], entry.package);
  // An entry point whose declarations are not built yet (a package another contributor is still writing) keeps what
  // the previous run recorded for it instead of failing the whole step.
  let previous = [];
  try {
    previous = JSON.parse(await readFile(join(out, 'exports.json'), 'utf8'));
  } catch {
    // First run.
  }
  const built = await Promise.all(
    entries.map((entry) =>
      readFile(entry.file).then(
        () => true,
        () => false,
      ),
    ),
  );
  const unbuilt = entries.filter((_, index) => !built[index]);
  entries.splice(0, entries.length, ...entries.filter((_, index) => built[index]));

  const program = ts.createProgram(
    entries.map((entry) => entry.file),
    {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      strict: true,
      skipLibCheck: true,
      noEmit: true,
    },
  );
  const checker = program.getTypeChecker();
  const result = [];
  for (const entry of entries) {
    const source = program.getSourceFile(entry.file);
    if (!source)
      throw new Error(
        `Missing ${relative(root, entry.file)}; run \`pnpm build\` at the root first`,
      );
    const moduleSymbol = checker.getSymbolAtLocation(source);
    const items = [];
    for (const exported of moduleSymbol ? checker.getExportsOfModule(moduleSymbol) : []) {
      const symbol =
        exported.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(exported) : exported;
      const kind = exportKind(symbol);
      if (!kind) continue;
      const type = checker.getTypeOfSymbolAtLocation(symbol, source);
      const signature =
        kind === 'class' ? undefined : checker.getSignaturesOfType(type, ts.SignatureKind.Call)[0];
      const params = signature?.getParameters().map((param) => {
        const declaration = param.valueDeclaration;
        const rest = Boolean(
          declaration && ts.isParameter(declaration) && declaration.dotDotDotToken,
        );
        const optional =
          declaration &&
          ts.isParameter(declaration) &&
          !rest &&
          Boolean(declaration.questionToken || declaration.initializer);
        // Destructured parameters are named __0 in declarations.
        const name = param.name.startsWith('__')
          ? /^[A-Z]/.test(exported.name)
            ? 'props'
            : 'options'
          : param.name;
        return `${rest ? '...' : ''}${name}${optional ? '?' : ''}`;
      });
      const declaredIn = symbol.declarations?.[0]?.getSourceFile().fileName;
      const origin = declaredIn
        ? packageOfDirectory.get(relative(root, declaredIn).split(/[\\/]/)[1])
        : undefined;
      items.push({
        name: exported.name,
        kind,
        params: params ?? null,
        doc: ts.displayPartsToString(symbol.getDocumentationComment(checker)).trim(),
        deprecated: symbol.getJsDocTags(checker).some((tag) => tag.name === 'deprecated'),
        ...(origin && origin !== entry.package ? { from: origin } : {}),
      });
    }
    items.sort((a, b) => a.name.localeCompare(b.name));
    result.push({ specifier: entry.specifier, package: entry.package, exports: items });
  }
  const carried = [];
  for (const entry of unbuilt) {
    const earlier = previous.find((item) => item.specifier === entry.specifier);
    if (earlier) {
      result.push(earlier);
      carried.push(entry.specifier);
    }
  }
  result.sort((a, b) => a.specifier.localeCompare(b.specifier));
  await writeFile(join(out, 'exports.json'), JSON.stringify(result, null, 1));
  const total = result.reduce((sum, entry) => sum + entry.exports.length, 0);
  await writeStats({ exports: total });
  const skipped = unbuilt
    .map((entry) => entry.specifier)
    .filter((specifier) => !carried.includes(specifier));
  return `exports.json (${result.length} entry points, ${total} runtime exports${
    unbuilt.length
      ? `; not built yet: ${unbuilt.map((entry) => entry.specifier).join(', ')}${
          carried.length ? ` (kept the previous run's entries for ${carried.join(', ')})` : ''
        }${skipped.length ? ` (left out: ${skipped.join(', ')})` : ''}`
      : ''
  })`;
}

// ---------------------------------------------------------------------------------------------------------
// Changelog
// ---------------------------------------------------------------------------------------------------------

async function generateChangelog() {
  const changelog = await readFile(join(root, 'CHANGELOG.md'), 'utf8');
  const body = changelog.replace(/^# .*\n+/, '');
  const target = join(app, 'content/docs/reference/changelog.md');
  await mkdir(dirname(target), { recursive: true });
  await writeFile(
    target,
    `---\ntitle: Changelog\ndescription: Release notes for the Better IAM packages and documentation site, every notable change in each version, newest first.\nicon: RotateCcwClock\n---\n\n<!-- Generated from CHANGELOG.md by apps/docs/scripts/generate.mjs. Do not edit. -->\n\n${body}`,
  );
  return `changelog (${relative(root, target)})`;
}

const notice =
  '{/* Generated by apps/docs/scripts/generate.mjs from the repository. Do not edit by hand. */}';

/** Escapes prose for MDX: braces and angle brackets outside inline code would be parsed as JSX. */
function prose(text) {
  return text
    .split(/(`[^`]*`)/g)
    .map((part) => (part.startsWith('`') ? part : part.replace(/[{}<>]/g, (char) => `\\${char}`)))
    .join('');
}

const attr = (value) => JSON.stringify(value ?? '');
const kebab = (name) => name.replace(/[A-Z]/g, (char) => `-${char.toLowerCase()}`);

const groupInfo = {
  accessPaths: [
    'Route',
    'Self-service answers to "how can I get access?": the requests, packages, and elevations that would grant an action.',
  ],
  accessRequests: [
    'Inbox',
    'Time-boxed access requests that reviewers approve under their own authority.',
  ],
  actions: ['Zap', 'Tenant-defined actions added to the permission catalog.'],
  agreements: [
    'FilePenLine',
    'Versioned terms of use that members accept and policies can require.',
  ],
  analysis: [
    'Radar',
    'Access-analysis findings (dormant access, stale keys, policy lint, separation of duties) and suppressions.',
  ],
  assertions: [
    'Stamp',
    'Short-lived signed assertions for calling downstream services without sharing sessions.',
  ],
  audit: [
    'ScrollText',
    'The tamper-evident audit log: search, chain verification, and JSON Lines export.',
  ],
  auth: [
    'KeyRound',
    'End-user authentication: sign-in methods, MFA, passkeys, sessions, devices, and account recovery.',
  ],
  authorities: ['Crown', 'Delegated grant authorities: who may hand out which roles below them.'],
  bindings: [
    'Link2',
    'Role bindings for identities and groups, including temporary, future-dated, and just-in-time eligible bindings.',
  ],
  certifications: [
    'BadgeCheck',
    'Access certification campaigns: reviewers keep or revoke access with evidence.',
  ],
  config: [
    'FileCodeCorner',
    'Configuration as code: export, plan, and apply a tenant’s access model by name.',
  ],
  credentials: ['KeySquare', 'API keys with scopes, labels, expiry, and last-use tracking.'],
  domains: ['Globe', 'Verified email domains for discovery and single sign-on routing.'],
  groups: ['Users', 'Groups and (optionally temporary) group memberships.'],
  identities: [
    'UserRound',
    'People in a tenant: invitations, profiles, attributes, sessions, offboarding, and data-subject export.',
  ],
  impact: [
    'Activity',
    'Change-impact previews: who gains and loses access before a role, policy, or binding changes.',
  ],
  invariants: [
    'ShieldCheck',
    'Access invariants: guardrails that must hold whatever roles and policies say.',
  ],
  links: [
    'ArrowLeftRight',
    'Explicit account linking between identities, and switching between linked accounts.',
  ],
  packages: [
    'Package',
    'Access packages: bundles of roles and memberships assigned, requested, or granted by rule.',
  ],
  policies: [
    'FileBracesCorner',
    'Versioned JSON policies, candidate testing, simulation, and who-can / what-can reviews.',
  ],
  relationships: [
    'Share2',
    'Relationship tuples (ReBAC) that policies read as `resource.relations`.',
  ],
  reports: [
    'FileChartColumnIncreasing',
    'The access report: what ends soon, unused keys, live activations, and pending requests.',
  ],
  resourceTypes: [
    'Boxes',
    'Tenant-defined resource types with actions, typed attributes, and relations.',
  ],
  resources: ['Box', 'IAM-managed resources with owners and parents.'],
  roleMining: [
    'Pickaxe',
    'Role mining: bundle suggestions, right-sizing, peer outliers, and usage.',
  ],
  roles: [
    'ShieldHalf',
    'Custom roles built from permissions or conditional policies, inheritance, and role assumption.',
  ],
  root: ['Crown', 'Platform root administration.'],
  security: ['ShieldAlert', 'Network blocks for addresses and ranges.'],
  serviceAccounts: ['Bot', 'Service accounts for machines, with scheduled deactivation.'],
  sod: ['Split', 'Separation-of-duties rules enforced when access is granted.'],
  tenants: [
    'BuildingComplex',
    'Tenant trees: organizations, settings, authentication and access policies, limits, and usage.',
  ],
  trust: ['Handshake', 'Cross-tenant trust for platform-controlled role assumption.'],
  webhooks: ['Webhook', 'Signed webhook subscriptions, filters, delivery history, and redelivery.'],
  sts: [
    'Hourglass',
    'Temporary security credentials: short-lived sessions for assumed roles, with a duration, session policies, and tags.',
  ],
  oidcProviders: [
    'IdCard',
    'Trusted external OpenID Connect providers whose tokens can be exchanged for temporary credentials.',
  ],
  hostnames: [
    'Signpost',
    'Custom hostnames organizations verify with DNS and use as their own sign-in address.',
  ],
  features: [
    'ToggleRight',
    'Feature flags at platform and organization level: definitions, targets, overrides, and evaluation.',
  ],
  onboarding: [
    'ClipboardCheck',
    'Onboarding checklists for newcomers and new tenants, customized at platform, organization, and project level.',
  ],
  teams: [
    'UsersRound',
    'Nested teams with maintainers, join requests, and access through a team-managed group.',
  ],
  departments: [
    'Network',
    'The org chart: departments with heads, one department per person, import from attributes, heads as managers.',
  ],
  billing: [
    'Receipt',
    'Spend tracking for people, teams, and organizations: meters, prices, usage, budgets, credits, and statements.',
  ],
  agents: ['Bot', 'AI agents as accounts: sponsors, ceilings, and a kill switch.'],
  delegations: ['Handshake', "Agents acting on a person's behalf, within a scope and for a time."],
  inference: ['Cpu', 'Model access, provider keys, budgets, and metering.'],
};

function signature(group, method) {
  const params = method.params.map((param) => {
    const type = param.type.replace(/\n/g, '\n  ');
    return `  ${param.name}${param.optional ? '?' : ''}: ${type},`;
  });
  const target = group ? `iam.api.${group}.${method.name}` : `iam.${method.name}`;
  const result = method.async ? `Promise<${method.result}>` : method.result;
  return params.length
    ? `${target}(\n${params.join('\n')}\n): ${result}`
    : `${target}(): ${result}`;
}

// ---------------------------------------------------------------------------------------------------------
// Curated descriptions (apps/docs/descriptions)
// ---------------------------------------------------------------------------------------------------------
//
// Hand-written explanations merged into the generated pages. Each file is MDX-safe Markdown:
//
//   # groups                      <- optional title line, ignored
//   Overview paragraphs: what the group is and why it exists.
//   ## How membership works       <- a section that is not a method name: rendered as an overview section
//   ## addMember                  <- a method section; its first paragraph is the summary used in tables
//   Adds a person to a group ...
//
// The same shape is used for `api/_instance.md` (instance functions), `cli.md` (commands), and `errors.md` (codes).

const descriptionsDir = join(app, 'descriptions');

async function readDescriptions(relativePath) {
  let text;
  try {
    text = (await readFile(join(descriptionsDir, relativePath), 'utf8')).replace(/\r\n/g, '\n');
  } catch (error) {
    if (error.code === 'ENOENT') return { overview: '', sections: new Map() };
    throw error;
  }
  text = text.replace(/^# .*\n+/, '');
  const sections = new Map();
  const parts = text.split(/^## +/m);
  const overview = parts.shift().trim();
  for (const part of parts) {
    const newline = part.indexOf('\n');
    const heading = (newline === -1 ? part : part.slice(0, newline)).trim().replace(/^`|`$/g, '');
    sections.set(heading, (newline === -1 ? '' : part.slice(newline + 1)).trim());
  }
  return { overview, sections };
}

/** The first paragraph of a section (its summary) and everything after it. */
function splitSummary(body) {
  const blocks = body.split(/\n{2,}/);
  const first = blocks[0] ?? '';
  if (!first || /^(```|- |\* |\||<|>|\d+\. )/.test(first)) return { summary: '', rest: body };
  return { summary: first.replace(/\n/g, ' ').trim(), rest: blocks.slice(1).join('\n\n').trim() };
}

/** Plain text for frontmatter and table cells. */
function plain(markdown, max = 160) {
  const text = markdown
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/[*_`]/g, '')
    .replace(/\\([{}<>])/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
  if (text.length <= max) return text;
  const sentence = text.slice(0, max).match(/^.*[.!?](?=\s|$)/)?.[0];
  return sentence ?? `${text.slice(0, max - 1).trimEnd()}…`;
}

const cell = (markdown) => markdown.replace(/\n/g, ' ').replace(/\|/g, '\\|');
const firstSentence = (markdown) => markdown.match(/^[\s\S]*?[.!?](?=\s|$)/)?.[0] ?? markdown;

function access(method) {
  if (!method.http) return 'Server only';
  return method.credential === 'none' ? 'Public' : 'Credential';
}

function coverage(label, names, sections) {
  const missing = names.filter((name) => !sections.has(name));
  return { label, total: names.length, missing };
}

// ---------------------------------------------------------------------------------------------------------
// Generated MDX pages (API groups, errors, CLI)
// ---------------------------------------------------------------------------------------------------------

/** The input and result JSON Schemas of every method, for the `<ApiShape>` field tables on the API pages. */
async function writeApiShapes(api) {
  const methods = {};
  for (const group of api.groups)
    for (const method of group.methods) {
      const input = method.params.find(
        (param) => param.name !== 'credential' && param.name !== 'credentials',
      );
      methods[`${group.name}.${method.name}`] = {
        ...(input?.schema ? { input: input.schema, inputOptional: input.optional } : {}),
        ...(method.resultSchema ? { result: method.resultSchema } : {}),
      };
    }
  const file = join(out, 'api-shapes.json');
  const next = JSON.stringify({ methods, components: api.schemas ?? {} });
  // Several writers regenerate pages in parallel; rewriting identical data would only race the dev server.
  const current = await readFile(file, 'utf8').catch(() => '');
  if (current !== next) await writeFile(file, next);
}

async function generateApiPages(filter) {
  const api = JSON.parse(await readFile(join(out, 'api.json'), 'utf8'));
  const dir = join(app, 'content/docs/reference/api');
  await mkdir(dir, { recursive: true });
  await writeApiShapes(api);
  const wanted = filter ? new Set(filter.split(',')) : undefined;
  const report = [];
  for (const group of api.groups) {
    if (wanted && !wanted.has(group.name)) continue;
    // Groups a peer is still building have no methods yet; they get a page once they do.
    if (!group.methods.length) continue;
    const [icon, fallback] = groupInfo[group.name] ?? [
      'Braces',
      `The \`${group.name}\` API group.`,
    ];
    const curated = await readDescriptions(`api/${group.name}.md`);
    report.push(
      coverage(
        group.name,
        group.methods.map((method) => method.name),
        curated.sections,
      ),
    );
    const overview = curated.overview || prose(fallback);
    const lines = [
      '---',
      `title: ${group.name}`,
      `description: ${JSON.stringify(plain(firstSentence(curated.overview || fallback)))}`,
      `icon: ${icon}`,
      '---',
      '',
      notice,
      '',
      overview,
      '',
    ];
    const methodNames = new Set(group.methods.map((method) => method.name));
    for (const [heading, body] of curated.sections)
      if (!methodNames.has(heading)) lines.push(`## ${heading}`, '', body, '');
    lines.push(
      `<ApiGroupSummary group=${attr(group.name)} methods={${group.methods.length}} routed={${group.routed}} />`,
      '',
      '| Method | What it does | Access |',
      '| --- | --- | --- |',
    );
    const details = group.methods.map((method) => {
      const body = curated.sections.get(method.name);
      const { summary, rest } = body
        ? splitSummary(body)
        : { summary: prose(method.description), rest: '' };
      return { method, summary, rest };
    });
    for (const { method, summary } of details)
      lines.push(
        `| [\`${method.name}\`](#${method.name.toLowerCase()}) | ${cell(summary) || '—'} | ${access(method)} |`,
      );
    lines.push('');
    for (const { method, summary, rest } of details) {
      lines.push(`## ${method.name}`, '');
      if (summary) lines.push(summary, '');
      lines.push(
        `<ApiEndpoint group=${attr(group.name)} method=${attr(method.name)} http=${attr(method.http)} credential=${attr(method.credential)} />`,
        '',
      );
      if (rest) lines.push(rest, '');
      for (const tag of method.tags.filter((tag) => tag.name === 'deprecated'))
        lines.push(
          `<Callout type="warn" title="Deprecated">${prose(tag.text || 'This method is deprecated.')}</Callout>`,
          '',
        );
      lines.push(
        `<ApiShape id=${attr(`${group.name}.${method.name}`)}${method.http ? (method.credential === 'none' ? ' http="public"' : ' http') : ''} />`,
        '',
      );
      lines.push('```ts title="Signature"', signature(group.name, method), '```', '');
    }
    await writeFile(join(dir, `${kebab(group.name)}.mdx`), lines.join('\n'));
  }

  if (!wanted || wanted.has('_instance')) {
    const curated = await readDescriptions('api/_instance.md');
    const top = api.topLevel.filter((method) => !['handler', 'nodeHandler'].includes(method.name));
    report.push(
      coverage(
        'instance',
        top.map((method) => method.name),
        curated.sections,
      ),
    );
    const index = [
      '---',
      'title: API reference',
      `description: ${JSON.stringify(`Every method of the Better IAM server API: ${api.groups.length} groups and ${api.groups.reduce((sum, group) => sum + group.methods.length, 0)} methods, what each does, its HTTP route, and its TypeScript signature.`)}`,
      'icon: Braces',
      '---',
      '',
      notice,
      '',
      curated.overview ||
        'The server API is everything your application can ask Better IAM to do: create organizations, invite people, grant and review access, sign people in, and read the audit log. It is organized into groups (`tenants`, `identities`, `roles`, …), and every group method is authorized and audited the same way no matter where the call comes from.',
      '',
      '## Three ways to call it',
      '',
      'Every group method is called three ways: on the server as `iam.api.{group}.{method}(credential, input)`, from the typed browser client as `client.{group}.{method}(input)`, and over HTTP as `POST {basePath}/{group}/{method}` with a JSON body. The default `basePath` is `/api/iam`. The first server argument, the credential, says who is calling: a session token, an API key, or the incoming request headers (which carry the session cookie or an `Authorization: Bearer` token).',
      '',
      'Over HTTP every call is a `POST` with `Content-Type: application/json` and the `X-Better-IAM: 1` header (anything else is refused with `CSRF_REJECTED`). Requests that carry cookies must also send an exact trusted `Origin`. Responses use a `{ "data": … }` or `{ "error": { "code", "message" } }` envelope; the browser client unwraps it for you. Root bootstrap, recovery, raw storage, and session-issuance primitives are never exposed over HTTP.',
      '',
      '<Callout title="OpenAPI 3.1 specification">',
      'The HTTP API is also described as an [OpenAPI 3.1 document](/openapi.json), generated from the same TypeScript types as this reference, with JSON Schemas for every request and response. Import it into Postman, Insomnia, or Bruno, or feed it to a client generator for languages other than TypeScript.',
      '</Callout>',
      '',
      "<Tabs groupId=\"api-surface\" persist items={['Server', 'Browser client', 'HTTP']}>",
      '<Tab value="Server">',
      '',
      '```ts',
      "import { iam } from './iam';",
      '',
      '// The first argument is the caller: a session token, an API key, or request headers.',
      'const credential = { headers: request.headers };',
      "const group = await iam.api.groups.create(credential, { tenantId, name: 'Finance' });",
      '```',
      '',
      '</Tab>',
      '<Tab value="Browser client">',
      '',
      '```ts',
      "import { createIamClient } from 'better-iam/client';",
      "import type { iam } from './iam';",
      '',
      "const client = createIamClient<typeof iam>({ baseURL: 'https://identity.example.com' });",
      "const group = await client.groups.create({ tenantId, name: 'Finance' }); // the session cookie is the credential",
      '```',
      '',
      '</Tab>',
      '<Tab value="HTTP">',
      '',
      '```bash',
      'curl -X POST https://identity.example.com/api/iam/groups/create \\',
      '  -H "Authorization: Bearer $BETTER_IAM_TOKEN" \\',
      '  -H "Content-Type: application/json" \\',
      '  -H "X-Better-IAM: 1" \\',
      '  -d \'{ "tenantId": "ten_…", "name": "Finance" }\'',
      '```',
      '',
      '</Tab>',
      '</Tabs>',
      '',
    ];
    for (const [heading, body] of curated.sections)
      if (!top.some((method) => method.name === heading)) index.push(`## ${heading}`, '', body, '');
    // Groups by what a reader is trying to do, so the index reads as a map rather than an alphabetical list.
    const categories = [
      [
        'Sign-in and people',
        'Authenticate people and machines, manage who exists in a tenant, and how they are organized.',
        [
          'auth',
          'identities',
          'teams',
          'departments',
          'serviceAccounts',
          'credentials',
          'links',
          'domains',
          'security',
        ],
      ],
      [
        'Organizations',
        'The tenant tree, organization addresses and settings, and platform administration.',
        ['tenants', 'hostnames', 'features', 'onboarding', 'root', 'trust', 'sts', 'oidcProviders'],
      ],
      [
        'Access model',
        'What can be done to what, and who holds which permissions.',
        [
          'roles',
          'policies',
          'bindings',
          'groups',
          'authorities',
          'resourceTypes',
          'actions',
          'resources',
          'relationships',
        ],
      ],
      [
        'Access lifecycle',
        'Granting access for a purpose and a time, and reporting on it.',
        ['packages', 'accessRequests', 'accessPaths', 'reports', 'config'],
      ],
      [
        'Governance',
        'Reviewing, analyzing, and constraining access over time.',
        ['certifications', 'analysis', 'roleMining', 'sod', 'invariants', 'impact', 'agreements'],
      ],
      [
        'Events and integrations',
        'The audit log, outgoing events, and service-to-service trust.',
        ['audit', 'webhooks', 'assertions'],
      ],
      [
        'AI agents and models',
        'Agents as accounts, what they may do for people, and governed access to models.',
        ['agents', 'delegations', 'inference'],
      ],
      [
        'Billing',
        'What people, teams, and organizations spend, and the budgets and statements around it.',
        ['billing'],
      ],
    ];
    const live = api.groups.filter((entry) => entry.methods.length);
    const placed = new Set(categories.flatMap(([, , names]) => names));
    const other = live.filter((group) => !placed.has(group.name)).map((group) => group.name);
    if (other.length)
      categories.push(['Other', 'Groups added since this index was organized.', other]);
    index.push('## Groups', '');
    for (const [title, blurb, names] of categories) {
      const groups = names.map((name) => live.find((group) => group.name === name)).filter(Boolean);
      if (!groups.length) continue;
      index.push(`### ${title}`, '', blurb, '', '<Cards>');
      for (const group of groups) {
        const [icon, description] = groupInfo[group.name] ?? ['Braces', ''];
        index.push(
          `  <Card icon={<${icon} />} title=${attr(group.name)} href="/docs/reference/api/${kebab(group.name)}">${prose(description)} (${group.methods.length} methods)</Card>`,
        );
      }
      index.push('</Cards>', '');
    }
    index.push(
      '## Instance functions',
      '',
      'Functions on the object `betterIam()` returns, outside the `api` groups. Checks such as `authorize` and `require` are what your routes call; deployment operations (migrations, scheduled jobs, secret rotation) have no HTTP routes, so you run them from a worker, a cron job, or the [CLI](/docs/reference/cli).',
      '',
      '| Function | What it does |',
      '| --- | --- |',
    );
    const topDetails = top.map((method) => {
      const body = curated.sections.get(method.name);
      const { summary, rest } = body
        ? splitSummary(body)
        : { summary: prose(method.description), rest: '' };
      return { method, summary, rest };
    });
    for (const { method, summary } of topDetails)
      index.push(
        `| [\`${method.name}\`](#${method.name.toLowerCase()}) | ${cell(summary) || '—'} |`,
      );
    index.push('');
    for (const { method, summary, rest } of topDetails) {
      index.push(`### ${method.name}`, '');
      if (summary) index.push(summary, '');
      if (rest) index.push(rest, '');
      index.push('```ts title="Signature"', signature(undefined, method), '```', '');
    }
    const icons = [
      ...new Set(
        api.groups
          .filter((entry) => entry.methods.length)
          .map((group) => (groupInfo[group.name] ?? ['Braces'])[0]),
      ),
    ];
    index.splice(8, 0, `import { ${icons.join(', ')} } from '@/lib/icons';`, '');
    await writeFile(join(dir, 'index.mdx'), index.join('\n'));
    await writeFile(
      join(dir, 'meta.json'),
      JSON.stringify({ title: 'Server API', icon: 'Braces', pages: ['index', '...'] }, null, 2) +
        '\n',
    );
  }

  const total = report.reduce((sum, entry) => sum + entry.total, 0);
  const missing = report.flatMap((entry) => entry.missing.map((name) => `${entry.label}.${name}`));
  if (missing.length && process.env.DOCS_COVERAGE)
    console.log(`  undocumented (${missing.length}): ${missing.join(', ')}`);
  return `${report.length} API pages; curated descriptions for ${total - missing.length}/${total} functions`;
}

async function generateErrorsPage() {
  const errors = JSON.parse(await readFile(join(out, 'errors.json'), 'utf8'));
  const curated = await readDescriptions('errors.md');
  const classes = [
    [
      400,
      'Bad request',
      'The request itself is the problem: an input failed validation, or the operation is not allowed in the current state of the record. Fix the input or the order of operations; retrying the same request will fail the same way.',
    ],
    [
      401,
      'Unauthenticated',
      'Better IAM could not establish who is calling, or the proof it was given is no longer good enough: the session expired or was revoked, the key is invalid, or a code was wrong. Send the person back through sign-in (or step-up) and retry.',
    ],
    [
      403,
      'Forbidden',
      'The caller is known, but this action is not allowed for them: no role or policy grants it, a deny or boundary blocks it, or a tenant policy (MFA, network, sign-in method) refuses the request. Retrying will not help until access or context changes.',
    ],
    [
      404,
      'Not found',
      'The record does not exist in this tenant. Better IAM also answers 404 for records in other tenants, so responses never reveal what exists elsewhere.',
    ],
    [
      409,
      'Conflict',
      'The request conflicts with the current state: a duplicate name or email, a version that changed since it was read, or a one-time token that was already used. Reload the current state and decide again.',
    ],
    [
      429,
      'Rate limited',
      'Too many attempts in a short time. The error carries `retryAfterMs` and the HTTP response a `Retry-After` header; wait that long before retrying.',
    ],
  ];
  const lines = [
    '---',
    'title: Error codes',
    `description: ${JSON.stringify(`What each of the ${errors.length} Better IAM error codes means, why it happens, and how to handle it, grouped by HTTP status.`)}`,
    'icon: OctagonAlert',
    '---',
    '',
    notice,
    '',
    curated.overview ||
      'Every failure is an `IamError` with a stable `code`, a human-readable `message`, and an HTTP `status`. Codes are part of the public contract and do not change between releases; messages are for people and may be reworded. Over HTTP the body is `{ "error": { "code", "message" } }`; the browser client rethrows it as `IamClientError` with the same `code`, `status`, and `requestId`. Branch on `code`, never on `message`.',
    '',
    '```ts',
    "import { IamError } from 'better-iam';",
    '',
    'try {',
    "  await iam.require({ headers, tenantId, action: 'documents:write', resource: { type: 'document', id } });",
    '} catch (error) {',
    "  if (error instanceof IamError && error.code === 'ACCESS_DENIED') return forbidden();",
    "  if (error instanceof IamError && error.code === 'RATE_LIMITED') return retryLater(error);",
    '  throw error;',
    '}',
    '```',
    '',
  ];
  const codes = new Set(errors.map((error) => error.code));
  for (const [heading, body] of curated.sections)
    if (!codes.has(heading)) lines.push(`## ${heading}`, '', body, '');
  const byStatus = new Map();
  for (const error of errors) {
    const primary =
      error.statuses.includes(400) && error.statuses.length > 1
        ? error.statuses.find((status) => status !== 400)
        : error.statuses[0];
    const bucket = byStatus.get(primary) ?? [];
    bucket.push(error);
    byStatus.set(primary, bucket);
  }
  const known = new Set(classes.map(([status]) => status));
  const all = [
    ...classes,
    ...[...byStatus.keys()]
      .filter((status) => !known.has(status))
      .sort()
      .map((status) => [status, `HTTP ${status}`, '']),
  ];
  for (const [status, title, text] of all) {
    const bucket = byStatus.get(status);
    if (!bucket?.length) continue;
    lines.push(`## ${status} ${title}`, '');
    if (text) lines.push(prose(text), '');
    lines.push('| Code | Meaning |', '| --- | --- |');
    for (const error of bucket) {
      const body = curated.sections.get(error.code);
      const summary = body
        ? splitSummary(body).summary
        : error.messages[0]
          ? prose(error.messages[0])
          : '';
      lines.push(`| [\`${error.code}\`](#${error.code.toLowerCase()}) | ${cell(summary) || '—'} |`);
    }
    lines.push('');
    for (const error of bucket) {
      lines.push(`### ${error.code}`, '');
      const body = curated.sections.get(error.code);
      if (body) lines.push(body, '');
      const statuses = error.statuses.map((value) => `\`${value}\``).join(', ');
      lines.push(
        `<small>HTTP ${statuses} · thrown by ${error.packages.map((name) => `\`${name}\``).join(', ')}</small>`,
        '',
      );
      if (error.messages.length) {
        lines.push('Example messages:', '');
        for (const message of error.messages) lines.push(`- ${prose(message)}`);
        lines.push('');
      }
    }
  }
  await writeFile(join(app, 'content/docs/reference/errors.mdx'), lines.join('\n'));
  const missing = errors
    .filter((error) => !curated.sections.has(error.code))
    .map((error) => error.code);
  if (missing.length && process.env.DOCS_COVERAGE)
    console.log(`  undocumented codes (${missing.length}): ${missing.join(', ')}`);
  return `errors page; curated descriptions for ${errors.length - missing.length}/${errors.length} codes`;
}

async function generateCliPage() {
  const cli = JSON.parse(await readFile(join(out, 'cli.json'), 'utf8'));
  const curated = await readDescriptions('cli.md');
  const lines = [
    '---',
    'title: CLI',
    'metaTitle: CLI reference',
    `description: ${JSON.stringify(`The better-iam command line: what each of its ${cli.commands.length} commands does, when to run it, and its flags.`)}`,
    'icon: SquareTerminal',
    '---',
    '',
    notice,
    '',
    curated.overview ||
      'The `better-iam` command line runs the operations that should not live inside a web request: creating and upgrading the database schema, creating the first administrator, verifying and archiving the audit log, applying configuration as code, and the scheduled jobs that expire, remind, and clean up. It ships in `@better-iam/cli` (and the umbrella `better-iam` package). Commands load your application configuration from `--config` or the nearest `better-iam.config.*`, a module whose default export is the options you pass to `betterIam()`; it is executable JavaScript, so only point it at trusted files.',
    '',
    '```npm',
    'npx better-iam migrate',
    '```',
    '',
    '<Callout title="Secrets never go on the command line">',
    `Bootstrap and recovery read ${cli.env
      .filter((name) => name.startsWith('BETTER_IAM_ROOT'))
      .map((name) => `\`${name}\``)
      .join(
        ', ',
      )} from the environment, and \`login\` reads the password from \`BETTER_IAM_PASSWORD\` or a hidden prompt. Commands that act as a member (configuration, analysis, reports, \`api\`, \`can\`) use the session token or API key in \`BETTER_IAM_TOKEN\`, or the session saved by \`login\`, in process or against \`--url\`, and are authorized and audited like console operations.`,
    '</Callout>',
    '',
  ];
  const names = new Set(cli.commands.map((command) => command.name));
  for (const [heading, body] of curated.sections)
    if (!names.has(heading)) lines.push(`## ${heading}`, '', body, '');
  // Flags and variables shared by many commands, described once (from any command that has each flag).
  const common = new Map();
  for (const command of cli.commands)
    for (const flag of command.flags ?? [])
      if (commonCliFlags.has(flag.flag) && !common.has(flag.flag)) common.set(flag.flag, flag);
  if (common.size) {
    lines.push(
      '## Common flags',
      '',
      'Commands that load the configuration take `--config`; commands that act as a member also take `--url` and `--profile`; every command that prints JSON takes `--format` and `--query`. Every flag also accepts the `--flag=value` form, and `better-iam help <command>` prints the flags of the installed version.',
      '',
      '| Flag | Value | Description |',
      '| --- | --- | --- |',
    );
    for (const flag of common.values())
      lines.push(
        `| \`${flag.flag}\` | ${flag.value ? cell(`\`${flag.value}\``) : '—'} | ${cell(flag.description + (flag.env ? ` (env \`${flag.env}\`)` : ''))} |`,
      );
    lines.push('');
  }
  if (cli.environment?.length) {
    lines.push('## Environment variables', '', '| Variable | Meaning |', '| --- | --- |');
    for (const entry of cli.environment)
      lines.push(`| \`${entry.name}\` | ${cell(entry.description)} |`);
    lines.push('');
  }
  lines.push('## Commands', '', '| Command | What it does |', '| --- | --- |');
  const details = cli.commands.map((command) => {
    const body = curated.sections.get(command.name);
    const { summary, rest } = body
      ? splitSummary(body)
      : {
          summary: prose(command.description.split(/(?<=\.)\s/)[0] ?? ''),
          rest: prose(command.description),
        };
    return { command, summary, rest };
  });
  for (const { command, summary } of details)
    lines.push(`| [\`${command.name}\`](#${command.name}) | ${cell(summary) || '—'} |`);
  lines.push('');
  for (const { command, summary, rest } of details) {
    lines.push(`### ${command.name}`, '');
    if (summary) lines.push(summary, '');
    lines.push('```bash', command.usage, '```', '');
    if (rest) lines.push(rest, '');
    const flags = command.flags.filter((flag) => !commonCliFlags.has(flag.flag));
    if (flags.length) {
      lines.push('| Flag | Value | Required | Description |', '| --- | --- | --- | --- |');
      for (const flag of flags) {
        const notes = [
          flag.default !== undefined ? `default \`${flag.default}\`` : undefined,
          flag.env ? `env \`${flag.env}\`` : undefined,
        ].filter(Boolean);
        const description = `${flag.description ?? ''}${notes.length ? ` (${notes.join('; ')})` : ''}`;
        lines.push(
          `| \`${flag.flag}\` | ${flag.value ? cell(`\`${flag.value}\``) : '—'} | ${flag.optional ? 'no' : 'yes'} | ${cell(description) || '—'} |`,
        );
      }
      lines.push('');
    }
    // Curated sections carry their own examples; the CLI's examples fill in for the rest.
    if (!curated.sections.has(command.name) && command.examples?.length)
      lines.push('```bash', ...command.examples, '```', '');
  }
  await writeFile(join(app, 'content/docs/reference/cli.mdx'), lines.join('\n'));
  const missing = cli.commands.filter((command) => !curated.sections.has(command.name)).length;
  return `CLI page; curated descriptions for ${cli.commands.length - missing}/${cli.commands.length} commands`;
}

/**
 * An OpenAPI 3.1 description of the HTTP API (`POST {basePath}/{group}/{method}`), built from the API catalog and its
 * JSON Schemas plus the curated summaries, served at /openapi.json for Postman, Insomnia, and client generators.
 */
async function generateOpenApi() {
  const api = JSON.parse(await readFile(join(out, 'api.json'), 'utf8'));
  if (!api.schemas) throw new Error('api.json has no schemas; run the `api` step first');
  const markdownToText = (text) => text.replace(/\\([{}<>])/g, '$1');
  const paths = {};
  const tags = [];
  let operations = 0;
  for (const group of api.groups) {
    if (!group.routed) continue;
    const curated = await readDescriptions(`api/${group.name}.md`);
    const [, fallback] = groupInfo[group.name] ?? ['', ''];
    tags.push({
      name: group.name,
      description: markdownToText(curated.overview ? firstSentence(curated.overview) : fallback),
      externalDocs: { url: `${siteUrl}/docs/reference/api/${kebab(group.name)}` },
    });
    for (const method of group.methods) {
      if (!method.http) continue;
      const body = curated.sections.get(method.name);
      const { summary, rest } = body
        ? splitSummary(body)
        : { summary: method.description, rest: '' };
      // Credentialed methods take (credential, input); public auth methods take (input).
      const input = method.params.find(
        (param) => param.name !== 'credential' && param.name !== 'credentials',
      );
      const operation = {
        operationId: `${group.name}.${method.name}`,
        tags: [group.name],
        summary: markdownToText(plain(summary || `${group.name}.${method.name}`, 200)),
        ...(rest || method.description
          ? { description: markdownToText(rest || method.description) }
          : {}),
        externalDocs: {
          url: `${siteUrl}/docs/reference/api/${kebab(group.name)}#${method.name.toLowerCase()}`,
        },
        parameters: [{ $ref: '#/components/parameters/XBetterIam' }],
        security: method.credential === 'none' ? [] : [{ bearerAuth: [] }, { sessionCookie: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: input?.schema ?? { type: 'object' } } },
        },
        responses: {
          200: {
            description: 'Success. The result is wrapped in `data`.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['data'],
                  properties: { data: method.resultSchema ?? {} },
                },
              },
            },
          },
          default: { $ref: '#/components/responses/Error' },
        },
      };
      paths[`/${group.name}/${method.name}`] = { post: operation };
      operations++;
    }
  }
  const spec = {
    openapi: '3.1.0',
    info: {
      title: 'Better IAM HTTP API',
      version,
      description:
        'The HTTP surface of a Better IAM instance. Every operation is a POST with a JSON body, the `X-Better-IAM: 1` header, and either a bearer token or the session cookie; cookie requests must also send a trusted `Origin`. Responses are `{ "data": … }` on success and `{ "error": { "code", "message" } }` on failure.',
    },
    externalDocs: { description: 'Better IAM documentation', url: `${siteUrl}/docs/reference/api` },
    servers: [
      {
        url: '{origin}/api/iam',
        description: 'Your deployment (the default basePath is /api/iam)',
        variables: { origin: { default: 'https://identity.example.com' } },
      },
    ],
    tags,
    paths,
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          description:
            'A session token, API key, or assumed-role token in `Authorization: Bearer …`.',
        },
        sessionCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: 'better-iam.session',
          description:
            'The browser session cookie. Cookie requests must send an exact trusted Origin header.',
        },
      },
      parameters: {
        XBetterIam: {
          name: 'X-Better-IAM',
          in: 'header',
          required: true,
          description:
            'Must be `1`. Together with the JSON content type it blocks cross-site form posts (CSRF).',
          schema: { type: 'string', const: '1' },
        },
      },
      responses: {
        Error: {
          description: 'An IamError. See the error codes reference.',
          headers: {
            'Retry-After': {
              description: 'Seconds to wait, on RATE_LIMITED responses.',
              schema: { type: 'integer' },
            },
            'X-Request-Id': {
              description: 'The request id, echoed for support.',
              schema: { type: 'string' },
            },
          },
          content: {
            'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } },
          },
        },
      },
      schemas: {
        ...api.schemas,
        ErrorEnvelope: {
          type: 'object',
          required: ['error'],
          properties: {
            error: {
              type: 'object',
              required: ['code', 'message'],
              properties: {
                code: {
                  type: 'string',
                  description: 'Stable error code, for example ACCESS_DENIED.',
                },
                message: {
                  type: 'string',
                  description: 'Human-readable explanation; may change between releases.',
                },
                retryAfterMs: { type: 'number', description: 'Present on RATE_LIMITED.' },
              },
            },
          },
        },
      },
    },
  };
  await mkdir(join(app, 'public'), { recursive: true });
  await writeFile(join(app, 'public', 'openapi.json'), JSON.stringify(spec, null, 1));
  return `openapi.json (${operations} operations, ${Object.keys(spec.components.schemas).length} schemas)`;
}

async function generateGlossaryPage() {
  const terms = JSON.parse(await readFile(join(descriptionsDir, 'glossary.json'), 'utf8')).sort(
    (a, b) => a.term.localeCompare(b.term),
  );
  const lines = [
    '---',
    'title: Glossary',
    'description: Plain-language definitions of the identity and access terms used throughout the Better IAM documentation.',
    'icon: BookA',
    '---',
    '',
    notice,
    '',
    'Identity and access management has its own vocabulary, and Better IAM uses it precisely. Each term below is',
    'defined in one or two sentences with a link to the page that explains it in depth. Throughout the guides, terms',
    'shown with a dotted underline open the same definition on hover.',
    '',
  ];
  let letter = '';
  for (const entry of terms) {
    const initial = entry.term[0].toUpperCase();
    if (initial !== letter) {
      letter = initial;
      lines.push(`## ${letter}`, '');
    }
    lines.push(`### ${entry.term}`, '', prose(entry.definition), '');
    if (entry.href) lines.push(`[Learn more](${entry.href})`, '');
  }
  await writeFile(join(app, 'content/docs/reference/glossary.mdx'), lines.join('\n'));
  return `glossary page (${terms.length} terms)`;
}

/** Every guide page (not the reference) with its URL, title, documented packages, and code text. */
async function readGuides() {
  const docs = join(app, 'content', 'docs');
  const pages = [];
  async function visit(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (relative(docs, path) !== 'reference') await visit(path);
      } else if (entry.name.endsWith('.mdx')) {
        const text = (await readFile(path, 'utf8')).replace(/\r\n/g, '\n');
        const frontmatter = text.match(/^---\n([\s\S]*?)\n---/)?.[1] ?? '';
        const slug = relative(docs, path)
          .replace(/\\/g, '/')
          .replace(/(\/index)?\.mdx$/, '');
        // Only code counts as a mention: fenced blocks and inline code, not the prose around them.
        const code = [
          ...text.matchAll(/```[^\n]*\n([\s\S]*?)```/g),
          ...text.matchAll(/`([^`\n]+)`/g),
        ]
          .map((match) => match[1])
          .join('\n');
        pages.push({
          url: `/docs/${slug}`,
          title: frontmatter.match(/^title:\s*(.+)$/m)?.[1].replace(/^['"]|['"]$/g, '') ?? slug,
          // `packages: ['a', 'b']` or a YAML block list of `- 'a'` lines.
          packages: [
            ...(
              frontmatter.match(/^packages:[ \t]*(\[.*\]|(?:\n[ \t]+-[ \t]+.*)+)/m)?.[1] ?? ''
            ).matchAll(/['"]?(@better-iam\/[\w/-]+|better-iam)['"]?/g),
          ].map((match) => match[1]),
          code,
        });
      }
    }
  }
  await visit(docs);
  return pages;
}

/** Packages that integrate one framework; a page about one of them never explains another's exports. */
const frameworkPackages = new Set([
  '@better-iam/react',
  '@better-iam/vue',
  '@better-iam/svelte',
  '@better-iam/next',
  '@better-iam/nuxt',
  '@better-iam/nestjs',
  '@better-iam/react-router',
  '@better-iam/middleware',
]);

/**
 * The guide that explains an export best: the page mentioning it most in code, preferring pages that document its
 * package. Short, generic names (`guard`, `Can`) are only matched on their own package's pages, and a page about
 * another framework is never used. Without a mention, a focused package (documented on at most three pages) links
 * to its main page.
 */
function explainingPage(name, packageName, origin, guides) {
  const pattern = new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}(?![\\w$])`, 'g');
  const distinctive = name.length >= 8 || /^.+[A-Z]/.test(name);
  let best;
  for (const page of guides) {
    const count = page.code.match(pattern)?.length ?? 0;
    if (!count) continue;
    const own = page.packages.includes(packageName);
    if (!own && !distinctive) continue;
    if (
      !own &&
      page.packages.some((documented) => frameworkPackages.has(documented) && documented !== origin)
    )
      continue;
    const score = count * (own ? 10 : 1);
    if (
      !best ||
      score > best.score ||
      (score === best.score && page.url.length < best.page.url.length)
    )
      best = { page, score };
  }
  if (best) return best.page;
  const home = guides.filter((page) => page.packages.includes(packageName));
  return home.length && home.length <= 3
    ? home.reduce((shortest, page) => (page.url.length < shortest.url.length ? page : shortest))
    : undefined;
}

/** At most `max` characters of whole sentences, keeping Markdown (inline code) intact. */
function leadingSentences(markdown, max = 320) {
  const text = markdown.replace(/\s+/g, ' ').trim();
  if (text.length <= max) return text;
  const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z`(])/);
  let kept = sentences[0];
  for (const sentence of sentences.slice(1)) {
    if (kept.length + sentence.length + 1 > max) break;
    kept += ` ${sentence}`;
  }
  return kept;
}

async function generateExportsPage() {
  const entries = JSON.parse(await readFile(join(out, 'exports.json'), 'utf8'));
  const packages = JSON.parse(await readFile(join(out, 'packages.json'), 'utf8'));
  const { sections } = await readDescriptions('exports.md');
  const guides = await readGuides();
  // A re-export shares the curated text of its original entry point (`@better-iam/client/session` for the React,
  // Vue, and Svelte copies of `isUnauthenticated`).
  const curatedFor = (entry, item) =>
    sections.get(`${entry.specifier} ${item.name}`) ??
    (item.from
      ? [...sections].find(
          ([key]) =>
            key.endsWith(` ${item.name}`) &&
            (key.startsWith(`${item.from} `) || key.startsWith(`${item.from}/`)),
        )?.[1]
      : undefined);
  const describe = (entry, item) => {
    const text = curatedFor(entry, item) ?? item.doc;
    // The first paragraph, before any example.
    return text ? leadingSentences(text.split(/\n\s*\n|```/)[0]) : '';
  };
  const missing = [];
  const lines = [
    '---',
    'title: Package exports',
    'description: Every function, class, and constant the Better IAM packages export, what each one does, and which guide explains it.',
    'icon: PackageOpen',
    '---',
    '',
    notice,
    '',
    'Most code reaches Better IAM through the `betterIam()` instance and its [server API](/docs/reference/api). The',
    'packages also export standalone functions: the hooks, guards, and components of each framework integration,',
    'policy helpers that run anywhere, verifiers for webhooks, assertions, and session tokens, and the building blocks',
    'of custom integrations. This page lists every one of them by entry point, with what it does and the guide that',
    'shows it in use. Types are not listed here: the ones you handle most are explained on',
    '[Types](/docs/reference/types), and hovering a name in a code example shows its full type.',
    '',
    'Each entry point is also available through the umbrella `better-iam` package; see',
    '[Installation](/docs/guides/installation#all-packages) for the subpath map.',
    '',
  ];
  let total = 0;
  for (const pkg of packages) {
    const own = entries.filter((entry) => entry.package === pkg.name && entry.exports.length);
    if (!own.length) continue;
    lines.push(`## ${pkg.name}`, '', prose(pkg.description ?? ''), '');
    for (const entry of own) {
      if (entry.specifier !== pkg.name) lines.push(`### ${entry.specifier}`, '');
      lines.push('| Export | What it does | Explained in |', '| --- | --- | --- |');
      for (const item of entry.exports) {
        total++;
        const label =
          item.name === 'default'
            ? 'export default'
            : item.kind === 'function' || (item.kind === 'const' && item.params)
              ? `${item.name}(${item.params.join(', ')})`
              : `${item.kind === 'class' ? 'class' : item.kind === 'enum' ? 'enum' : 'const'} ${item.name}`;
        let text = describe(entry, item);
        if (!text) missing.push(`${entry.specifier} ${item.name}`);
        if (item.from) text = `${text}${text ? ' ' : ''}Re-exported from \`${item.from}\`.`;
        if (item.deprecated) text = `**Deprecated.** ${text}`;
        const page = explainingPage(item.name, pkg.name, item.from, guides);
        lines.push(
          `| \`${label}\` | ${cell(prose(text || 'No description yet.'))} | ${page ? `[${cell(page.title)}](${page.url})` : ''} |`,
        );
      }
      lines.push('');
    }
  }
  await writeFile(join(app, 'content/docs/reference/exports.mdx'), lines.join('\n'));
  if (missing.length && process.env.DOCS_COVERAGE)
    console.log(`  exports without a description:\n    ${missing.join('\n    ')}`);
  return `exports page (${total} exports, ${total - missing.length} described)`;
}

// `node scripts/generate.mjs api-pages=groups,roles errors-page` runs those steps (with an optional filter).
const only = new Map(
  process.argv.slice(2).map((arg) => {
    const [name, value] = arg.split('=');
    return [name, value];
  }),
);
const steps = {
  api: generateApi,
  errors: generateErrors,
  cli: generateCli,
  packages: generatePackages,
  exports: generateExports,
  changelog: generateChangelog,
  'api-pages': generateApiPages,
  'errors-page': generateErrorsPage,
  'cli-page': generateCliPage,
  glossary: generateGlossaryPage,
  'exports-page': generateExportsPage,
  openapi: generateOpenApi,
};
for (const [name, step] of Object.entries(steps)) {
  if (only.size && !only.has(name)) continue;
  try {
    console.log(`✓ ${await step(only.get(name))}`);
  } catch (error) {
    console.error(`✗ ${name}: ${error.stack ?? error}`);
    process.exitCode = 1;
  }
}
