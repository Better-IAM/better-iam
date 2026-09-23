import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { betterIam, type BetterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { CliError, usageError } from '../errors.js';
import { defineCommand, type CommandContext, type FlagSpecs } from '../framework.js';
import { formatResult, type OutputFormat } from '../output.js';
import { isPublicRoute, listRoutes, parseEndpoint, routePath } from '../transport.js';

const unsafeKeys = new Set(['__proto__', 'constructor', 'prototype']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** Sets `a.b.c` (and `list[]` to append) on a plain object, refusing prototype keys. */
function assign(target: Record<string, unknown>, key: string, value: unknown): void {
  const parts = key.split('.');
  if (parts.some((part) => !part || unsafeKeys.has(part.replace(/\[\]$/, ''))))
    throw usageError(`${key} is not a usable field name`);
  let current = target;
  for (const [index, raw] of parts.entries()) {
    const append = raw.endsWith('[]');
    const part = append ? raw.slice(0, -2) : raw;
    const last = index === parts.length - 1;
    if (last) {
      if (append) {
        const existing = current[part];
        if (existing !== undefined && !Array.isArray(existing))
          throw usageError(`${part} is already set to a non-list value`);
        current[part] = [...((existing as unknown[] | undefined) ?? []), value];
      } else current[part] = value;
      return;
    }
    if (append) throw usageError(`${key}: [] may only end a field name`);
    const next = current[part];
    if (next === undefined) current[part] = Object.create(null) as Record<string, unknown>;
    else if (!isRecord(next)) throw usageError(`${part} is already set to a non-object value`);
    current = current[part] as Record<string, unknown>;
  }
}

async function readJson(text: string, source: string): Promise<unknown> {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw usageError(`${source} is not valid JSON`);
  }
}

/**
 * Builds the request body from `--data` (JSON, `@file.json`, or `-` for stdin) and `key=value` items, like HTTPie:
 * `name=Admin` (string), `limit:=10` / `actions:='["a"]'` (JSON), `document:=@policy.json` (JSON file),
 * `content=@terms.md` (file text), `resource.type=project` (nested), `actions[]=a` (append).
 */
export async function requestBody(
  context: Pick<CommandContext<FlagSpecs>, 'io' | 'path'>,
  data: string | undefined,
  items: string[],
): Promise<Record<string, unknown>> {
  let body: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  if (data !== undefined) {
    let parsed: unknown;
    if (data === '-') {
      if (!context.io.stdin) throw usageError('--data - needs standard input');
      parsed = await readJson(await context.io.stdin(), 'Standard input');
    } else if (data.startsWith('@'))
      parsed = await readJson(await readFile(context.path(data.slice(1)), 'utf8'), data.slice(1));
    else parsed = await readJson(data, '--data');
    if (!isRecord(parsed)) throw usageError('--data must be a JSON object');
    body = JSON.parse(JSON.stringify(parsed), (key, value: unknown) =>
      unsafeKeys.has(key) ? undefined : value,
    ) as Record<string, unknown>;
  }
  for (const item of items) {
    const match = /^([^=:]+)(:=|=)(.*)$/s.exec(item);
    if (!match)
      throw usageError(
        `${item} is not key=value or key:=json`,
        'Quote values with spaces; see better-iam help api.',
      );
    const [, key, operator, raw] = match as unknown as [string, string, string, string];
    let value: unknown;
    if (operator === ':=')
      value = raw.startsWith('@')
        ? await readJson(await readFile(context.path(raw.slice(1)), 'utf8'), raw.slice(1))
        : await readJson(raw, `${key}:=`);
    else
      value =
        raw.startsWith('@') && raw.length > 1
          ? await readFile(context.path(raw.slice(1)), 'utf8')
          : raw;
    assign(body, key.trim(), value);
  }
  return JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
}

/** The instance whose routes `api --list` shows: the configuration's, else a throwaway in-memory one. */
async function routeSource(
  context: CommandContext<FlagSpecs>,
): Promise<{ iam: BetterIam; basePath: string; close?: () => Promise<void> }> {
  const { flags } = context;
  if (!flags.url && ((await context.configPath()) || context.env.BETTER_IAM_DATABASE_URL)) {
    const iam = await context.iam();
    return { iam, basePath: iam.endpoint.basePath };
  }
  // The route table is the same for every deployment of this version. Plugin endpoints are not listed; call them
  // as plugins/{pluginId}/{path}.
  const iam = betterIam({
    database: sqliteAdapter({ filename: ':memory:' }),
    secret: randomBytes(32).toString('base64url'),
    baseURL: 'http://localhost:3000',
  });
  return {
    iam,
    basePath: flags.url ? parseEndpoint(flags.url).basePath : '/api/iam',
    close: () => iam.store.close(),
  };
}

export const apiCommands = [
  defineCommand({
    name: 'api',
    group: 'API',
    summary: 'Call any IAM API method as the current token',
    description:
      'api calls any method of the HTTP API (the same routes and permission checks as POST {basePath}/{group}/{method}) as BETTER_IAM_TOKEN or the session saved by login, in process through the configuration or against --url, and prints the result. Build the input with --data (JSON, @file.json, or - for standard input) and key=value items: name=Admin sets a string, limit:=10 or actions:=\'["a","b"]\' sets JSON, document:=@policy.json reads a JSON file, content=@terms.md reads a text file, resource.type=project nests, and actions[]=a appends. --tenant (or BETTER_IAM_TENANT, or the saved profile) fills tenantId when the input has none. api --list [GROUP] lists every route with whether it needs a credential.',
    usage:
      'better-iam api GROUP.METHOD [key=value ...] [--data JSON|@FILE|-] [--tenant TENANT_ID] [--list] [--url URL] [--profile NAME]',
    target: 'token',
    args: [
      { name: 'route', description: 'group.method (roles.create, auth.getSession) or authorize' },
      {
        name: 'fields',
        description: 'key=value, key:=json, key:=@file.json, key=@file.txt',
        variadic: true,
      },
    ],
    flags: {
      data: {
        type: 'string',
        value: 'JSON|@FILE|-',
        description: 'Request body as JSON, a JSON file, or standard input',
      },
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        env: 'BETTER_IAM_TENANT',
        profile: 'tenantId',
        description: 'tenantId for inputs that do not set one',
      },
      list: {
        type: 'boolean',
        description: 'List routes (optionally of one group) instead of calling one',
      },
    },
    examples: [
      'better-iam api --list roles',
      'better-iam api roles.create name=Reader permissions:=\'["documents:read"]\'',
      'better-iam api policies.create name=Deny-deletes document:=@deny.json --tenant ten_123',
      'better-iam api identities.list limit:=5 --query "[].email"',
      'echo \'{"slug":"acme"}\' | better-iam api tenants.lookup --data -',
    ],
    async run(context) {
      const { flags, args } = context;
      const [route, ...items] = args;
      if (flags.list || !route) {
        if (items.length) throw usageError('api --list takes at most a group name');
        const source = await routeSource(context);
        try {
          const group = route?.replace(/[./].*$/, '');
          const routes = listRoutes(source.iam).filter(
            (entry) => !group || entry.route.split('/')[0] === group,
          );
          if (group && !routes.length)
            throw new CliError(
              'NOT_FOUND',
              `No API group named ${group}`,
              'Run better-iam api --list for all groups.',
            );
          // A table by default: this is for reading; --format json gives tools the same rows.
          context.io.out(
            formatResult(
              routes.map((entry) => ({
                method: entry.route.replace('/', '.'),
                access: entry.access,
                http: `POST ${source.basePath}/${entry.route}`,
              })),
              (flags.format as OutputFormat | undefined) ?? 'table',
              flags.query,
            ),
          );
        } finally {
          await source.close?.();
        }
        return;
      }
      const path = routePath(route);
      const body = await requestBody(context, flags.data, items);
      if (flags.tenant && body.tenantId === undefined) body.tenantId = flags.tenant;
      // MFA enrollment is public for a sign-in challenge but uses the caller's own session without one.
      const nested = isRecord(body.credential) ? body.credential : {};
      const ownSession =
        (path === 'auth/beginMfa' && typeof body.challenge !== 'string') ||
        (path === 'auth/confirmMfa' && typeof nested.challenge !== 'string');
      const transport = await context.api({ authenticated: ownSession || !isPublicRoute(path) });
      return transport.call(path, body);
    },
  }),
];
