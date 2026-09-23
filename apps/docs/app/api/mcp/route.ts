import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import { registerSearchTool, registerSourceTools } from 'fumadocs-core/mcp';
import { z } from 'zod';
import { searchApi } from '@/lib/search';
import { docsLlms, source } from '@/lib/source';
import { siteUrl, version } from '@/lib/shared';

/**
 * A Model Context Protocol endpoint for these docs, so AI assistants can search and read them while writing code
 * against Better IAM: `search`, `list_pages`, and `get_page` over the whole site, plus `lookup_api_method`,
 * `lookup_export`, and `lookup_error_code` for exact reference answers. Connect a client to `{site}/api/mcp`
 * (Streamable HTTP).
 */

interface ApiMethod {
  name: string;
  http: string | null;
  credential: string;
  params: { name: string; optional: boolean; type: string }[];
  result: string;
  async?: boolean;
}

interface ExportEntry {
  specifier: string;
  exports: { name: string; kind: string; params: string[] | null; doc: string; from?: string }[];
}

// Paths stay statically scoped to their folders so the bundler can trace exactly which files the route needs.
const readGenerated = (file: 'api.json' | 'errors.json' | 'exports.json') =>
  readFileSync(join(process.cwd(), 'generated', file), 'utf8');
const readDescription = (file: string) =>
  readFileSync(join(process.cwd(), 'descriptions', file), 'utf8');
let api: { groups: { name: string; methods: ApiMethod[] }[] } | undefined;
let errors: { code: string; statuses: number[]; messages: string[] }[] | undefined;
let exportsIndex: ExportEntry[] | undefined;

/** The curated `## name` section of a descriptions file, or undefined. */
function section(file: string, name: string): string | undefined {
  try {
    const text = readDescription(file).replace(/\r\n/g, '\n');
    const start = text.indexOf(`\n## ${name}\n`);
    if (start === -1) return undefined;
    const rest = text.slice(start + name.length + 5);
    const end = rest.search(/\n## /);
    return (end === -1 ? rest : rest.slice(0, end)).trim();
  } catch {
    return undefined;
  }
}

const kebab = (name: string) => name.replace(/[A-Z]/g, (char) => `-${char.toLowerCase()}`);

function lookupMethod(query: string): string {
  api ??= JSON.parse(readGenerated('api.json'));
  const [groupName, methodName] = query.replace(/^iam\.api\.|^client\./, '').split('.');
  const group = api!.groups.find((entry) => entry.name.toLowerCase() === groupName?.toLowerCase());
  if (!group)
    return `Unknown API group "${groupName}". Groups: ${api!.groups.map((entry) => entry.name).join(', ')}.`;
  const method = group.methods.find(
    (entry) => entry.name.toLowerCase() === methodName?.toLowerCase(),
  );
  if (!method)
    return `Unknown method "${methodName}" in ${group.name}. Methods: ${group.methods.map((entry) => entry.name).join(', ')}.`;
  const params = method.params
    .map((param) => `  ${param.name}${param.optional ? '?' : ''}: ${param.type}`)
    .join(',\n');
  return [
    `# iam.api.${group.name}.${method.name}`,
    '',
    section(`api/${group.name}.md`, method.name) ?? '',
    '',
    `HTTP: ${method.http ? `${method.http.replace('POST ', 'POST /api/iam')} (credential: ${method.credential})` : 'not routed; call it from server code'}`,
    '',
    '```ts',
    `iam.api.${group.name}.${method.name}(\n${params}\n): ${method.async ? `Promise<${method.result}>` : method.result}`,
    '```',
    '',
    `Reference: ${siteUrl}/docs/reference/api/${kebab(group.name)}#${method.name.toLowerCase()}`,
  ].join('\n');
}

function lookupError(code: string): string {
  errors ??= JSON.parse(readGenerated('errors.json'));
  const entry = errors!.find((item) => item.code === code.trim().toUpperCase());
  if (!entry)
    return `Unknown error code "${code}". See ${siteUrl}/docs/reference/errors for every code.`;
  return [
    `# ${entry.code} (HTTP ${entry.statuses.join(', ')})`,
    '',
    section('errors.md', entry.code) ?? '',
    '',
    entry.messages.length
      ? `Example messages:\n${entry.messages.map((message) => `- ${message}`).join('\n')}`
      : '',
    '',
    `Reference: ${siteUrl}/docs/reference/errors#${entry.code.toLowerCase()}`,
  ].join('\n');
}

/** The heading anchor of an entry point on the exports page (github-slugger drops `@` and `/`). */
const exportsAnchor = (specifier: string) => specifier.replace(/[@/]/g, '');

function lookupExport(query: string): string {
  exportsIndex ??= JSON.parse(readGenerated('exports.json'));
  // "useSession", "@better-iam/react useSession", or the umbrella form "better-iam/react#useSession".
  const match = query.trim().match(/^(?:(@?better-iam(?:\/[\w/-]+)?)[\s#:.]+)?([\w$]+)$/);
  if (!match) return `Give an export name such as "useSession", optionally after its package.`;
  const [, rawSpecifier, name] = match;
  const specifier = rawSpecifier?.startsWith('better-iam/')
    ? `@better-iam/${rawSpecifier.slice('better-iam/'.length)}`
    : rawSpecifier;
  // A package name also covers its other entry points: `@better-iam/next` finds `@better-iam/next/client` exports.
  const inScope = (entry: ExportEntry) =>
    !specifier || entry.specifier === specifier || entry.specifier.startsWith(`${specifier}/`);
  const found = exportsIndex!.flatMap((entry) =>
    (inScope(entry) ? entry.exports : [])
      .filter((item) => item.name.toLowerCase() === name!.toLowerCase())
      .map((item) => ({ entry, item })),
  );
  // Curated text lives under the entry point that declares an export; re-exports share it.
  const curated = (entry: ExportEntry, item: ExportEntry['exports'][number]) =>
    section('exports.md', `${entry.specifier} ${item.name}`) ??
    exportsIndex!
      .filter(
        (origin) =>
          item.from &&
          (origin.specifier === item.from || origin.specifier.startsWith(`${item.from}/`)) &&
          origin.exports.some((other) => other.name === item.name && !other.from),
      )
      .map((origin) => section('exports.md', `${origin.specifier} ${item.name}`))
      .find(Boolean);
  if (!found.length)
    return `No export named "${name}"${specifier ? ` in ${specifier}` : ''}. Every export is listed at ${siteUrl}/docs/reference/exports.`;
  return found
    .map(({ entry, item }) => {
      const label =
        item.params && item.kind !== 'class'
          ? `${item.name}(${item.params.join(', ')})`
          : `${item.kind} ${item.name}`;
      return [
        `# ${item.name} from ${entry.specifier}`,
        '',
        `\`${label}\``,
        '',
        curated(entry, item) ?? item.doc,
        item.from ? `\nRe-exported from ${item.from}.` : '',
        '',
        `Reference: ${siteUrl}/docs/reference/exports#${exportsAnchor(entry.specifier)}`,
      ].join('\n');
    })
    .join('\n\n---\n\n');
}

const handler = createMcpHandler(() => {
  const mcp = new McpServer(
    { name: 'better-iam-docs', version },
    {
      instructions:
        'Documentation for Better IAM, an embeddable TypeScript authentication, authorization, and identity-governance platform. Use `search` to find pages, `get_page` to read one as Markdown, `lookup_api_method` for the exact signature and behaviour of an `iam.api.{group}.{method}` call, `lookup_export` for a function, hook, or component a package exports, and `lookup_error_code` for what an IamError code means and how to handle it.',
    },
  );
  registerSearchTool(mcp, searchApi);
  registerSourceTools(mcp, source, docsLlms);
  mcp.registerTool(
    'lookup_api_method',
    {
      title: 'Look up an API method',
      description:
        'Signature, HTTP route, permission, errors, and behaviour of one server API method, for example "groups.addMember" or "iam.api.auth.signIn".',
      inputSchema: z.object({
        method: z.string().describe('group.method, for example "bindings.activate"'),
      }),
    },
    async ({ method }) => ({ content: [{ type: 'text', text: lookupMethod(method) }] }),
  );
  mcp.registerTool(
    'lookup_error_code',
    {
      title: 'Look up an error code',
      description:
        'What an IamError code (for example ACCESS_DENIED or RATE_LIMITED) means, why it happens, and how to handle it.',
      inputSchema: z.object({ code: z.string() }),
    },
    async ({ code }) => ({ content: [{ type: 'text', text: lookupError(code) }] }),
  );
  mcp.registerTool(
    'lookup_export',
    {
      title: 'Look up a package export',
      description:
        'What a function, hook, component, class, or constant exported by a Better IAM package does, with its parameters, for example "useSession", "createIamMiddleware", or "@better-iam/core evaluatePolicy".',
      inputSchema: z.object({
        name: z
          .string()
          .describe('Export name, optionally after its package: "@better-iam/react useSession"'),
      }),
    },
    async ({ name }) => ({ content: [{ type: 'text', text: lookupExport(name) }] }),
  );
  return mcp;
});

export const dynamic = 'force-dynamic';

export const POST = (request: Request) => handler.fetch(request);
export const GET = (request: Request) => handler.fetch(request);
export const DELETE = (request: Request) => handler.fetch(request);
