import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ReactNode } from 'react';
import { highlight } from 'fumadocs-core/highlight';
import { CodeBlock, Pre } from 'fumadocs-ui/components/codeblock';
import { TypeTable, type TypeNode } from 'fumadocs-ui/components/type-table';

interface Schema {
  $ref?: string;
  type?: string;
  const?: unknown;
  enum?: unknown[];
  anyOf?: Schema[];
  allOf?: Schema[];
  items?: Schema;
  prefixItems?: Schema[];
  properties?: Record<string, Schema>;
  required?: string[];
  additionalProperties?: Schema | boolean;
  description?: string;
}

interface Shapes {
  components: Record<string, Schema>;
  methods: Record<string, { input?: Schema; inputOptional?: boolean; result?: Schema }>;
}

// Read at render time instead of imported: the catalog is large, and a static import would make TypeScript infer
// (and the bundler inline) a literal type for every schema. Pages render on the server, from the app directory.
let cached: Shapes | undefined;
function shapes(): Shapes {
  cached ??= JSON.parse(
    readFileSync(join(process.cwd(), 'generated', 'api-shapes.json'), 'utf8'),
  ) as Shapes;
  return cached;
}

/** Plain-language descriptions of common field names, used when the source has no doc comment for a field. */
let fieldDocs: Record<string, string> | undefined;
function fieldDescription(name: string): string | undefined {
  fieldDocs ??= JSON.parse(
    readFileSync(join(process.cwd(), 'descriptions', 'fields.json'), 'utf8'),
  ) as Record<string, string>;
  return Object.hasOwn(fieldDocs, name) ? fieldDocs[name] : undefined;
}

/** Renders `code` spans in a plain-text description. */
function inline(text?: string): ReactNode {
  if (!text) return undefined;
  return text
    .split(/(`[^`]+`)/g)
    .map((part, index) =>
      part.startsWith('`') ? <code key={index}>{part.slice(1, -1)}</code> : part,
    );
}

const refName = (schema: Schema) => schema.$ref?.split('/').pop();
function resolve(schema: Schema, seen = new Set<string>()): Schema {
  const name = refName(schema);
  if (!name || seen.has(name)) return schema;
  seen.add(name);
  return resolve(shapes().components[name] ?? {}, seen);
}

/** A short TypeScript-style label for a schema. */
function label(schema: Schema): string {
  const name = refName(schema);
  if (name) return name;
  if (schema.const !== undefined) return JSON.stringify(schema.const);
  if (schema.enum) return schema.enum.map((value) => JSON.stringify(value)).join(' | ');
  if (schema.anyOf) return schema.anyOf.map(label).join(' | ');
  if (schema.allOf) return schema.allOf.map(label).join(' & ');
  if (schema.type === 'array') return schema.items ? `${wrap(label(schema.items))}[]` : 'array';
  if (schema.type === 'object') {
    if (schema.properties && Object.keys(schema.properties).length) return 'object';
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object')
      return `Record<string, ${label(schema.additionalProperties)}>`;
    return 'object';
  }
  if (schema.type) return schema.type;
  return schema.description === 'Any JSON value' ? 'Json' : 'unknown';
}
const wrap = (text: string) => (text.includes(' ') ? `(${text})` : text);

/** Objects (directly, through a reference, or as array items) that are worth expanding into their own table. */
function expandable(schema: Schema): Schema | undefined {
  const resolved = resolve(schema);
  if (resolved.type === 'object' && resolved.properties && Object.keys(resolved.properties).length)
    return resolved;
  if (resolved.type === 'array' && resolved.items) return expandable(resolved.items);
  if (resolved.allOf) {
    // An intersection (`A & B`) reads best as one table with every member's fields.
    const parts = resolved.allOf.map(expandable).filter((part): part is Schema => Boolean(part));
    if (!parts.length) return undefined;
    return {
      type: 'object',
      properties: Object.assign({}, ...parts.map((part) => part.properties)),
      required: parts.flatMap((part) => part.required ?? []),
    };
  }
  if (resolved.anyOf) {
    const objects = resolved.anyOf.map(expandable).filter(Boolean);
    if (objects.length === 1) return objects[0];
  }
  return undefined;
}

function Fields({ schema, depth }: { schema: Schema; depth: number }) {
  const properties = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  const type: Record<string, TypeNode> = {};
  for (const [name, property] of Object.entries(properties)) {
    const resolved = resolve(property);
    const nested = depth < 3 ? expandable(property) : undefined;
    type[name] = {
      type: <code>{label(property)}</code>,
      description: inline(property.description ?? resolved.description ?? fieldDescription(name)),
      required: required.has(name),
      ...(nested ? { typeDescription: <Fields schema={nested} depth={depth + 1} /> } : {}),
    };
  }
  return <TypeTable type={type} className="my-2" />;
}

function Shape({
  title,
  schema,
  optional,
}: {
  title: string;
  schema?: Schema;
  optional?: boolean;
}): ReactNode {
  if (!schema) return null;
  const resolved = resolve(schema);
  const object = expandable(schema);
  const name = refName(schema);
  let summary: ReactNode;
  if (resolved.type === 'array')
    summary = (
      <>
        An array of <code>{label(resolved.items ?? {})}</code>.
      </>
    );
  else if (resolved.anyOf && !object)
    summary = (
      <>
        One of <code>{label(resolved)}</code>.
      </>
    );
  else if (!object && !resolved.type && !resolved.anyOf)
    summary = <>Nothing meaningful (resolves with no value).</>;
  else if (!object)
    summary = (
      <>
        A <code>{label(schema)}</code>.
      </>
    );
  else if (resolved.anyOf)
    summary = (
      <>
        One of <code>{label(resolved)}</code>; the object form has these fields:
      </>
    );
  else if (name)
    summary = (
      <>
        A <code>{name}</code> object{optional ? ' (the argument is optional)' : ''}:
      </>
    );
  else summary = optional ? <>An optional object:</> : null;
  return (
    <div className="not-prose my-4 flex flex-col gap-1">
      <div className="text-sm font-semibold text-fd-foreground">{title}</div>
      {summary ? <p className="text-sm text-fd-muted-foreground">{summary}</p> : null}
      {object ? <Fields schema={object} depth={0} /> : null}
    </div>
  );
}

/**
 * A request body built from the input schema: required fields only, with placeholders that say what to put there
 * (`"<tenantId>"`), realistic numbers for times and durations, and the first allowed value of enums.
 */
function sample(schema: Schema | undefined, name = '', depth = 0): unknown {
  if (!schema || depth > 4) return {};
  const resolved = resolve(schema);
  if (resolved.const !== undefined) return resolved.const;
  if (resolved.enum?.length) return resolved.enum[0];
  const object = resolved.type === 'object' || resolved.allOf ? expandable(resolved) : undefined;
  if (object) {
    const required = new Set(object.required ?? []);
    const body: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(object.properties ?? {}))
      if (required.has(key)) body[key] = sample(value, key, depth + 1);
    return body;
  }
  if (resolved.anyOf?.length) {
    const concrete = resolved.anyOf.find((option) => option.type !== 'null') ?? resolved.anyOf[0];
    return sample(concrete, name, depth + 1);
  }
  switch (resolved.type) {
    case 'array':
      return [sample(resolved.items, name.replace(/s$/, ''), depth + 1)];
    case 'number':
      return /At$/.test(name) ? 1790000000000 : /Ms$/.test(name) ? 3600000 : 1;
    case 'boolean':
      return true;
    case 'string':
      return `<${name || 'value'}>`;
    default:
      return {};
  }
}

async function HttpExample({ id, input, open }: { id: string; input?: Schema; open: boolean }) {
  const [group, method] = id.split('.');
  const body = JSON.stringify(input ? sample(input) : {}, null, 2);
  const code = [
    `curl -X POST "$IAM_URL/api/iam/${group}/${method}" \\`,
    // Public methods (sign-in, discovery) take no credential.
    ...(open ? [] : [`  -H "Authorization: Bearer $BETTER_IAM_TOKEN" \\`]),
    `  -H "Content-Type: application/json" \\`,
    `  -H "X-Better-IAM: 1" \\`,
    `  -d '${body.replace(/'/g, "'\\''")}'`,
  ].join('\n');
  const rendered = await highlight(code, {
    lang: 'bash',
    themes: { light: 'github-light', dark: 'github-dark' },
    defaultColor: false,
    components: { pre: (props) => <Pre {...props} /> },
  });
  return (
    <details className="group my-4 rounded-xl border bg-fd-card">
      <summary className="cursor-pointer select-none px-4 py-2.5 text-sm font-medium text-fd-muted-foreground hover:text-fd-foreground">
        Example HTTP request
      </summary>
      <div className="border-t px-4 pb-4 pt-2 text-sm text-fd-muted-foreground">
        <p className="mb-2">
          Only the required fields are shown; replace each <code>{'<placeholder>'}</code>. The
          response is <code>{'{ "data": … }'}</code> on success or{' '}
          <code>{'{ "error": { "code", "message" } }'}</code>.
        </p>
        <CodeBlock className="my-0">{rendered}</CodeBlock>
      </div>
    </details>
  );
}

/**
 * The input and return value of an API method as readable field tables, generated from its TypeScript types, plus a
 * ready-to-run HTTP example for routed methods. Fields that are objects expand into their own table.
 */
export function ApiShape({ id, http }: { id: string; http?: boolean | 'public' }) {
  const entry = shapes().methods[id];
  if (!entry) return null;
  return (
    <>
      <Shape title="Input" schema={entry.input} optional={entry.inputOptional} />
      <Shape title="Returns" schema={entry.result} />
      {http ? <HttpExample id={id} input={entry.input} open={http === 'public'} /> : null}
    </>
  );
}
