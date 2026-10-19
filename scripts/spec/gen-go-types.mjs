#!/usr/bin/env node
// Generates the typed Go API surface, go/apitypes/*_gen.go, from spec/api/openapi.json and spec/api/routes.json.
//
//   node scripts/spec/gen-go-types.mjs             regenerate go/apitypes/*_gen.go
//   node scripts/spec/gen-go-types.mjs --out DIR   write the *_gen.go files into DIR instead
//   (--spec DIR and --core DIR override the spec/ and go/core/ directories that are read)
//
// Output is deterministic: it depends only on the two spec files and on the exported type names declared in
// go/core/*.go, and every file is passed through gofmt (Go must be installed). scripts/spec/check-generated.mjs
// regenerates into a temporary directory and fails when the checked-in files differ.
//
// Mapping (see go/apitypes/doc.go for the user-facing description):
//
// - Every component schema becomes one Go type of the same name, except the names go/core already declares (Tenant,
//   Identity, Session, AuditEvent, ...): those become aliases of the core types (`type Tenant = core.Tenant`).
// - Every RPC route of routes.json becomes <Group><Method>Input and <Group><Method>Output (the request body and the
//   `data` of the answer), an Op[<In>, <Out>] value Op<Group><Method>, and a row of the operation table. The special
//   routes authorize, authorizeMany and listAccessible are added from the TypeScript operation signatures.
// - Objects become structs (fields in schema order, JSON names as tags). A required member is a plain field; an
//   optional one is `omitzero` and a pointer (or a nil-able slice/map), so an absent member and an empty or zero value
//   stay distinct; a nullable member is a pointer without omitzero; optional and nullable is Optional[*T], which keeps
//   absent, null and a value apart. Objects that also allow other members (TypeScript index signatures) keep them in an
//   Extra map.
// - String enums become string types with one constant per value; `string & {}` style open enums keep their known
//   values as constants. `true | false` is bool.
// - anyOf unions become a struct with one pointer field per variant (exactly one is set). Decoding picks the first
//   variant whose shape (JSON kind, constants and discriminators, required and allowed members) the value matches.
// - Free-form JSON objects are *core.Object (JavaScript property order kept); unknown values are `any`.
// - go/core structs without JSON tags (core.CredentialInput, core.AuthenticatedPrincipal) are in-process forms, not
//   wire forms, so their schemas get generated types.
// - CORRECTIONS (below) fixes the few members where openapi.json disagrees with what the TypeScript server sends.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? resolve(args[index + 1]) : fallback;
};
const outDir = option('--out', join(root, 'go', 'apitypes'));
const specDir = option('--spec', join(root, 'spec'));
const coreDir = option('--core', join(root, 'go', 'core'));

const GENERATOR = 'scripts/spec/gen-go-types.mjs';
const CORE_IMPORT = 'github.com/Better-IAM/better-iam/go/core';

const openapi = JSON.parse(readFileSync(join(specDir, 'api', 'openapi.json'), 'utf8'));
const routes = JSON.parse(readFileSync(join(specDir, 'api', 'routes.json'), 'utf8'));
const schemas = openapi.components.schemas;
const warnings = [];

// --- go/core types ------------------------------------------------------------------------------------------------

/**
 * Exported top-level types declared in go/core (non-test files): name → nil-ability category of the type, or 'nojson'
 * for a struct without any JSON tags (an in-process type such as core.CredentialInput, whose fields are http.Header and
 * Go names: it is not the wire form of the schema, so the schema gets its own type).
 */
function readCoreTypes(dir) {
  const types = new Map();
  for (const file of readdirSync(dir)
    .filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
    .sort()) {
    const text = readFileSync(join(dir, file), 'utf8');
    for (const match of text.matchAll(
      /^type ([A-Z]\w*)(\[[^\]\n]*\])?[ \t]*(=)?[ \t]*([^\n]*)$/gm,
    )) {
      const [, name, generic, , restRaw] = match;
      if (generic) continue;
      const rest = restRaw.replace(/\/\/.*$/, '').trim();
      let category;
      if (rest === 'any' || rest === 'interface{}' || rest.startsWith('interface'))
        category = 'any';
      else if (rest.startsWith('struct')) {
        const start = match.index + match[0].length;
        const end = text.indexOf('\n}', start);
        const body = text.slice(start, end < 0 ? undefined : end);
        const hasMarshaler = new RegExp(`^func \\([a-z]+ \\*?${name}\\) MarshalJSON\\(`, 'm').test(
          text,
        );
        category = body.includes('json:"') || hasMarshaler || !body.trim() ? 'value' : 'nojson';
      } else if (/^(\[\]|map\[|\*|func|chan )/.test(rest)) category = 'ptrlike';
      else category = 'value';
      types.set(name, category);
    }
  }
  return types;
}

const coreTypes = readCoreTypes(coreDir);
const coreMapped = new Set(
  Object.keys(schemas).filter((name) => coreTypes.has(name) && coreTypes.get(name) !== 'nojson'),
);
const coreInProcess = new Set(
  Object.keys(schemas).filter((name) => coreTypes.get(name) === 'nojson'),
);

// --- corrections ----------------------------------------------------------------------------------------------------
//
// Places where spec/api/openapi.json disagrees with what the TypeScript server actually sends and accepts, found by
// go/apitypes TestTraceRoundTrip on the recorded traces. Keys are generated Go type names ("Type" or "Type.member").
//   optional: the member is listed as required, but the server leaves it out. The docs generator
//             (apps/docs/scripts/generate.mjs, describeObject) marks every non-`?` member required, so an inferred
//             `member: T | undefined` (from `{ member: record.member }`) loses its optionality; JSON omits undefined.
//   add:      members the server reads although the declared TypeScript input type does not list them.
//   open:     the answer spreads a stored record, so it carries members the declared type does not list.
// The generator fails when a correction no longer matches anything, so entries are dropped once the spec is fixed.
const CORRECTIONS = {
  'CredentialsCreateOutput.name': { optional: true },
  'DomainsAddOutput.verifiedAt': { optional: true },
  'DomainsAddOutput.lastCheckedAt': { optional: true },
  'DomainsVerifyOutputDomain.verifiedAt': { optional: true },
  'DomainsVerifyOutputDomain.lastCheckedAt': { optional: true },
  'WebhooksListDeliveriesOutputItem.deliveredAt': { optional: true },
  'WebhooksListDeliveriesOutputItem.failedAt': { optional: true },
  'WebhooksListDeliveriesOutputItem.lastError': { optional: true },
  'RoleMiningApplyOutput.createdBindingId': { optional: true },
  'ComplianceListControlsOutputItem.latest': { optional: true },
  // routes.json dispatch: auth/confirmMfa uses the request credential unless body.credential carries a challenge.
  'AuthConfirmMfaInput.credential': { optional: true },
  // billing.spend passes the rest of its input to the spend report, which reads SpendQuery.shareUnattributed.
  BillingSpendInput: { add: { shareUnattributed: { type: 'boolean' } } },
  // tenants.revokeInvitation answers the stored invitation without tokenHash and uniqueKey (creatorId included).
  TenantsRevokeInvitationOutput: { open: true },
  // packages/server/src/http.ts errorResponse: WRONG_REGION answers also carry region and, when known, location
  // (routes.json response.error.body).
  ErrorEnvelopeError: {
    add: {
      region: {
        type: 'string',
        description: 'On WRONG_REGION: the region that serves the organization.',
      },
      location: {
        type: 'string',
        description: "On WRONG_REGION: the organization's sign-in URL there, when known.",
      },
    },
  },
};
const correctionsApplied = new Set();

function correct(name, ir) {
  const whole = CORRECTIONS[name];
  if (whole) {
    correctionsApplied.add(name);
    for (const [member, schema] of Object.entries(whole.add ?? {})) {
      if (ir.props.some((prop) => prop.name === member))
        throw new Error(`${name}.${member} is already declared`);
      ir.props.push({ name: member, ir: norm(schema), required: false, schema });
    }
    if (whole.open) ir.extra ??= { k: 'any' };
  }
  for (const prop of ir.props) {
    const key = `${name}.${prop.name}`;
    if (!CORRECTIONS[key]) continue;
    correctionsApplied.add(key);
    if (CORRECTIONS[key].optional) prop.required = false;
  }
}

// --- schema normalization -------------------------------------------------------------------------------------------
//
// IR nodes: { k: 'any' | 'null' | 'ref' | 'string' | 'number' | 'bool' | 'array' | 'tuple' | 'map' | 'freeobject' |
// 'object' | 'union', nullable? }. Scalars carry `open` (any value of the type) and `consts` (the listed values; with
// open, only the known ones). Objects carry `props` [{ name, ir, required, schema }] and `extra` (the IR of other
// members, null when the object is closed).

const refName = (ref) => {
  const prefix = '#/components/schemas/';
  if (!ref.startsWith(prefix)) throw new Error(`unsupported $ref ${ref}`);
  const name = ref.slice(prefix.length);
  if (!schemas[name]) throw new Error(`dangling $ref ${ref}`);
  return name;
};

const componentIR = new Map();
function comp(name) {
  if (!componentIR.has(name)) {
    componentIR.set(name, undefined);
    componentIR.set(name, norm(schemas[name]));
  }
  const ir = componentIR.get(name);
  if (!ir) throw new Error(`cyclic allOf through components/schemas/${name}`);
  return ir;
}

function deref(ir) {
  let current = ir;
  let nullable = !!ir.nullable;
  for (let depth = 0; current.k === 'ref'; depth++) {
    if (depth > 64) throw new Error(`$ref loop at ${ir.name}`);
    current = comp(current.name);
    nullable ||= !!current.nullable;
  }
  return nullable && !current.nullable ? { ...current, nullable } : current;
}

function constIR(value) {
  if (value === null) return { k: 'null' };
  if (typeof value === 'string') return { k: 'string', open: false, consts: [value] };
  if (typeof value === 'number') return { k: 'number', open: false, consts: [value] };
  if (typeof value === 'boolean') return { k: 'bool', open: false, consts: [value] };
  return { k: 'any' };
}

function norm(schema) {
  if (schema === undefined || schema === true || schema === null) return { k: 'any' };
  if (schema === false) throw new Error('the false schema is not supported');
  if (schema.$ref) return { k: 'ref', name: refName(schema.$ref) };
  if (schema.anyOf) return normAnyOf(schema.anyOf.map(norm));
  if (schema.oneOf) return normAnyOf(schema.oneOf.map(norm));
  if (schema.allOf) return normAllOf(schema.allOf.map(norm));
  if ('const' in schema) return constIR(schema.const);
  if (schema.enum) return normAnyOf(schema.enum.map(constIR));
  if (Array.isArray(schema.type))
    return normAnyOf(schema.type.map((type) => norm({ ...schema, type })));
  switch (schema.type) {
    case 'string':
      return { k: 'string', open: true };
    case 'number':
    case 'integer':
      return { k: 'number', open: true };
    case 'boolean':
      return { k: 'bool', open: true };
    case 'null':
      return { k: 'null' };
    case 'array':
      if (schema.prefixItems) return { k: 'tuple', items: schema.prefixItems.map(norm) };
      return { k: 'array', items: norm(schema.items) };
    case 'object':
      return normObject(schema);
    case undefined:
      return { k: 'any' };
    default:
      throw new Error(`unsupported schema type ${JSON.stringify(schema.type)}`);
  }
}

function normObject(schema) {
  const required = new Set(schema.required ?? []);
  const props = Object.entries(schema.properties ?? {}).map(([name, propSchema]) => ({
    name,
    ir: norm(propSchema),
    required: required.has(name),
    schema: propSchema,
  }));
  const additional = schema.additionalProperties;
  let extra;
  if (additional === false) extra = null;
  // Without additionalProperties, a schema with members is the closed shape the docs generator writes for envelopes;
  // one without members is TypeScript's `object` / `{}`: any members.
  else if (additional === undefined) extra = props.length ? null : { k: 'any' };
  else if (additional === true) extra = { k: 'any' };
  else extra = norm(additional);
  if (!props.length) {
    if (!extra) return { k: 'object', props: [], extra: null };
    return extra.k === 'any' ? { k: 'freeobject' } : { k: 'map', value: extra };
  }
  return { k: 'object', props, extra };
}

function normAnyOf(list) {
  let nullable = false;
  const flat = [];
  const push = (variant) => {
    if (variant.k === 'null') {
      nullable = true;
      return;
    }
    let v = variant;
    if (v.nullable) {
      nullable = true;
      v = { ...v, nullable: false };
    }
    if (v.k === 'union') {
      v.variants.forEach(push);
      return;
    }
    flat.push(v);
  };
  list.forEach(push);
  if (flat.some((v) => v.k === 'any')) return { k: 'any' };
  const out = [];
  const scalars = {};
  for (const v of flat) {
    if (v.k === 'string' || v.k === 'number' || v.k === 'bool') {
      const previous = scalars[v.k];
      if (!previous) {
        const copy = { k: v.k, open: v.open };
        if (v.consts) copy.consts = [...v.consts];
        scalars[v.k] = copy;
        out.push(copy);
      } else {
        previous.open = previous.open || v.open;
        for (const value of v.consts ?? []) {
          previous.consts ??= [];
          if (!previous.consts.includes(value)) previous.consts.push(value);
        }
      }
    } else out.push(v);
  }
  const bool = scalars.bool;
  if (bool?.consts?.includes(true) && bool.consts.includes(false)) {
    bool.open = true;
    delete bool.consts;
  }
  if (bool?.open) delete bool.consts;
  if (!out.length) return { k: 'any' };
  if (out.length === 1) return nullable ? { ...out[0], nullable: true } : out[0];
  return { k: 'union', variants: out, nullable };
}

const isEmptyObject = (ir) => ir.k === 'freeobject' || (ir.k === 'object' && !ir.props.length);

function normAllOf(parts) {
  const resolved = parts.map((part) => (part.k === 'ref' ? deref(part) : part));
  // TypeScript's `string & {}` (a string that keeps editor completions for the listed literals).
  const strings = resolved.filter((part) => part.k === 'string');
  if (strings.length && resolved.every((part) => part.k === 'string' || isEmptyObject(part)))
    return { ...strings[0], open: true };
  // An intersection with a union distributes over its variants.
  const unionIndex = resolved.findIndex((part) => part.k === 'union');
  if (unionIndex >= 0) {
    const union = resolved[unionIndex];
    const merged = normAnyOf(
      union.variants.map((variant) =>
        normAllOf([...resolved.slice(0, unionIndex), variant, ...resolved.slice(unionIndex + 1)]),
      ),
    );
    return union.nullable ? { ...merged, nullable: true } : merged;
  }
  // `Omit<T, 'k'> & { k?: string }[]`: TypeScript reads it as `Omit<T, 'k'> & ({ k?: string }[])`, but the server
  // treats the value as an array of objects with the members of both parts (billing.recordMany's `events`).
  const arrays = resolved.filter((part) => part.k === 'array');
  if (arrays.length) {
    const objects = resolved.filter((part) => part.k !== 'array');
    return {
      k: 'array',
      items: mergeObjects([...objects, ...arrays.map((array) => deref(array.items))]),
    };
  }
  return mergeObjects(resolved);
}

/** Whether two IR nodes accept the same values (enum constants compared as sets). */
function sameType(a, b) {
  const x = deref(a);
  const y = deref(b);
  if (
    ['string', 'number', 'bool'].includes(x.k) &&
    x.k === y.k &&
    !!x.open === !!y.open &&
    !!x.nullable === !!y.nullable
  ) {
    const left = [...(x.consts ?? [])].map(String).sort();
    const right = [...(y.consts ?? [])].map(String).sort();
    return JSON.stringify(left) === JSON.stringify(right);
  }
  return JSON.stringify(x) === JSON.stringify(y);
}

function mergeObjects(list) {
  const props = [];
  const index = new Map();
  let extra = null;
  for (const part of list.map((item) => (item.k === 'ref' ? deref(item) : item))) {
    if (part.k === 'freeobject') {
      extra ??= { k: 'any' };
      continue;
    }
    if (part.k === 'map') {
      extra ??= part.value;
      continue;
    }
    if (part.k !== 'object') throw new Error(`allOf over a ${part.k} schema is not supported`);
    for (const prop of part.props) {
      if (index.has(prop.name)) {
        const previous = props[index.get(prop.name)];
        previous.required ||= prop.required;
        if (previous.ir.k === 'any') previous.ir = prop.ir;
        else if (!sameType(previous.ir, prop.ir))
          warnings.push(
            `allOf: member "${prop.name}" is declared twice with different types; the first is kept`,
          );
        continue;
      }
      index.set(prop.name, props.length);
      props.push({ ...prop });
    }
    if (part.extra) extra ??= part.extra;
  }
  if (!props.length) {
    if (!extra) return { k: 'object', props: [], extra: null };
    return extra.k === 'any' ? { k: 'freeobject' } : { k: 'map', value: extra };
  }
  return { k: 'object', props, extra };
}

// --- naming ------------------------------------------------------------------------------------------------------------

const INITIALISMS = {
  id: 'ID',
  ids: 'IDs',
  url: 'URL',
  urls: 'URLs',
  uri: 'URI',
  uris: 'URIs',
  ip: 'IP',
  ips: 'IPs',
  api: 'API',
  http: 'HTTP',
  https: 'HTTPS',
  json: 'JSON',
};

function words(text) {
  return String(text)
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function pascal(text) {
  const name = words(text)
    .map((word) => {
      const initialism = INITIALISMS[word.toLowerCase()];
      if (initialism) return initialism;
      if (word.length > 1 && word === word.toUpperCase() && /[A-Z]/.test(word))
        return word[0] + word.slice(1).toLowerCase();
      return word[0].toUpperCase() + word.slice(1);
    })
    .join('');
  if (!name) return '';
  return /^[0-9]/.test(name) ? `N${name}` : name;
}

const snake = (text) =>
  words(text)
    .map((word) => word.toLowerCase())
    .join('_');

const RESERVED = [
  // runtime.go and operations.go
  'Optional',
  'Some',
  'Null',
  'Operation',
  'Op',
  'Operations',
  'LookupOperation',
  'SchemaType',
  'CoreSchemas',
  'DefaultBasePath',
  'PluginRoutePrefix',
];

const used = new Set([...RESERVED, ...Object.keys(schemas)]);
function claim(name, what) {
  let candidate = name;
  for (let suffix = 2; used.has(candidate); suffix++) candidate = `${name}${suffix}`;
  if (candidate !== name && what) warnings.push(`${what}: ${name} is taken, using ${candidate}`);
  used.add(candidate);
  return candidate;
}

for (const name of Object.keys(schemas))
  if (!/^[A-Z][A-Za-z0-9]*$/.test(name))
    throw new Error(`schema name ${name} is not an exported Go identifier`);

// encoding/json ignores a tag name it considers invalid (and then uses the Go field name).
function checkTagName(name) {
  if (!name || /[^A-Za-z0-9!#$%&()*+\-./:;<=>?@[\]^_{|}~ ]/.test(name) || name === '-')
    throw new Error(`member name ${JSON.stringify(name)} cannot be a Go JSON tag`);
}

// --- emission ----------------------------------------------------------------------------------------------------------

/** file → declarations (Go source text), in emission order. */
const files = new Map();
const declare = (file, code) => {
  if (!files.has(file)) files.set(file, []);
  files.get(file).push(code);
};
/** Reserves the place of a declaration whose nested types are declared while it is built, so that it comes first. */
const reserve = (file) => {
  if (!files.has(file)) files.set(file, []);
  const list = files.get(file);
  const index = list.push('') - 1;
  return (code) => {
    list[index] = code;
  };
};

function comment(text, indent = '') {
  if (typeof text !== 'string' || !text.trim()) return '';
  return `${text
    .replace(/\r\n?/g, '\n')
    .trim()
    .split('\n')
    .map((line) => (line.trim() ? `${indent}// ${line.replace(/\s+$/, '')}` : `${indent}//`))
    .join('\n')}\n`;
}

const goString = (value) => JSON.stringify(value);
const goNumber = (value) => {
  const text = String(value);
  return /[.eE]/.test(text) ? text : `${text}.0`;
};
const goConst = (value) =>
  typeof value === 'string'
    ? goString(value)
    : typeof value === 'number'
      ? goNumber(value)
      : String(value);

const componentCategories = new Map();
function componentCategory(name) {
  if (coreMapped.has(name)) return coreTypes.get(name);
  if (!componentCategories.has(name)) {
    componentCategories.set(name, 'value'); // provisional, for recursive references
    const ir = comp(name);
    componentCategories.set(name, categoryOf(ir));
  }
  return componentCategories.get(name);
}

/** The category of the Go type an IR node becomes at top level (component aliases included). */
function categoryOf(ir) {
  switch (ir.k) {
    case 'any':
    case 'null':
      return 'any';
    case 'ref':
      return componentCategory(ir.name);
    case 'array':
    case 'map':
    case 'freeobject':
      return 'ptrlike';
    case 'tuple':
      return tupleType(ir) ? (ir.nullable ? 'ptrlike' : 'value') : 'ptrlike';
    default:
      return ir.nullable ? 'ptrlike' : 'value';
  }
}

function tupleType(ir) {
  const kinds = ir.items.map((item) => JSON.stringify(item));
  return kinds.every((kind) => kind === kinds[0]) && ir.items.length > 0 ? ir.items[0] : null;
}

const strip = (ir) => (ir.nullable ? { ...ir, nullable: false } : ir);

/**
 * The Go type expression for an IR node (ignoring its nullability), declaring named types under `context` as needed.
 * Returns { expr, cat } with cat 'value' (needs a pointer to be nil), 'ptrlike' (nil-able) or 'any'.
 */
function typeExpr(ir, context, file) {
  switch (ir.k) {
    case 'any':
    case 'null':
      return { expr: 'any', cat: 'any' };
    case 'ref':
      return { expr: ir.name, cat: componentCategory(ir.name) };
    case 'string':
    case 'number': {
      const goType = ir.k === 'string' ? 'string' : 'float64';
      if (ir.consts && (ir.consts.length > 1 || ir.open)) {
        const name = claim(context, 'enum');
        emitEnum(name, ir, file);
        return { expr: name, cat: 'value' };
      }
      return { expr: goType, cat: 'value' };
    }
    case 'bool':
      return { expr: 'bool', cat: 'value' };
    case 'array': {
      const item = valueType(ir.items, `${context}Item`, file);
      return { expr: `[]${item.expr}`, cat: 'ptrlike' };
    }
    case 'tuple': {
      const item = tupleType(ir);
      if (!item) return { expr: '[]any', cat: 'ptrlike' };
      return {
        expr: `[${ir.items.length}]${valueType(item, `${context}Item`, file).expr}`,
        cat: 'value',
      };
    }
    case 'map':
      return {
        expr: `map[string]${valueType(ir.value, `${context}Value`, file).expr}`,
        cat: 'ptrlike',
      };
    case 'freeobject':
      return { expr: '*core.Object', cat: 'ptrlike' };
    case 'object': {
      const name = claim(context, 'struct');
      emitStruct(name, ir, file);
      return { expr: name, cat: 'value' };
    }
    case 'union': {
      const name = claim(context, 'union');
      emitUnion(name, ir, file);
      return { expr: name, cat: 'value' };
    }
    default:
      throw new Error(`unknown IR kind ${ir.k}`);
  }
}

/** A type in a position without optionality (array items, map values, aliases): nullable values become pointers. */
function valueType(ir, context, file) {
  const base = typeExpr(strip(ir), context, file);
  if (ir.nullable && base.cat === 'value') return { expr: `*${base.expr}`, cat: 'ptrlike' };
  return base;
}

function constDoc(ir) {
  if (!ir.consts) return '';
  const values = ir.consts.map((value) => JSON.stringify(value)).join(', ');
  if (ir.open) return `Known values: ${values}; others are allowed.`;
  return ir.consts.length === 1 ? `Always ${values}.` : `One of ${values}.`;
}

function emitEnum(name, ir, file, description) {
  const goType = ir.k === 'string' ? 'string' : 'float64';
  let code = ir.open
    ? `// ${name} is an open set of ${ir.k} values: the constants below are the known ones; others are allowed.\n`
    : `// ${name} is one of the ${ir.k} constants below.\n`;
  if (description) code = `${comment(description)}//\n${code}`;
  code += `type ${name} ${goType}\n`;
  const names = new Set();
  const lines = ir.consts.map((value) => {
    const suffix = pascal(String(value)) || (value === '' ? 'Empty' : 'Value');
    let constName = `${name}${suffix}`;
    while (names.has(constName)) constName += 'X';
    names.add(constName);
    constName = claim(constName, 'enum constant');
    return `\t${constName} ${name} = ${goConst(value)}\n`;
  });
  code += `\nconst (\n${lines.join('')})\n`;
  declare(file, code);
}

function fieldName(prop, taken) {
  let name = pascal(prop) || 'Field';
  if (!/^[A-Z]/.test(name)) name = `X${name}`;
  let candidate = name;
  for (let suffix = 2; taken.has(candidate); suffix++) candidate = `${name}${suffix}`;
  taken.add(candidate);
  return candidate;
}

/** The field type and tag options for a member, from its requiredness and nullability. */
function memberType(prop, context, file) {
  const nullable = !!prop.ir.nullable;
  const base = typeExpr(strip(prop.ir), context, file);
  if (prop.required) {
    if (!nullable) return { expr: base.expr, omit: false };
    return { expr: base.cat === 'value' ? `*${base.expr}` : base.expr, omit: false };
  }
  if (!nullable) {
    if (base.cat === 'any') return { expr: `Optional[${base.expr}]`, omit: true };
    return { expr: base.cat === 'value' ? `*${base.expr}` : base.expr, omit: true };
  }
  const inner = base.cat === 'value' ? `*${base.expr}` : base.expr;
  return { expr: `Optional[${inner}]`, omit: true };
}

function emitStruct(name, ir, file, description) {
  correct(name, ir);
  const place = reserve(file);
  const taken = new Set();
  let body = '';
  const known = [];
  for (const prop of ir.props) {
    checkTagName(prop.name);
    known.push(prop.name);
    const goName = fieldName(prop.name, taken);
    const member = memberType(prop, `${name}${pascal(prop.name) || 'Field'}`, file);
    const single =
      ['bool', 'string', 'number'].includes(prop.ir.k) &&
      prop.ir.consts?.length === 1 &&
      !prop.ir.open
        ? constDoc(prop.ir)
        : '';
    const docs = [prop.schema?.description, single]
      .filter((text) => typeof text === 'string' && text.trim())
      .join('\n\n');
    body += comment(docs, '\t');
    body += `\t${goName} ${member.expr} \`json:"${prop.name}${member.omit ? ',omitzero' : ''}"\`\n`;
  }
  let extraField;
  if (ir.extra) {
    extraField = fieldName('Extra', taken);
    const extraType = valueType(ir.extra, `${name}Extra`, file).expr;
    body += `\t// ${extraField} holds the members the schema does not list (the type allows any others).\n`;
    body += `\t${extraField} map[string]${extraType} \`json:"-"\`\n`;
  }
  let code = description ? comment(description) : '';
  code += `type ${name} struct {\n${body}}\n`;
  if (extraField) {
    const knownVar = `known${name}`;
    code += `
var ${knownVar} = []string{${known.map(goString).join(', ')}}

// MarshalJSON writes the listed members, then ${extraField}.
func (v ${name}) MarshalJSON() ([]byte, error) {
	type plain ${name}
	return marshalWithExtra(plain(v), ${knownVar}, v.${extraField})
}

// UnmarshalJSON reads the listed members into their fields and every other member into ${extraField}.
func (v *${name}) UnmarshalJSON(data []byte) error {
	type plain ${name}
	if err := json.Unmarshal(data, (*plain)(v)); err != nil {
		return err
	}
	return unmarshalExtra(data, ${knownVar}, &v.${extraField})
}
`;
  }
  place(code);
}

// --- unions ------------------------------------------------------------------------------------------------------------

const KIND = {
  null: 'kindNull',
  bool: 'kindBool',
  number: 'kindNumber',
  string: 'kindString',
  array: 'kindArray',
  object: 'kindObject',
};

function kindsOf(ir) {
  const kinds = new Set();
  const add = (node) => {
    const n = node.k === 'ref' ? deref(node) : node;
    if (n.nullable) kinds.add('null');
    switch (n.k) {
      case 'any':
        Object.keys(KIND).forEach((kind) => kinds.add(kind));
        break;
      case 'null':
        kinds.add('null');
        break;
      case 'string':
      case 'number':
      case 'bool':
        kinds.add(n.k);
        break;
      case 'array':
      case 'tuple':
        kinds.add('array');
        break;
      case 'map':
      case 'freeobject':
      case 'object':
        kinds.add('object');
        break;
      case 'union':
        n.variants.forEach(add);
        break;
      default:
        throw new Error(`kindsOf ${n.k}`);
    }
  };
  add(ir);
  return Object.keys(KIND).filter((kind) => kinds.has(kind));
}

/** A Go `shape` literal (see runtime.go) describing what JSON values an IR node accepts, `depth` levels deep. */
function shapeOf(node, depth) {
  const ir = node.k === 'ref' ? deref(node) : node;
  const kinds = kindsOf(ir);
  const parts = [
    `kinds: ${kinds.length === 6 ? 'kindAny' : kinds.map((kind) => KIND[kind]).join(' | ')}`,
  ];
  if ((ir.k === 'string' || ir.k === 'number' || ir.k === 'bool') && ir.consts && !ir.open)
    parts.push(`consts: []any{${ir.consts.map(goConst).join(', ')}}`);
  if (depth > 0) {
    if (ir.k === 'object') {
      const required = ir.props.filter((prop) => prop.required).map((prop) => goString(prop.name));
      if (required.length) parts.push(`required: []string{${required.join(', ')}}`);
      if (ir.props.length)
        parts.push(
          `props: map[string]*shape{${ir.props.map((prop) => `${goString(prop.name)}: ${shapeOf(prop.ir, depth - 1)}`).join(', ')}}`,
        );
      if (!ir.extra) parts.push('closed: true');
      else if (ir.extra.k !== 'any') parts.push(`values: ${shapeOf(ir.extra, depth - 1)}`);
    } else if (ir.k === 'map') parts.push(`values: ${shapeOf(ir.value, depth - 1)}`);
    else if (ir.k === 'array') parts.push(`items: ${shapeOf(ir.items, depth - 1)}`);
    else if (ir.k === 'tuple') {
      const item = tupleType(ir);
      if (item) parts.push(`items: ${shapeOf(item, depth - 1)}`);
    }
  }
  return `&shape{${parts.join(', ')}}`;
}

/** The member every object variant has as a single constant, with distinct values: the union's discriminator. */
function discriminator(objects) {
  if (objects.length < 2) return null;
  const constOf = (variant, name) => {
    const prop = variant.props.find((item) => item.name === name);
    if (!prop || !prop.required) return undefined;
    const ir = prop.ir.k === 'ref' ? deref(prop.ir) : prop.ir;
    return ir.consts?.length === 1 && !ir.open ? ir.consts[0] : undefined;
  };
  for (const prop of objects[0].props) {
    const values = objects.map((variant) => constOf(variant, prop.name));
    if (
      values.every((value) => value !== undefined) &&
      new Set(values.map(String)).size === values.length
    )
      return { name: prop.name, values };
  }
  return null;
}

function emitUnion(name, ir, file, description) {
  const place = reserve(file);
  const variants = ir.variants;
  const objects = variants
    .map((v) => (v.k === 'ref' ? deref(v) : v))
    .filter((v) => v.k === 'object');
  const tag = discriminator(objects);
  const taken = new Set();
  const fields = [];
  let objectIndex = 0;
  for (const variant of variants) {
    let goName;
    let goType;
    let doc = '';
    const resolved = variant.k === 'ref' ? deref(variant) : variant;
    if (variant.k === 'ref') {
      goName = fieldName(variant.name, taken);
      const category = componentCategory(variant.name);
      // A component that is already a pointer (an alias of *core.Object) is not wrapped in another one.
      const pointer = !coreMapped.has(variant.name) && comp(variant.name).k === 'freeobject';
      goType = category === 'any' || pointer ? variant.name : `*${variant.name}`;
      if (resolved.k === 'object') {
        if (tag) doc = `${tag.name} = ${JSON.stringify(tag.values[objectIndex])}.`;
        objectIndex++;
      }
    } else if (variant.k === 'string' || variant.k === 'number' || variant.k === 'bool') {
      goName = fieldName({ string: 'String', number: 'Number', bool: 'Bool' }[variant.k], taken);
      goType = `*${typeExpr(variant, `${name}${goName}`, file).expr}`;
      doc = constDoc(variant);
    } else if (variant.k === 'array' || variant.k === 'tuple' || variant.k === 'map') {
      goName = fieldName({ array: 'Array', tuple: 'Tuple', map: 'Map' }[variant.k], taken);
      goType = `*${typeExpr(variant, `${name}${goName}`, file).expr}`;
    } else if (variant.k === 'freeobject') {
      goName = fieldName('Object', taken);
      goType = '*core.Object';
    } else if (variant.k === 'object') {
      let label;
      if (tag) label = pascal(String(tag.values[objectIndex]));
      else {
        const distinct = variant.props.find(
          (prop) =>
            prop.required &&
            !objects.every((other) => other.props.some((item) => item.name === prop.name)),
        );
        label = distinct ? pascal(distinct.name) : '';
      }
      if (tag) doc = `${tag.name} = ${JSON.stringify(tag.values[objectIndex])}.`;
      objectIndex++;
      goName = fieldName(label || 'Object', taken);
      goType = `*${typeExpr(variant, `${name}${goName}`, file).expr}`;
    } else throw new Error(`union variant ${variant.k} in ${name}`);
    fields.push({ goName, goType, variant, doc });
  }
  const tagDoc = tag ? ` The "${tag.name}" member tells the objects apart.` : '';
  let code = description ? `${comment(description)}//\n` : '';
  code += `// ${name} is a union: exactly one field is set.${tagDoc}\n// Decoding sets the first variant whose shape the value matches.\n`;
  code += `type ${name} struct {\n`;
  for (const field of fields) {
    code += comment(field.doc, '\t');
    code += `\t${field.goName} ${field.goType}\n`;
  }
  code += '}\n';
  const shapesVar = `shapes${name}`;
  const cases = fields
    .map((field, index) =>
      field.goType.startsWith('*')
        ? `\tcase ${index}:\n\t\tu.${field.goName} = new(${field.goType.slice(1)})\n\t\treturn json.Unmarshal(data, u.${field.goName})\n`
        : `\tcase ${index}:\n\t\treturn json.Unmarshal(data, &u.${field.goName})\n`,
    )
    .join('');
  const sets = fields
    .map(
      (field) => `\tcase u.${field.goName} != nil:\n\t\treturn json.Marshal(u.${field.goName})\n`,
    )
    .join('');
  code += `
var ${shapesVar} = []*shape{
${fields.map((field) => `\t${shapeOf(field.variant, 2)},\n`).join('')}}

// MarshalJSON writes the variant that is set.
func (u ${name}) MarshalJSON() ([]byte, error) {
	switch {
${sets}\t}
	return nil, errNoVariant(${goString(name)})
}

// UnmarshalJSON sets the first variant whose shape the value matches.
func (u *${name}) UnmarshalJSON(data []byte) error {
	*u = ${name}{}
	index, err := matchVariant(${goString(name)}, data, ${shapesVar})
	if err != nil {
		return err
	}
	switch index {
${cases}\t}
	return nil
}
`;
  place(code);
}

/** Declares `name` for an IR node at top level: a struct, union or enum type, or an alias of another type. */
function emitNamed(name, ir, file, description) {
  if (!ir.nullable && ir.k === 'object') return emitStruct(name, ir, file, description);
  if (!ir.nullable && ir.k === 'union') return emitUnion(name, ir, file, description);
  if (
    !ir.nullable &&
    (ir.k === 'string' || ir.k === 'number') &&
    ir.consts &&
    (ir.consts.length > 1 || ir.open)
  )
    return emitEnum(name, ir, file, description);
  // Array items and map values are named after the alias (FooItem); a nullable struct, union or enum gets FooValue.
  const named = ['object', 'union', 'string', 'number'].includes(ir.k);
  const target = valueType(ir, named ? `${name}Value` : name, file);
  let doc = comment(description);
  const single = ir.k === 'string' || ir.k === 'number' || ir.k === 'bool' ? constDoc(ir) : '';
  if (single) doc += `${doc ? '//\n' : ''}// ${single}\n`;
  declare(file, `${doc}type ${name} = ${target.expr}\n`);
}

// --- components ----------------------------------------------------------------------------------------------------------

const schemaTypes = [];
for (const name of Object.keys(schemas)) {
  const raw = schemas[name];
  const description = `${name} is the components/schemas/${name} schema.${raw.description ? `\n\n${raw.description}` : ''}`;
  if (coreMapped.has(name)) {
    const ir = comp(name);
    let code = `// ${name} is core.${name}: go/core already defines the components/schemas/${name} record.\n`;
    code += `type ${name} = core.${name}\n`;
    if ((ir.k === 'string' || ir.k === 'number') && ir.consts && !ir.nullable) {
      const lines = ir.consts.map((value) => {
        const constName = claim(`${name}${pascal(String(value)) || 'Empty'}`, 'enum constant');
        return `\t${constName} ${name} = ${goConst(value)}\n`;
      });
      code += `\n// Values of ${name}.\nconst (\n${lines.join('')})\n`;
    }
    declare('core', code);
  } else {
    const note = coreInProcess.has(name)
      ? `

This is the JSON form; core.${name} is the in-process form of the same value (it has no JSON encoding).`
      : '';
    emitNamed(name, comp(name), 'models', description + note);
  }
  schemaTypes.push(name);
}

// --- operations ------------------------------------------------------------------------------------------------------------

const operations = [];
const bodySchema = (operation) => operation.requestBody?.content?.['application/json']?.schema;
const dataSchema = (operation) =>
  operation.responses?.['200']?.content?.['application/json']?.schema?.properties?.data;

for (const route of routes.rpc) {
  const path = openapi.paths[`/${route.path}`];
  if (!path?.post)
    throw new Error(`routes.json route ${route.path} has no POST operation in openapi.json`);
  const operation = path.post;
  if (operation.operationId !== `${route.group}.${route.method}`)
    throw new Error(
      `operationId ${operation.operationId} does not match ${route.group}.${route.method}`,
    );
  const base = `${pascal(route.group)}${pascal(route.method)}`;
  const file = `ops_${snake(route.group)}`;
  const body = bodySchema(operation);
  const data = dataSchema(operation);
  if (!body) throw new Error(`${route.path}: no JSON request body`);
  if (!data) throw new Error(`${route.path}: no data member in the 200 answer`);
  // A body or answer that is the component named <Group><Method>Input/Output is that type itself.
  const input =
    body.$ref && refName(body.$ref) === `${base}Input`
      ? `${base}Input`
      : claim(`${base}Input`, 'operation input');
  const output =
    data.$ref && refName(data.$ref) === `${base}Output`
      ? `${base}Output`
      : claim(`${base}Output`, 'operation output');
  const title = `POST {basePath}/${route.path} (${operation.operationId})`;
  const summary = operation.summary ? `\n\n${operation.summary}` : '';
  const docs = operation.externalDocs?.url ? `\n\nSee ${operation.externalDocs.url}.` : '';
  if (!(body.$ref && refName(body.$ref) === input))
    emitNamed(
      input,
      norm(body),
      file,
      `${input} is the request body of ${title}.${summary}${docs}`,
    );
  if (!(data.$ref && refName(data.$ref) === output))
    emitNamed(
      output,
      norm(data),
      file,
      `${output} is the data of a successful answer to ${title}.`,
    );
  operations.push({
    route,
    base,
    input,
    output,
    operationId: operation.operationId,
    summary: operation.summary,
  });
}

// The routes that call the operations directly (routes.json `special`). Their bodies are the request types of
// packages/server/src/operations.ts without the credential members, and the answers are its return types.
const credentialMembers = new Set(Object.keys(schemas.CredentialInput.properties));
const special = [
  { path: 'authorize', request: 'AuthorizationRequest', output: { k: 'ref', name: 'Decision' } },
  {
    path: 'authorizeMany',
    request: 'BatchAuthorizationRequest',
    output: norm({
      type: 'object',
      properties: {
        results: { type: 'array', items: { $ref: '#/components/schemas/BatchResult' } },
      },
      required: ['results'],
      additionalProperties: false,
    }),
  },
  {
    path: 'listAccessible',
    request: 'AccessibleResourcesRequest',
    output: norm({
      type: 'object',
      properties: {
        resources: { type: 'array', items: { $ref: '#/components/schemas/ResourceRecord' } },
        total: { type: 'number' },
      },
      required: ['resources', 'total'],
      additionalProperties: false,
    }),
  },
];
for (const entry of special) {
  const declared = routes.special.find((item) => item.path === entry.path);
  if (!declared) throw new Error(`routes.json has no special route ${entry.path}`);
  const request = comp(entry.request);
  const props = request.props.filter((prop) => !credentialMembers.has(prop.name));
  const names = props.map((prop) => prop.name).sort();
  const expected = Object.keys(declared.body).sort();
  if (JSON.stringify(names) !== JSON.stringify(expected))
    throw new Error(
      `${entry.path}: ${entry.request} members ${names} do not match routes.json ${expected}`,
    );
  const base = pascal(entry.path);
  const input = claim(`${base}Input`, 'operation input');
  const output = claim(`${base}Output`, 'operation output');
  const title = `POST {basePath}/${entry.path} (operations.${entry.path})`;
  emitNamed(
    input,
    { k: 'object', props, extra: null },
    'ops_special',
    `${input} is the request body of ${title}.`,
  );
  emitNamed(
    output,
    entry.output,
    'ops_special',
    `${output} is the data of a successful answer to ${title}.`,
  );
  operations.push({
    route: {
      path: entry.path,
      group: '',
      method: entry.path,
      credential: declared.credential,
      call: 'request',
    },
    base,
    input,
    output,
    operationId: entry.path,
    special: true,
  });
}

// --- operation table -----------------------------------------------------------------------------------------------------------

{
  let code = `// DefaultBasePath is the default basePath of the routes (routes.json basePath).
const DefaultBasePath = ${goString(routes.basePath)}

// PluginRoutePrefix starts the plugin routes, POST {basePath}/plugins/{pluginId}/{endpointPath...}; they are not in the
// operation table because plugins define them at run time.
const PluginRoutePrefix = "plugins/"

// operationTable lists every RPC route of routes.json in its order, then the special routes authorize, authorizeMany
// and listAccessible.
var operationTable = [...]Operation{
`;
  for (const op of operations) {
    const r = op.route;
    code += `\t{Path: ${goString(r.path)}, OperationID: ${goString(op.operationId)}, Group: ${goString(r.group)}, Method: ${goString(r.method)}, Public: ${r.credential === 'none'}, Call: ${goString(r.call)}, TenantBound: ${!!r.tenantBound}, SetsSessionCookie: ${!!r.setsSessionCookie}, ReadsDeviceCookie: ${!!r.readsDeviceCookie}, Special: ${!!op.special}, Input: reflect.TypeFor[${op.input}](), Output: reflect.TypeFor[${op.output}]()},\n`;
  }
  code += '}\n';
  declare('operations', code);
  let vars =
    '// Typed operation descriptors, one per route: Op<Group><Method> carries the Input and Output types.\nvar (\n';
  operations.forEach((op, index) => {
    const name = claim(`Op${op.base}`, 'operation descriptor');
    vars += `\t// ${name} is POST {basePath}/${op.route.path}.${op.summary ? ` ${op.summary.split('\n')[0]}` : ''}\n`;
    vars += `\t${name} = Op[${op.input}, ${op.output}]{&operationTable[${index}]}\n`;
  });
  vars += ')\n';
  declare('operations', vars);
}

// --- schema registry -------------------------------------------------------------------------------------------------------

declare(
  'models',
  `// schemaTypes maps every components/schemas name to its Go type.
var schemaTypes = map[string]reflect.Type{
${schemaTypes.map((name) => `\t${goString(name)}: reflect.TypeFor[${name}](),\n`).join('')}}
`,
);
declare(
  'core',
  `// coreSchemas lists the components/schemas names that are aliases of go/core types.
var coreSchemas = []string{
${[...coreMapped].map((name) => `\t${goString(name)},\n`).join('')}}
`,
);

// --- output ---------------------------------------------------------------------------------------------------------------------

function findGofmt() {
  const candidates = ['gofmt'];
  const goroot = spawnSync('go', ['env', 'GOROOT'], { encoding: 'utf8' });
  if (goroot.status === 0 && goroot.stdout.trim())
    candidates.push(
      join(goroot.stdout.trim(), 'bin', process.platform === 'win32' ? 'gofmt.exe' : 'gofmt'),
    );
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ['-l'], { input: 'package x\n', encoding: 'utf8' });
    if (probe.status === 0) return candidate;
  }
  throw new Error('gofmt was not found: install Go (https://go.dev/dl) or put gofmt on PATH');
}

const gofmt = findGofmt();
function format(name, source) {
  const result = spawnSync(gofmt, [], {
    input: source,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const debug = join(outDir, `${name}.broken`);
    writeFileSync(debug, source);
    throw new Error(`gofmt rejected ${name} (source kept in ${debug}):\n${result.stderr}`);
  }
  return result.stdout.replace(/\r\n/g, '\n');
}

const fileDocs = {
  core: 'Aliases of the go/core types that components/schemas names (core types are not duplicated).',
  models:
    'One Go type per components/schemas entry of spec/api/openapi.json, with the types inlined in them.',
  operations: 'The operation table (spec/api/routes.json) and the typed operation descriptors.',
  ops_special:
    'Request and answer types of the authorize, authorizeMany and listAccessible routes.',
};

const unused = Object.keys(CORRECTIONS).filter((key) => !correctionsApplied.has(key));
if (unused.length)
  throw new Error(`corrections that no longer apply (remove them): ${unused.join(', ')}`);

mkdirSync(outDir, { recursive: true });
const written = new Set();
for (const [file, decls] of [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
  const text = decls.join('\n');
  const imports = [];
  if (/\bjson\./.test(text)) imports.push('"encoding/json"');
  if (/\breflect\./.test(text)) imports.push('"reflect"');
  if (/\bcore\./.test(text)) imports.push(...(imports.length ? [''] : []), `"${CORE_IMPORT}"`);
  const doc =
    fileDocs[file] ??
    `Request and answer types of the ${file.replace(/^ops_/, '').replace(/_/g, ' ')} API group (POST {basePath}/<group>/<method>).`;
  const source = `// Code generated by ${GENERATOR} from spec/api/openapi.json and spec/api/routes.json. DO NOT EDIT.

// ${doc}

package apitypes
${imports.length ? `\nimport (\n${imports.map((line) => (line ? `\t${line}\n` : '\n')).join('')})\n` : ''}
${text}`;
  const name = `${file}_gen.go`;
  writeFileSync(join(outDir, name), format(name, source));
  written.add(name);
}
for (const name of existsSync(outDir) ? readdirSync(outDir) : []) {
  if (name.endsWith('_gen.go') && !written.has(name)) rmSync(join(outDir, name));
}

for (const warning of [...new Set(warnings)]) console.warn(`warning: ${warning}`);
console.log(
  `go/apitypes: ${written.size} files, ${schemaTypes.length} schemas (${coreMapped.size} from go/core), ${operations.length} operations`,
);
