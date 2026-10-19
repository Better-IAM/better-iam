#!/usr/bin/env node
// One-shot generator of the Rust server skeleton (kernel B, step 4 of the Rust foundation).
//
//   node crates/server/tools/gen-skeleton.mjs [--dry-run]
//
// For every module of packages/server/src that has no Rust counterpart yet, it writes crates/server/src/<module>.rs
// with a stub for every exported function, constant, class and type another server module imports (found by
// scanning the imports), translated from the TypeScript signature (through the TypeScript checker). Every stub
// returns IamError NOT_IMPLEMENTED (501). For every api/*.ts file it writes crates/server/src/api/<file>.rs with one
// struct per API group the file creates and a typed method stub per route of spec/api/routes.json, and it writes the
// route dispatch table crates/server/src/api/dispatch.rs.
//
// It never overwrites a module file that exists (ported modules stay as they are); for a few partially ported
// modules (APPEND) it appends stubs for the symbols the Rust file still lacks, below a marker. The dispatch table is
// always regenerated. The generator is kept for reference: once the skeleton is filled in, modules are edited by hand.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const tsRoot = path.join(root, 'packages', 'server', 'src');
const rsRoot = path.join(root, 'crates', 'server', 'src');
const dryRun = process.argv.includes('--dry-run');
const norm = (p) => p.split(path.sep).join('/');

/** Modules ported by hand (kernel A and kernel B): never generated. */
const HAND = new Set([
  'access-policy.ts', 'assertions.ts', 'catalog.ts', 'client-info.ts', 'context-keys.ts', 'context.ts',
  'define.ts', 'events.ts', 'grant-deadline.ts', 'guarded.ts', 'metrics.ts', 'models.ts', 'observe.ts',
  'options.ts', 'plugins.ts', 'safe-fetch.ts', 'secrets.ts', 'session-kinds.ts', 'tenant-policy.ts', 'utils.ts',
  'validation.ts', 'decisions.ts', 'operations.ts', 'principals.ts', 'http.ts', 'index.ts', 'lifecycle.ts',
  'api/index.ts', 'api/filters.ts',
]);
/** Partially ported modules: missing symbols are appended to the existing Rust file. */
const APPEND = new Set(['delegations.ts', 'temporary-credentials.ts', 'web-identity.ts', 'hosts.ts']);
/** Symbols written by hand even in generated or appended modules. */
const SKIP_SYMBOLS = new Set([
  'hosts.ts:createHosts', 'hosts.ts:HostService', 'hosts.ts:HostMatch', 'hosts.ts:WrongRegionError',
  'hosts.ts:normalizeHost', 'hosts.ts:resolveHostConfig', 'hosts.ts:resolveRegionConfig', 'hosts.ts:TenantHostname',
  'hosts.ts:HostnameOwner', 'hosts.ts:HostOptions', 'hosts.ts:RegionOptions', 'hosts.ts:ResolvedHostConfig',
  'hosts.ts:ResolvedRegionConfig', 'delegations.ts:needsConfirmation', 'delegations.ts:useConfirmation',
  'temporary-credentials.ts:auditSessionContext', 'web-identity.ts:webIdentityIssuer',
]);
/** Services the composition root attaches to the context: they keep a weak reference back to it. */
const ATTACHED = new Set(['createFlows', 'createUsageRecorder', 'createHosts']);

// --- naming ---------------------------------------------------------------------------------------------------------
const KEYWORDS = new Set(
  'as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while abstract become box do final gen macro override priv try typeof unsized virtual yield'.split(
    ' ',
  ),
);
const snake = (name) =>
  name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9_]/g, '_')
    .toLowerCase();
const ident = (name) => {
  const value = snake(name);
  if (value === 'self' || value === 'crate' || value === 'super' || value === 'Self') return `${value}_`;
  return KEYWORDS.has(value) ? `r#${value}` : value;
};
const screaming = (name) => (/^[A-Z0-9_]+$/.test(name) ? name : snake(name).toUpperCase());
const pascal = (name) => name.charAt(0).toUpperCase() + name.slice(1);
const moduleOf = (file) => file.replace(/\.ts$/, '').replace(/-/g, '_');
const rustPath = (file) => (file.startsWith('api/') ? `crate::api::${moduleOf(file.slice(4))}` : `crate::${moduleOf(file)}`);

// --- the program ------------------------------------------------------------------------------------------------------
const files = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (fs.statSync(full).isDirectory()) walk(full);
    else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) files.push(full);
  }
})(tsRoot);
const config = ts.getParsedCommandLineOfConfigFile(
  path.join(root, 'packages', 'server', 'tsconfig.json'),
  {},
  { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} },
);
const program = ts.createProgram(files, { ...config.options, noEmit: true });
const checker = program.getTypeChecker();
const rel = (file) => norm(path.relative(tsRoot, file));

// --- which exported symbols other modules use -------------------------------------------------------------------------
/** module -> Map(symbol -> { type: boolean }) */
const used = new Map();
for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const re = /import\s+(type\s+)?\{([^}]*)\}\s+from\s+'(\.[^']+)'/gs;
  let match;
  while ((match = re.exec(src))) {
    const target = norm(path.relative(tsRoot, path.resolve(path.dirname(file), match[3].replace(/\.js$/, '.ts'))));
    for (let spec of match[2].split(',').map((s) => s.trim()).filter(Boolean)) {
      const isType = Boolean(match[1]) || spec.startsWith('type ');
      spec = spec.replace(/^type\s+/, '').split(/\s+as\s+/)[0].trim();
      if (!used.has(target)) used.set(target, new Map());
      const entry = used.get(target).get(spec) ?? { type: true };
      entry.type &&= isType;
      used.get(target).set(spec, entry);
    }
  }
}

// --- Rust types already defined ---------------------------------------------------------------------------------------
const coreTypes = new Set();
const coreTraits = new Set();
/** Core types that derive Serialize (usable inside serde structs). */
const coreSerde = new Set();
for (const file of fs.readdirSync(path.join(root, 'crates', 'core', 'src')))
  if (file.endsWith('.rs')) {
    const text = fs.readFileSync(path.join(root, 'crates', 'core', 'src', file), 'utf8');
    for (const m of text.matchAll(/^pub (?:struct|enum|type|trait) ([A-Za-z0-9]+)/gm)) coreTypes.add(m[1]);
    for (const m of text.matchAll(/^pub trait ([A-Za-z0-9]+)/gm)) coreTraits.add(m[1]);
    for (const m of text.matchAll(/#\[derive\(([^)]*)\)\]\s*(?:#\[[^\]]*\]\s*)*pub (?:struct|enum) ([A-Za-z0-9]+)/g))
      if (/Serialize/.test(m[1])) coreSerde.add(m[2]);
    for (const m of text.matchAll(/^pub type ([A-Za-z0-9]+)/gm)) coreSerde.add(m[1]);
    for (const m of text.matchAll(/impl(?:<[^>]*>)? (?:serde::)?Serialize for ([A-Za-z0-9]+)/g)) coreSerde.add(m[1]);
  }
/** Rust items defined in existing server files: module -> Set(name). */
const existingItems = new Map();
function scanRust(file) {
  const items = new Set();
  const text = fs.readFileSync(file, 'utf8');
  for (const m of text.matchAll(/pub (?:async )?(?:fn|struct|enum|type|trait|const|static) (?:r#)?([A-Za-z0-9_]+)/g))
    items.add(m[1]);
  return items;
}
for (const file of fs.readdirSync(rsRoot))
  if (file.endsWith('.rs')) existingItems.set(file.replace(/\.rs$/, ''), scanRust(path.join(rsRoot, file)));
const modelTypes = existingItems.get('models') ?? new Set();
const optionTypes = existingItems.get('options') ?? new Set();

// --- type translation --------------------------------------------------------------------------------------------------
/** Types emitted per module (so references resolve): module file -> Set(name). Filled before emission. */
const emittedTypes = new Map();
const declFile = (symbol) => {
  const decl = symbol?.declarations?.[0];
  return decl ? norm(decl.getSourceFile().fileName) : '';
};

/**
 * A TypeScript type as a Rust type: { own, kind } where kind decides the parameter form.
 * kinds: str num bool unit value opt vec set map named ctx store callback bytes request response
 */
function rustType(type, depth = 0) {
  if (depth > 6) return { own: 'Value', kind: 'value' };
  const flags = type.flags;
  if (flags & ts.TypeFlags.Any || flags & ts.TypeFlags.Unknown) return { own: 'Value', kind: 'unknown' };
  if (flags & (ts.TypeFlags.String | ts.TypeFlags.StringLiteral | ts.TypeFlags.TemplateLiteral))
    return { own: 'String', kind: 'str' };
  if (flags & (ts.TypeFlags.Number | ts.TypeFlags.NumberLiteral)) return { own: 'f64', kind: 'num' };
  if (flags & (ts.TypeFlags.Boolean | ts.TypeFlags.BooleanLiteral)) return { own: 'bool', kind: 'bool' };
  if (flags & (ts.TypeFlags.Void | ts.TypeFlags.Undefined | ts.TypeFlags.Null | ts.TypeFlags.Never))
    return { own: '()', kind: 'unit' };
  if (flags & ts.TypeFlags.BigInt) return { own: 'Value', kind: 'value' };
  const alias = type.aliasSymbol;
  if (alias) {
    const named = namedType(alias.getName(), declFile(alias));
    if (named) return named;
  }
  if (type.isUnion()) {
    const parts = type.types.filter(
      (part) => !(part.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Null | ts.TypeFlags.Void)),
    );
    const optional = parts.length !== type.types.length;
    let inner;
    if (parts.every((part) => part.flags & (ts.TypeFlags.String | ts.TypeFlags.StringLiteral | ts.TypeFlags.TemplateLiteral)))
      inner = { own: 'String', kind: 'str' };
    else if (parts.every((part) => part.flags & (ts.TypeFlags.Number | ts.TypeFlags.NumberLiteral)))
      inner = { own: 'f64', kind: 'num' };
    else if (parts.every((part) => part.flags & (ts.TypeFlags.Boolean | ts.TypeFlags.BooleanLiteral)))
      inner = { own: 'bool', kind: 'bool' };
    else if (parts.length === 1) inner = rustType(parts[0], depth + 1);
    else inner = { own: 'Value', kind: 'value' };
    if (!optional) return inner;
    if (inner.kind === 'unknown' || inner.kind === 'unit') return { own: 'Value', kind: 'unknown' };
    return { own: `Option<${inner.own}>`, kind: 'opt', inner };
  }
  if (type.isIntersection()) return { own: 'Value', kind: 'value' };
  if (flags & ts.TypeFlags.Object) {
    if (checker.isTupleType(type)) return { own: 'Value', kind: 'value' };
    if (checker.isArrayType(type)) {
      const element = rustType(checker.getTypeArguments(type)[0], depth + 1);
      return { own: `Vec<${element.own === '()' ? 'Value' : element.own}>`, kind: 'vec', inner: element };
    }
    const symbol = type.getSymbol();
    const name = symbol?.getName();
    const args = type.aliasTypeArguments ?? (type.target ? checker.getTypeArguments(type) : []);
    if (name === 'ReadonlyArray') {
      const element = rustType(args[0], depth + 1);
      return { own: `Vec<${element.own}>`, kind: 'vec', inner: element };
    }
    if (name === 'Set' || name === 'ReadonlySet') {
      const element = rustType(args[0], depth + 1);
      return { own: `IndexSet<${element.own === 'f64' ? 'String' : element.own}>`, kind: 'set' };
    }
    if (name === 'Map' || name === 'ReadonlyMap') {
      const key = rustType(args[0], depth + 1);
      const value = rustType(args[1], depth + 1);
      return {
        own: `IndexMap<${key.kind === 'str' ? 'String' : 'String'}, ${value.own === '()' ? 'Value' : value.own}>`,
        kind: 'map',
      };
    }
    if (name === 'Promise') return rustType(args[0], depth + 1);
    if (name === 'Uint8Array' || name === 'Buffer' || name === 'ArrayBuffer') return { own: 'Vec<u8>', kind: 'bytes' };
    if (name === 'Date') return { own: 'Value', kind: 'value' };
    if (name === 'Request') return { own: 'HttpRequest', kind: 'request' };
    if (name === 'Response') return { own: 'HttpResponse', kind: 'response' };
    if (type.getCallSignatures().length) return { own: 'Callback', kind: 'callback' };
    if (symbol && name !== '__type' && name !== '__object') {
      const named = namedType(name, declFile(symbol));
      if (named) return named;
    }
    // Record<string, T> and index signatures.
    const index = type.getStringIndexType();
    if (index && !type.getProperties().length) {
      const value = rustType(index, depth + 1);
      return value.kind === 'value' || value.kind === 'unknown'
        ? { own: 'Map<String, Value>', kind: 'jsonmap' }
        : { own: `IndexMap<String, ${value.own}>`, kind: 'map' };
    }
    return { own: 'Value', kind: 'value' };
  }
  return { own: 'Value', kind: 'value' };
}

function namedType(name, file) {
  if (name === 'ServerContext') return { own: 'Arc<ServerContext>', kind: 'ctx' };
  if (name === 'IamStore') return { own: 'Store', kind: 'store' };
  if (file.includes('/packages/core/')) {
    if (name === 'StoredRecord') return { own: 'Record', kind: 'jsonmap' };
    if (coreTraits.has(name)) return { own: `Arc<dyn better_iam_core::${name}>`, kind: 'trait' };
    if (coreTypes.has(name)) return { own: `better_iam_core::${name}`, kind: 'named', serde: coreSerde.has(name) };
    return undefined;
  }
  if (file.includes('/packages/auth/')) {
    if (name === 'AuthService') return { own: 'better_iam_auth::AuthService', kind: 'named' };
    return undefined;
  }
  if (file.includes('/packages/server/src/')) {
    const module = norm(path.relative(tsRoot, file));
    if (module === 'models.ts' && modelTypes.has(name)) return { own: `crate::models::${name}`, kind: 'named' };
    if (module === 'options.ts' && name === 'ProtocolMount')
      return { own: 'Arc<dyn crate::options::ProtocolMount>', kind: 'trait' };
    if (module === 'options.ts' && optionTypes.has(name))
      return { own: `crate::options::${name}`, kind: 'named', serde: false };
    const rsModule = moduleOf(module.replace(/^api\//, ''));
    const existing = module.startsWith('api/') ? undefined : existingItems.get(rsModule);
    if (existing?.has(name)) return { own: `${rustPath(module)}::${name}`, kind: 'named' };
    if (emittedTypes.get(module)?.has(name)) return { own: `${rustPath(module)}::${name}`, kind: 'named' };
  }
  return undefined;
}

/** The parameter form of a type. */
function paramType(t, optional) {
  const base = (() => {
    switch (t.kind) {
      case 'str':
        return '&str';
      case 'num':
        return 'f64';
      case 'bool':
        return 'bool';
      case 'unknown':
        return 'Option<&Value>';
      case 'value':
        return '&Value';
      case 'vec':
        return `&[${t.own.slice(4, -1)}]`;
      case 'ctx':
        return '&Arc<ServerContext>';
      case 'store':
        return '&Store';
      case 'callback':
        return '&Callback';
      case 'trait':
        return `&${t.own}`;
      case 'bytes':
        return '&[u8]';
      case 'unit':
        return 'Option<&Value>';
      case 'opt':
        return paramType(t.inner, true);
      default:
        return `&${t.own}`;
    }
  })();
  if (!optional || base.startsWith('Option<')) return base;
  return `Option<${base}>`;
}

/** A Rust function signature for a TypeScript signature. */
function signature(sig, declNode) {
  const params = [];
  sig.getParameters().forEach((param, index) => {
    const decl = param.valueDeclaration;
    const type = checker.getTypeOfSymbolAtLocation(param, decl ?? declNode);
    const optional = Boolean(decl && (decl.questionToken || decl.initializer));
    const rest = Boolean(decl?.dotDotDotToken);
    let name = param.getName();
    if (name.startsWith('__')) name = index === 0 ? 'input' : `input${index}`;
    const t = rustType(type);
    params.push(`${ident(name)}: ${rest ? `&[Value]` : paramType(t, optional)}`);
  });
  const returnType = checker.getReturnTypeOfSignature(sig);
  const isAsync = returnType.getSymbol()?.getName() === 'Promise';
  const predicate = checker.getTypePredicateOfSignature(sig);
  const ret = predicate ? { own: 'bool' } : rustType(returnType);
  return { params, isAsync, ret: ret.own === 'unknown' ? 'Value' : ret.own };
}

// --- emission ------------------------------------------------------------------------------------------------------------
const doc = (node) => {
  const text = ts
    .getJSDocCommentsAndTags(node)
    .map((d) => (typeof d.comment === 'string' ? d.comment : ''))
    .filter(Boolean)
    .join(' ');
  return text
    ? text
        .replace(/\s+/g, ' ')
        .trim()
        .match(/.{1,112}(\s|$)/g)
        .map((line) => `/// ${line.trim()}`)
        .join('\n') + '\n'
    : '';
};

function literalValue(node) {
  // Only pure literal expressions are evaluated: numbers, strings, arrays/objects/sets of them, arithmetic.
  const pure = (n) =>
    ts.isNumericLiteral(n) ||
    ts.isStringLiteral(n) ||
    ts.isNoSubstitutionTemplateLiteral(n) ||
    n.kind === ts.SyntaxKind.TrueKeyword ||
    n.kind === ts.SyntaxKind.FalseKeyword ||
    n.kind === ts.SyntaxKind.NullKeyword ||
    (ts.isPrefixUnaryExpression(n) && pure(n.operand)) ||
    (ts.isBinaryExpression(n) &&
      [ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken, ts.SyntaxKind.SlashToken].includes(
        n.operatorToken.kind,
      ) &&
      pure(n.left) &&
      pure(n.right)) ||
    (ts.isParenthesizedExpression(n) && pure(n.expression)) ||
    (ts.isArrayLiteralExpression(n) && n.elements.every(pure)) ||
    (ts.isAsExpression(n) && pure(n.expression)) ||
    (ts.isSatisfiesExpression?.(n) && pure(n.expression)) ||
    (ts.isObjectLiteralExpression(n) &&
      n.properties.every(
        (p) => ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && pure(p.initializer),
      ));
  let target = node;
  let set = false;
  if (ts.isNewExpression(node) && node.expression.getText() === 'Set' && node.arguments?.length === 1) {
    target = node.arguments[0];
    set = true;
  }
  if (!pure(target)) return undefined;
  const text = target.getText().replace(/\bas const\b/g, '').replace(/\bas [A-Za-z<>[\]|' ]+/g, '');
  try {
    return { value: Function(`"use strict"; return (${text});`)(), set };
  } catch {
    return undefined;
  }
}

function rustLiteral(value) {
  if (typeof value === 'number') {
    const text = Number.isInteger(value) ? `${value}.0` : String(value);
    return { type: 'f64', text: text.replace(/^(-?\d+)e/, '$1.0e') };
  }
  if (typeof value === 'string') return { type: '&str', text: JSON.stringify(value) };
  if (typeof value === 'boolean') return { type: 'bool', text: String(value) };
  if (Array.isArray(value) && value.every((v) => typeof v === 'string'))
    return { type: '&[&str]', text: `&[${value.map((v) => JSON.stringify(v)).join(', ')}]` };
  if (Array.isArray(value) && value.every((v) => typeof v === 'number'))
    return { type: '&[f64]', text: `&[${value.map((v) => rustLiteral(v).text).join(', ')}]` };
  return undefined;
}

/** Fields of an interface or object type, or undefined when it has methods (no plain-data form). */
function fieldsOf(type, selfName, plain = { serde: true, debug: true }) {
  const fields = [];
  for (const property of checker.getPropertiesOfType(type)) {
    const decl = property.valueDeclaration ?? property.declarations?.[0];
    if (!decl) return undefined;
    if (ts.isMethodSignature(decl) || ts.isMethodDeclaration(decl)) return undefined;
    const propType = checker.getTypeOfSymbolAtLocation(property, decl);
    const optional = Boolean(property.flags & ts.SymbolFlags.Optional);
    let t = rustType(propType);
    const inner = t.kind === 'opt' || t.kind === 'vec' ? t.inner : t;
    const opaque = (k) => ['callback', 'trait', 'ctx', 'store', 'request', 'response'].includes(k);
    if (opaque(t.kind) || opaque(inner?.kind)) {
      plain.debug = false;
      plain.serde = false;
    }
    if (t.serde === false || inner?.serde === false) plain.serde = false;
    let own = t.kind === 'unknown' ? 'Value' : t.own === '()' ? 'Value' : t.own;
    if (own === selfName || own.endsWith(`::${selfName}`)) own = `Box<${own}>`;
    if (own === `Option<${selfName}>`) own = `Option<Box<${selfName}>>`;
    const name = property.getName();
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
    const isOption = own.startsWith('Option<');
    const fieldType = optional && !isOption ? `Option<${own}>` : own;
    fields.push({
      json: name,
      rust: ident(name),
      type: fieldType,
      optional: optional || isOption,
      doc: doc(decl),
    });
  }
  return fields;
}

function emitStruct(name, type, docText) {
  const plain = { serde: true, debug: true };
  const fields = fieldsOf(type, name, plain);
  if (!fields)
    return (
      `${docText}/// TODO(port): an interface with methods in TypeScript; give it its Rust form (a trait or a struct of\n` +
      `/// closures) when the module is ported.\n#[derive(Clone, Default)]\npub struct ${name} {}\n`
    );
  const serdeAttr = (field) =>
    plain.serde
      ? `    #[serde(rename = "${field.json}"${field.optional ? ', default, skip_serializing_if = "Option::is_none"' : ''})]\n`
      : '';
  const body = fields
    .map(
      (field) =>
        `${field.doc.replace(/^/gm, '    ').replace(/    $/, '')}${serdeAttr(field)}    pub ${field.rust}: ${field.type},\n`,
    )
    .join('');
  if (!plain.serde) return `${docText}#[derive(${plain.debug ? 'Debug, ' : ''}Clone)]\npub struct ${name} {\n${body}}\n`;
  return `${docText}#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\npub struct ${name} {\n${body}    /// Members this type does not declare.\n    #[serde(flatten)]\n    pub extra: Map<String, Value>,\n}\n`;
}

const notImplemented = (module, name) => `Err(not_ported("${module} ${name}"))`;

function emitFunction(module, name, sig, declNode, docText, receiver) {
  const s = signature(sig, declNode);
  const params = receiver ? [receiver, ...s.params] : s.params;
  const ret = s.ret === '()' ? '()' : s.ret;
  return `${docText}pub ${s.isAsync ? 'async ' : ''}fn ${ident(name)}(${params.join(', ')}) -> IamResult<${ret}> {\n    ${notImplemented(module, name)}\n}\n`;
}

/** An object type returned by a factory: its methods (function-valued members) and plain members. */
function factoryMembers(type) {
  const members = [];
  for (const property of checker.getPropertiesOfType(type)) {
    const decl = property.valueDeclaration ?? property.declarations?.[0];
    if (!decl) continue;
    const propType = checker.getTypeOfSymbolAtLocation(property, decl);
    const sigs = propType.getCallSignatures();
    members.push({ name: property.getName(), sig: sigs[0], decl, type: propType, doc: doc(decl) });
  }
  return members;
}

function emitFactory(module, fnName, sig, declNode, docText) {
  const returnType = checker.getReturnTypeOfSignature(sig);
  const members = factoryMembers(returnType);
  const structName = pascal(fnName.replace(/^create/, '')) || pascal(fnName);
  const s = signature(sig, declNode);
  const weak = ATTACHED.has(fnName);
  const ctxParam = s.params.find((p) => p.endsWith('&Arc<ServerContext>'));
  const ctxName = ctxParam?.split(':')[0];
  let out = `${docText}pub struct ${structName} {\n`;
  if (ctxName) out += `    ${weak ? 'ctx: Weak<ServerContext>' : 'ctx: Arc<ServerContext>'},\n`;
  out += `}\n\n`;
  out += `/// \`${fnName}(...)\`. Construction never fails in the skeleton; validation the TypeScript factory does on\n/// construction belongs here when the module is ported.\n`;
  out += `pub fn ${ident(fnName)}(${s.params.join(', ')}) -> IamResult<${structName}> {\n    Ok(${structName} {${ctxName ? ` ctx: ${weak ? `Arc::downgrade(${ctxName})` : `${ctxName}.clone()`} ` : ''}})\n}\n\n`;
  out += `impl ${structName} {\n`;
  const callable = [];
  for (const member of members) {
    if (member.sig) {
      const ms = signature(member.sig, member.decl);
      const ret = ms.ret === '()' ? '()' : ms.ret;
      out += `${member.doc.replace(/^/gm, '    ').replace(/    $/, '')}    pub ${ms.isAsync ? 'async ' : ''}fn ${ident(member.name)}(${['&self', ...ms.params].join(', ')}) -> IamResult<${ret}> {\n        ${notImplemented(module, `${structName}.${member.name}`)}\n    }\n`;
      callable.push(member.name);
    } else {
      const t = rustType(member.type);
      out += `${member.doc.replace(/^/gm, '    ').replace(/    $/, '')}    pub fn ${ident(member.name)}(&self) -> IamResult<${t.own === '()' || t.kind === 'unknown' ? 'Value' : t.own}> {\n        ${notImplemented(module, `${structName}.${member.name}`)}\n    }\n`;
    }
  }
  out += `    /// The conformance server's \`call\` for a member of this object: JSON arguments in, the JSON result out;\n    /// None for a name it does not have. Each arm decodes the arguments and calls the typed method once it is ported.\n`;
  out += `    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {\n        let _ = &args;\n        match method {\n`;
  for (const name of callable) out += `            "${name}" => Some(${notImplemented(module, `${structName}.${name}`)}),\n`;
  out += `            _ => None,\n        }\n    }\n}\n`;
  return out;
}

const header = (file, generated) => `//! Port of \`packages/server/src/${file}\`.
//!
//! SKELETON (generated by \`crates/server/tools/gen-skeleton.mjs\`): every item another module uses has its final
//! signature and returns \`NOT_IMPLEMENTED\` (501) until this module is ported. Port the bodies from the TypeScript
//! source line by line (see crates/PORTING.md); keep the signatures, which other modules already call.
#![allow(unused_variables, unused_imports, dead_code, clippy::too_many_arguments, clippy::module_inception)]

use std::sync::{Arc, Weak};

use better_iam_core::{IamError, IamResult};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::options::{HttpRequest, HttpResponse};
use crate::port::{Callback, not_ported};
${generated}`;

/** The declarations of a module's exported symbol (following re-exports). */
function exportsOf(sourceFile) {
  const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
  const result = new Map();
  if (!moduleSymbol) return result;
  for (const symbol of checker.getExportsOfModule(moduleSymbol)) {
    let target = symbol;
    if (target.flags & ts.SymbolFlags.Alias) target = checker.getAliasedSymbol(target);
    result.set(symbol.getName(), target);
  }
  return result;
}

const plan = [];
for (const file of files) {
  const module = rel(file);
  if (module.includes('.test.') || HAND.has(module)) continue;
  const symbols = used.get(module) ?? new Map();
  const rsName = moduleOf(module.replace(/^api\//, ''));
  const target = module.startsWith('api/') ? path.join(rsRoot, 'api', `${rsName}.rs`) : path.join(rsRoot, `${rsName}.rs`);
  const exists = fs.existsSync(target);
  if (exists && !APPEND.has(module)) continue;
  // An appended file is appended to once; its skeleton block is edited by hand afterwards.
  if (exists && fs.readFileSync(target, 'utf8').includes('// --- Skeleton stubs (generated by')) continue;
  plan.push({ module, file, symbols, target, exists, rsName });
}

// First pass: the exported interfaces/aliases each module emits (used ones, plus same-module types they reference).
for (const item of plan) {
  const sourceFile = program.getSourceFile(item.file);
  const exports = exportsOf(sourceFile);
  const names = new Set();
  for (const [name] of item.symbols) {
    const symbol = exports.get(name);
    if (!symbol || SKIP_SYMBOLS.has(`${item.module}:${name}`)) continue;
    if (declFile(symbol) !== norm(item.file)) continue;
    if (symbol.flags & (ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias | ts.SymbolFlags.Class | ts.SymbolFlags.Enum))
      names.add(name);
  }
  emittedTypes.set(item.module, names);
}

const apiIndex = fs.readFileSync(path.join(tsRoot, 'api', 'index.ts'), 'utf8');
const importFile = new Map();
for (const m of apiIndex.matchAll(/import \{([^}]*)\} from '(\.\.?\/[^']+)\.js';/g))
  for (const spec of m[1].split(',').map((s) => s.trim()).filter(Boolean)) importFile.set(spec, m[2]);
/** group -> { factory, file (relative to src) } */
const groups = new Map();
for (const m of apiIndex.matchAll(/^\s+(\w+): (create\w+)\(ctx\),$/gm)) {
  const from = importFile.get(m[2]);
  const file = from.startsWith('../') ? `${from.slice(3)}.ts` : `api/${from.slice(2)}.ts`;
  groups.set(m[1], { factory: m[2], file });
}
const routes = JSON.parse(fs.readFileSync(path.join(root, 'spec', 'api', 'routes.json'), 'utf8'));
const publicApi = new Set(routes.sets.publicApiMethods);
const routesByGroup = new Map();
for (const route of routes.rpc) {
  if (route.group === 'auth') continue;
  if (!routesByGroup.has(route.group)) routesByGroup.set(route.group, []);
  routesByGroup.get(route.group).push(route);
}

function emitGroup(group, factory) {
  const struct = `${pascal(group)}Api`;
  const typesModule = snake(group);
  let out = `/// The \`${group}\` API group (\`${factory}(ctx)\`): one method per route \`${group}/{method}\`.\npub struct ${struct} {\n    ctx: Arc<ServerContext>,\n}\n\n`;
  out += `/// \`${factory}(ctx)\`.\npub fn ${ident(factory)}(ctx: &Arc<ServerContext>) -> IamResult<${struct}> {\n    Ok(${struct} { ctx: ctx.clone() })\n}\n\n`;
  out += `impl ${struct} {\n`;
  for (const route of routesByGroup.get(group) ?? []) {
    const method = route.method;
    const typeName = pascal(method);
    const isPublic = publicApi.has(route.path);
    out += `    /// \`${route.path}\`${isPublic ? ' (public: no credential)' : ''}.\n`;
    out += `    pub async fn ${ident(method)}(\n        &self,\n${isPublic ? '' : '        credential: &CredentialInput,\n'}        input: Body<${typesModule}::${typeName}Input>,\n    ) -> IamResult<Reply<${typesModule}::${typeName}Output>> {\n        ${notImplemented(`${group}`, method)}\n    }\n`;
  }
  out += `}\n`;
  return out;
}

const written = [];
for (const item of plan) {
  const sourceFile = program.getSourceFile(item.file);
  const exports = exportsOf(sourceFile);
  const existing = item.exists ? scanRust(item.target) : new Set();
  const parts = [];
  // API groups this file creates.
  const groupsHere = [...groups].filter(([, g]) => g.file === item.module);
  for (const [group, g] of groupsHere) parts.push(emitGroup(group, g.factory));
  const groupFactories = new Set(groupsHere.map(([, g]) => g.factory));
  const factoryStructs = new Set(
    [...item.symbols.keys()].filter((n) => /^create[A-Z]/.test(n)).map((n) => pascal(n.replace(/^create/, ''))),
  );
  for (const [name] of [...item.symbols].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (groupFactories.has(name) || SKIP_SYMBOLS.has(`${item.module}:${name}`)) continue;
    const symbol = exports.get(name);
    if (!symbol) continue;
    const rsIdent = ident(name).replace(/^r#/, '');
    if (existing.has(rsIdent) || existing.has(name) || existing.has(screaming(name))) continue;
    const from = declFile(symbol);
    if (from !== norm(item.file)) {
      const other = norm(path.relative(tsRoot, from));
      if (from.includes('/packages/server/src/')) {
        const isType = symbol.flags & (ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias);
        parts.push(`pub use ${rustPath(other)}::${isType ? name : ident(name)};\n`);
      } else parts.push(`// TODO(port): \`${name}\` is re-exported from ${other}.\n`);
      continue;
    }
    const decl = symbol.valueDeclaration ?? symbol.declarations[0];
    const docText = doc(decl.kind === ts.SyntaxKind.VariableDeclaration ? decl.parent.parent : decl);
    if (symbol.flags & ts.SymbolFlags.Class) {
      const ctor = checker.getTypeOfSymbolAtLocation(symbol, decl).getConstructSignatures()[0];
      const s = ctor ? signature(ctor, decl) : { params: [] };
      parts.push(
        `${docText}/// TODO(port): a class in TypeScript (an error subclass or a stateful helper).\n#[derive(Debug, Clone, PartialEq)]\npub struct ${name} {\n    pub error: IamError,\n}\n\nimpl ${name} {\n    /// \`new ${name}(...)\`.\n    pub fn new(${s.params.join(', ')}) -> IamResult<Self> {\n        ${notImplemented(item.module, `new ${name}`)}\n    }\n}\n\nimpl From<${name}> for IamError {\n    fn from(error: ${name}) -> Self {\n        error.error\n    }\n}\n`,
      );
      continue;
    }
    if (symbol.flags & (ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias) && factoryStructs.has(name)) {
      parts.push(`// \`${name}\` is the struct its factory below returns.\n`);
      continue;
    }
    if (symbol.flags & ts.SymbolFlags.Interface) {
      parts.push(emitStruct(name, checker.getDeclaredTypeOfSymbol(symbol), docText));
      continue;
    }
    if (symbol.flags & ts.SymbolFlags.TypeAlias) {
      const type = checker.getDeclaredTypeOfSymbol(symbol);
      const t = rustType(type);
      if (t.kind === 'str' || t.kind === 'num' || t.kind === 'bool')
        parts.push(`${docText}pub type ${name} = ${t.own};\n`);
      else if (type.flags & ts.TypeFlags.Object && !type.isUnion() && !type.isIntersection())
        parts.push(emitStruct(name, type, docText));
      else parts.push(`${docText}/// TODO(port): a union or intersection type in TypeScript; JSON until ported.\npub type ${name} = Value;\n`);
      continue;
    }
    if (symbol.flags & ts.SymbolFlags.Function) {
      const fnDecl = symbol.declarations.find((d) => d.body) ?? decl;
      const sig = checker.getSignatureFromDeclaration(fnDecl);
      const returnType = checker.getReturnTypeOfSignature(sig);
      const returnsFactory =
        /^create[A-Z]/.test(name) &&
        returnType.flags & ts.TypeFlags.Object &&
        !checker.isArrayType(returnType) &&
        returnType.getSymbol()?.getName() !== 'Promise' &&
        factoryMembers(returnType).some((m) => m.sig) &&
        !returnType.getCallSignatures().length;
      parts.push(returnsFactory ? emitFactory(item.module, name, sig, fnDecl, docText) : emitFunction(item.module, name, sig, fnDecl, docText));
      continue;
    }
    if (symbol.flags & ts.SymbolFlags.Variable) {
      const init = decl.initializer;
      const type = checker.getTypeOfSymbolAtLocation(symbol, decl);
      if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) {
        const sig = checker.getSignatureFromDeclaration(init);
        parts.push(emitFunction(item.module, name, sig, init, docText));
        continue;
      }
      if (type.getCallSignatures().length) {
        parts.push(emitFunction(item.module, name, type.getCallSignatures()[0], decl, docText));
        continue;
      }
      const literal = init ? literalValue(init) : undefined;
      const rust = literal ? rustLiteral(literal.value) : undefined;
      if (rust) {
        parts.push(`${docText}${literal.set ? '/// A `Set` in TypeScript.\n' : ''}pub const ${screaming(name)}: ${rust.type} = ${rust.text};\n`);
        continue;
      }
      if (literal) {
        parts.push(
          `${docText}pub static ${screaming(name)}: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| json!(${JSON.stringify(literal.value)}));\n`,
        );
        continue;
      }
      const t = rustType(type);
      parts.push(
        `${docText}/// TODO(port): a computed constant in TypeScript (\`${(init?.getText() ?? '').slice(0, 60).replace(/\s+/g, ' ')}\`).\npub fn ${ident(name)}() -> IamResult<${t.own === '()' || t.kind === 'unknown' ? 'Value' : t.own}> {\n    ${notImplemented(item.module, name)}\n}\n`,
      );
      continue;
    }
    parts.push(`// TODO(port): exported symbol \`${name}\` has no generated form.\n`);
  }
  const needsBody = parts.some((p) => p.includes('Body<'));
  const typeImports = groupsHere.length
    ? `use better_iam_core::CredentialInput;\nuse better_iam_types::api::{${groupsHere.map(([g]) => snake(g)).join(', ')}};\n\nuse crate::api::{Body, Reply};\n`
    : '';
  let text;
  if (item.exists) {
    if (!parts.length) continue;
    text =
      fs.readFileSync(item.target, 'utf8').replace(/\s*$/, '\n') +
      `\n// --- Skeleton stubs (generated by crates/server/tools/gen-skeleton.mjs): items other modules use that this\n// file does not port yet. Each returns NOT_IMPLEMENTED (501) until ported.\n\nmod skeleton {\n    #![allow(unused_variables, unused_imports, dead_code, clippy::too_many_arguments)]\n    use std::sync::{Arc, Weak};\n    use better_iam_core::{IamError, IamResult};\n    use indexmap::{IndexMap, IndexSet};\n    use serde::{Deserialize, Serialize};\n    use serde_json::{Map, Value, json};\n    use crate::context::{ServerContext, Store};\n    use crate::options::{HttpRequest, HttpResponse};\n    use crate::port::{Callback, not_ported};\n\n${parts.join('\n').replace(/^(?=.)/gm, '    ')}}\npub use skeleton::*;\n`;
  } else {
    text = header(item.module, typeImports) + (parts.length ? `\n${parts.join('\n')}` : '');
  }
  void needsBody;
  written.push(norm(path.relative(root, item.target)));
  if (!dryRun) {
    fs.mkdirSync(path.dirname(item.target), { recursive: true });
    fs.writeFileSync(item.target, text);
  }
}

// --- the dispatch table (always regenerated) ----------------------------------------------------------------------------
let dispatch = `// @generated by crates/server/tools/gen-skeleton.mjs from spec/api/routes.json. Do not edit: regenerate instead.
//! The route table of the provisioning API: \`POST {basePath}/{group}/{method}\` for every group route of
//! spec/api/routes.json (the \`auth\` group, \`authorize\`, \`authorizeMany\`, \`listAccessible\` and \`plugins/*\` are
//! dispatched by [\`crate::http\`]). Public routes (\`publicApiMethods\`) are called with the body only, all others with
//! the request credential and the body, as \`http.ts\` \`dispatch\` does.
#![allow(clippy::too_many_lines)]

use better_iam_core::{CredentialInput, IamResult};
use serde_json::{Map, Value};

use crate::api::index::Api;
use crate::api::{Body, Reply};

/// Each route's future is boxed, so this function's own future stays small however large the methods' grow.
fn answer<T: serde::Serialize>(result: IamResult<Reply<T>>) -> IamResult<Value> {
    result?.into_value()
}

/** Whether \`path\` (\`group/method\`) is a group route the table dispatches. */
pub fn is_route(path: &str) -> bool {
    ROUTE_PATHS.binary_search(&path).is_ok()
}

/// Every group route path, sorted.
pub const ROUTE_PATHS: &[&str] = &[
`;
const rpc = routes.rpc.filter((r) => r.group !== 'auth').sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
for (const route of rpc) dispatch += `    "${route.path}",\n`;
dispatch += `];

/// Calls the route \`path\`; None when \`path\` is not a group route.
pub async fn dispatch(
    api: &Api,
    path: &str,
    body: Map<String, Value>,
    credential: &CredentialInput,
) -> Option<IamResult<Value>> {
    let _ = credential;
    Some(match path {
`;
for (const route of rpc) {
  const call = publicApi.has(route.path)
    ? `api.${ident(route.group)}.${ident(route.method)}(Body::new(body))`
    : `api.${ident(route.group)}.${ident(route.method)}(credential, Body::new(body))`;
  dispatch += `        "${route.path}" => answer(Box::pin(${call}).await),\n`;
}
dispatch += `        _ => return None,
    })
}
`;
dispatch = dispatch.replace('/** Whether', '/// Whether').replace('dispatches. */', 'dispatches.');
if (!dryRun) fs.writeFileSync(path.join(rsRoot, 'api', 'dispatch.rs'), dispatch);
written.push('crates/server/src/api/dispatch.rs');

// --- the module lists ---------------------------------------------------------------------------------------------------
const modules = [];
const apiModules = [];
for (const file of files) {
  const module = rel(file);
  if (module.includes('.test.')) continue;
  if (module.startsWith('api/')) apiModules.push(moduleOf(module.slice(4)));
  else if (module !== 'index.ts') modules.push(moduleOf(module));
}
console.log(JSON.stringify({ written: written.length, modules: modules.sort(), apiModules: apiModules.sort(), groups: [...groups.keys()] }, null, 0));
