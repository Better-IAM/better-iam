// spec/storage/collections.json: every collection the packages read or write through IamStore, with the record types,
// filter, order and natural-key (uniqueKey) usage found at the call sites, plus the storage constants of
// packages/core/src/storage.ts and sql.ts (indexed, ordered and expiry fields, lookup index steps).
import { literal, location, packageNames, parse, sourceFiles, ts, unwrap, visit } from './ts.mjs';
import { codePointCompare, dist, json, repoPath } from './util.mjs';

const collectionName = /^[a-z][A-Za-z0-9]*$/;
/** Store methods and the minimum argument count that distinguishes them from Map/Headers/Array methods. */
const methods = { get: 2, find: 1, findOrdered: 3, insert: 2, put: 2, delete: 2 };

/**
 * Module-level constants that hold collection names, across every source file: `const name = 'literal'`,
 * `const map = { key: 'literal' } as const`, and destructured aliases `const { key: alias } = map`.
 */
function collectConstants(sourceFiles) {
  const strings = new Map();
  const objects = new Map();
  const aliases = new Map();
  for (const sourceFile of sourceFiles)
    visit(sourceFile, (node) => {
      if (!ts.isVariableDeclaration(node) || !node.initializer) return;
      const init = unwrap(node.initializer);
      if (ts.isIdentifier(node.name)) {
        const text = literal(init);
        if (text !== undefined)
          strings.set(node.name.text, [...(strings.get(node.name.text) ?? []), text]);
        else if (ts.isObjectLiteralExpression(init)) {
          const entries = {};
          for (const property of init.properties)
            if (ts.isPropertyAssignment(property)) {
              const value = literal(unwrap(property.initializer));
              if (value !== undefined)
                entries[property.name.getText().replace(/^['"]|['"]$/g, '')] = value;
            }
          if (Object.keys(entries).length) objects.set(node.name.text, entries);
        }
      } else if (ts.isObjectBindingPattern(node.name) && ts.isIdentifier(init)) {
        for (const element of node.name.elements) {
          const key = (element.propertyName ?? element.name).getText();
          if (ts.isIdentifier(element.name))
            aliases.set(element.name.text, { object: init.text, key });
        }
      }
    });
  return { strings, objects, aliases };
}

/** Candidate collection names an argument can hold: a literal, a conditional of literals, or a known constant. */
function candidates(node, sourceFile, constants) {
  node = unwrap(node);
  if (!node) return { names: [] };
  const text = literal(node);
  if (text !== undefined) return { names: collectionName.test(text) ? [text] : [], literal: true };
  if (ts.isConditionalExpression(node)) {
    const left = candidates(node.whenTrue, sourceFile, constants);
    const right = candidates(node.whenFalse, sourceFile, constants);
    return { names: [...left.names, ...right.names] };
  }
  if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
    const value = constants.objects.get(node.expression.text)?.[node.name.text];
    return {
      names: value && collectionName.test(value) ? [value] : [],
      resolvedFrom: node.getText(),
    };
  }
  if (ts.isIdentifier(node)) {
    const names = [];
    // A local declaration in the same file first (function-scoped helpers), then module constants anywhere.
    visit(sourceFile, (child) => {
      if (
        ts.isVariableDeclaration(child) &&
        ts.isIdentifier(child.name) &&
        child.name.text === node.text &&
        child.initializer &&
        !ts.isIdentifier(unwrap(child.initializer))
      )
        names.push(...candidates(child.initializer, sourceFile, constants).names);
    });
    if (!names.length) {
      const alias = constants.aliases.get(node.text);
      const value = alias ? constants.objects.get(alias.object)?.[alias.key] : undefined;
      if (value && collectionName.test(value)) names.push(value);
      else
        for (const item of constants.strings.get(node.text) ?? [])
          if (collectionName.test(item)) names.push(item);
    }
    return { names: [...new Set(names)], resolvedFrom: node.text };
  }
  return { names: [] };
}

const objectKeys = (node) => {
  node = unwrap(node);
  if (!node || !ts.isObjectLiteralExpression(node)) return undefined;
  const keys = [];
  for (const property of node.properties) {
    if (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property))
      keys.push(property.name.getText().replace(/^['"]|['"]$/g, ''));
    else if (ts.isSpreadAssignment(property)) keys.push(`...${property.expression.getText()}`);
  }
  return keys;
};

const propertyText = (node, key) => {
  node = unwrap(node);
  if (!node || !ts.isObjectLiteralExpression(node)) return undefined;
  for (const property of node.properties) {
    if (ts.isPropertyAssignment(property) && property.name.getText() === key)
      return property.initializer.getText();
    if (ts.isShorthandPropertyAssignment(property) && property.name.getText() === key) return key;
  }
  return undefined;
};

export async function generateCollections(output) {
  const core = await dist('core');
  const sql = await dist('core', 'sql.js');
  const collections = new Map();
  const unresolved = [];
  const entry = (name) => {
    let found = collections.get(name);
    if (!found) {
      found = {
        name,
        operations: new Set(),
        packages: new Set(),
        recordTypes: new Set(),
        filterFields: new Set(),
        orderFields: new Set(),
        uniqueKeys: new Set(),
        sites: [],
      };
      collections.set(name, found);
    }
    return found;
  };
  const parsed = [];
  for (const pkg of await packageNames())
    for (const file of await sourceFiles(pkg)) {
      // The adapter conformance suite and the store instrumentation take collection names as parameters or use
      // fixture collections of their own; they are not part of the schema.
      const path = repoPath(file);
      if (
        ['conformance', 'instrument', 'snapshot'].some(
          (name) => path === `packages/core/src/${name}.ts`,
        )
      )
        continue;
      parsed.push({ pkg, sourceFile: await parse(file) });
    }
  const constants = collectConstants(parsed.map((item) => item.sourceFile));
  for (const { pkg, sourceFile } of parsed) {
    {
      visit(sourceFile, (node) => {
        // `{ collection: 'outbox', ... }` descriptors (retention sweeps, snapshots).
        if (ts.isPropertyAssignment(node) && node.name.getText() === 'collection') {
          const name = literal(unwrap(node.initializer));
          if (name && collectionName.test(name)) {
            const item = entry(name);
            item.packages.add(pkg);
            item.operations.add('descriptor');
            item.sites.push(location(node));
          }
          return;
        }
        if (!ts.isCallExpression(node)) return;
        let method;
        let args = [...node.arguments];
        if (ts.isPropertyAccessExpression(node.expression)) method = node.expression.name.text;
        else if (
          ts.isIdentifier(node.expression) &&
          node.expression.text === 'findOrdered' &&
          args.length >= 4
        ) {
          method = 'findOrdered';
          args = args.slice(1);
        }
        if (!method || !Object.hasOwn(methods, method) || args.length < methods[method]) return;
        const found = candidates(args[0], sourceFile, constants);
        if (!found.names.length) {
          // A string first argument that is not a collection name (Map keys, headers) is not a store call.
          if (literal(unwrap(args[0])) !== undefined) return;
          if (method === 'find' && args.length === 1) return; // Array#find(predicate)
          if (['get', 'delete'].includes(method) && args.length < 2) return;
          const receiver = node.expression.expression?.getText() ?? '';
          if (!/(?:^|\.)(?:tx|store|reader|writer|db|target|source|transaction)$/i.test(receiver))
            return;
          unresolved.push({ at: location(node), method, argument: args[0].getText() });
          return;
        }
        for (const name of found.names) {
          const item = entry(name);
          item.operations.add(method);
          item.packages.add(pkg);
          item.sites.push(location(node));
          for (const typeArgument of node.typeArguments ?? [])
            item.recordTypes.add(typeArgument.getText());
          if (method === 'find' || method === 'findOrdered') {
            for (const key of objectKeys(args[1]) ?? []) item.filterFields.add(key);
            const unique = propertyText(args[1], 'uniqueKey');
            if (unique) item.uniqueKeys.add(unique);
          }
          if (method === 'findOrdered') {
            const field = propertyText(args[2], 'field');
            if (field) item.orderFields.add(field.replace(/^['"]|['"]$/g, ''));
          }
          if (method === 'insert' || method === 'put') {
            const unique = propertyText(args[1], 'uniqueKey');
            if (unique) item.uniqueKeys.add(unique);
          }
        }
      });
    }
  }
  const list = [...collections.values()]
    .map((item) => ({
      name: item.name,
      operations: [...item.operations].sort(codePointCompare),
      packages: [...item.packages]
        .sort(codePointCompare)
        .map((pkg) => (pkg === 'better-iam' ? pkg : `@better-iam/${pkg}`)),
      recordTypes: [...item.recordTypes].sort(codePointCompare),
      filterFields: [...item.filterFields].sort(codePointCompare),
      orderFields: [...item.orderFields].sort(codePointCompare),
      uniqueKeyExpressions: [...item.uniqueKeys].sort(codePointCompare),
      indexedFields: [...core.INDEXED_FIELDS].filter((field) => item.filterFields.has(field)),
      sites: item.sites.sort(codePointCompare),
    }))
    .sort((a, b) => codePointCompare(a.name, b.name));
  const value = {
    source: ['packages/core/src/storage.ts', 'packages/core/src/sql.ts'],
    description:
      'Collections are rows of iam_records (collection, id, tenant_id, unique_key, data); data is JSON.stringify(record) with camelCase fields. Every record has string id and tenantId; uniqueKey, when present, is unique per (collection, tenantId). The per-collection details are read from the call sites: record types (TypeScript type arguments), filter keys, findOrdered fields and the expressions that build uniqueKey.',
    storage: {
      table: 'iam_records',
      columns: ['collection', 'id', 'tenant_id', 'unique_key', 'data'],
      primaryKey: ['collection', 'id'],
      unique: ['collection', 'tenant_id', 'unique_key'],
      indexedFields: [...core.INDEXED_FIELDS],
      orderedFields: [...core.ORDERED_FIELDS],
      expiryFields: [...core.EXPIRY_FIELDS],
      lookupIndexSteps: Object.fromEntries(
        Object.entries(core.LOOKUP_INDEX_STEPS).map(([step, fields]) => [step, [...fields]]),
      ),
      queryableField: core.QUERYABLE_FIELD.source,
      maxQueryConditions: core.MAX_QUERY_CONDITIONS,
      jsonbEscapeKey: {
        utf16: [...core.JSONB_ESCAPE_KEY].map((char) => char.charCodeAt(0)),
        text: '\\u0001better-iam',
      },
      collectionsSql: sql.COLLECTIONS_SQL,
      limits: {
        identifierMaxUtf8Bytes: 512,
        identifierRules:
          'collection, id, tenantId and uniqueKey: nonempty strings of at most 512 UTF-16 units and 512 UTF-8 bytes, no U+0000-U+001F, no unpaired surrogates (INVALID_RECORD)',
        recordMaxJsonLength: 1048576,
        maxNestingDepth: 64,
        unsafeKeys: ['__proto__', 'constructor', 'prototype'],
      },
      idOrder: 'code-point (UTF-8 byte) order: SQLite BINARY, PostgreSQL COLLATE "C" (compareIds)',
      writesRequireTransaction: { code: 'TRANSACTION_REQUIRED', status: 500 },
    },
    collections: list,
    unresolvedSites: unresolved.sort((a, b) => codePointCompare(a.at, b.at)),
  };
  output.add('storage/collections.json', json(value));
  return `collections.json (${list.length} collections, ${unresolved.length} store calls with a computed collection name)`;
}

export { repoPath };
