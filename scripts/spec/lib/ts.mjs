// TypeScript AST helpers: read constants and call sites straight from packages/*/src, so the spec follows the source.
import { readdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { root, repoPath } from './util.mjs';

const require = createRequire(join(root, 'package.json'));
export const ts = require('typescript');

export async function parse(path) {
  const text = await readFile(path, 'utf8');
  return ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

export function visit(node, fn) {
  fn(node);
  ts.forEachChild(node, (child) => visit(child, fn));
}

/** The value of a string literal or no-substitution template; undefined otherwise. */
export function literal(node) {
  if (!node) return undefined;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return undefined;
}

/** Strips `as const`, parentheses, `Object.freeze(...)` and satisfies wrappers. */
export function unwrap(node) {
  for (;;) {
    if (!node) return node;
    if (
      ts.isAsExpression(node) ||
      ts.isSatisfiesExpression?.(node) ||
      ts.isParenthesizedExpression(node)
    )
      node = node.expression;
    else if (
      ts.isCallExpression(node) &&
      node.expression.getText() === 'Object.freeze' &&
      node.arguments.length === 1
    )
      node = node.arguments[0];
    else return node;
  }
}

/** Every `const name = new Set([...literals])` in the file, by name (nested declarations included). */
export function stringSets(sourceFile) {
  const sets = new Map();
  visit(sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !node.initializer || !ts.isIdentifier(node.name)) return;
    const init = unwrap(node.initializer);
    if (!ts.isNewExpression(init) || init.expression.getText() !== 'Set') return;
    const [arg] = init.arguments ?? [];
    const array = unwrap(arg);
    if (!array || !ts.isArrayLiteralExpression(array)) return;
    const values = [];
    for (const element of array.elements) {
      const value = literal(unwrap(element));
      if (value === undefined) {
        values.push({ unresolved: element.getText() });
        continue;
      }
      values.push(value);
    }
    sets.set(node.name.text, { values, line: lineOf(node) });
  });
  return sets;
}

/** Every `const name = [...string literals]` (optionally frozen) in the file. */
export function stringArrays(sourceFile) {
  const arrays = new Map();
  visit(sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !node.initializer || !ts.isIdentifier(node.name)) return;
    let init = unwrap(node.initializer);
    // `[...].map(fn)` is reported with its mapping source so callers can apply it.
    let map;
    if (
      ts.isCallExpression(init) &&
      ts.isPropertyAccessExpression(init.expression) &&
      init.expression.name.text === 'map'
    ) {
      map = init.arguments[0]?.getText();
      init = unwrap(init.expression.expression);
    }
    if (!ts.isArrayLiteralExpression(init)) return;
    const values = init.elements.map((element) => literal(unwrap(element)));
    if (values.some((value) => value === undefined)) return;
    arrays.set(node.name.text, { values, map, line: lineOf(node) });
  });
  return arrays;
}

export function lineOf(node) {
  const sourceFile = node.getSourceFile();
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

export const location = (node) => `${repoPath(node.getSourceFile().fileName)}:${lineOf(node)}`;

/** Every non-declaration .ts source file of a package (`packages/<pkg>/src`), sorted. */
export async function sourceFiles(pkg) {
  const files = [];
  async function walk(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'dist') await walk(path);
      } else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) files.push(path);
    }
  }
  await walk(join(root, 'packages', pkg, 'src'));
  return files.sort();
}

export async function packageNames() {
  const entries = await readdir(join(root, 'packages'), { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}
