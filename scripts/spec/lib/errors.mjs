// spec/api/errors.json: every IamError code the TypeScript code base can raise, with its HTTP statuses, the message of
// every raise site, error subclasses with fixed codes, error-like classes with `code`/`status` members, and the
// default mappings (constructor default status, unknown errors, storage driver errors).
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { literal, location, packageNames, parse, sourceFiles, ts, unwrap, visit } from './ts.mjs';
import { codePointCompare, json, repoPath, root } from './util.mjs';

/** A message argument as ports should reproduce it: literal text, or a template with `${...}` placeholders kept. */
function messageOf(node) {
  if (!node) return undefined;
  node = unwrap(node);
  const text = literal(node);
  if (text !== undefined) return { message: text };
  if (ts.isTemplateExpression(node)) {
    let out = node.head.text;
    for (const span of node.templateSpans)
      out += `\${${span.expression.getText()}}${span.literal.text}`;
    return { template: out };
  }
  return { expression: node.getText() };
}

function statusOf(node) {
  if (!node) return { status: 400, defaulted: true };
  node = unwrap(node);
  if (ts.isNumericLiteral(node)) return { status: Number(node.text) };
  return { statusExpression: node.getText() };
}

const packageOf = (file) => {
  const pkg = repoPath(file).split('/')[1];
  return pkg === 'better-iam' ? 'better-iam' : `@better-iam/${pkg}`;
};

export async function generateErrors(output) {
  const files = [];
  for (const pkg of await packageNames()) files.push(...(await sourceFiles(pkg)));
  const parsed = [];
  for (const file of files) parsed.push(await parse(file));

  // Pass 1: classes that extend IamError (directly or through another subclass) and error-like classes.
  const subclasses = new Map();
  const errorLike = [];
  const superOf = new Map();
  for (const sourceFile of parsed)
    visit(sourceFile, (node) => {
      if (!ts.isClassDeclaration(node) || !node.name) return;
      const heritage = node.heritageClauses?.find(
        (clause) => clause.token === ts.SyntaxKind.ExtendsKeyword,
      );
      const base = heritage?.types[0]?.expression.getText();
      if (base) superOf.set(node.name.text, { base, node });
    });
  const extendsIamError = (name, seen = new Set()) => {
    if (name === 'IamError') return true;
    const entry = superOf.get(name);
    if (!entry || seen.has(name)) return false;
    seen.add(name);
    return extendsIamError(entry.base, seen);
  };
  for (const [name, { base, node }] of superOf) {
    if (name !== 'IamError' && extendsIamError(name)) {
      let call;
      visit(node, (child) => {
        if (
          !call &&
          ts.isCallExpression(child) &&
          child.expression.kind === ts.SyntaxKind.SuperKeyword
        )
          call = child;
      });
      const [codeArg, messageArg, statusArg] = call?.arguments ?? [];
      const code = literal(unwrap(codeArg));
      subclasses.set(name, {
        name,
        extends: base,
        at: location(node),
        ...(code !== undefined ? { code } : { codeExpression: codeArg?.getText() ?? null }),
        ...(messageArg ? messageOf(messageArg) : {}),
        ...(call ? statusOf(statusArg) : {}),
      });
      continue;
    }
    // Error classes with their own `code` and `status` members (not IamError, but answered like one).
    let code;
    let status;
    for (const member of node.members) {
      if (!ts.isPropertyDeclaration(member) || !member.initializer || !member.name) continue;
      const memberName = member.name.getText();
      if (memberName === 'code') code = literal(unwrap(member.initializer));
      if (memberName === 'status' && ts.isNumericLiteral(unwrap(member.initializer)))
        status = Number(unwrap(member.initializer).text);
    }
    if (code !== undefined)
      errorLike.push({
        name,
        extends: base,
        at: location(node),
        code,
        ...(status ? { status } : {}),
      });
  }

  // Pass 2: raise sites.
  const codes = new Map();
  const dynamic = [];
  const add = (code, site, pkg) => {
    const entry = codes.get(code) ?? { code, statuses: new Set(), packages: new Set(), sites: [] };
    if (site.status !== undefined) entry.statuses.add(site.status);
    entry.packages.add(pkg);
    entry.sites.push(site);
    codes.set(code, entry);
  };
  for (const sourceFile of parsed) {
    const pkg = packageOf(sourceFile.fileName);
    visit(sourceFile, (node) => {
      if (!ts.isNewExpression(node)) return;
      const name = node.expression.getText();
      const args = node.arguments ?? [];
      if (name === 'IamError') {
        const code = literal(unwrap(args[0]));
        const site = { at: location(node), ...statusOf(args[2]), ...(messageOf(args[1]) ?? {}) };
        if (code !== undefined) {
          add(code, site, pkg);
          return;
        }
        // `cond ? 'A' : 'B'` with matching conditional messages and statuses: one site per branch.
        const branch = (node, pick) => {
          node = unwrap(node);
          return node && ts.isConditionalExpression(node)
            ? pick
              ? node.whenTrue
              : node.whenFalse
            : node;
        };
        const codeNode = unwrap(args[0]);
        if (
          codeNode &&
          ts.isConditionalExpression(codeNode) &&
          literal(unwrap(codeNode.whenTrue)) !== undefined &&
          literal(unwrap(codeNode.whenFalse)) !== undefined
        ) {
          for (const pick of [true, false])
            add(
              literal(unwrap(branch(codeNode, pick))),
              {
                at: location(node),
                condition: codeNode.condition.getText(),
                branch: pick ? 'true' : 'false',
                ...statusOf(branch(args[2], pick)),
                ...(messageOf(branch(args[1], pick)) ?? {}),
              },
              pkg,
            );
          return;
        }
        dynamic.push({ ...site, codeExpression: args[0]?.getText() ?? null });
        return;
      }
      const subclass = subclasses.get(name);
      if (subclass?.code !== undefined) {
        add(
          subclass.code,
          {
            at: location(node),
            via: name,
            ...(subclass.status !== undefined
              ? { status: subclass.status }
              : { statusExpression: subclass.statusExpression }),
            ...(args[0]
              ? messageOf(args[0])
              : subclass.message !== undefined
                ? { message: subclass.message }
                : {}),
          },
          pkg,
        );
      }
    });
  }
  for (const item of errorLike) {
    const entry = codes.get(item.code) ?? {
      code: item.code,
      statuses: new Set(),
      packages: new Set(),
      sites: [],
    };
    if (item.status) entry.statuses.add(item.status);
    entry.packages.add(packageOf(join(root, item.at.split(':')[0])));
    entry.sites.push({
      at: item.at,
      via: item.name,
      ...(item.status ? { status: item.status } : {}),
      errorClass: true,
    });
    codes.set(item.code, entry);
  }

  // Core defaults, read from the source so they cannot drift silently.
  const core = await readFile(join(root, 'packages/core/src/index.ts'), 'utf8');
  const defaultStatus = /public readonly status = (\d+)/.exec(core);
  if (!defaultStatus)
    throw new Error('IamError default status not found in packages/core/src/index.ts');
  const storage = await readFile(join(root, 'packages/core/src/storage.ts'), 'utf8');
  for (const fragment of [
    "code === '23505' ||\n    code === 'SQLITE_CONSTRAINT_UNIQUE' ||\n    code === 'SQLITE_CONSTRAINT_PRIMARYKEY'",
    "'40001',\n      '40P01',\n      '55P03',\n      '57014',\n      'SQLITE_BUSY',\n      'SQLITE_BUSY_SNAPSHOT',\n      'SQLITE_LOCKED',",
  ])
    if (!storage.includes(fragment))
      throw new Error('storageError mapping changed: update scripts/spec/lib/errors.mjs');

  const list = [...codes.values()]
    .map((entry) => ({
      code: entry.code,
      statuses: [...entry.statuses].sort((a, b) => a - b),
      packages: [...entry.packages].sort(codePointCompare),
      occurrences: entry.sites.length,
      sites: entry.sites.sort((a, b) => codePointCompare(a.at, b.at)),
    }))
    .sort((a, b) => codePointCompare(a.code, b.code));
  const value = {
    description:
      'Every error code the TypeScript implementation raises. An IamError carries { code, message, status }; the HTTP layer answers status with { error: { code, message } }. `sites` lists every raise site with its status and message (literal text, a template with ${...} placeholders, or the expression passed).',
    defaults: {
      constructorStatus: Number(defaultStatus[1]),
      unknownError: {
        code: 'INTERNAL_ERROR',
        status: 500,
        message: 'Internal server error',
        source: 'packages/server/src/http.ts errorResponse',
      },
      storageErrors: {
        source: 'packages/core/src/storage.ts storageError',
        rules: [
          {
            driverCodes: ['23505', 'SQLITE_CONSTRAINT_UNIQUE', 'SQLITE_CONSTRAINT_PRIMARYKEY'],
            code: 'CONFLICT',
            status: 409,
            message: 'A record with this identifier or tenant key already exists',
          },
          {
            driverCodes: [
              '40001',
              '40P01',
              '55P03',
              '57014',
              'SQLITE_BUSY',
              'SQLITE_BUSY_SNAPSHOT',
              'SQLITE_LOCKED',
            ],
            code: 'STORAGE_BUSY',
            status: 503,
            message: 'Database is busy; retry the complete operation',
          },
          {
            driverCodes: ['*'],
            code: 'STORAGE_ERROR',
            status: 500,
            message: 'Database operation failed',
          },
        ],
        iamErrorsPassThrough: true,
      },
      retryAfter:
        'An IamError with a numeric retryAfterMs > 0 adds error.retryAfterMs and the Retry-After header (seconds, rounded up).',
      wrongRegion: 'WrongRegionError adds error.region and error.location (when known).',
    },
    subclasses: [...subclasses.values()].sort((a, b) => codePointCompare(a.name, b.name)),
    errorClasses: errorLike.sort((a, b) => codePointCompare(a.name, b.name)),
    codes: list,
    dynamicSites: dynamic.sort((a, b) => codePointCompare(a.at, b.at)),
  };
  output.add('api/errors.json', json(value));
  const sites = list.reduce((sum, entry) => sum + entry.occurrences, 0);
  return `errors.json (${list.length} codes, ${sites} raise sites, ${dynamic.length} dynamic-code sites, ${subclasses.size} subclasses, ${errorLike.length} error classes)`;
}
