#!/usr/bin/env node
// Generates the language-neutral contract in spec/ from the TypeScript implementation (see spec/README.md).
//
//   node scripts/spec/generate.mjs              regenerate spec/ (pnpm spec)
//   node scripts/spec/generate.mjs --check      regenerate into a temporary directory and fail on any difference
//                                               with the checked-in spec/ (pnpm spec:check)
//   node scripts/spec/generate.mjs --out DIR    write into DIR instead of spec/
//   node scripts/spec/generate.mjs --only routes,vectors
//
// Requires `pnpm build` first: the generators import packages/*/dist and call the implementation. Output is
// deterministic: sorted keys in the metadata artifacts, no timestamps, LF line endings, seeded randomness.
//
// The deterministic randomness patch must load before any package code.
import './lib/determinism.mjs';
import { mkdtemp, readFile, rm, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { generateCatalog } from './lib/catalog.mjs';
import { generateCollections } from './lib/collections.mjs';
import { generateErrors } from './lib/errors.mjs';
import { generateMigrations } from './lib/migrations.mjs';
import { buildOpenApi, generateOpenApi } from './lib/openapi.mjs';
import { generateRoutes } from './lib/routes.mjs';
import { Output, specDir, walkFiles } from './lib/util.mjs';
import { generateVectors } from './lib/vectors/index.mjs';

/** The directories of spec/ this generator owns; everything else (BUILDOUT.md, README.md, conformance/) is left alone. */
const managed = ['api', 'catalog', 'storage', 'vectors'];

const args = process.argv.slice(2);
const check = args.includes('--check');
const outIndex = args.indexOf('--out');
const onlyIndex = args.indexOf('--only');
const only = onlyIndex >= 0 ? new Set(args[onlyIndex + 1].split(',')) : undefined;
if (check && only) throw new Error('--check always regenerates everything');

const target = check
  ? await mkdtemp(join(tmpdir(), 'better-iam-spec-'))
  : outIndex >= 0
    ? args[outIndex + 1]
    : specDir;
const output = new Output(target);

const steps = [
  [
    'openapi',
    async (state) => {
      state.openapi = await buildOpenApi();
      return generateOpenApi(output, state.openapi);
    },
  ],
  [
    'routes',
    async (state) => {
      state.openapi ??= await buildOpenApi();
      return generateRoutes(output, { openapi: state.openapi });
    },
  ],
  ['errors', () => generateErrors(output)],
  ['catalog', () => generateCatalog(output)],
  ['collections', () => generateCollections(output)],
  ['migrations', () => generateMigrations(output)],
  ['vectors', () => generateVectors(output)],
];

const state = {};
let failed = false;
for (const [name, step] of steps) {
  if (only && !only.has(name)) continue;
  try {
    console.log(`✓ ${await step(state)}`);
  } catch (error) {
    failed = true;
    console.error(`✗ ${name}: ${error.stack ?? error}`);
  }
}
if (failed) {
  if (check) await rm(target, { recursive: true, force: true });
  process.exit(1);
}
await output.flush();

const relativePath = (base, path) => relative(base, path).split(sep).join('/');
if (check) {
  const differences = [];
  const expected = new Set();
  for (const dir of managed)
    for await (const path of walkFiles(join(specDir, dir)))
      expected.add(relativePath(specDir, path));
  for (const [path, content] of output.files) {
    let current;
    try {
      current = await readFile(join(specDir, ...path.split('/')), 'utf8');
    } catch {
      differences.push(`missing in spec/: ${path}`);
      continue;
    }
    if (current !== content) differences.push(`differs: ${path}`);
    expected.delete(path);
  }
  for (const path of expected) differences.push(`not generated (stale): ${path}`);
  await rm(target, { recursive: true, force: true });
  if (differences.length) {
    console.error(
      `spec/ is out of date (${differences.length}):\n  ${differences.join('\n  ')}\nRun: pnpm build && pnpm spec`,
    );
    process.exit(1);
  }
  console.log(`spec/ is up to date (${output.files.size} files)`);
} else if (!only) {
  // Remove files of managed directories the generators no longer produce.
  for (const dir of managed)
    for await (const path of walkFiles(join(target, dir))) {
      const name = relativePath(target, path);
      if (!output.files.has(name)) {
        await unlink(path);
        console.log(`  removed stale ${name}`);
      }
    }
  console.log(`wrote ${output.files.size} files to ${relativePath(process.cwd(), target) || '.'}`);
}
