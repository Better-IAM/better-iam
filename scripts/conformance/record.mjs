#!/usr/bin/env node
// Records conformance traces from the TypeScript test suite (spec/conformance/FORMAT.md).
//
//   node scripts/conformance/record.mjs [--out <dir>] [vitest arguments, e.g. test files]
//
// Runs `vitest run` with BETTER_IAM_RECORD=<dir> (default spec/conformance/traces), which makes vitest.config.ts load
// the recorder; each test file's traces are rewritten under <dir>/<test file>/.
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const argv = process.argv.slice(2);
let out = join(root, 'spec', 'conformance', 'traces');
const rest = [];
for (let index = 0; index < argv.length; index++) {
  if (argv[index] === '--out') out = resolve(argv[++index]);
  else rest.push(argv[index]);
}
const result = spawnSync(
  process.execPath,
  [join(root, 'node_modules', 'vitest', 'vitest.mjs'), 'run', ...rest],
  {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, BETTER_IAM_RECORD: out },
  },
);
console.log(`\nTraces written under ${out}`);
process.exit(result.status ?? 1);
