#!/usr/bin/env node
// Freshness check for the code the ports generate from spec/: runs each language's generator into a temporary
// directory and fails when the result differs from the checked-in files.
//
//   node scripts/spec/check-generated.mjs              check every language
//   node scripts/spec/check-generated.mjs go           check only the named languages
//   node scripts/spec/check-generated.mjs --fix [go]   regenerate the checked-in files instead
//
// A generator is a Node script that accepts `--out DIR` and writes its generated files under DIR, laid out as in the
// checked-in directory. `owns(path)` picks the generated files of that directory (a path relative to it, with "/"
// separators); everything else there (hand-written helpers, tests) is left out of the comparison. To add a language,
// add an entry to `generators`.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

const generators = [
  {
    name: 'go',
    description: 'go/apitypes from spec/api (openapi.json, routes.json)',
    script: 'scripts/spec/gen-go-types.mjs',
    dir: 'go/apitypes',
    owns: (path) => !path.includes('/') && path.endsWith('_gen.go'),
  },
  {
    name: 'rust',
    description: 'crates/types (better-iam-types) from spec/api (openapi.json, routes.json)',
    script: 'scripts/spec/gen-rust-types.mjs',
    dir: 'crates/types',
    // lib.rs, macros.rs and runtime.rs are hand-written; rustfmt must be installed (PATH, $RUSTFMT or ~/.cargo/bin).
    owns: (path) =>
      path === 'src/schemas.rs' || path === 'src/routes.rs' || /^src\/api\/[^/]+\.rs$/.test(path),
  },
];

const args = process.argv.slice(2);
const fix = args.includes('--fix');
const wanted = args.filter((arg) => !arg.startsWith('--'));
const unknown = wanted.filter((name) => !generators.some((generator) => generator.name === name));
if (unknown.length) {
  console.error(
    `unknown language ${unknown.join(', ')}; known: ${generators.map((g) => g.name).join(', ')}`,
  );
  process.exit(2);
}
const selected = wanted.length ? generators.filter((g) => wanted.includes(g.name)) : generators;

function listFiles(dir, owns) {
  const out = [];
  if (!existsSync(dir)) return out;
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else {
        const name = relative(dir, path).split(sep).join('/');
        if (owns(name)) out.push(name);
      }
    }
  };
  walk(dir);
  return out.sort();
}

function run(generator, out) {
  const result = spawnSync(
    process.execPath,
    [join(root, generator.script), ...(out ? ['--out', out] : [])],
    {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (result.status !== 0)
    throw new Error(`${generator.script} failed:\n${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}

function firstDifference(a, b) {
  const left = a.split('\n');
  const right = b.split('\n');
  for (let line = 0; line < Math.max(left.length, right.length); line++) {
    if (left[line] !== right[line]) return line + 1;
  }
  return 0;
}

let failed = false;
for (const generator of selected) {
  if (fix) {
    try {
      console.log(`✓ ${generator.name}: ${run(generator)}`);
    } catch (error) {
      failed = true;
      console.error(`✗ ${generator.name}: ${error.message}`);
    }
    continue;
  }
  const temp = mkdtempSync(join(tmpdir(), `better-iam-generated-${generator.name}-`));
  try {
    run(generator, temp);
    const checkedIn = join(root, generator.dir);
    const fresh = listFiles(temp, generator.owns);
    const current = listFiles(checkedIn, generator.owns);
    const problems = [];
    for (const name of fresh.filter((file) => !current.includes(file)))
      problems.push(`${generator.dir}/${name} is missing`);
    for (const name of current.filter((file) => !fresh.includes(file)))
      problems.push(`${generator.dir}/${name} is no longer generated`);
    for (const name of fresh.filter((file) => current.includes(file))) {
      const want = readFileSync(join(temp, name), 'utf8');
      const got = readFileSync(join(checkedIn, name), 'utf8').replace(/\r\n/g, '\n');
      if (want !== got)
        problems.push(`${generator.dir}/${name} differs from line ${firstDifference(got, want)}`);
    }
    if (problems.length) {
      failed = true;
      console.error(
        `✗ ${generator.name} (${generator.description}) is stale:\n  ${problems.join('\n  ')}\n` +
          `  regenerate with: node scripts/spec/check-generated.mjs --fix ${generator.name}`,
      );
    } else console.log(`✓ ${generator.name}: ${fresh.length} generated files are up to date`);
  } catch (error) {
    failed = true;
    console.error(`✗ ${generator.name}: ${error.message}`);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}
process.exit(failed ? 1 : 0);
