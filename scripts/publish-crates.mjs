// Publishes every publishable crate of the Cargo workspace to crates.io in dependency order, skipping versions that
// are already there, so a rerun finishes a partial release. crates.io rate-limits brand-new crates (a small burst,
// then one every few minutes): on 429 this waits for Retry-After (or 10 minutes) and tries again.
//
//   node scripts/publish-crates.mjs [--dry-run]
//
// Needs CARGO_REGISTRY_TOKEN in the environment for a real publish.
import { execFileSync, spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const dryRun = process.argv.includes('--dry-run');
const userAgent = 'better-iam-release (https://github.com/Better-IAM/better-iam)';
const metadata = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  }),
);
const members = new Set(metadata.workspace_members);
const crates = metadata.packages.filter(
  (pkg) => members.has(pkg.id) && !(Array.isArray(pkg.publish) && pkg.publish.length === 0),
);
const byName = new Map(crates.map((pkg) => [pkg.name, pkg]));

// Topological order over normal and build dependencies (dev-dependencies are stripped on publish).
const order = [];
const state = new Map();
function visit(pkg, trail) {
  if (state.get(pkg.name) === 'done') return;
  if (state.get(pkg.name) === 'visiting')
    throw new Error(`Dependency cycle: ${[...trail, pkg.name].join(' -> ')}`);
  state.set(pkg.name, 'visiting');
  for (const dep of pkg.dependencies) {
    if (dep.kind === 'dev') continue;
    const internal = byName.get(dep.name);
    if (internal) visit(internal, [...trail, pkg.name]);
  }
  state.set(pkg.name, 'done');
  order.push(pkg);
}
for (const pkg of [...crates].sort((a, b) => a.name.localeCompare(b.name))) visit(pkg, []);

async function published(name, version) {
  const response = await fetch(`https://crates.io/api/v1/crates/${name}/${version}`, {
    headers: { 'user-agent': userAgent },
  });
  if (response.status === 200) return true;
  if (response.status === 404) return false;
  throw new Error(`crates.io answered ${response.status} for ${name}@${version}`);
}

for (const pkg of order) {
  if (await published(pkg.name, pkg.version)) {
    console.log(`${pkg.name}@${pkg.version} is already on crates.io`);
    continue;
  }
  const args = ['publish', '-p', pkg.name, '--locked', ...(dryRun ? ['--dry-run'] : [])];
  for (let attempt = 1; ; attempt++) {
    console.log(`cargo ${args.join(' ')}${attempt > 1 ? ` (attempt ${attempt})` : ''}`);
    const run = spawnSync('cargo', args, { encoding: 'utf8', stdio: ['ignore', 'inherit', 'pipe'] });
    process.stderr.write(run.stderr ?? '');
    if (run.status === 0) break;
    const limited = /429|too many (new )?crates|rate limit/i.test(run.stderr ?? '');
    if (!limited || attempt >= 30) process.exit(run.status ?? 1);
    const retryAfter = /retry after ([^\n.]+)/i.exec(run.stderr ?? '')?.[1];
    const until = retryAfter ? Date.parse(retryAfter) : NaN;
    const waitMs = Number.isFinite(until) ? Math.max(until - Date.now(), 30_000) : 600_000;
    console.log(`crates.io rate limit; waiting ${Math.round(waitMs / 1000)}s`);
    await sleep(waitMs);
  }
  // The index needs a moment before dependents can resolve the new version.
  if (!dryRun)
    for (let i = 0; i < 60 && !(await published(pkg.name, pkg.version)); i++) await sleep(5_000);
}
console.log(`${dryRun ? 'Checked' : 'Published'} ${order.length} crates`);
