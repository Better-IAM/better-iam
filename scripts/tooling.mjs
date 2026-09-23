import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const require = createRequire(import.meta.url);
/** Execute the pinned JS package-manager entrypoint directly; no shell interpolation. */
export function runPnpm(args, options = {}) {
  const manifestPath = resolve(import.meta.dirname, '..', 'node_modules', 'pnpm', 'package.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const entry = resolve(
    dirname(manifestPath),
    typeof manifest.bin === 'string' ? manifest.bin : manifest.bin.pnpm,
  );
  const result = spawnSync(process.execPath, [entry, ...args], {
    stdio: 'inherit',
    ...options,
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`pnpm ${args[0]} failed (${result.status})`);
}
