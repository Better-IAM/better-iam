import { readdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version ?? ''))
  throw new Error('Usage: node scripts/release-version.mjs VERSION');
const root = resolve(import.meta.dirname, '..');
for (const name of await readdir(resolve(root, 'packages'))) {
  const path = resolve(root, 'packages', name, 'package.json');
  const pkg = JSON.parse(await readFile(path, 'utf8'));
  pkg.version = version;
  await writeFile(path, JSON.stringify(pkg, null, 2) + '\n');
}

// Rust: the workspace version, and the `version` of every internal crate in [workspace.dependencies]
// (those entries carry a `path`), so `cargo publish --workspace` resolves them at the same release.
const cargoPath = resolve(root, 'Cargo.toml');
let cargo = await readFile(cargoPath, 'utf8');
cargo = cargo.replace(
  /(\[workspace\.package\][^[]*?\nversion = )"[^"]*"/,
  (_, head) => `${head}"${version}"`,
);
cargo = cargo.replace(
  /^(better-iam[\w-]* = \{[^}\n]*\bpath = "[^"]*"[^}\n]*\bversion = )"[^"]*"/gm,
  (_, head) => `${head}"${version}"`,
);
cargo = cargo.replace(
  /^(better-iam[\w-]* = \{[^}\n]*\bversion = )"[^"]*"([^}\n]*\bpath = )/gm,
  (_, head, tail) => `${head}"${version}"${tail}`,
);
await writeFile(cargoPath, cargo);

// Go: modules publish by tag (go/vX.Y.Z); the constant only reports the version at run time.
const goVersionPath = resolve(root, 'go', 'version.go');
const goVersion = await readFile(goVersionPath, 'utf8');
await writeFile(
  goVersionPath,
  goVersion.replace(/const Version = "[^"]*"/, `const Version = "${version}"`),
);

console.log(
  `Updated npm, Cargo, and Go metadata to ${version}; review changes, update changelog, and run pnpm install, pnpm check, cargo test --workspace, and go test ./... (in go/) before packing.`,
);
