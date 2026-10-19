// spec/vectors/*.json: deterministic test vectors produced by calling the TypeScript implementation.
import { coreVectors } from './core.mjs';
import { cryptoVectors } from './crypto.mjs';
import { scimVectors } from './scim.mjs';

export async function generateVectors(output) {
  const counts = {
    ...(await coreVectors(output)),
    ...(await cryptoVectors(output)),
    ...(await scimVectors(output)),
  };
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  return `vectors (${Object.keys(counts).length} files, ${total} cases: ${Object.entries(counts)
    .map(([name, count]) => `${name} ${count}`)
    .join(', ')})`;
}
