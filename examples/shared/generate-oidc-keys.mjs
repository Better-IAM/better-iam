import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const output = process.argv[2];
if (!output) throw new Error('Usage: node generate-oidc-keys.mjs /absolute/path/to/oidc-keys.json');
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = {
  ...pair.privateKey.export({ format: 'jwk' }),
  use: 'sig',
  alg: 'RS256',
  kid: randomUUID(),
};
await writeFile(
  resolve(output),
  JSON.stringify(
    {
      jwks: { keys: [jwk] },
      cookieKeys: [randomBytes(32).toString('base64url')],
      encryptionKey: randomBytes(32).toString('base64'),
    },
    null,
    2,
  ),
  { flag: 'wx', mode: 0o600 },
);
console.log(
  `Created private OAuth keys at ${resolve(output)}. Set OIDC_KEY_FILE to this path and keep the file outside version control.`,
);
