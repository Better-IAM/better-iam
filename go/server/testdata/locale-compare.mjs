// Writes locale-compare.json: string pairs and the sign of a.localeCompare(b) in this Node (ICU), for the Go
// metrics renderer, which sorts series as TypeScript does (String.prototype.localeCompare).
// Regenerate: node go/server/testdata/locale-compare.mjs > go/server/testdata/locale-compare.json
const words = [
  'operation', 'authorize', 'authorizeMany', 'listAccessible', 'auth', 'http', '(other)', '(invalid)', '(unknown)',
  'iam:groups:create', 'iam:groups:read', 'iam:tenants:create', 'iam:roles:assume', 'signIn', 'signUp', 'getSession',
  'ok', 'denied', 'error', '', 'ACCESS_DENIED', 'INVALID_INPUT', 'NOT_FOUND', 'UNAUTHENTICATED', 'RATE_LIMITED',
  'INTERNAL_ERROR', 'access_denied', 'a', 'A', 'b', 'B', 'a-b', 'a_b', 'ab', 'a:b', 'a.b', 'a/b', 'a b', 'a1', 'a10',
  'a2', 'Z', 'z', '_', '-', ':', '/', '.', '(', ')', '0', '9', 'é', 'e', 'f', 'É', '/api/iam/auth/signIn',
  '/api/iam/groups/create', '/api/iam/authorize', '/api/iam/health', 'documents:read', 'documents:write',
  'operationiam:groups:createokACCESS_DENIED', 'operationiam:groups:createok', 'operationiam:groups:createerrorINVALID_INPUT',
  'authsignInok', 'authsignIndeniedUNAUTHENTICATED', 'httpPOST /api/iam/groups/createok', 'c"d\e\n', 'a"b', 'a\b',
];
const random = [];
let seed = 42;
const next = () => ((seed = (seed * 1103515245 + 12345) % 2147483648), seed);
const alphabet = 'aAbBzZ09_-:/.() "\\néÉ';
for (let i = 0; i < 400; i++) {
  let s = '';
  const length = next() % 8;
  for (let j = 0; j < length; j++) s += alphabet[next() % alphabet.length];
  random.push(s);
}
const all = [...words, ...random];
const pairs = [];
for (let i = 0; i < all.length; i++)
  for (let j = 0; j < all.length; j += 7) pairs.push([all[i], all[(i + j) % all.length]]);
process.stdout.write(
  JSON.stringify({
    node: process.version,
    icu: process.versions.icu,
    pairs: pairs.map(([a, b]) => [a, b, Math.sign(a.localeCompare(b))]),
  }) + '\n',
);
