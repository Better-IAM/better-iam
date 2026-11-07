// Differential fixture for the Go port of @better-iam/auth: runs the TypeScript implementation (packages/auth/dist,
// built with `pnpm build`) and the libraries it depends on over many inputs and records the outputs in
// differential.json. The Go tests (differential_test.go) replay every case. Regenerate after changing the
// TypeScript auth package:
//
//   node go/auth/testdata/differential.mjs > go/auth/testdata/differential.json
//
// Output is deterministic except for the WebAuthn keys, challenges and IVs, which are random but self-contained.
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign, webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const dist = (file) => pathToFileURL(path.join(root, 'packages/auth/dist', file)).href;
const auth = await import(dist('index.js'));
const validation = await import(dist('validation.js'));
const policy = await import(dist('password-policy.js'));
const safeFetch = await import(dist('safe-fetch.js'));
const requireAuth = createRequire(path.join(root, 'packages/auth/package.json'));
const simple = await import(pathToFileURL(requireAuth.resolve('@simplewebauthn/server')).href);
const helpers = await import(pathToFileURL(requireAuth.resolve('@simplewebauthn/server/helpers')).href);
const requireSimple = createRequire(requireAuth.resolve('@simplewebauthn/server'));
const tinyCbor = await import(pathToFileURL(requireSimple.resolve('@levischuck/tiny-cbor')).href);
const x509 = await import(pathToFileURL(requireSimple.resolve('@peculiar/x509')).href);
x509.cryptoProvider.set(webcrypto);

const outcome = (fn) => {
  try {
    const value = fn();
    return { value: value === undefined ? { $undefined: true } : value };
  } catch (error) {
    return { error: { name: error?.name, code: error?.code, status: error?.status, message: error?.message } };
  }
};
const outcomeAsync = async (fn) => {
  try {
    const value = await fn();
    return { value: value === undefined ? { $undefined: true } : value };
  } catch (error) {
    return { error: { name: error?.name, code: error?.code, status: error?.status, message: error?.message } };
  }
};

// Deterministic PRNG (mulberry32) for the template payload combinations.
let seed = 0x9e3779b9;
const random = () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(random() * list.length)];

// --- templates ------------------------------------------------------------------------------------------------------

const link = (name) => (input) =>
  `https://app.test/${name}?` +
  Object.keys(input)
    .sort()
    .map((key) => `${key}=${input[key]}`)
    .join('&');
const allLinks = Object.fromEntries(
  [
    'invitation', 'passwordReset', 'verifyEmail', 'emailChange', 'magicLink', 'account', 'certification', 'delegation',
    'team', 'billing', 'privacy', 'threats', 'guestInvitation', 'guests', 'clearances',
  ].map((name) => [name, link(name)]),
);
const linkSets = { none: {}, account: { account: allLinks.account }, all: allLinks };

const text = ['Acme <b>&</b> "Co"', 'Ünïcode ✓ 🔐', 'line\nbreak sep\u0007bell', '', ' padded ', "O'Brien"];
const numbers = ['1', '0', '2', '12', 'abc', '1e3', ' 5 ', '-3', '0x10', '', 'Infinity', '1.5'];
const dates = [
  '2026-10-19T12:00:00.000Z', '2026-02-30', '2026', 'not a date', '2026-06-01T10:00:00+05:30', '2024-02-29T23:59:59Z',
  'Mon, 01 Jun 2026 10:00:00 GMT', '',
];
const millis = ['1767225600000', '0', 'abc', '', '1.7e12', '8640000000000001'];
const pools = {
  token: ['tok_123', '', '<x>'],
  code: ['654321', ''],
  tenantId: ['t1', ''],
  tenantName: text,
  inviterName: text,
  sponsorName: ['Sam', 'Owner', ''],
  message: text,
  expiresAt: dates,
  reviewDueAt: dates,
  dueAt: dates,
  label: ['My laptop', 'x'.repeat(100), '\u0000label\u001f', ''],
  userAgent: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'curl/8.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0',
    '',
  ],
  ip: ['203.0.113.7', '2001:db8::1', ''],
  method: ['password', 'passkey', ''],
  time: ['2026-09-22T00:00:00.000Z', ''],
  attempts: numbers,
  campaignName: text,
  pending: numbers,
  items: [...numbers, '[{"what":"Ada","spent":"$5","usual":"$1"},{"what":3},7,"x",[1,2]]', '[]', '{"a":1}', 'not json', '[{"what":{"a":1},"spent":[1,2]}]'],
  campaignId: ['c1', ''],
  agentName: text,
  days: numbers,
  delegationId: ['d1', ''],
  model: ['gpt', ''],
  scopes: ['read, write', ''],
  reason: ['subscription', 'unverified', 'unfounded', 'no-data', 'nope', '', 'Because “quoted”'],
  teamName: text,
  teamId: ['team1', ''],
  memberCount: numbers,
  onUndecided: ['remove', 'keep', ''],
  note: text,
  requesterName: text,
  requesterEmail: ['r@example.test', ''],
  justification: text,
  decision: ['approved', 'denied', ''],
  action: ['iam:delete', ''],
  resource: ['doc/1', ''],
  minutes: numbers,
  statementId: ['st1', ''],
  count: numbers,
  day: ['2026-10-18', ''],
  overdue: ['true', 'false', ''],
  number: ['INV-1', '', ' A  B '],
  amountDue: ['$10.00', ''],
  period: ['2026-09', ''],
  total: ['$9', ''],
  subtotal: ['$8', ''],
  credits: ['$1', ''],
  budgetName: text,
  subjectName: text,
  windowStart: ['2026-10-01', ''],
  windowEnd: ['2026-10-31', '2026-10-01', ''],
  kind: ['forecast', 'threshold', ''],
  threshold: numbers,
  forecast: ['$99', ''],
  amount: ['$50', ''],
  spent: ['$40', ''],
  percent: numbers,
  type: ['access', 'portability', 'erasure', 'rectification', 'restriction', 'objection', 'opt-out', 'other', ''],
  requestId: ['req1', ''],
  regulation: ['gdpr', 'ccpa', ''],
  channel: ['web', ''],
  event: ['completed', 'extended', 'rejected', 'weird', ''],
  exportReady: ['true', ''],
  incidentId: ['inc1', ''],
  title: text,
  severity: ['critical', 'low', '', 'ßharp'],
  detections: numbers,
  subject: text,
  summary: text,
  body: ['one\r\ntwo\nthree', '', 'x\n'.repeat(250)],
  guestId: ['g1', ''],
  guestName: text,
  guestEmail: ['g@example.test', ''],
  productName: text,
  productKey: ['seat-pro', ''],
  levelName: ['Secret', ''],
  identityId: ['idn1', ''],
  personName: text,
  reinvestigationDue: dates,
  status: ['interim', 'reinstated', 'revoked', 'suspended', ''],
};
const templateKeys = {
  'verify-email': ['token', 'tenantId'],
  'password-reset': ['token', 'tenantId'],
  'email-change': ['token', 'tenantId'],
  'magic-link': ['token', 'tenantId'],
  code: ['token'],
  'mfa-code': ['code'],
  'new-sign-in': ['label', 'userAgent', 'ip', 'method', 'time'],
  'sign-in-failures': ['userAgent', 'ip', 'attempts', 'time'],
  'certification-review': ['campaignName', 'items', 'pending', 'dueAt', 'tenantId', 'campaignId'],
  'certification-reminder': ['campaignName', 'items', 'pending', 'dueAt', 'tenantId', 'campaignId'],
  'delegation-request': ['agentName', 'days', 'tenantId', 'delegationId', 'model', 'scopes', 'reason'],
  'delegation-confirmation': ['agentName', 'tenantId', 'delegationId', 'action', 'resource', 'reason', 'minutes'],
  'team-review-requested': ['teamName', 'tenantId', 'teamId', 'dueAt', 'memberCount', 'onUndecided', 'note'],
  'team-join-request': ['teamName', 'tenantId', 'teamId', 'requesterName', 'requesterEmail', 'justification'],
  'team-join-decided': ['teamName', 'tenantId', 'teamId', 'decision', 'note'],
  'spend-alert': ['tenantId', 'budgetName', 'subjectName', 'windowStart', 'windowEnd', 'kind', 'threshold', 'forecast', 'amount', 'spent', 'percent'],
  'spend-anomaly': ['tenantId', 'items', 'count', 'day', 'tenantName'],
  'billing-statement': ['tenantId', 'statementId', 'tenantName', 'reason', 'number', 'period', 'total', 'dueAt', 'subtotal', 'credits'],
  'payment-reminder': ['tenantId', 'statementId', 'overdue', 'days', 'number', 'amountDue', 'tenantName', 'period', 'dueAt'],
  'privacy-request-verify': ['tenantId', 'tenantName', 'number', 'type', 'requestId', 'token'],
  'privacy-request-received': ['tenantId', 'tenantName', 'number', 'type', 'dueAt', 'requestId', 'regulation', 'channel'],
  'privacy-request-update': ['tenantId', 'tenantName', 'number', 'type', 'dueAt', 'requestId', 'event', 'reason', 'exportReady'],
  'privacy-request-due': ['tenantId', 'tenantName', 'number', 'type', 'dueAt', 'requestId', 'overdue'],
  'workflow-message': ['subject', 'tenantName', 'body'],
  'threat-alert': ['tenantId', 'incidentId', 'tenantName', 'title', 'severity', 'detections', 'subject', 'summary'],
  'license-waiting': ['productName', 'productKey', 'tenantName'],
  'license-activated': ['productName', 'productKey', 'tenantName'],
  'guest-invitation': ['token', 'tenantId', 'tenantName', 'inviterName', 'sponsorName', 'message', 'expiresAt'],
  'guest-review': ['tenantId', 'guestId', 'tenantName', 'guestName', 'guestEmail', 'expiresAt', 'reviewDueAt'],
  'guest-sponsor-missing': ['tenantId', 'guestId', 'tenantName', 'guestName', 'guestEmail', 'sponsorName'],
  'clearance-reminder': ['tenantId', 'tenantName', 'levelName', 'identityId', 'personName', 'reinvestigationDue', 'expiresAt', 'status'],
  'clearance-status': ['tenantId', 'tenantName', 'levelName', 'status'],
  'owner-invitation': ['token', 'tenantId', 'tenantName', 'inviterName'],
  'member-invitation': ['token', 'tenantId', 'tenantName', 'inviterName'],
  'unknown-template': ['token'],
};
const privacyMillis = new Set(['privacy-request-received', 'privacy-request-update', 'privacy-request-due']);
const templates = [];
for (const [template, keys] of Object.entries(templateKeys)) {
  for (let variant = 0; variant < 24; variant++) {
    const payload = {};
    for (const key of keys) {
      if (variant === 0) continue; // empty payload
      if (variant > 1 && random() < 0.3) continue;
      const pool = key === 'dueAt' && privacyMillis.has(template) ? millis : pools[key];
      payload[key] = variant === 1 ? pool[0] : pick(pool);
    }
    const message = { template, to: pick(['a@example.test', '+15550001', 'Odd <to>']), payload };
    if (random() < 0.6) message.tenantId = pick(['tenant-1', 't1']);
    if (random() < 0.4) message.signInUrl = 'https://acme.example.test/login';
    const linkSet = variant < 3 ? ['none', 'account', 'all'][variant] : pick(['none', 'account', 'all']);
    const options = { links: linkSets[linkSet] };
    if (random() < 0.3) options.appName = pick(['Acme Cloud', '']);
    templates.push({ message, links: linkSet, appName: options.appName, result: outcome(() => auth.renderDeliveryMessage(message, options)) });
  }
}

// --- small functions ------------------------------------------------------------------------------------------------

const strings = [
  '', ' ', 'a', 'A@B.CO', ' Mixed@Example.COM ', 'no-at-sign', 'two@@example.com', 'a@b', 'a@b.', 'a@.b', '.@b.c', 'a@b.c',
  'İstanbul@example.com', 'ΣΑΣ@example.com', 'x'.repeat(255) + '@e.co', 'a b@c.d', 'a b@c.d', 'tab\t@c.d', ' @c.d',
  '+15551234567', '+1555', '+0123456789', '15551234567', '+1555123456789012', '+12345678901234567', '+１２３４５６７８',
  'correct horse battery staple', 'password1234', 'Password1234', 'P@ssw0rd1234!', 'aaaaaaaaaaaa', 'abcdabcdabcd',
  'qwertyuiopas', 'zyxwvutsrqpo', '1qaz2wsx3edc', '!@#$%^&*()_+', '9876543210987', 'aB3$aB3$aB3$', 'Tr0ub4dor&3xyz',
  'thequickbrownfox', 'Summer2024!!', 'correct-horse-battery-staple', 'ünïcödé-pässwörd', '🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐',
  'Ada Lovelace', 'Control\u0000Name\u0085X', '  Spaced  ', '  ', 'x'.repeat(300), 'é'.repeat(256),
  '\ud800lone', 'ok\udfffend',
];
const valueInputs = [...strings, 42, null, true, { $undefined: true }];
const decode = (value) => (value && typeof value === 'object' && value.$undefined ? undefined : value);
const validators = [];
for (const value of valueInputs) {
  const v = decode(value);
  validators.push({
    value,
    text: outcome(() => validation.text(v, 'field')),
    text6: outcome(() => validation.text(v, 'code', 6)),
    email: outcome(() => validation.email(v)),
    phone: outcome(() => validation.phone(v)),
    password: outcome(() => validation.password(v)),
    displayName: outcome(() => validation.displayName(v)),
  });
}
const passwords = strings.map((value) => ({
  value,
  common: policy.isCommonPassword(value),
  classes: policy.characterClasses(value),
}));
const policies = [
  undefined,
  { minPasswordLength: 16 },
  { passwordMinClasses: 3 },
  { passwordMinClasses: 4, minPasswordLength: 14 },
  { passwordRejectPersonalInfo: true },
];
const identities = [
  undefined,
  { email: 'ada.lovelace@example.com', name: 'Ada Lovelace' },
  { email: 'bob@example.com', name: 'Robert "Bob" Smith-Jones' },
  { name: 'Zoë Ünïcode' },
];
const rules = [];
for (const value of strings.filter((s) => s.length >= 12)) {
  for (const [p, tenantPolicy] of policies.entries())
    for (const [i, identity] of identities.entries())
      for (const block of [undefined, false]) {
        if ((p + i) % 2 && block === false) continue;
        rules.push({
          value,
          policy: tenantPolicy ?? null,
          identity: identity ?? null,
          block: block ?? null,
          result: outcome(() =>
            policy.assertPasswordRules(value, tenantPolicy, block === undefined ? undefined : { blockCommonPasswords: block }, identity),
          ),
        });
      }
}
const userAgents = [
  ...pools.userAgent,
  'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0 Mobile Safari/537.36',
  'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
  'Opera/9.80 OPR/100',
  'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) FxiOS/120.0',
  'Mozilla/5.0 (iPhone) CriOS/120.0',
  'Something Windows',
];
const describeUserAgent = userAgents.map((value) => ({ value, result: auth.describeUserAgent(value) ?? null }));

const addresses = [
  '8.8.8.8', '1.1.1.1', '10.0.0.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', '172.32.0.1', '192.168.1.1', '100.64.0.1',
  '100.128.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '192.0.2.1', '198.18.0.1', '203.0.113.9', '::1', '::',
  '::ffff:8.8.8.8', '::ffff:10.0.0.1', '::ffff:0:10.0.0.1', '64:ff9b::808:808', '64:ff9b:1::1', '2001:db8::1',
  '2001::1', '2002::1', 'fc00::1', 'fe80::1', 'fec0::1', 'ff02::1', '2606:4700::1111', '2a00:1450:4001::200e',
  ' 8.8.8.8 ', 'example.com', '', '1.2.3', '::ffff:1.1.1.1', '100::1',
];
const publicAddresses = addresses.map((value) => ({ value, result: safeFetch.isPublicAddress(value) }));
const urls = [
  'https://example.com/path?q=1', 'https://example.com:443/x', 'https://example.com:8443/x', 'http://example.com/',
  'https://user:pass@example.com/', 'https://example.com/#frag', 'https://example.com/#', 'https://EXAMPLE.com/',
  'https://10.0.0.1/', 'https://8.8.8.8/', 'https://[::1]/', 'https://[2606:4700::1111]/', 'https://0x7f.1/',
  'https://2130706433/', 'https://127.1/', 'https://0177.0.0.1/', 'http://localhost:3000/x', 'http://127.0.0.1:8080/',
  'http://[::1]:9000/', 'https://localhost/', 'ftp://localhost/', 'not a url', '/relative', 'https://example.com:0443/',
  'https://example.com:99999/', 'https://8.8.8.8:443/', 'HTTPS://Example.COM/A', 'https://xn--bcher-kva.example/',
  'https://192.168.1.1:443/', 'https://[::ffff:127.0.0.1]/', 'https://1.2.3.4.5/', 'https://256.1.1.1/',
];
const urlOptions = [{}, { anyPort: true }, { allowInsecureLocalhost: true }, { allowPrivateNetworks: true }];
const fetchUrls = [];
for (const value of urls)
  for (const options of urlOptions)
    fetchUrls.push({
      value,
      options,
      result: (() => {
        try {
          const url = safeFetch.checkFetchUrl(value, options);
          return { href: url.href, hostname: url.hostname, port: url.port, protocol: url.protocol };
        } catch (error) {
          return { reason: error.reason, message: error.message };
        }
      })(),
    });

const numberStrings = [...numbers, '  ', '1_000', '.5', '5.', '.', '+5', '-0', '0b101', '0o17', '0X1f', '1e', '1e+', '1e-3',
  '-Infinity', 'infinity', '12abc', '\n7\t', '0x', '1e1000', '00012', '-0x10'];
const jsNumbers = numberStrings.map((value) => ({ value, result: Object.is(Number(value), -0) ? '-0' : String(Number(value)) }));
const dateStrings = [
  '2026-10-19T12:00:00.000Z', '2026-02-30', '2026-02-29', '2024-02-29', '2026-13-01', '2026-01-01T25:00Z',
  '2026-01-01T24:00Z', '2026-01-01T10:00:60Z', '+002026-01-01', '-000001-01-01T00:00:00Z', '2026', '2026-06',
  '2026-06-01T10:00:00.1234Z', '2026-06-01T10:00:00,5Z', '2026-06-01 10:00:00Z', '2026-06-01T10:00:00+05:30',
  '2026-06-01t10:00:00z', 'Mon, 01 Jun 2026 10:00:00 GMT', '1767225600000', '', 'abc', '2026-06-01T10:00:00.000+0530',
  '275760-09-13', '+275760-09-13T00:00:00.000Z', '+275760-09-13T00:00:00.001Z', '-271821-04-20T00:00:00Z',
  '2026-06-01T10:00:00.000-00:00', '2026-06-01T10:00:00.000+23:59',
];
const jsDates = dateStrings.map((value) => {
  const date = new Date(value);
  return {
    value,
    time: Number.isNaN(date.getTime()) ? null : date.getTime(),
    utc: Number.isNaN(date.getTime()) ? null : date.toUTCString(),
    iso: Number.isNaN(date.getTime()) ? null : date.toISOString(),
  };
});
const encodeURIs = ['Better IAM', 'ada@example.com', 'ünï code', "!'()*-._~", 'a+b=c&d/e?f#g', '🔐', ''].map((value) => ({
  value,
  result: encodeURIComponent(value),
}));
const base64Inputs = ['AAAA', 'AA=A', 'AA!AAA', 'A', 'AB', 'ABC', 'AB==CD', '+/+/', '-_-_', 'AA AA', 'AAA=A', 'QUJD\nREVG',
  'QQ', 'QR', 'Q=QQ', '====QUJD', 'QU=JD', 'SGVsbG8', 'SGVsbG8=', 'SGVs bG8', 'SGVsébG8'];
const base64 = base64Inputs.map((value) => ({
  value,
  node: Buffer.from(value, 'base64url').toString('hex'),
  hexagonUrl: Buffer.from(helpers.isoBase64URL.toBuffer(value)).toString('hex'),
  hexagon: Buffer.from(helpers.isoBase64URL.toBuffer(value, 'base64')).toString('hex'),
}));

// --- CBOR -----------------------------------------------------------------------------------------------------------

const hexCases = [
  'a301634f4b500327206745643235353139', 'a50102032620012158200000000000000000000000000000000000000000000000000000000000000000225820',
  '80', 'a0', '00', '17', '1818', '1817', '190100', '19000a', '1a00010000', '1b0000000000000019', '1b0020000000000000',
  '20', '3818', '40', '4401020304', '440102', '6161', '63e282ac', '62c328', '8301020', '83010203', 'a2616101616202',
  'a2616101616102', 'a1f401', 'f4', 'f5', 'f6', 'f7', 'f8ff', 'f97c00', 'f97e00', 'f93c00', 'fa3fc00000', 'fb3ff8000000000000',
  'fb3ff1999999999999', 'c11a5f5e1000', '9f01ff', 'bf6161ff', '5f4101ff', 'a1a10101', 'a10102', '1c', '',
];
const cbor = hexCases.map((hex) => ({
  hex,
  result: outcome(() => {
    const decoded = tinyCbor.decodePartialCBOR(Uint8Array.from(Buffer.from(hex, 'hex')), 0);
    return { consumed: decoded[1], encoded: Buffer.from(tinyCbor.encodeCBOR(decoded[0])).toString('hex') };
  }),
}));

// --- WebAuthn -------------------------------------------------------------------------------------------------------

const RP_ID = 'iam.example.com';
const ORIGIN = 'https://iam.example.com';
const rpHash = createHash('sha256').update(RP_ID).digest();
const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const encode = (value) => Buffer.from(tinyCbor.encodeCBOR(value));
const u32 = (n) => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(n);
  return buffer;
};

function makeKey(kind) {
  if (kind === 'ES256' || kind === 'ES384-35' || kind === 'ES512') {
    const curve = kind === 'ES256' ? 'prime256v1' : kind === 'ES512' ? 'secp521r1' : 'secp384r1';
    const pair = generateKeyPairSync('ec', { namedCurve: curve });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const crv = kind === 'ES256' ? 1 : kind === 'ES512' ? 3 : 2;
    const alg = kind === 'ES256' ? -7 : kind === 'ES512' ? -36 : -35;
    const hash = kind === 'ES256' ? 'sha256' : kind === 'ES512' ? 'sha512' : 'sha384';
    return {
      cose: new Map([[1, 2], [3, alg], [-1, crv], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]),
      sign: (data) => sign(hash, data, pair.privateKey),
      pair,
    };
  }
  if (kind === 'EdDSA') {
    const pair = generateKeyPairSync('ed25519');
    const jwk = pair.publicKey.export({ format: 'jwk' });
    return {
      cose: new Map([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(jwk.x, 'base64url')]]),
      sign: (data) => sign(null, data, pair.privateKey),
      pair,
    };
  }
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const pss = kind === 'PS256';
  return {
    cose: new Map([[1, 3], [3, pss ? -37 : kind === 'RS1' ? -65535 : -257], [-1, Buffer.from(jwk.n, 'base64url')], [-2, Buffer.from(jwk.e, 'base64url')]]),
    sign: (data) =>
      pss
        ? sign('sha256', data, { key: pair.privateKey, padding: 6, saltLength: 32 })
        : sign(kind === 'RS1' ? 'sha1' : 'sha256', data, pair.privateKey),
    pair,
  };
}

async function selfSignedCertificate(pair, subject, extensions = [], issuer) {
  const keys = await (async () => {
    const algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
    const privateKey = await webcrypto.subtle.importKey('pkcs8', pair.privateKey.export({ format: 'der', type: 'pkcs8' }), algorithm, false, ['sign']);
    const publicKey = await webcrypto.subtle.importKey('spki', pair.publicKey.export({ format: 'der', type: 'spki' }), algorithm, true, ['verify']);
    return { privateKey, publicKey };
  })();
  const signingKey = issuer
    ? await webcrypto.subtle.importKey('pkcs8', issuer.pair.privateKey.export({ format: 'der', type: 'pkcs8' }), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
    : keys.privateKey;
  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber: randomBytes(8).toString('hex').replace(/^[89a-f]/, '1'),
    subject,
    issuer: issuer ? issuer.subject : subject,
    notBefore: new Date('2020-01-01T00:00:00Z'),
    notAfter: new Date('2099-01-01T00:00:00Z'),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: keys.publicKey,
    signingKey,
    extensions,
  });
  return Buffer.from(certificate.rawData);
}

const aaguidOf = (hex) => Buffer.from(hex.padEnd(32, '0'), 'hex');

function registration({ key, credentialId = randomBytes(16), challenge, origin = ORIGIN, type = 'webauthn.create', flags = 0x45,
  aaguid = Buffer.alloc(16), fmt = 'none', attStmt = new Map(), rp = rpHash, counter = 0, trailing = Buffer.alloc(0),
  coseBytes, transports = ['internal'], extensions, id, rawId, credentialType = 'public-key', tokenBinding, clientExtra = {},
  attestation }) {
  const cose = coseBytes ?? encode(key.cose);
  const authData = Buffer.concat([
    rp, Buffer.from([flags]), u32(counter), aaguid, Buffer.from([credentialId.length >> 8, credentialId.length & 255]),
    credentialId, cose, extensions ? encode(extensions) : Buffer.alloc(0), trailing,
  ]);
  const client = { type, challenge, origin, ...clientExtra };
  if (tokenBinding !== undefined) client.tokenBinding = tokenBinding;
  const clientData = Buffer.from(JSON.stringify(client));
  const statement = typeof attStmt === 'function' ? attStmt({ authData, clientDataHash: createHash('sha256').update(clientData).digest(), credentialId, cose }) : attStmt;
  const object = attestation ?? encode(new Map([['fmt', fmt], ['attStmt', statement], ['authData', authData]]));
  const response = {
    id: id ?? b64url(credentialId),
    rawId: rawId ?? id ?? b64url(credentialId),
    type: credentialType,
    clientExtensionResults: {},
    response: { clientDataJSON: b64url(clientData), attestationObject: b64url(object) },
  };
  if (transports !== undefined) response.response.transports = transports;
  return response;
}

function assertion({ key, credentialId, challenge, origin = ORIGIN, type = 'webauthn.get', flags = 0x05, counter = 1, rp = rpHash,
  userHandle, tamper, signatureOverride, trailing = Buffer.alloc(0), extensions, tokenBinding }) {
  const authData = Buffer.concat([rp, Buffer.from([flags]), u32(counter), extensions ? encode(extensions) : Buffer.alloc(0), trailing]);
  const client = { type, challenge, origin };
  if (tokenBinding !== undefined) client.tokenBinding = tokenBinding;
  const clientData = Buffer.from(JSON.stringify(client));
  let signature = signatureOverride ?? key.sign(Buffer.concat([authData, createHash('sha256').update(clientData).digest()]));
  if (tamper) {
    signature = Buffer.from(signature);
    signature[signature.length - 1] ^= 1;
  }
  const response = {
    id: b64url(credentialId),
    rawId: b64url(credentialId),
    type: 'public-key',
    clientExtensionResults: {},
    response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(signature) },
  };
  if (userHandle !== undefined) response.response.userHandle = userHandle;
  return response;
}

const registrationOptions = (challenge) => ({
  expectedChallenge: challenge,
  expectedOrigin: [ORIGIN, 'https://acme.example.test'],
  expectedRPID: RP_ID,
  requireUserVerification: true,
});
const webauthn = [];
async function registrationCase(name, build) {
  const challenge = b64url(randomBytes(32));
  const response = await build(challenge);
  const options = registrationOptions(challenge);
  let result;
  try {
    const verified = await simple.verifyRegistrationResponse({ response, ...options });
    result = verified.verified
      ? {
          verified: true,
          info: {
            fmt: verified.registrationInfo.fmt,
            aaguid: verified.registrationInfo.aaguid,
            credentialID: verified.registrationInfo.credential.id,
            publicKey: b64url(verified.registrationInfo.credential.publicKey),
            counter: verified.registrationInfo.credential.counter,
            transports: verified.registrationInfo.credential.transports ?? null,
            userVerified: verified.registrationInfo.userVerified,
            deviceType: verified.registrationInfo.credentialDeviceType,
            backedUp: verified.registrationInfo.credentialBackedUp,
            origin: verified.registrationInfo.origin,
            rpID: verified.registrationInfo.rpID,
          },
        }
      : { verified: false };
  } catch (error) {
    result = { error: error.message };
  }
  webauthn.push({ kind: 'registration', name, response, options, result });
  return result;
}
async function authenticationCase(name, { key, credentialId, publicKey, counter = 0, ...rest }) {
  const challenge = b64url(randomBytes(32));
  const response = assertion({ key, credentialId, challenge, ...rest });
  const options = {
    expectedChallenge: challenge,
    expectedOrigin: [ORIGIN],
    expectedRPID: RP_ID,
    requireUserVerification: true,
    credential: { id: b64url(credentialId), publicKey, counter },
  };
  let result;
  try {
    const verified = await simple.verifyAuthenticationResponse({
      response,
      ...options,
      credential: { ...options.credential, publicKey: new Uint8Array(Buffer.from(publicKey, 'base64url')) },
    });
    result = {
      verified: verified.verified,
      info: {
        newCounter: verified.authenticationInfo.newCounter,
        userVerified: verified.authenticationInfo.userVerified,
        deviceType: verified.authenticationInfo.credentialDeviceType,
        backedUp: verified.authenticationInfo.credentialBackedUp,
        origin: verified.authenticationInfo.origin,
        rpID: verified.authenticationInfo.rpID,
      },
    };
  } catch (error) {
    result = { error: error.message };
  }
  webauthn.push({ kind: 'authentication', name, response, options, result });
}

for (const kind of ['ES256', 'EdDSA', 'RS256', 'PS256', 'ES512', 'ES384-35', 'RS1']) {
  const key = makeKey(kind);
  const credentialId = randomBytes(kind === 'RS256' ? 64 : 32);
  const result = await registrationCase(`none ${kind}`, (challenge) => registration({ key, credentialId, challenge }));
  if (!result.verified) continue;
  const publicKey = result.info.publicKey;
  await authenticationCase(`assert ${kind}`, { key, credentialId, publicKey });
  await authenticationCase(`assert ${kind} tampered`, { key, credentialId, publicKey, tamper: true });
  await authenticationCase(`assert ${kind} counter replay`, { key, credentialId, publicKey, counter: 5, ...{ counter: 5 } });
  await authenticationCase(`assert ${kind} counter grows`, { key, credentialId, publicKey, counter: 3, ...{} });
}
{
  const key = makeKey('ES256');
  const credentialId = randomBytes(32);
  const ok = await registrationCase('baseline', (challenge) => registration({ key, credentialId, challenge, transports: ['usb', 'nfc'] }));
  const publicKey = ok.info.publicKey;
  const variants = {
    'wrong origin': { origin: 'https://attacker.example' },
    'second origin': { origin: 'https://acme.example.test' },
    'wrong type': { type: 'webauthn.get' },
    'wrong rp': { rp: createHash('sha256').update('evil.example').digest() },
    'no user verification': { flags: 0x41 },
    'no user presence': { flags: 0x44 },
    'backup eligible': { flags: 0x4d },
    'backed up': { flags: 0x5d },
    'backed up without eligibility': { flags: 0x55 },
    'leftover bytes': { trailing: Buffer.from([0]) },
    'with extensions': { flags: 0xc5, extensions: new Map([['credProtect', 2]]) },
    'extension flag without data': { flags: 0xc5 },
    'non-minimal cose key': { coseBytes: Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(key.cose.get(-2)), Buffer.from([0x22, 0x58, 0x20]), Buffer.from(key.cose.get(-3))]).map((b, i) => (i === 3 ? 0x26 : b)) },
    'cose key with 2-byte int': { coseBytes: Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x19, 0x00, 0x01]), Buffer.from([0x21, 0x58, 0x20]), Buffer.from(key.cose.get(-2)), Buffer.from([0x22, 0x58, 0x20]), Buffer.from(key.cose.get(-3))]) },
    'unsupported alg': { key: { cose: new Map([[1, 2], [3, -35], [-1, 2], [-2, Buffer.alloc(48)], [-3, Buffer.alloc(48)]]) } },
    'alg missing': { key: { cose: new Map([[1, 2], [-1, 1], [-2, key.cose.get(-2)], [-3, key.cose.get(-3)]]) } },
    'token binding present': { tokenBinding: { status: 'present', id: 'x' } },
    'token binding bad status': { tokenBinding: { status: 'notSupported' } },
    'token binding string': { tokenBinding: 'yes' },
    'id mismatch': { id: 'abc', rawId: 'abd' },
    'missing id': { id: '', rawId: '' },
    'credential type': { credentialType: 'password' },
    'no transports': { transports: undefined },
    'odd transports': { transports: 'usb' },
    'aaguid': { aaguid: aaguidOf('adce000235bcc60a648b0b25f1f05503') },
    'none with statement': { attStmt: new Map([['x', 1]]) },
    'unknown format': { fmt: 'custom' },
    'challenge in extra field': { clientExtra: { crossOrigin: false } },
    'counter set': { counter: 7 },
    'garbage attestation': { attestation: Buffer.from([0x01, 0x02]) },
    'attestation array': { attestation: encode([1, 2]) },
  };
  for (const [name, variant] of Object.entries(variants))
    await registrationCase(name, (challenge) => registration({ key, credentialId, challenge, ...variant }));
  await registrationCase('wrong challenge', () => registration({ key, credentialId, challenge: 'not-the-challenge' }));
  const assertVariants = {
    'wrong origin': { origin: 'https://attacker.example' },
    'wrong type': { type: 'webauthn.create' },
    'wrong rp': { rp: createHash('sha256').update('evil.example').digest() },
    'no user verification': { flags: 0x01 },
    'no user presence': { flags: 0x04 },
    'backup flags': { flags: 0x1d },
    'bad backup flags': { flags: 0x15 },
    'leftover bytes': { trailing: Buffer.from([1, 2]) },
    'extensions': { flags: 0x85, extensions: new Map([['appid', true]]) },
    'zero counter': { counter: 0 },
    'user handle': { userHandle: 'dXNy' },
    'user handle number': { userHandle: 5 },
    'malformed signature': { signatureOverride: Buffer.from([0x30, 0x02, 0x01]) },
    'raw signature': { signatureOverride: Buffer.alloc(64, 1) },
    'token binding': { tokenBinding: { status: 'notSupported' } },
  };
  for (const [name, variant] of Object.entries(assertVariants))
    await authenticationCase(`assert ${name}`, { key, credentialId, publicKey, ...variant });
  // packed self attestation
  await registrationCase('packed self', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'packed',
      attStmt: ({ authData, clientDataHash }) => new Map([['alg', -7], ['sig', key.sign(Buffer.concat([authData, clientDataHash]))]]) }));
  await registrationCase('packed self bad signature', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'packed',
      attStmt: ({ authData }) => new Map([['alg', -7], ['sig', key.sign(authData)]]) }));
  await registrationCase('packed missing alg', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'packed', attStmt: () => new Map([['sig', Buffer.alloc(8)]]) }));
  await registrationCase('packed invalid alg', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'packed', attStmt: () => new Map([['alg', -999], ['sig', Buffer.alloc(8)]]) }));
  // packed full attestation with a self-made certificate (no metadata, no packed roots)
  const attestationKey = makeKey('ES256');
  const goodSubject = 'C=US, O=Example Vendor, OU=Authenticator Attestation, CN=Example Attestation';
  const aaguid = aaguidOf('0123456789abcdef0123456789abcdef');
  const extension = (oid, value) => new x509.Extension(oid, false, value);
  const fidoAaguid = (bytes) => extension('1.3.6.1.4.1.45724.1.1.4', Buffer.concat([Buffer.from([0x04, bytes.length]), bytes]));
  const certificates = {
    good: await selfSignedCertificate(attestationKey.pair, goodSubject, [new x509.BasicConstraintsExtension(false)]),
    aaguid: await selfSignedCertificate(attestationKey.pair, goodSubject, [fidoAaguid(aaguid)]),
    wrongAaguid: await selfSignedCertificate(attestationKey.pair, goodSubject, [fidoAaguid(Buffer.alloc(16, 7))]),
    ca: await selfSignedCertificate(attestationKey.pair, goodSubject, [new x509.BasicConstraintsExtension(true)]),
    noOU: await selfSignedCertificate(attestationKey.pair, 'C=US, O=Example Vendor, CN=Example'),
    badCountry: await selfSignedCertificate(attestationKey.pair, 'C=USA, O=Example Vendor, OU=Authenticator Attestation, CN=X'),
    u2f: await selfSignedCertificate(attestationKey.pair, 'CN=U2F Device'),
  };
  for (const [name, certificate] of Object.entries(certificates)) {
    await registrationCase(`packed full ${name}`, (challenge) =>
      registration({ key, credentialId: randomBytes(32), challenge, fmt: 'packed', aaguid,
        attStmt: ({ authData, clientDataHash }) => new Map([['alg', -7], ['sig', attestationKey.sign(Buffer.concat([authData, clientDataHash]))], ['x5c', [certificate]]]) }));
  }
  const u2fBase = ({ authData, clientDataHash, credentialId: id, signWith = attestationKey }) => {
    const x = key.cose.get(-2);
    const y = key.cose.get(-3);
    return signWith.sign(Buffer.concat([Buffer.from([0]), rpHash, clientDataHash, id, Buffer.from([4]), x, y]));
  };
  await registrationCase('fido-u2f', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'fido-u2f', flags: 0x41,
      attStmt: (data) => new Map([['sig', u2fBase(data)], ['x5c', [certificates.u2f]]]) }));
  await registrationCase('fido-u2f with uv', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'fido-u2f',
      attStmt: (data) => new Map([['sig', u2fBase(data)], ['x5c', [certificates.u2f]]]) }));
  await registrationCase('fido-u2f nonzero aaguid', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'fido-u2f', aaguid,
      attStmt: (data) => new Map([['sig', u2fBase(data)], ['x5c', [certificates.u2f]]]) }));
  await registrationCase('fido-u2f no x5c', (challenge) =>
    registration({ key, credentialId: randomBytes(32), challenge, fmt: 'fido-u2f', attStmt: (data) => new Map([['sig', u2fBase(data)]]) }));
  for (const fmt of ['apple', 'android-key', 'android-safetynet', 'tpm']) {
    await registrationCase(`${fmt} empty statement`, (challenge) => registration({ key, credentialId: randomBytes(32), challenge, fmt }));
    await registrationCase(`${fmt} self-made certificate`, (challenge) =>
      registration({ key, credentialId: randomBytes(32), challenge, fmt,
        attStmt: ({ authData, clientDataHash }) => new Map([['alg', -7], ['ver', '2.0'], ['sig', attestationKey.sign(Buffer.concat([authData, clientDataHash]))], ['x5c', [certificates.good]], ['response', Buffer.from('a.b.c')]]) }));
  }
}

// --- options shapes --------------------------------------------------------------------------------------------------

const registrationShape = await simple.generateRegistrationOptions({
  rpID: RP_ID,
  rpName: 'Better IAM',
  userName: 'ada@example.com',
  userID: new TextEncoder().encode('usr_123'),
  userDisplayName: 'Ada',
  attestationType: 'none',
  excludeCredentials: [{ id: 'AAAA', transports: ['usb'] }, { id: 'BBBB', transports: undefined }, { id: 'CC==' }],
  authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
});
const authenticationShape = await simple.generateAuthenticationOptions({
  rpID: RP_ID,
  userVerification: 'required',
  allowCredentials: [{ id: 'AAAA', transports: ['internal'] }, { id: 'BBBB' }],
});
const discoveryShape = await simple.generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'required' });

process.stdout.write(
  JSON.stringify({
    templates,
    validators,
    passwords,
    rules,
    describeUserAgent,
    publicAddresses,
    fetchUrls,
    jsNumbers,
    jsDates,
    encodeURIs,
    base64,
    cbor,
    webauthn,
    shapes: { registration: registrationShape, authentication: authenticationShape, discovery: discoveryShape },
  }, (key, value) => (value instanceof Uint8Array ? Buffer.from(value).toString('base64url') : value)),
);
