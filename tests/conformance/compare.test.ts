import { describe, expect, it } from 'vitest';
// @ts-expect-error plain ESM helpers of the conformance harness
import {
  Bindings,
  compareValues,
  shape,
  substitute,
} from '../../scripts/conformance/lib/compare.mjs';
// @ts-expect-error plain ESM helpers of the conformance harness
import {
  configFromOptions,
  isEchoResolver,
  optionsFromConfig,
} from '../../scripts/conformance/lib/config.mjs';
// @ts-expect-error plain ESM helpers of the conformance harness
import { decodeValue, encodeValue, errorShape } from '../../scripts/conformance/lib/encode.mjs';
// @ts-expect-error plain ESM helpers of the conformance harness
import { totp } from '../../scripts/conformance/lib/totp.mjs';

const compare = (recorded: unknown, actual: unknown, bindings = new Bindings(), context = {}) =>
  compareValues(recorded, actual, bindings, { maxDiffs: 10, ...context }, '$', '', []);

describe('conformance replay comparison', () => {
  it('binds generated values by position and substitutes them into later inputs', () => {
    const bindings = new Bindings();
    const recorded = {
      id: '11111111-2222-4333-8444-555555555555',
      token: 'biam_ses_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1234AB',
      owner: 'usr_abcdefghijklmnopqrstuv',
      name: 'Acme',
    };
    const actual = {
      id: '99999999-8888-4777-8666-555555555555',
      token: 'biam_ses_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9876ZY',
      owner: 'usr_zyxwvutsrqponmlkjihgfe',
      name: 'Acme',
    };
    expect(compare(recorded, actual, bindings)).toEqual([]);
    expect(
      substitute(
        {
          tenantId: recorded.id,
          header: `Bearer ${recorded.token}`,
          path: `/x/${recorded.owner}/y`,
        },
        bindings,
      ),
    ).toEqual({
      tenantId: actual.id,
      header: `Bearer ${actual.token}`,
      path: `/x/${actual.owner}/y`,
    });
    // A bound value must come back as its binding.
    expect(
      compare({ again: recorded.id }, { again: '00000000-0000-4000-8000-000000000000' }, bindings),
    ).toHaveLength(1);
  });

  it('reports stable differences, missing members and status codes', () => {
    expect(
      compare({ name: 'Acme', status: 'active' }, { name: 'Acme', status: 'pending' }),
    ).toMatchObject([{ path: '$.status', problem: 'value differs' }]);
    expect(compare({ a: 1, b: 2 }, { a: 1 })).toMatchObject([{ path: '$.b', problem: 'missing' }]);
    expect(compare({ a: 1 }, { a: 1, c: 3 })).toMatchObject([
      { path: '$.c', problem: 'unexpected member' },
    ]);
    expect(compare([1, 2], [1, 2, 3])).toMatchObject([{ problem: 'length 2 != 3' }]);
    // Words, paths and action names are not generated tokens.
    expect(
      shape('documents:read-write /api/iam/oauth2/authorize organizationAdministrator').tokens,
    ).toEqual([]);
  });

  it('matches lists that come back in another order', () => {
    const recorded = [
      { id: 'aaaaaaaa-0000-4000-8000-000000000001', name: 'Reader' },
      { id: 'aaaaaaaa-0000-4000-8000-000000000002', name: 'Writer' },
    ];
    const actual = [
      { id: 'bbbbbbbb-0000-4000-8000-000000000002', name: 'Writer' },
      { id: 'bbbbbbbb-0000-4000-8000-000000000001', name: 'Reader' },
    ];
    const bindings = new Bindings();
    expect(compare(recorded, actual, bindings)).toEqual([]);
    expect(bindings.get(recorded[0]!.id)).toBe(actual[1]!.id);
    // Audit events of one operation interleaved differently: same events, same set of sequence numbers.
    const event = (id: string, resourceId: string, sequence: number, hash: string) => ({
      id,
      resourceId,
      sequence,
      hash: hash.repeat(64),
      previousHash: 'f'.repeat(64),
    });
    expect(
      compare(
        [event('e1', 'r1', 1, 'a'), event('e2', 'r2', 2, 'b')],
        [event('e2', 'r2', 1, 'c'), event('e1', 'r1', 2, 'd')],
      ),
    ).toEqual([]);
  });

  it('compares instants by where they came from', () => {
    const at = 1_800_000_000_000;
    const controlled = { clockControlled: true, stepAt: at, wallReplayed: true };
    // From the injected clock (whole seconds away from it): exact.
    expect(
      compare(
        { expiresAt: at + 3_600_000 },
        { expiresAt: at + 3_600_000 },
        new Bindings(),
        controlled,
      ),
    ).toEqual([]);
    expect(
      compare(
        { expiresAt: at + 3_600_000 },
        { expiresAt: at + 3_601_000 },
        new Bindings(),
        controlled,
      ),
    ).toHaveLength(1);
    // From the wall clock: within the tolerance, and bound for later inputs.
    const bindings = new Bindings();
    expect(
      compare({ timestamp: at + 17 }, { timestamp: at + 2_345 }, bindings, controlled),
    ).toEqual([]);
    expect(substitute({ until: at + 17 }, bindings)).toEqual({ until: at + 2_345 });
    expect(
      compare({ timestamp: at + 17 }, { timestamp: at + 600_017 }, new Bindings(), controlled),
    ).toHaveLength(1);
    expect(
      compare(
        'at 2026-10-19T09:06:41.583Z',
        'at 2026-10-19T09:06:43.002Z',
        new Bindings(),
        controlled,
      ),
    ).toEqual([]);
  });

  it('pairs list elements by the values both runs agree on, and keeps unchanged tokens bound to themselves', () => {
    const bindings = new Bindings();
    const recorded = [
      { id: '11111111-2222-4333-8444-000000000001', jti: 'aaaaaaaa-2222-4333-8444-555555555555' },
      { id: '11111111-2222-4333-8444-000000000002', jti: 'bbbbbbbb-2222-4333-8444-555555555555' },
    ];
    // Same shape, other order: the right partner shares the test's own jti.
    const actual = [
      { id: '99999999-2222-4333-8444-000000000002', jti: 'bbbbbbbb-2222-4333-8444-555555555555' },
      { id: '99999999-2222-4333-8444-000000000001', jti: 'aaaaaaaa-2222-4333-8444-555555555555' },
    ];
    expect(compare(recorded, actual, bindings)).toEqual([]);
    expect(bindings.get('11111111-2222-4333-8444-000000000001')).toBe(
      '99999999-2222-4333-8444-000000000001',
    );
    expect(bindings.get('aaaaaaaa-2222-4333-8444-555555555555')).toBe(
      'aaaaaaaa-2222-4333-8444-555555555555',
    );
    // A token that came back unchanged cannot later be paired with another value.
    expect(
      compare(
        { jti: 'aaaaaaaa-2222-4333-8444-555555555555' },
        { jti: 'cccccccc-2222-4333-8444-555555555555' },
        bindings,
      ),
    ).toHaveLength(1);
  });

  it('binds format-preserving tokens, generated passwords and epoch-second strings', () => {
    expect(compare({ tokens: ['902-26-6789'] }, { tokens: ['925-10-6789'] })).toEqual([]);
    expect(
      compare({ tokens: ['Atzz Vxfrdb ZLCU-6178'] }, { tokens: ['Xdna Wcixef DMDJ-8447'] }),
    ).toEqual([]);
    expect(
      compare({ tokens: ['Atzz Vxfrdb ZLCU-6178'] }, { tokens: ['Xdna Wcixef DMD-J8447'] }),
    ).toHaveLength(1);
    expect(
      compare({ value: 'lh]rswfE|7_wWyh(jL>~-ITx' }, { value: '.ns0<+1gveQS2F|:U~dN?,=!' }),
    ).toEqual([]);
    expect(
      compare({ name: 'lh]rswfE|7_wWyh(jL>~-ITx' }, { name: '.ns0<+1gveQS2F|:U~dN?,=!' }),
    ).toHaveLength(1);
    expect(
      compare(
        { 'x-better-iam-timestamp': '1792404969' },
        { 'x-better-iam-timestamp': '1792404972' },
        new Bindings(),
        { wallReplayed: true },
      ),
    ).toEqual([]);
  });

  it('remembers a record only from the pairing that matched', () => {
    const bindings = new Bindings();
    const recorded = [
      { id: '11111111-2222-4333-8444-000000000001', name: 'a', sequence: 1 },
      { id: '11111111-2222-4333-8444-000000000002', name: 'b', sequence: 2 },
    ];
    const actual = [
      { id: '99999999-2222-4333-8444-000000000002', name: 'b', sequence: 2 },
      { id: '99999999-2222-4333-8444-000000000001', name: 'a', sequence: 1 },
    ];
    expect(compare(recorded, actual, bindings)).toEqual([]);
    expect(substitute({ ...recorded[1], name: 'changed' }, bindings, {})).toEqual({
      id: '99999999-2222-4333-8444-000000000002',
      name: 'changed',
      sequence: 2,
    });
  });

  it('honors tolerated paths during matching', () => {
    const ignore = [/^\$\.data\[\*\]\.value$/];
    expect(
      compare(
        { data: [{ key: 'k', value: true }] },
        { data: [{ key: 'k', value: false }] },
        new Bindings(),
        { ignore },
      ),
    ).toEqual([]);
  });
});

describe('conformance helpers', () => {
  it('computes RFC 6238 codes', () => {
    // RFC 6238 appendix B, SHA-1, T = 59 s, secret "12345678901234567890" (base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).
    expect(totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59_000, { digits: 8 })).toBe('94287082');
  });

  it('round-trips the tagged encoding and shapes errors', () => {
    const value = {
      bytes: new Uint8Array([1, 2, 3]),
      when: new Date(0),
      list: [undefined, 1n],
      map: new Map([['a', 1]]),
    };
    const decoded = decodeValue(JSON.parse(JSON.stringify(encodeValue(value))));
    expect(decoded.bytes).toEqual(new Uint8Array([1, 2, 3]));
    expect(decoded.when).toEqual(new Date(0));
    expect(decoded.list).toEqual([undefined, 1n]);
    expect(decoded.map).toEqual(new Map([['a', 1]]));
    expect(errorShape(new TypeError('x'))).toMatchObject({ code: 'INTERNAL_ERROR', status: 500 });
  });

  it('describes options as better-iam.json and reads it back', async () => {
    const options = {
      database: {},
      secret: 'a-secret-with-at-least-32-characters-ok',
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read'] },
      authentication: { sendEmail: async () => {}, now: () => 1, sessionLifetimeMs: 1000 },
      events: { onEvent: () => {}, webhookTimeoutMs: 2000 },
      resolveResource: async (reference: unknown) => reference,
    };
    const described = configFromOptions(options);
    expect(described).toMatchObject({ reasons: [], clock: true });
    expect(described.config).toEqual({
      store: { kind: 'sqlite', path: ':memory:' },
      secret: options.secret,
      baseURL: options.baseURL,
      permissions: { actions: ['documents:read'] },
      authentication: { sessionLifetimeMs: 1000 },
      delivery: { email: { kind: 'capture' }, events: { kind: 'capture' } },
      events: { webhookTimeoutMs: 2000 },
      resolveResource: { kind: 'echo' },
    });
    expect(configFromOptions({ ...options, plugins: [{ id: 'p' }] }).reasons).toContain(
      'options.plugins is set',
    );
    expect(isEchoResolver(async (ref: unknown) => ({ ...(ref as object), extra: 1 }))).toBe(false);
    const delivered: unknown[] = [];
    const rebuilt = await optionsFromConfig(described.config, {
      adapters: { sqliteAdapter: (input: unknown) => ({ input }) },
      now: () => 42,
      deliver: async (kind: string, message: unknown) => void delivered.push({ kind, message }),
    });
    expect(rebuilt.database).toEqual({ input: { filename: ':memory:' } });
    expect(rebuilt.authentication.now()).toBe(42);
    await rebuilt.authentication.sendEmail({ id: 'm' });
    await rebuilt.events.onEvent({ id: 'e' });
    expect(delivered).toEqual([
      { kind: 'email', message: { id: 'm' } },
      { kind: 'events', message: { id: 'e' } },
    ]);
    await expect(
      optionsFromConfig({ ...described.config, nope: 1 }, { adapters: {} }),
    ).rejects.toMatchObject({
      code: 'INVALID_CONFIG',
    });
  });

  it('writes application callbacks as scripted ones and refuses them outside conformance mode', async () => {
    const options = {
      database: {},
      secret: 'a-secret-with-at-least-32-characters-ok',
      baseURL: 'http://localhost:3000',
      resolveResource: async (reference: { id: string }) => ({ ...reference, tenantId: 't' }),
      resolveContext: async () => ({}),
      authentication: { requireMfa: () => true },
      domains: { resolveTxt: async () => [['x']], recordName: '_iam' },
      http: { clientInfo: () => ({ ip: '192.0.2.1' }) },
    };
    const described = configFromOptions(options);
    expect(described.scripted.sort()).toEqual([
      'authentication.requireMfa',
      'domains.resolveTxt',
      'resolveContext',
      'resolveResource',
    ]);
    expect(described.reasons).toEqual(['options.http.clientInfo is a function']);
    // A clientInfo that only copies request headers has a JSON form.
    expect(
      configFromOptions({
        ...options,
        http: {
          clientInfo: (request: Request) => ({
            ip: request.headers.get('x-real-ip') ?? undefined,
            userAgent: request.headers.get('user-agent') ?? undefined,
          }),
        },
      }).config.http,
    ).toEqual({ clientInfo: { userAgent: true, ipHeader: 'x-real-ip', ipValue: 'whole' } });
    expect(described.config.domains).toEqual({
      resolveTxt: { $scripted: true },
      recordName: '_iam',
    });
    const { http: _http, ...config } = described.config;
    const calls: string[] = [];
    const rebuilt = await optionsFromConfig(config, {
      adapters: { sqliteAdapter: () => ({}) },
      scripted: (path: string) => () => calls.push(path),
    });
    rebuilt.authentication.requireMfa();
    rebuilt.domains.resolveTxt();
    expect(calls).toEqual(['authentication.requireMfa', 'domains.resolveTxt']);
    await expect(
      optionsFromConfig(config, { adapters: { sqliteAdapter: () => ({}) } }),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
    await expect(
      optionsFromConfig(
        { ...config, hierarchy: { $scripted: true } },
        { adapters: { sqliteAdapter: () => ({}) }, scripted: () => () => {} },
      ),
    ).rejects.toMatchObject({ message: 'Invalid better-iam.json: hierarchy cannot be scripted' });
  });
});
