import { Readable } from 'node:stream';
import type { GetServerSidePropsContext, NextApiRequest, NextApiResponse } from 'next';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createIamNext } from '@better-iam/next';
import type { IamStore } from '@better-iam/core';
import { createRequire } from 'node:module';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const iam = betterIam({
    database,
    secret: 'next-pages-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    permissions: { actions: ['documents:read'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const rootSession = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  await iam.api.identities.create(
    { token: rootSession.token },
    {
      tenantId: root.tenant.id,
      email: 'member@example.test',
      name: 'Member',
      password: 'a strong member test password',
    },
  );
  const login = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'member@example.test',
    password: 'a strong member test password',
  });
  if (!('token' in login)) throw new Error('Unexpected MFA');
  return {
    iam,
    tenantId: root.tenant.id,
    cookie: `better-iam.session=${login.token}`,
    rootToken: rootSession.token,
  };
}

/** A NextApiResponse stand-in that records what the handler wrote. */
function response() {
  const headers = new Map<string, number | string | string[]>();
  const state = { status: 200, body: undefined as unknown, ended: false };
  const res = {
    headersSent: false,
    get writableEnded() {
      return state.ended;
    },
    get statusCode() {
      return state.status;
    },
    set statusCode(value: number) {
      state.status = value;
    },
    getHeader: (name: string) => headers.get(name.toLowerCase()),
    setHeader(name: string, value: number | string | string[]) {
      headers.set(name.toLowerCase(), value);
      return res;
    },
    status(code: number) {
      state.status = code;
      return res;
    },
    json(body: unknown) {
      state.body = body;
      state.ended = true;
      return res;
    },
    end(body?: unknown) {
      if (body !== undefined) state.body = body;
      state.ended = true;
      return res;
    },
  };
  return { res: res as unknown as NextApiResponse, headers, state };
}
function request(
  input: { headers?: Record<string, string>; method?: string; url?: string; body?: unknown } = {},
  stream?: string,
): NextApiRequest {
  const base = stream === undefined ? Readable.from([]) : Readable.from([Buffer.from(stream)]);
  return Object.assign(base, {
    headers: input.headers ?? {},
    method: input.method ?? 'GET',
    url: input.url ?? '/',
    body: input.body,
    query: {},
    cookies: {},
  }) as unknown as NextApiRequest;
}
function context(
  headers: Record<string, string>,
  params: Record<string, string> = {},
): GetServerSidePropsContext {
  return {
    req: { headers },
    res: {},
    params,
    query: {},
    resolvedUrl: '/documents/a?tab=1',
  } as unknown as GetServerSidePropsContext;
}

describe('Next.js Pages Router helpers', () => {
  it('guards getServerSideProps with redirects, notFound, and serialized sessions', async () => {
    const f = await fixture();
    const iamNext = createIamNext(f.iam, { loginPath: '/signin' });
    const gssp = iamNext.pages.withSession(
      async (_context, { session }) => ({ props: { greeting: `hi ${session.identity.name}` } }),
      {
        authorize: {
          action: 'documents:read',
          resource: ({ params }) => ({ type: 'document', id: String(params.id) }),
        },
      },
    );
    expect(await gssp(context({}, { id: 'a' }))).toEqual({
      redirect: { destination: '/signin?next=%2Fdocuments%2Fa%3Ftab%3D1', permanent: false },
    });
    expect(await gssp(context({ cookie: f.cookie }, { id: 'a' }))).toEqual({ notFound: true });
    const allowed = await gssp(context({ authorization: `Bearer ${f.rootToken}` }, { id: 'a' }));
    if (!('props' in allowed)) throw new Error('Expected props');
    const props = await allowed.props;
    expect(props.greeting).toBe('hi Root');
    expect(props.session.identity.name).toBe('Root');
    expectTypeOf(props.session.identity.id).toEqualTypeOf<string>();

    const redirecting = iamNext.pages.withSession(undefined, {
      authorize: { action: 'documents:read', redirectTo: '/forbidden' },
    });
    expect(await redirecting(context({ cookie: f.cookie }))).toEqual({
      redirect: { destination: '/forbidden', permanent: false },
    });
    const passthrough = iamNext.pages.withSession(async () => ({ notFound: true as const }));
    expect(await passthrough(context({ cookie: f.cookie }))).toEqual({ notFound: true });
    const bare = await iamNext.pages.withSession()(context({ cookie: f.cookie }));
    expect('props' in bare && (await bare.props).session.identity.name).toBe('Member');
    expect((await iamNext.pages.getSession({ headers: { cookie: f.cookie } }))?.identity.name).toBe(
      'Member',
    );
  });

  it('wraps API routes, binds a cookie-writing client, and serves the IAM handler', async () => {
    const f = await fixture();
    const iamNext = createIamNext(f.iam);
    const route = iamNext.pages.api(
      async (req, _res, { session }) => ({ id: req.query.id ?? null, who: session.identity.name }),
      { authorize: { action: 'documents:read' } },
    );
    let out = response();
    await route(request(), out.res);
    expect(out.state).toMatchObject({ status: 401, body: { error: { code: 'UNAUTHENTICATED' } } });
    out = response();
    await route(request({ headers: { cookie: f.cookie } }), out.res);
    expect(out.state).toMatchObject({ status: 403, body: { error: { code: 'ACCESS_DENIED' } } });
    out = response();
    await route(request({ headers: { authorization: `Bearer ${f.rootToken}` } }), out.res);
    expect(out.state).toMatchObject({ status: 200, body: { who: 'Root' } });
    expect(out.headers.get('cache-control')).toBe('no-store');

    out = response();
    out.res.setHeader('set-cookie', 'theme=dark; Path=/');
    await iamNext.pages.client(request(), out.res).auth.signIn({
      tenantId: f.tenantId,
      email: 'member@example.test',
      password: 'a strong member test password',
    });
    const cookies = out.headers.get('set-cookie') as string[];
    expect(cookies[0]).toBe('theme=dark; Path=/');
    expect(cookies[1]).toMatch(
      /^better-iam\.session=[^;]+; HttpOnly; SameSite=Lax; Path=\/; Max-Age=\d+$/,
    );

    const handler = iamNext.pages.handler();
    const headers = {
      host: 'localhost:3000',
      'content-type': 'application/json',
      'x-better-iam': '1',
      origin: 'http://localhost:3000',
      cookie: f.cookie,
    };
    for (const [label, req] of [
      ['parsed', request({ headers, method: 'POST', url: '/api/iam/auth/getSession', body: {} })],
      ['stream', request({ headers, method: 'POST', url: '/api/iam/auth/getSession' }, '{}')],
    ] as const) {
      out = response();
      await handler(req, out.res);
      expect(out.state.status, label).toBe(200);
      const body = JSON.parse(Buffer.from(out.state.body as Uint8Array).toString('utf8'));
      expect(body.data.identity.name, label).toBe('Member');
    }
    out = response();
    await handler(
      request({
        headers,
        method: 'POST',
        url: '/api/iam/auth/signIn',
        body: {
          tenantId: f.tenantId,
          email: 'member@example.test',
          password: 'a strong member test password',
        },
      }),
      out.res,
    );
    expect(out.state.status).toBe(200);
    expect((out.headers.get('set-cookie') as string[])[0]).toMatch(/^better-iam\.session=/);
  });
});
