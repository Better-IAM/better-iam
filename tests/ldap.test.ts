import { connect } from 'node:net';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import {
  OID,
  ResultCode,
  createLdapServer,
  decodeResponse,
  encodeBind,
  encodeCompare,
  encodeExtended,
  encodeSearch,
  escapeDnValue,
  isUnder,
  matchFilter,
  normalizeDn,
  pagedResultsRequest,
  parseFilter,
  readElement,
  type LdapResponse,
} from '@better-iam/ldap';
import { closeFixtures, organizationFixture, type OrganizationFixture } from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))('otplib');

const servers: { close(): Promise<void> }[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await closeFixtures();
});

const BASE = 'dc=acme,dc=test';
/** Final answers: bind, search done, modify, add, delete, modify DN, compare, extended. */
const DONE = new Set([0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78]);

/** A minimal LDAP client over TCP: one call at a time, answers collected by message ID. */
async function ldapClient(port: number) {
  const socket = connect(port, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('error', reject);
  });
  let buffer = Buffer.alloc(0);
  let closed = false;
  const received: LdapResponse[] = [];
  const waiters: (() => void)[] = [];
  const wake = () => waiters.splice(0).forEach((resolve) => resolve());
  socket.on('data', (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const item = readElement(buffer, 0, 1 << 24);
      if (!item) break;
      buffer = buffer.subarray(item.size);
      received.push(decodeResponse(item));
    }
    wake();
  });
  socket.on('close', () => {
    closed = true;
    wake();
  });
  let next = 1;
  async function call(encode: (id: number) => Buffer) {
    const id = next++;
    const request = encode(id);
    socket.write(request);
    const deadline = Date.now() + 5000;
    for (;;) {
      if (Date.now() > deadline) throw new Error(`No answer to request ${id} (${request.subarray(0, 12).toString('hex')})`);
      const done = received.find((response) => response.id === id && DONE.has(response.tag));
      if (done) {
        const entries = received.filter((response) => response.id === id && response.tag === 0x64);
        return { ...done, entries };
      }
      if (closed) throw new Error(`Connection closed: ${received.find((response) => response.id === 0)?.message}`);
      await new Promise<void>((resolve) => {
        waiters.push(resolve);
        setTimeout(resolve, 500);
      });
    }
  }
  return {
    bind: (name: string, password: string) => call((id) => encodeBind(id, name, password)),
    search: (base: string, filter: string, options: { scope?: 'base' | 'one' | 'sub'; attributes?: string[] } = {}, controls?: Buffer) =>
      call((id) => encodeSearch(id, { base, filter: parseFilter(filter), ...options }, controls)),
    compare: (entry: string, attribute: string, value: string) => call((id) => encodeCompare(id, entry, attribute, value)),
    whoAmI: () => call((id) => encodeExtended(id, OID.whoAmI)),
    /** A delete request (`[APPLICATION 10]`), which a read-only directory refuses. */
    remove: (dn: string) =>
      call((id) => {
        const name = Buffer.from(dn);
        const body = Buffer.concat([Buffer.from([0x02, 0x01, id, 0x4a, name.length]), name]);
        return Buffer.concat([Buffer.from([0x30, body.length]), body]);
      }),
    close: () => new Promise<void>((resolve) => socket.end(resolve)),
  };
}

function totp(f: OrganizationFixture, secret: string): string {
  const generator = authenticator.clone();
  generator.options = { epoch: f.now() };
  return generator.generate(secret) as string;
}

/** Acme publishing its directory under dc=acme,dc=test, with a directory reader service account and a gateway. */
async function setup() {
  const f = await organizationFixture();
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  const engineering = await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Engineering' });
  await f.iam.api.groups.addMembers(f.ownerCredential, {
    tenantId: f.tenantId,
    groupId: engineering.id,
    identityIds: [alice.id],
  });
  const reader = await f.iam.api.serviceAccounts.create(f.ownerCredential, { tenantId: f.tenantId, name: 'vpn' });
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Directory readers',
    document: { version: 1, statements: [{ effect: 'allow', actions: ['iam:ldap:read'], resources: ['*'] }] },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: reader.id,
  });
  const key = await f.iam.api.credentials.create(f.ownerCredential, { tenantId: f.tenantId, identityId: reader.id });
  const settings = await f.iam.api.ldap.updateSettings(f.ownerCredential, {
    tenantId: f.tenantId,
    enabled: true,
    baseDn: 'dc=acme, dc=test',
    includeServiceAccounts: true,
  });
  const gateway = createLdapServer({ iam: f.iam, cacheMs: 0 });
  servers.push(gateway);
  const { port } = await gateway.listen(0);
  return { f, alice, bob, engineering, key, settings, port };
}

describe('LDAP primitives', () => {
  it('normalizes and escapes DNs and matches filters', () => {
    expect(normalizeDn('UID=Alice,  OU=People , DC=Acme,DC=Test')).toBe('uid=alice,ou=people,dc=acme,dc=test');
    expect(escapeDnValue('Smith, John+1')).toBe('Smith\\, John\\+1');
    expect(isUnder('uid=a,ou=people,dc=acme,dc=test', 'dc=acme,dc=test')).toBe(true);
    expect(isUnder('dc=acme,dc=test', 'ou=people,dc=acme,dc=test')).toBe(false);
    const entry = new Map([
      ['objectclass', ['top', 'inetOrgPerson']],
      ['mail', ['alice@acme.test']],
      ['cn', ['Alice Liddell']],
    ]);
    expect(matchFilter(parseFilter('(&(objectClass=inetOrgPerson)(mail=ALICE@acme.test))'), entry)).toBe(true);
    expect(matchFilter(parseFilter('(|(cn=Bob*)(!(mail=*)))'), entry)).toBe(false);
    expect(matchFilter(parseFilter('(cn=*Lid*)'), entry)).toBe(true);
    expect(matchFilter(parseFilter('(title=*)'), entry)).toBe(false);
    expect(() => parseFilter('(cn=unbalanced')).toThrow();
  });
});

describe('LDAP directory gateway', () => {
  it('lets people and service accounts bind, and serves the directory each may read', async () => {
    const { f, settings, port, key } = await setup();
    expect(settings).toMatchObject({ enabled: true, baseDn: 'dc=acme,dc=test', uid: 'email', attributes: [] });
    const client = await ldapClient(port);

    // Before a bind: the root DSE only.
    const dse = await client.search('', '(objectClass=*)', { scope: 'base' });
    expect(dse.entries[0]!.attributes).toMatchObject({ supportedLDAPVersion: ['3'] });
    expect((await client.search(BASE, '(objectClass=*)')).code).toBe(ResultCode.insufficientAccessRights);

    // People bind with their password, under the uid the organization chose.
    const alice = `uid=alice@acme.test,ou=people,${BASE}`;
    expect((await client.bind(alice, 'wrong password')).code).toBe(ResultCode.invalidCredentials);
    expect((await client.bind(alice, '')).code).toBe(ResultCode.unwillingToPerform);
    expect((await client.bind(`uid=nobody@acme.test,ou=people,${BASE}`, 'x')).code).toBe(ResultCode.invalidCredentials);
    // DNs compare without regard to case.
    expect((await client.bind(alice.toUpperCase(), 'a strong alice password')).code).toBe(ResultCode.success);
    expect((await client.whoAmI()).responseValue?.toString()).toBe(`dn:${alice.toUpperCase()}`);

    // Without iam:ldap:read a person sees only their own entry, and their groups with only them in it.
    const own = await client.search(BASE, '(|(objectClass=inetOrgPerson)(objectClass=groupOfNames))');
    expect(own.code).toBe(ResultCode.success);
    expect(own.entries.map((entry) => entry.dn).sort()).toEqual([`cn=Engineering,ou=groups,${BASE}`, alice].sort());
    expect(own.entries.find((entry) => entry.dn === alice)!.attributes).toMatchObject({
      mail: ['alice@acme.test'],
      memberOf: [`cn=Engineering,ou=groups,${BASE}`],
    });
    expect((await client.compare(alice, 'mail', 'alice@acme.test')).code).toBe(ResultCode.compareTrue);
    expect((await client.compare(alice, 'mail', 'bob@acme.test')).code).toBe(ResultCode.compareFalse);
    // The directory is read-only, and other trees do not exist for this binding.
    expect((await client.remove(alice)).code).toBe(ResultCode.unwillingToPerform);
    expect((await client.search('dc=other,dc=test', '(objectClass=*)')).code).toBe(ResultCode.noSuchObject);

    // A service account binds with an API key; with iam:ldap:read it reads the whole published directory.
    expect((await client.bind(`cn=vpn,ou=services,${BASE}`, key.token)).code).toBe(ResultCode.success);
    const people = await client.search(`ou=people,${BASE}`, '(objectClass=inetOrgPerson)', {
      scope: 'one',
      attributes: ['mail', 'memberOf'],
    });
    expect(people.entries.map((entry) => entry.attributes!.mail![0]).sort()).toEqual([
      'alice@acme.test',
      'bob@acme.test',
      'owner@acme.test',
    ]);
    const group = await client.search(`cn=Engineering,ou=groups,${BASE}`, '(objectClass=*)', { scope: 'base' });
    expect(group.entries[0]!.attributes!.member).toEqual([alice]);
    const services = await client.search(`ou=services,${BASE}`, '(cn=vpn)', { scope: 'one' });
    expect(services.entries).toHaveLength(1);

    // Paged results (RFC 2696) walk the people one page at a time.
    const seen: string[] = [];
    let cookie = Buffer.alloc(0);
    do {
      const page = await client.search(`ou=people,${BASE}`, '(objectClass=inetOrgPerson)', { scope: 'one' }, pagedResultsRequest(2, cookie));
      seen.push(...page.entries.map((entry) => entry.dn!));
      const control = page.controls?.find((item) => item.type === OID.pagedResults);
      const [, next] = readPaged(control!.value!);
      cookie = next;
    } while (cookie.length);
    expect(seen).toHaveLength(3);

    const reads = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId, action: 'ldap:directory:read' });
    const events = (Array.isArray(reads) ? reads : (reads as { events: typeof reads }).events) as unknown[];
    expect(events.length).toBeGreaterThan(0);
    await client.close();
  });

  it('takes the one-time code after the password from people who use MFA, and stops when turned off', async () => {
    const { f, port } = await setup();
    const first = await f.signIn('bob');
    const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
    await f.iam.api.auth.confirmMfa({ credential: { token: first.token }, code: totp(f, enrollment.secret) });
    f.advance(30_000);
    const client = await ldapClient(port);
    const bob = `uid=bob@acme.test,ou=people,${BASE}`;
    expect((await client.bind(bob, 'a strong bob password')).code).toBe(ResultCode.invalidCredentials);
    expect((await client.bind(bob, `a strong bob password${totp(f, enrollment.secret)}`)).code).toBe(ResultCode.success);

    // Only declared identity attributes can be published.
    await expect(
      f.iam.api.ldap.updateSettings(f.ownerCredential, { tenantId: f.tenantId, attributes: ['salary'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    await f.iam.api.ldap.updateSettings(f.ownerCredential, { tenantId: f.tenantId, enabled: false });
    expect((await client.bind(`uid=alice@acme.test,ou=people,${BASE}`, 'a strong alice password')).code).toBe(
      ResultCode.invalidCredentials,
    );
    await client.close();
  });
});

/** The size and cookie of a paged results response control value. */
function readPaged(value: Buffer): [number, Buffer] {
  const outer = readElement(value, 0, value.length)!;
  const size = readElement(outer.value, 0, outer.value.length)!;
  const cookie = readElement(outer.value, size.size, outer.value.length)!;
  return [size.value.readUIntBE(0, size.value.length), cookie.value];
}
