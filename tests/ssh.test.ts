import { afterEach, describe, expect, it } from 'vitest';
import { parseSshCertificate, parseSshPublicKey, SSH_CERT_HOST, SSH_CERT_USER } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { runKeygen, sshKeygen, sshPublicKey, withSshFiles } from './support/ssh.js';

afterEach(closeFixtures);

const keygen = sshKeygen();
const HOUR = 3_600_000;

/**
 * Acme with a verified domain (acme.test), the SSH CA set up, two enrolled hosts (web-01 staging, db-01 production),
 * and alice allowed `deploy` on staging hosts with port forwarding everywhere.
 */
async function setup(ssh: Record<string, unknown> | true = true) {
  const txt = new Map<string, string[][]>();
  const f = await organizationFixture({ ssh, domains: { resolveTxt: async (name) => txt.get(name) ?? [] } });
  const claim = await f.iam.api.domains.add(f.ownerCredential, { tenantId: f.tenantId, domain: 'acme.test' });
  txt.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
  await f.iam.api.domains.verify(f.ownerCredential, { tenantId: f.tenantId, domainId: claim.id });
  const setupResult = await f.iam.api.ssh.setup(f.ownerCredential, { tenantId: f.tenantId });
  const web = await f.iam.api.ssh.createHost(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'web-01',
    addresses: ['web-01.acme.test', '10.0.0.5'],
    logins: ['deploy', 'root'],
    labels: { environment: 'staging' },
  });
  const db = await f.iam.api.ssh.createHost(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'db-01',
    logins: ['postgres', 'root'],
    labels: { environment: 'production' },
  });
  const webHostKey = sshPublicKey('ed25519', 'root@web-01');
  const webSetup = await f.iam.api.ssh.enrollHost({ joinToken: web.joinToken, publicKey: webHostKey });
  const dbSetup = await f.iam.api.ssh.enrollHost({
    joinToken: db.joinToken,
    publicKey: sshPublicKey('ecdsa', 'root@db-01'),
  });
  const alice = await f.member('alice');
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Staging deploy',
    document: {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['ssh:login'],
          resources: ['ssh-login/*/deploy'],
          conditions: { StringEquals: { 'resource.environment': 'staging' } },
        },
        { effect: 'allow', actions: ['ssh:port-forward'], resources: ['ssh-host/*'] },
      ],
    },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const aliceSession = { token: (await f.signIn('alice')).token };
  return { f, setupResult, web, db, webSetup, dbSetup, webHostKey, alice, aliceSession, role };
}

async function auditOf(f: Awaited<ReturnType<typeof organizationFixture>>) {
  const events = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId, limit: 500 });
  return (Array.isArray(events) ? events : (events as { events: typeof events }).events) as {
    action: string;
    outcome: string;
    metadata?: Record<string, unknown>;
  }[];
}

describe('SSH certificate authority', () => {
  it('is off unless the ssh option is set', async () => {
    const f = await organizationFixture();
    await expect(f.iam.api.ssh.setup(f.ownerCredential, { tenantId: f.tenantId })).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
    });
    // The ssh-login type and ssh:login are not in the catalog either.
    await expect(
      f.iam.api.roles.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'x',
        document: { version: 1, statements: [{ effect: 'allow', actions: ['ssh:login'], resources: ['*'] }] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
  });

  it('sets up authorities, enrolls hosts, and hands them what sshd needs', async () => {
    const { f, setupResult, webSetup, web, webHostKey } = await setup();
    expect(setupResult.created).toEqual(['user', 'host']);
    expect(setupResult.authorities.map((a) => [a.kind, a.status])).toEqual([
      ['user', 'active'],
      ['host', 'active'],
    ]);
    // Setup is idempotent.
    expect((await f.iam.api.ssh.setup(f.ownerCredential, { tenantId: f.tenantId })).created).toEqual([]);
    // Authority keys are sealed at rest and never leave in views.
    const stored = await f.database.find('sshAuthorities', { tenantId: f.tenantId });
    expect(stored.every((row) => typeof row.keySealed === 'string' && !String(row.keySealed).includes('MC4C'))).toBe(true);
    expect(JSON.stringify(setupResult)).not.toContain('keySealed');

    const cert = parseSshCertificate(webSetup.certificate);
    expect(cert).toMatchObject({
      kind: SSH_CERT_HOST,
      keyId: 'host:web-01',
      principals: ['web-01', 'web-01.acme.test', '10.0.0.5'],
      publicKeyFingerprint: parseSshPublicKey(webHostKey).fingerprint,
      signatureValid: true,
    });
    const hostAuthority = setupResult.authorities.find((a) => a.kind === 'host')!;
    expect(cert.signatureKeyFingerprint).toBe(hostAuthority.fingerprint);
    expect(webSetup.principals).toEqual({ deploy: 'deploy@web-01\n', root: 'root@web-01\n' });
    expect(webSetup.trustedUserCaKeys).toContain(setupResult.authorities[0]!.publicKey.split(' ')[1]);
    expect(webSetup.sshdConfig).toContain('AuthorizedPrincipalsFile /etc/ssh/better-iam/principals/%u');
    expect(webSetup.sshdConfig).toContain('HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub');
    expect(webSetup.files.map((file) => file.path)).toEqual(
      expect.arrayContaining(['/etc/ssh/better-iam/revoked.krl', '/etc/ssh/sshd_config.d/00-better-iam.conf']),
    );
    expect(webSetup.managedDirectories).toEqual(['/etc/ssh/better-iam/principals']);
    expect(webSetup.renewalToken).toMatch(/^biam_sshr\./);
    expect(webSetup.host).not.toHaveProperty('renewalTokenHash');

    // The join token works once.
    await expect(
      f.iam.api.ssh.enrollHost({ joinToken: web.joinToken, publicKey: webHostKey }),
    ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    // Syncing with the renewal token reuses a fresh certificate and hands out the same setup.
    const sync = await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken! });
    expect(sync.certificateRenewed).toBe(false);
    expect(sync.certificate).toBe(webSetup.certificate);
    expect(sync).not.toHaveProperty('renewalToken');
    await expect(f.iam.api.ssh.syncHost({ renewalToken: `${webSetup.renewalToken}x` })).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });

    // Members' clients trust the host authority for exactly the enrolled names; the public trust lists no names.
    const client = await f.iam.api.ssh.clientTrust(f.ownerCredential, { tenantId: f.tenantId });
    expect(client.knownHosts).toMatch(/^@cert-authority 10\.0\.0\.5,db-01,web-01,web-01\.acme\.test ssh-ed25519 \S+ better-iam:/);
    const trust = await f.iam.api.ssh.trust({ tenantId: f.tenantId });
    expect(trust.userAuthorities).toHaveLength(1);
    expect(trust.knownHosts).toBe('');
    expect(JSON.stringify(trust)).not.toContain('web-01');
  });

  it('issues certificates for exactly the hosts and logins policies allow', async () => {
    const { f, aliceSession, alice } = await setup();
    const publicKey = sshPublicKey('ed25519', 'alice@laptop');
    const access = await f.iam.api.ssh.myAccess(aliceSession, { tenantId: f.tenantId });
    expect(access.hosts).toEqual([
      {
        name: 'web-01',
        addresses: ['web-01.acme.test', '10.0.0.5'],
        labels: { environment: 'staging' },
        logins: ['deploy'],
        forwarding: { port: true, agent: false, x11: false },
      },
    ]);

    const issued = await f.iam.api.ssh.issueCertificate(aliceSession, {
      tenantId: f.tenantId,
      publicKey,
      ttlMs: HOUR,
      reason: 'deploy release 42',
    });
    expect(issued.principals).toEqual(['deploy@web-01']);
    expect(issued.hosts).toEqual([{ name: 'web-01', addresses: ['web-01.acme.test', '10.0.0.5'], logins: ['deploy'] }]);
    expect(issued.validBefore - f.now()).toBe(HOUR);
    const cert = parseSshCertificate(issued.certificate);
    expect(cert).toMatchObject({
      kind: SSH_CERT_USER,
      principals: ['deploy@web-01'],
      publicKeyFingerprint: parseSshPublicKey(publicKey).fingerprint,
      extensions: ['permit-port-forwarding', 'permit-pty', 'permit-user-rc'],
      signatureValid: true,
    });
    expect(cert.keyId).toBe(`alice@acme.test (${alice.id})`);
    expect(cert.validBefore).toBe(Math.floor(issued.validBefore / 1000));
    expect(issued.knownHosts).toContain('@cert-authority');
    expect(Buffer.from(issued.revokedHostKeys, 'base64').subarray(0, 6).toString()).toBe('SSHKRL');

    // Asking for a host or login outside the grant is refused and audited.
    await expect(
      f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey, hosts: ['db-01'] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey, logins: ['root'] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey, hosts: ['nope'] }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const events = await auditOf(f);
    expect(events.some((event) => event.action === 'ssh:login' && event.outcome === 'deny')).toBe(true);
    expect(
      events.some(
        (event) =>
          event.action === 'ssh:certificate:issue' &&
          event.outcome === 'allow' &&
          event.metadata?.reason === 'deploy release 42',
      ),
    ).toBe(true);

    // The owner (every grant) gets every login on every host; lifetimes are capped by the tenant maximum.
    const owner = await f.iam.api.ssh.issueCertificate(f.ownerCredential, {
      tenantId: f.tenantId,
      publicKey: sshPublicKey('rsa'),
      ttlMs: 20 * HOUR,
    });
    expect(owner.principals).toEqual(['postgres@db-01', 'root@db-01', 'deploy@web-01', 'root@web-01']);
    expect(owner.validBefore - f.now()).toBe(16 * HOUR);
    expect(owner.extensions).toEqual([
      'permit-X11-forwarding',
      'permit-agent-forwarding',
      'permit-port-forwarding',
      'permit-pty',
      'permit-user-rc',
    ]);

    // The generic decision API and access reviews see the same resources.
    expect(
      (
        await f.iam.authorize({
          token: aliceSession.token,
          tenantId: f.tenantId,
          action: 'ssh:login',
          resource: { type: 'ssh-login', id: 'web-01/deploy' },
        })
      ).allowed,
    ).toBe(true);
    const hosts = await f.iam.api.ssh.listHosts(f.ownerCredential, { tenantId: f.tenantId });
    const web = hosts.find((host) => host.name === 'web-01')!;
    const who = await f.iam.api.ssh.whoCanLogin(f.ownerCredential, { tenantId: f.tenantId, hostId: web.id });
    expect(who.identities.map((entry) => [entry.email, entry.logins])).toEqual(
      expect.arrayContaining([
        ['alice@acme.test', ['deploy']],
        ['owner@acme.test', ['deploy', 'root']],
      ]),
    );

    const mine = await f.iam.api.ssh.myCertificates(aliceSession, { tenantId: f.tenantId });
    expect(mine.map((c) => [c.id, c.status])).toEqual([[issued.id, 'active']]);
    expect(mine[0]).not.toHaveProperty('sessionId');
  });

  it('enforces tenant settings: MFA, security keys, source address, lifetimes', async () => {
    const { f, aliceSession } = await setup();
    await f.iam.api.ssh.updateSettings(f.ownerCredential, { tenantId: f.tenantId, requireMfa: true });
    await expect(
      f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() }),
    ).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
    await f.iam.api.ssh.updateSettings(f.ownerCredential, {
      tenantId: f.tenantId,
      requireMfa: false,
      requireSecurityKey: true,
      requireUserVerification: true,
      defaultCertificateMs: 600_000,
    });
    await expect(
      f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() }),
    ).rejects.toMatchObject({ code: 'SECURITY_KEY_REQUIRED' });
    const sk = await f.iam.api.ssh.issueCertificate(aliceSession, {
      tenantId: f.tenantId,
      publicKey: sshPublicKey('sk-ed25519'),
    });
    expect(sk.validBefore - f.now()).toBe(600_000);
    const parsed = parseSshCertificate(sk.certificate);
    expect(parsed.type).toBe('sk-ssh-ed25519-cert-v01@openssh.com');
    expect(parsed.criticalOptions).toEqual({ 'verify-required': '' });

    await f.iam.api.ssh.updateSettings(f.ownerCredential, {
      tenantId: f.tenantId,
      requireSecurityKey: false,
      bindSourceAddress: true,
    });
    // No client address is known in-process: refused rather than issued unbound.
    await expect(
      f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() }),
    ).rejects.toMatchObject({ code: 'SOURCE_ADDRESS_UNKNOWN' });
    await expect(
      f.iam.api.ssh.updateSettings(f.ownerCredential, { tenantId: f.tenantId, defaultCertificateMs: 20 * HOUR }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.ssh.updateSettings(f.ownerCredential, { tenantId: f.tenantId, hostPatterns: ['bad pattern'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Members without iam:ssh:manage cannot change settings or enroll hosts.
    await expect(
      f.iam.api.ssh.updateSettings(aliceSession, { tenantId: f.tenantId, requireMfa: false }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.ssh.createHost(aliceSession, { tenantId: f.tenantId, name: 'x', logins: ['a'] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('revokes certificates and publishes them in the revocation lists', async () => {
    const { f, aliceSession, alice, db, dbSetup } = await setup();
    const publicKey = sshPublicKey();
    const first = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey });
    const second = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey });
    const empty = await f.iam.api.ssh.revocationList({ tenantId: f.tenantId });
    expect(empty.revokedCertificates).toBe(0);

    // A person may revoke their own certificate without any permission.
    const revoked = await f.iam.api.ssh.revokeCertificate(aliceSession, {
      tenantId: f.tenantId,
      certificateId: first.id,
    });
    expect(revoked).toMatchObject({ status: 'revoked', revocationReason: 'revoked', revokedBy: alice.id });
    const list = await f.iam.api.ssh.revocationList({ tenantId: f.tenantId });
    expect(list.revokedCertificates).toBe(1);
    expect(list.version).toBe(empty.version + 1);

    // Disabling the database host revokes its certificate and publishes its key to clients (never in the user list).
    await f.iam.api.ssh.disableHost(f.ownerCredential, { tenantId: f.tenantId, hostId: db.host.id });
    const users = await f.iam.api.ssh.revocationList({ tenantId: f.tenantId });
    expect(users).toMatchObject({ kind: 'user', revokedCertificates: 1, revokedHostKeys: 0 });
    const hosts = await f.iam.api.ssh.revocationList({ tenantId: f.tenantId, kind: 'host' });
    expect(hosts).toMatchObject({ kind: 'host', revokedCertificates: 1, revokedHostKeys: 1 });
    const client = await f.iam.api.ssh.clientTrust(aliceSession, { tenantId: f.tenantId });
    expect(client.knownHosts).toMatch(/@revoked \* ecdsa-sha2-nistp256 \S+ better-iam:revoked/);
    await expect(f.iam.api.ssh.syncHost({ renewalToken: dbSetup.renewalToken! })).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });

    if (keygen)
      withSshFiles(
        {
          'first-cert.pub': `${first.certificate}\n`,
          'second-cert.pub': `${second.certificate}\n`,
          'revoked.krl': Buffer.from(users.krl, 'base64'),
        },
        (path) => {
          expect(runKeygen(keygen, ['-Q', '-f', path('revoked.krl'), path('first-cert.pub')]).output).toContain(
            'REVOKED',
          );
          const fine = runKeygen(keygen, ['-Q', '-f', path('revoked.krl'), path('second-cert.pub')]);
          expect(fine.status, fine.output).toBe(0);
        },
      );

    // Incident response: everything alice holds, at once.
    expect(
      await f.iam.api.ssh.revokeIdentity(f.ownerCredential, { tenantId: f.tenantId, identityId: alice.id }),
    ).toEqual({ revoked: 1 });
    // Someone else's certificate needs iam:ssh:manage.
    const owners = await f.iam.api.ssh.issueCertificate(f.ownerCredential, { tenantId: f.tenantId, publicKey });
    await expect(
      f.iam.api.ssh.revokeCertificate(aliceSession, { tenantId: f.tenantId, certificateId: owners.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const all = await f.iam.api.ssh.listCertificates(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'user',
      status: 'revoked',
    });
    expect(all.total).toBe(2);
  });

  it('ends certificates with the session or API key that requested them', async () => {
    const { f, aliceSession, alice, role } = await setup();
    const cert = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    await f.iam.api.identities.revokeSessions(f.ownerCredential, { tenantId: f.tenantId, identityId: alice.id });
    // Hosts refuse it from their next revocation list, before the sweep even runs.
    expect((await f.iam.api.ssh.revocationList({ tenantId: f.tenantId })).revokedCertificates).toBe(1);

    const robot = await f.iam.api.serviceAccounts.create(f.ownerCredential, { tenantId: f.tenantId, name: 'deployer' });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: robot.id,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, { tenantId: f.tenantId, identityId: robot.id });
    const robotCert = await f.iam.api.ssh.issueCertificate({ token: key.token }, {
      tenantId: f.tenantId,
      publicKey: sshPublicKey(),
    });
    expect(robotCert.principals).toEqual(['deploy@web-01']);
    await f.iam.api.credentials.revoke(f.ownerCredential, { tenantId: f.tenantId, credentialId: key.credentialId });

    expect(await f.iam.ssh.sweep({ tenantId: f.tenantId })).toEqual({
      examined: 2,
      revoked: 2,
      byReason: { 'session-ended': 2 },
    });
    const records = await f.iam.api.ssh.listCertificates(f.ownerCredential, { tenantId: f.tenantId, kind: 'user' });
    expect(records.certificates.map((c) => c.id).sort()).toEqual([cert.id, robotCert.id].sort());
    expect(records.certificates.every((c) => c.revocationReason === 'session-ended')).toBe(true);
  });

  it('sweeps certificates whose holder, login or access went away', async () => {
    const { f, aliceSession, alice, role, web } = await setup();
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    for (const person of [bob, carol])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    const bobSession = { token: (await f.signIn('bob')).token };
    const carolSession = { token: (await f.signIn('carol')).token };
    const aliceCert = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    const bobCert = await f.iam.api.ssh.issueCertificate(bobSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    expect(await f.iam.ssh.sweep()).toEqual({ examined: 2, revoked: 0, byReason: {} });

    // Alice's account is disabled: the revocation list refuses her certificate even before the sweep runs.
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    expect((await f.iam.api.ssh.revocationList({ tenantId: f.tenantId })).revokedCertificates).toBe(1);
    // Bob loses the grant: his certificate no longer matches policy.
    const binding = (
      await f.iam.api.bindings.list(f.ownerCredential, { tenantId: f.tenantId, subjectId: bob.id })
    ).find((item: { roleId: string }) => item.roleId === role.id)!;
    await f.iam.api.bindings.delete(f.ownerCredential, { tenantId: f.tenantId, bindingId: binding.id });

    const swept = await f.iam.ssh.sweep({ tenantId: f.tenantId });
    expect(swept).toEqual({ examined: 2, revoked: 2, byReason: { 'identity-inactive': 1, 'access-changed': 1 } });
    const records = await f.iam.api.ssh.listCertificates(f.ownerCredential, { tenantId: f.tenantId, kind: 'user' });
    expect(Object.fromEntries(records.certificates.map((c) => [c.id, c.revocationReason]))).toEqual({
      [aliceCert.id]: 'identity-inactive',
      [bobCert.id]: 'access-changed',
    });
    const krl = await f.iam.ssh.revocationList(f.tenantId);
    expect(krl.bytes.subarray(0, 8).toString('latin1')).toBe('SSHKRL\n\0');

    // A login removed from the host takes the certificates naming it (the host deletes its principals file too).
    const carolCert = await f.iam.api.ssh.issueCertificate(carolSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    await f.iam.api.ssh.updateHost(f.ownerCredential, { tenantId: f.tenantId, hostId: web.host.id, logins: ['root'] });
    expect((await f.iam.ssh.sweep({ tenantId: f.tenantId })).byReason).toEqual({ 'access-changed': 1 });
    const carolRecord = await f.iam.api.ssh.getCertificate(f.ownerCredential, {
      tenantId: f.tenantId,
      certificateId: carolCert.id,
    });
    expect(carolRecord.status).toBe('revoked');
  });

  it('caps certificates at the time-limited grants that allow them', async () => {
    const { f, aliceSession } = await setup();
    const dave = await f.member('dave');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Database on call',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['ssh:login'], resources: ['ssh-login/db-01/postgres'] }],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: dave.id,
      expiresAt: f.now() + 2 * HOUR,
    });
    const daveSession = { token: (await f.signIn('dave')).token };
    const cert = await f.iam.api.ssh.issueCertificate(daveSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    expect(cert.principals).toEqual(['postgres@db-01']);
    expect(cert.validBefore).toBe(f.now() + 2 * HOUR);
    // A standing grant sets no such limit.
    const standing = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    expect(standing.validBefore - f.now()).toBe(8 * HOUR);
  });

  it('keeps the host authority to names the organization owns, unique per host', async () => {
    const { f, webSetup, web, setupResult } = await setup();
    // `*` and names outside the verified domains are refused as patterns; patterns must cover every host.
    for (const hostPatterns of [['*'], ['*.github.com'], ['*m']])
      await expect(
        f.iam.api.ssh.updateSettings(f.ownerCredential, { tenantId: f.tenantId, hostPatterns }),
      ).rejects.toMatchObject({ code: 'HOST_OUTSIDE_PATTERNS' });
    await expect(
      f.iam.api.ssh.updateSettings(f.ownerCredential, { tenantId: f.tenantId, hostPatterns: ['*.acme.test'] }),
    ).rejects.toMatchObject({ code: 'HOST_OUTSIDE_PATTERNS' });
    await f.iam.api.ssh.updateSettings(f.ownerCredential, {
      tenantId: f.tenantId,
      hostPatterns: ['*.acme.test', 'web-*', 'db-*', '10.0.0.*', '!bastion.acme.test'],
    });
    // A name outside them (github.com, a negated name) can never enter a host certificate.
    for (const input of [
      { name: 'web-02', addresses: ['github.com'], logins: ['deploy'] },
      { name: 'bastion.acme.test', logins: ['ops'] },
    ])
      await expect(f.iam.api.ssh.createHost(f.ownerCredential, { tenantId: f.tenantId, ...input })).rejects.toMatchObject({
        code: 'HOST_OUTSIDE_PATTERNS',
      });
    await expect(
      f.iam.api.ssh.updateHost(f.ownerCredential, { tenantId: f.tenantId, hostId: web.host.id, addresses: ['evil.example.com'] }),
    ).rejects.toMatchObject({ code: 'HOST_OUTSIDE_PATTERNS' });
    // Another host's names are taken.
    await expect(
      f.iam.api.ssh.createHost(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'web-02',
        addresses: ['web-01.acme.test'],
        logins: ['deploy'],
      }),
    ).rejects.toMatchObject({ code: 'HOST_NAME_TAKEN' });
    const trust = await f.iam.api.ssh.trust({ tenantId: f.tenantId });
    expect(trust.knownHosts).toMatch(/^@cert-authority \*\.acme\.test,web-\*,db-\*,10\.0\.0\.\*,!bastion\.acme\.test /);
    // An authority key or another host's key is never accepted as a host key.
    const spare = await f.iam.api.ssh.createHost(f.ownerCredential, { tenantId: f.tenantId, name: 'web-03', logins: ['deploy'] });
    await expect(
      f.iam.api.ssh.enrollHost({ joinToken: spare.joinToken, publicKey: setupResult.authorities[0]!.publicKey }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.ssh.enrollHost({ joinToken: spare.joinToken, publicKey: webSetup.host.hostKey! }),
    ).rejects.toMatchObject({ code: 'HOST_KEY_IN_USE' });
    const events = await auditOf(f);
    expect(
      events.filter((event) => event.action === 'iam:ssh:manage' && event.outcome === 'deny').map((event) => event.metadata?.reason),
    ).toEqual(expect.arrayContaining(['HOST_OUTSIDE_PATTERNS', 'HOST_NAME_TAKEN']));
  });

  it('scopes host administration to the names an administrator manages', async () => {
    const { f } = await setup();
    const bob = await f.member('bob');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team A hosts',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:ssh:manage'], resources: ['iam/ssh/hosts/team-a-*'] }],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const bobSession = { token: (await f.signIn('bob')).token };
    const create = (addresses: string[]) =>
      f.iam.api.ssh.createHost(bobSession, { tenantId: f.tenantId, name: 'team-a-box', addresses, logins: ['deploy'] });
    await expect(create(['web-01.acme.test'])).rejects.toMatchObject({ code: 'HOST_NAME_TAKEN' });
    await expect(create(['payroll.acme.test'])).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const created = await create(['team-a-box.acme.test']);
    expect(created.host.addresses).toEqual(['team-a-box.acme.test']);
  });

  it('rebuilds hosts: supersedes old certificates, rotates renewal tokens, refuses key swaps', async () => {
    const { f, webSetup, web } = await setup();
    // A renewal token cannot move the host to another key; the attempt is audited.
    await expect(
      f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken!, publicKey: sshPublicKey() }),
    ).rejects.toMatchObject({ code: 'HOST_KEY_CHANGED' });
    expect(
      (await auditOf(f)).some((event) => event.action === 'ssh:host:sync' && event.outcome === 'deny' && event.metadata?.reason === 'HOST_KEY_CHANGED'),
    ).toBe(true);
    // A forced renewal is honoured at most hourly, and rotates the renewal token (the old one works until the new is used).
    expect((await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken!, renew: true })).certificateRenewed).toBe(false);
    f.advance(2 * HOUR);
    const renewed = await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken!, renew: true });
    expect(renewed.certificateRenewed).toBe(true);
    expect(renewed.renewalToken).toMatch(/^biam_sshr\./);
    expect((await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken! })).certificateRenewed).toBe(false);
    await f.iam.api.ssh.syncHost({ renewalToken: renewed.renewalToken! });
    await expect(f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken! })).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
    // Re-enrolling a rebuilt host takes a fresh join token; every earlier certificate is superseded and the old key
    // is published to clients as revoked.
    const reset = await f.iam.api.ssh.resetJoinToken(f.ownerCredential, { tenantId: f.tenantId, hostId: web.host.id });
    const rebuilt = await f.iam.api.ssh.enrollHost({ joinToken: reset.joinToken, publicKey: sshPublicKey() });
    await expect(f.iam.api.ssh.syncHost({ renewalToken: renewed.renewalToken! })).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
    expect((await f.iam.api.ssh.syncHost({ renewalToken: rebuilt.renewalToken! })).certificateRenewed).toBe(false);
    const hostCerts = await f.iam.api.ssh.listCertificates(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'host',
      hostId: web.host.id,
    });
    expect(hostCerts.certificates.filter((c) => c.status === 'active')).toHaveLength(1);
    expect(hostCerts.certificates.filter((c) => c.status === 'revoked').map((c) => c.revocationReason)).toEqual([
      'superseded',
      'superseded',
    ]);
    const client = await f.iam.api.ssh.clientTrust(f.ownerCredential, { tenantId: f.tenantId });
    expect(client.knownHosts).toContain(`@revoked * ${webSetup.host.hostKey!.split(' ').slice(0, 2).join(' ')}`);
    expect(client.knownHosts).not.toContain(rebuilt.host.hostKey!.split(' ')[1]!);
  });

  it('revokes every user certificate while the organization is suspended', async () => {
    const { f, aliceSession, webSetup } = await setup();
    await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    await f.iam.api.tenants.setStatus(f.rootCredential, { tenantId: f.tenantId, status: 'suspended' });
    const list = await f.iam.api.ssh.revocationList({ tenantId: f.tenantId });
    expect(list).toMatchObject({ tenantActive: false, revokedCertificates: 1 });
    // Hosts still sync (and fetch that list), without new certificates.
    const sync = await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken!, renew: true });
    expect(sync.certificateRenewed).toBe(false);
    expect(sync.revocationList).toBe(list.krl);
  });

  it('rotates authorities without breaking certificates already issued', async () => {
    const { f, aliceSession, setupResult, webSetup } = await setup();
    const before = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    const pending = await f.iam.api.ssh.rotateAuthority(f.ownerCredential, { tenantId: f.tenantId, kind: 'user' });
    expect(pending.status).toBe('pending');
    // Published ahead of signing: hosts trust both keys from their next sync.
    const sync = await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken! });
    expect(sync.trustedUserCaKeys.trim().split('\n')).toHaveLength(2);
    await expect(
      f.iam.api.ssh.rotateAuthority(f.ownerCredential, { tenantId: f.tenantId, kind: 'user' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await f.iam.api.ssh.activateAuthority(f.ownerCredential, { tenantId: f.tenantId, authorityId: pending.id });
    const after = await f.iam.api.ssh.issueCertificate(aliceSession, { tenantId: f.tenantId, publicKey: sshPublicKey() });
    expect(parseSshCertificate(after.certificate).signatureKeyFingerprint).toBe(pending.fingerprint);
    const old = setupResult.authorities.find((a) => a.kind === 'user')!;
    expect(parseSshCertificate(before.certificate).signatureKeyFingerprint).toBe(old.fingerprint);
    // The previous key stays trusted while its certificates live; retiring it early needs force.
    await expect(
      f.iam.api.ssh.retireAuthority(f.ownerCredential, { tenantId: f.tenantId, authorityId: old.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    f.advance(17 * HOUR);
    const owner = await f.ownerSignIn();
    const retired = await f.iam.api.ssh.retireAuthority(owner, { tenantId: f.tenantId, authorityId: old.id });
    expect(retired.status).toBe('retired');
    const trust = await f.iam.api.ssh.trust({ tenantId: f.tenantId });
    expect(trust.userAuthorities.map((a) => a.id)).toEqual([pending.id]);

    // A host rotation re-issues host certificates at the next sync.
    const hostPending = await f.iam.api.ssh.rotateAuthority(owner, { tenantId: f.tenantId, kind: 'host', activate: true });
    const renewed = await f.iam.api.ssh.syncHost({ renewalToken: webSetup.renewalToken! });
    expect(renewed.certificateRenewed).toBe(true);
    expect(parseSshCertificate(renewed.certificate).signatureKeyFingerprint).toBe(hostPending.fingerprint);
  });

  it('never lets the platform root override open an organization host', async () => {
    const { f } = await setup();
    await expect(
      f.iam.api.ssh.issueCertificate(f.rootCredential, { tenantId: f.tenantId, publicKey: sshPublicKey() }),
    ).rejects.toMatchObject({ code: 'ROOT_SSH_RESTRICTED' });
    expect((await f.iam.api.ssh.myAccess(f.rootCredential, { tenantId: f.tenantId })).hosts).toEqual([]);
    // Root still administers the authority (audited as a root override).
    expect((await f.iam.api.ssh.status(f.rootCredential, { tenantId: f.tenantId })).hosts.enrolled).toBe(2);
  });

  it('serves hosts over HTTP without a session and members with a bearer token', async () => {
    const { f, aliceSession } = await setup();
    const call = (path: string, body: unknown, token?: string) =>
      f.iam.handler(
        new Request(`http://localhost:3000/api/iam/ssh/${path}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify(body),
        }),
      );
    const host = await f.iam.api.ssh.createHost(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci-runner',
      logins: ['ci'],
    });
    // A host enrolls with plain JSON (curl with the usual X-Better-IAM header), the join token its only credential.
    const enrolled = await call('enrollHost', { joinToken: host.joinToken, publicKey: sshPublicKey() });
    expect(enrolled.status).toBe(200);
    const setupBody = ((await enrolled.json()) as { data: { renewalToken: string; certificate: string } }).data;
    expect(setupBody.certificate).toMatch(/^ssh-ed25519-cert-v01@openssh\.com /);
    const synced = await call('syncHost', { renewalToken: setupBody.renewalToken });
    expect(synced.status).toBe(200);
    const krl = await call('revocationList', { tenantId: f.tenantId });
    expect(((await krl.json()) as { data: { krl: string } }).data.krl).toMatch(/^U1NIS1JM/);
    // Members call issueCertificate with their credential; without one it is refused.
    const issued = await call(
      'issueCertificate',
      { tenantId: f.tenantId, publicKey: sshPublicKey(), hosts: ['web-01'] },
      aliceSession.token,
    );
    expect(issued.status).toBe(200);
    expect(((await issued.json()) as { data: { principals: string[] } }).data.principals).toEqual(['deploy@web-01']);
    const anonymous = await call('issueCertificate', { tenantId: f.tenantId, publicKey: sshPublicKey() });
    expect(anonymous.status).toBe(401);
    const badToken = await call('syncHost', { renewalToken: 'biam_sshr.x.y' });
    expect(badToken.status).toBe(401);
  });

  it.skipIf(!keygen)('produces a user certificate ssh-keygen reads', async () => {
    const { f, aliceSession } = await setup();
    const issued = await f.iam.api.ssh.issueCertificate(aliceSession, {
      tenantId: f.tenantId,
      publicKey: sshPublicKey('ecdsa'),
    });
    withSshFiles({ 'id-cert.pub': `${issued.certificate}\n` }, (path) => {
      const listed = runKeygen(keygen!, ['-L', '-f', path('id-cert.pub')]);
      expect(listed.status, listed.output).toBe(0);
      expect(listed.output).toContain('user certificate');
      expect(listed.output).toContain('deploy@web-01');
      expect(listed.output).toContain('permit-port-forwarding');
      expect(listed.output).not.toContain('permit-agent-forwarding');
    });
  });
});
