import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { parseSshCertificate } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { sshPublicKey } from './support/ssh.js';

const folders: string[] = [];
afterEach(async () => {
  await closeFixtures();
  for (const folder of folders.splice(0)) await rm(folder, { recursive: true, force: true });
});

describe('SSH CLI', () => {
  it('enrolls and syncs a host, and gets a person a certificate', async () => {
    const f = await organizationFixture({ ssh: true });
    const folder = await mkdtemp(join(tmpdir(), 'better-iam-ssh-cli-'));
    folders.push(folder);
    const output: string[] = [];
    const notes: string[] = [];
    const io = (env: Record<string, string> = {}) => ({
      out: (message: string) => output.push(message),
      err: (message: string) => notes.push(message),
      env: env as NodeJS.ProcessEnv,
      cwd: folder,
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) =>
        f.iam.handler(new Request(input, init))) as typeof fetch,
    });
    const last = () => JSON.parse(output.at(-1)!);

    await f.iam.api.ssh.setup(f.ownerCredential, { tenantId: f.tenantId });
    const created = await f.iam.api.ssh.createHost(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'web-01',
      logins: ['deploy'],
    });
    await writeFile(join(folder, 'host_key.pub'), `${sshPublicKey('ed25519', 'root@web-01')}\n`);
    await runCli(
      ['ssh-host-enroll', '--url', 'http://localhost:3000', '--host-key', 'host_key.pub', '--root', 'root'],
      io({ BETTER_IAM_SSH_JOIN_TOKEN: created.joinToken }),
    );
    expect(last()).toMatchObject({ host: 'web-01', hostId: created.host.id });
    const etc = join(folder, 'root', 'etc', 'ssh');
    const certificate = await readFile(join(etc, 'ssh_host_ed25519_key-cert.pub'), 'utf8');
    expect(parseSshCertificate(certificate).principals).toEqual(['web-01']);
    expect(await readFile(join(etc, 'better-iam', 'principals', 'deploy'), 'utf8')).toBe('deploy@web-01\n');
    expect((await readFile(join(etc, 'better-iam', 'revoked.krl'))).subarray(0, 6).toString()).toBe('SSHKRL');
    expect(await readFile(join(etc, 'sshd_config.d', '00-better-iam.conf'), 'utf8')).toContain('TrustedUserCAKeys');
    expect(await readFile(join(etc, 'better-iam', 'renewal-token'), 'utf8')).toMatch(/^biam_sshr\./);

    await runCli(['ssh-host-sync', '--url', 'http://localhost:3000', '--root', 'root'], io());
    expect(last()).toMatchObject({ host: 'web-01', certificateRenewed: false });
    // A forced renewal is honoured hourly; it rotates the renewal token, which the CLI saves for the next sync.
    const firstToken = await readFile(join(etc, 'better-iam', 'renewal-token'), 'utf8');
    f.advance(2 * 3_600_000);
    await runCli(['ssh-host-sync', '--url', 'http://localhost:3000', '--root', 'root', '--renew'], io());
    expect(last()).toMatchObject({ certificateRenewed: true });
    expect(await readFile(join(etc, 'better-iam', 'renewal-token'), 'utf8')).not.toBe(firstToken);
    await runCli(['ssh-host-sync', '--url', 'http://localhost:3000', '--root', 'root'], io());
    expect(last()).toMatchObject({ certificateRenewed: false });

    // A person gets a certificate next to their key and the known_hosts lines for the host authority.
    await writeFile(join(folder, 'id_ed25519.pub'), `${sshPublicKey('ed25519', 'owner@laptop')}\n`);
    await runCli(
      [
        'ssh-cert',
        '--url',
        'http://localhost:3000',
        '--tenant',
        f.tenantId,
        '--key',
        'id_ed25519.pub',
        '--known-hosts',
        'known_hosts',
        '--ttl-minutes',
        '30',
      ],
      io({ BETTER_IAM_TOKEN: f.ownerCredential.token }),
    );
    expect(last()).toMatchObject({ principals: ['deploy@web-01'], hosts: [{ name: 'web-01' }] });
    const userCert = await readFile(join(folder, 'id_ed25519-cert.pub'), 'utf8');
    const parsed = parseSshCertificate(userCert);
    expect(parsed.principals).toEqual(['deploy@web-01']);
    expect(parsed.validBefore - parsed.validAfter).toBe(35 * 60);
    expect(await readFile(join(folder, 'known_hosts'), 'utf8')).toMatch(/^@cert-authority web-01 ssh-ed25519 /);

    // The host revocation list for RevokedHostKeys, beside the known_hosts file.
    expect((await readFile(join(folder, 'known_hosts_revoked_hosts'))).subarray(0, 6).toString()).toBe('SSHKRL');

    // The sweep job runs from the configuration (here: in process through the fixture instance).
    expect(await f.iam.ssh.sweep()).toMatchObject({ examined: 1, revoked: 0 });

    // A login removed from the host: the next sync deletes its principals file.
    await f.iam.api.ssh.updateHost(f.ownerCredential, { tenantId: f.tenantId, hostId: created.host.id, logins: ['ops'] });
    await runCli(['ssh-host-sync', '--url', 'http://localhost:3000', '--root', 'root'], io());
    expect(last().files).toContain('-/etc/ssh/better-iam/principals/deploy');
    expect(await readdir(join(etc, 'better-iam', 'principals'))).toEqual(['ops']);
  });
});
