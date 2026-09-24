import { chmod, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { CliError, usageError } from '../errors.js';
import { defineCommand, type CommandContext } from '../framework.js';
import { tenantFlag } from './access.js';

/** What `ssh/enrollHost` and `ssh/syncHost` return (the fields these commands use). */
interface HostSetup {
  host: { id: string; name: string; tenantId: string };
  certificateExpiresAt: number;
  certificateRenewed: boolean;
  renewalToken?: string;
  revocationVersion: number;
  files: { path: string; content: string; mode: string; encoding?: 'base64' }[];
  /** Directories the setup manages completely: files it no longer lists (a removed login) are deleted. */
  managedDirectories?: string[];
}

const commaList = (value: string | undefined) =>
  value
    ?.split(',')
    .map((item) => item.trim())
    .filter(Boolean);

const renewalTokenPath = '/etc/ssh/better-iam/renewal-token';

/** Only files under /etc/ssh, never outside it: the host trusts the server, but not blindly with paths. */
function hostFilePath(root: string, path: string): string {
  const normal = posix.normalize(path);
  if (!normal.startsWith('/etc/ssh/') || normal.includes('..') || normal !== path)
    throw new CliError('UNEXPECTED_RESPONSE', `The server named a file outside /etc/ssh: ${path.slice(0, 80)}`);
  return join(root, ...normal.split('/').filter(Boolean));
}

async function writeHostFiles(
  context: CommandContext,
  root: string,
  setup: HostSetup,
  dryRun: boolean,
): Promise<string[]> {
  const written: string[] = [];
  const files = [...setup.files];
  if (setup.renewalToken)
    files.push({ path: renewalTokenPath, content: `${setup.renewalToken}\n`, mode: '0600' });
  for (const file of files) {
    const target = hostFilePath(root, file.path);
    written.push(file.path);
    if (dryRun) continue;
    await mkdir(dirname(target), { recursive: true });
    await writeFile(
      target,
      file.encoding === 'base64' ? Buffer.from(file.content, 'base64') : file.content,
      { mode: Number.parseInt(file.mode, 8) },
    );
    // Also tighten an existing file (writeFile's mode applies to new files only); a no-op on Windows.
    await chmod(target, Number.parseInt(file.mode, 8)).catch(() => undefined);
  }
  // A login removed from the host must stop working here too: its principals file goes.
  for (const directory of setup.managedDirectories ?? []) {
    const folder = hostFilePath(root, `${directory.replace(/\/$/, '')}/`);
    const listed = new Set(files.map((file) => hostFilePath(root, file.path)));
    let present: string[] = [];
    try {
      present = await readdir(folder);
    } catch {
      continue;
    }
    for (const name of present) {
      const target = join(folder, name);
      if (listed.has(target)) continue;
      written.push(`-${posix.join(directory, name)}`);
      if (!dryRun) await rm(target, { force: true });
    }
  }
  if (!dryRun) context.note('Wrote the SSH files; reload sshd to apply them (systemctl reload ssh).');
  return written;
}

const rootFlag = {
  type: 'string',
  value: 'DIR',
  default: '/',
  description: 'Write under this directory instead of / (for images and tests)',
} as const;

/** SSH certificates: people get one for what policies allow; hosts enroll and check in; the sweep job. */
export const sshCommands = [
  defineCommand({
    name: 'ssh-cert',
    group: 'Access',
    summary: 'Get a short-lived SSH certificate for your key',
    description:
      'ssh-cert sends your public key (--key, default ~/.ssh/id_ed25519.pub) to the organization\'s SSH certificate authority as BETTER_IAM_TOKEN or the session saved by login, and saves the certificate it returns next to the key (id_ed25519-cert.pub), where ssh picks it up. The certificate names every enrolled host and login policies allow you (ssh:login on ssh-login/{host}/{login}), or only --hosts and --logins. It also writes the organization\'s host authority to --known-hosts (default ~/.ssh/better-iam_known_hosts): add that file to UserKnownHostsFile in ~/.ssh/config so hosts are verified by certificate, and the host revocation list written beside it (better-iam_revoked_hosts) to RevokedHostKeys.',
    target: 'token',
    flags: {
      tenant: tenantFlag,
      key: {
        type: 'string',
        value: 'PATH',
        description: 'Your OpenSSH public key (default ~/.ssh/id_ed25519.pub)',
      },
      hosts: { type: 'string', value: 'HOST,...', description: 'Only these hosts' },
      logins: { type: 'string', value: 'LOGIN,...', description: 'Only these logins' },
      'ttl-minutes': {
        type: 'integer',
        min: 1,
        max: 10080,
        description: 'Lifetime (default and maximum from the organization\'s settings)',
      },
      reason: { type: 'string', value: 'TEXT', description: 'Why you need access (audited)' },
      'known-hosts': {
        type: 'string',
        value: 'PATH',
        description: 'Where to write the known_hosts lines (default ~/.ssh/better-iam_known_hosts)',
      },
      'no-write': { type: 'boolean', description: 'Print the certificate instead of saving files' },
    },
    examples: [
      'better-iam ssh-cert --tenant ten_123',
      'better-iam ssh-cert --hosts web-01 --logins deploy --ttl-minutes 30 --reason "hotfix 42"',
    ],
    async run(context) {
      const { flags } = context;
      const keyPath = context.path(flags.key ?? join(homedir(), '.ssh', 'id_ed25519.pub'));
      if (!keyPath.endsWith('.pub')) throw usageError('--key must name the .pub public key file');
      let publicKey: string;
      try {
        publicKey = (await readFile(keyPath, 'utf8')).trim();
      } catch {
        throw new CliError('NOT_FOUND', `No public key at ${keyPath}`, 'Create one with ssh-keygen -t ed25519.');
      }
      const issued = await (await context.api()).call<{
        id: string;
        certificate: string;
        principals: string[];
        validBefore: number;
        hosts: { name: string; addresses: string[]; logins: string[] }[];
        knownHosts: string;
        revokedHostKeys: string;
      }>('ssh/issueCertificate', {
        tenantId: flags.tenant,
        publicKey,
        ...(flags.hosts ? { hosts: commaList(flags.hosts) } : {}),
        ...(flags.logins ? { logins: commaList(flags.logins) } : {}),
        ...(flags['ttl-minutes'] !== undefined ? { ttlMs: flags['ttl-minutes'] * 60_000 } : {}),
        ...(flags.reason ? { reason: flags.reason } : {}),
      });
      const summary = {
        id: issued.id,
        principals: issued.principals,
        validBefore: new Date(issued.validBefore).toISOString(),
        hosts: issued.hosts,
      };
      if (flags['no-write']) return { ...summary, certificate: issued.certificate, knownHosts: issued.knownHosts };
      const certificatePath = `${keyPath.slice(0, -'.pub'.length)}-cert.pub`;
      const knownHostsPath = context.path(
        flags['known-hosts'] ?? join(homedir(), '.ssh', 'better-iam_known_hosts'),
      );
      await writeFile(certificatePath, `${issued.certificate}\n`, { mode: 0o644 });
      await mkdir(dirname(knownHostsPath), { recursive: true });
      await writeFile(knownHostsPath, issued.knownHosts, { mode: 0o644 });
      // Revoked host keys and certificates, for `RevokedHostKeys` in ~/.ssh/config.
      const revokedHostsPath = `${knownHostsPath.replace(/_known_hosts$/, '')}_revoked_hosts`;
      await writeFile(revokedHostsPath, Buffer.from(issued.revokedHostKeys, 'base64'), { mode: 0o644 });
      return { ...summary, certificatePath, knownHostsPath, revokedHostsPath };
    },
  }),
  defineCommand({
    name: 'ssh-host-enroll',
    group: 'Setup',
    summary: 'Enroll this server with the SSH certificate authority',
    description:
      'ssh-host-enroll runs on a server: it sends the server\'s public host key (--host-key, default /etc/ssh/ssh_host_ed25519_key.pub) with the one-time join token from ssh.createHost, and writes what sshd needs under /etc/ssh: the host certificate, the trusted user authority, one principals file per login, the key revocation list, an sshd_config.d drop-in, and the renewal token (root-only) that ssh-host-sync uses from then on. Needs no session; point it at the server with --url.',
    target: 'token',
    flags: {
      'join-token': {
        type: 'string',
        value: 'TOKEN',
        required: true,
        env: 'BETTER_IAM_SSH_JOIN_TOKEN',
        description: 'The one-time join token from ssh.createHost or ssh.resetJoinToken',
      },
      'host-key': {
        type: 'string',
        value: 'PATH',
        default: '/etc/ssh/ssh_host_ed25519_key.pub',
        description: 'The server\'s public host key',
      },
      root: rootFlag,
      'dry-run': { type: 'boolean', description: 'List the files without writing them' },
    },
    examples: ['BETTER_IAM_SSH_JOIN_TOKEN=biam_sshj.... better-iam ssh-host-enroll --url https://iam.example.com'],
    async run(context) {
      const { flags } = context;
      const hostKey = (await readFile(context.path(flags['host-key'] ?? '/etc/ssh/ssh_host_ed25519_key.pub'), 'utf8')).trim();
      const setup = await (await context.api({ authenticated: false })).call<HostSetup>('ssh/enrollHost', {
        joinToken: flags['join-token'],
        publicKey: hostKey,
      });
      const files = await writeHostFiles(context, context.path(flags.root ?? '/'), setup, flags['dry-run']);
      return {
        host: setup.host.name,
        hostId: setup.host.id,
        certificateExpiresAt: new Date(setup.certificateExpiresAt).toISOString(),
        files,
        next: 'Schedule better-iam ssh-host-sync every 5 minutes, then reload sshd.',
      };
    },
  }),
  defineCommand({
    name: 'ssh-host-sync',
    group: 'Operations',
    summary: 'Refresh this server\'s SSH trust, principals, revocations and certificate',
    description:
      'ssh-host-sync runs on an enrolled server (every few minutes, from cron or a systemd timer): with the renewal token ssh-host-enroll saved, it fetches the current trusted user authorities, principals files and key revocation list, and a new host certificate when the current one nears its end or the host\'s addresses changed, and rewrites the files. Reload sshd when the certificate or trust changed; revocations and principals apply to the next login without a reload.',
    target: 'token',
    flags: {
      'renewal-token-file': {
        type: 'string',
        value: 'PATH',
        default: renewalTokenPath,
        description: 'Where ssh-host-enroll saved the renewal token',
      },
      renew: { type: 'boolean', description: 'Issue a new host certificate now' },
      root: rootFlag,
      'dry-run': { type: 'boolean', description: 'List the files without writing them' },
    },
    async run(context) {
      const { flags } = context;
      const root = context.path(flags.root ?? '/');
      const tokenFile = flags['renewal-token-file']
        ? context.path(flags['renewal-token-file'])
        : hostFilePath(root, renewalTokenPath);
      let renewalToken: string;
      try {
        renewalToken = (await readFile(tokenFile, 'utf8')).trim();
      } catch {
        throw new CliError('NOT_FOUND', `No renewal token at ${tokenFile}`, 'Enroll the host with ssh-host-enroll first.');
      }
      const setup = await (await context.api({ authenticated: false })).call<HostSetup>('ssh/syncHost', {
        renewalToken,
        ...(flags.renew ? { renew: true } : {}),
      });
      const files = await writeHostFiles(context, root, setup, flags['dry-run']);
      return {
        host: setup.host.name,
        certificateRenewed: setup.certificateRenewed,
        certificateExpiresAt: new Date(setup.certificateExpiresAt).toISOString(),
        revocationVersion: setup.revocationVersion,
        files,
      };
    },
  }),
  defineCommand({
    name: 'ssh-sweep',
    group: 'Operations',
    summary: 'Revoke SSH certificates whose holder or access went away',
    description:
      'ssh-sweep re-checks every live SSH user certificate (or one --tenant\'s): certificates of people and machines who are no longer active, whose temporary session ended, or whose hosts and logins policies no longer allow are revoked and published in the revocation list hosts fetch with ssh-host-sync. A deployment operation; run it every few minutes.',
    target: 'config',
    flags: {
      tenant: { type: 'string', value: 'TENANT_ID', description: 'Only this tenant' },
    },
    async run({ iam, flags }) {
      return (await iam()).ssh.sweep(flags.tenant ? { tenantId: flags.tenant } : {});
    },
  }),
];
