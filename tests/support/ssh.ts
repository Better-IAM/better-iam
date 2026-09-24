import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const write = (parts: Buffer[]) => {
  const out: Buffer[] = [];
  for (const part of parts) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(part.length);
    out.push(length, part);
  }
  return Buffer.concat(out);
};
const mpint = (value: Buffer) => (value[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value);

/** A fresh OpenSSH public key line generated in-process (no ssh-keygen needed). */
export function sshPublicKey(
  type: 'ed25519' | 'ecdsa' | 'rsa' | 'sk-ed25519' = 'ed25519',
  comment = 'test@example',
): string {
  if (type === 'ed25519' || type === 'sk-ed25519') {
    const { publicKey } = generateKeyPairSync('ed25519');
    const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url');
    const name = type === 'ed25519' ? 'ssh-ed25519' : 'sk-ssh-ed25519@openssh.com';
    const blob = write([
      Buffer.from(name),
      raw,
      ...(type === 'sk-ed25519' ? [Buffer.from('ssh:')] : []),
    ]);
    return `${name} ${blob.toString('base64')} ${comment}`;
  }
  if (type === 'ecdsa') {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const point = Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x!, 'base64url'),
      Buffer.from(jwk.y!, 'base64url'),
    ]);
    const blob = write([Buffer.from('ecdsa-sha2-nistp256'), Buffer.from('nistp256'), point]);
    return `ecdsa-sha2-nistp256 ${blob.toString('base64')} ${comment}`;
  }
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const blob = write([
    Buffer.from('ssh-rsa'),
    mpint(Buffer.from(jwk.e!, 'base64url')),
    mpint(Buffer.from(jwk.n!, 'base64url')),
  ]);
  return `ssh-rsa ${blob.toString('base64')} ${comment}`;
}

/** The system's ssh-keygen, when installed (OpenSSH on Linux/macOS, Windows' optional OpenSSH client). */
export function sshKeygen(): string | undefined {
  for (const candidate of ['ssh-keygen', 'C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe']) {
    try {
      execFileSync(candidate, ['-?'], { stdio: 'pipe' });
      return candidate;
    } catch (error) {
      // `-?` exits non-zero after printing usage; only a missing binary is ENOENT.
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return candidate;
    }
  }
  return undefined;
}

/** Runs ssh-keygen with files written to a temporary directory; returns stdout (stderr folded in). */
export function withSshFiles<T>(
  files: Record<string, string | Buffer>,
  run: (path: (name: string) => string) => T,
): T {
  const directory = mkdtempSync(join(tmpdir(), 'better-iam-ssh-'));
  try {
    for (const [name, content] of Object.entries(files)) writeFileSync(join(directory, name), content);
    return run((name) => join(directory, name));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function runKeygen(binary: string, args: string[]): { status: number; output: string } {
  try {
    const output = execFileSync(binary, args, { stdio: 'pipe' });
    return { status: 0, output: output.toString() };
  } catch (error) {
    const failure = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: failure.status ?? 1,
      output: `${failure.stdout?.toString() ?? ''}${failure.stderr?.toString() ?? ''}`,
    };
  }
}
