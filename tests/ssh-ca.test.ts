import { describe, expect, it } from 'vitest';
import {
  SSH_CERT_HOST,
  SSH_CERT_USER,
  buildSshKrl,
  generateSshAuthorityKey,
  parseSshCertificate,
  parseSshPublicKey,
  signSshCertificate,
  sshHostAddress,
  sshKeyLine,
  sshLogin,
  sshSerial,
  sshSigningKey,
} from '@better-iam/server';
import { runKeygen, sshKeygen, sshPublicKey, withSshFiles } from './support/ssh.js';

const keygen = sshKeygen();
const authority = () => {
  const generated = generateSshAuthorityKey();
  return sshSigningKey(generated.publicBlob, generated.privatePkcs8);
};

describe('SSH certificate primitives', () => {
  it('parses every supported key type and refuses malformed keys', () => {
    for (const type of ['ed25519', 'ecdsa', 'rsa', 'sk-ed25519'] as const) {
      const key = parseSshPublicKey(sshPublicKey(type, 'alice@laptop'));
      expect(key.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
      expect(key.comment).toBe('alice@laptop');
      expect(key.securityKey).toBe(type === 'sk-ed25519');
      if (type === 'rsa') expect(key.bits).toBe(2048);
    }
    const good = sshPublicKey();
    const [, data] = good.split(' ');
    expect(() => parseSshPublicKey('ssh-dss AAAA')).toThrow(/Unsupported key type/);
    expect(() => parseSshPublicKey(`ecdsa-sha2-nistp256 ${data}`)).toThrow(/does not match/);
    expect(() => parseSshPublicKey(`ssh-ed25519 ${data}AAAA`)).toThrow();
    expect(() => parseSshPublicKey('ssh-ed25519-cert-v01@openssh.com AAAA')).toThrow(
      /not a certificate/,
    );
    expect(() => parseSshPublicKey('ssh-ed25519')).toThrow();
  });

  it('issues certificates that verify, decode, and survive a round trip', () => {
    const ca = authority();
    const key = parseSshPublicKey(sshPublicKey('ecdsa'));
    const serial = sshSerial();
    const { line } = signSshCertificate(ca, {
      key,
      serial,
      kind: SSH_CERT_USER,
      keyId: 'alice@acme.test',
      principals: ['deploy@web-01', 'root@db-01'],
      validAfter: 1_700_000_000,
      validBefore: 1_700_003_600,
      criticalOptions: { 'source-address': '203.0.113.7/32' },
      extensions: ['permit-pty', 'permit-port-forwarding', 'permit-X11-forwarding'],
    });
    expect(line.startsWith('ecdsa-sha2-nistp256-cert-v01@openssh.com ')).toBe(true);
    const parsed = parseSshCertificate(line);
    expect(parsed).toMatchObject({
      keyType: 'ecdsa-sha2-nistp256',
      publicKeyFingerprint: key.fingerprint,
      serial,
      kind: SSH_CERT_USER,
      keyId: 'alice@acme.test',
      principals: ['deploy@web-01', 'root@db-01'],
      validAfter: 1_700_000_000,
      validBefore: 1_700_003_600,
      criticalOptions: { 'source-address': '203.0.113.7/32' },
      // Lexical (byte) order: uppercase X sorts first.
      extensions: ['permit-X11-forwarding', 'permit-port-forwarding', 'permit-pty'],
      signatureValid: true,
    });
    expect(sshKeyLine(parsed.signatureKey)).toBe(sshKeyLine(ca.publicBlob));
    // A flipped byte in the body breaks the signature.
    const [type, data] = line.split(' ');
    const blob = Buffer.from(data!, 'base64');
    blob[blob.length - 200] ^= 1;
    expect(parseSshCertificate(`${type} ${blob.toString('base64')}`).signatureValid).toBe(false);
  });

  it('validates host addresses and logins', () => {
    expect(sshHostAddress('Web-01.Prod.Example.com.')).toBe('web-01.prod.example.com');
    expect(sshHostAddress('10.0.0.5')).toBe('10.0.0.5');
    expect(sshHostAddress('2001:db8::1')).toBe('2001:db8::1');
    expect(() => sshHostAddress('*.example.com')).toThrow();
    expect(() => sshHostAddress('bad host')).toThrow();
    expect(sshLogin('deploy')).toBe('deploy');
    expect(sshLogin('_svc.ci-1')).toBe('_svc.ci-1');
    for (const bad of ['root@x', '1abc', 'a b', '', 'x'.repeat(33), 'dot.'])
      expect(() => sshLogin(bad)).toThrow();
  });

  it.skipIf(!keygen)('produces certificates and revocation lists ssh-keygen accepts', () => {
    const ca = authority();
    for (const type of ['ed25519', 'ecdsa', 'rsa'] as const) {
      const publicKey = sshPublicKey(type);
      const key = parseSshPublicKey(publicKey);
      const serial = sshSerial();
      const { line } = signSshCertificate(ca, {
        key,
        serial,
        kind: type === 'rsa' ? SSH_CERT_HOST : SSH_CERT_USER,
        keyId: `key-${type}`,
        principals: ['deploy@web-01'],
        validAfter: 1_700_000_000,
        validBefore: 4_100_000_000,
        criticalOptions: type === 'ed25519' ? { 'force-command': '/usr/bin/true' } : {},
        extensions: type === 'rsa' ? [] : ['permit-pty', 'permit-agent-forwarding'],
      });
      const other = signSshCertificate(ca, {
        key,
        serial: serial + 1n,
        kind: SSH_CERT_USER,
        keyId: 'other',
        principals: ['x'],
        validAfter: 0,
        validBefore: 4_100_000_000,
      });
      const krl = buildSshKrl({
        version: 7n,
        generatedAt: Date.now(),
        comment: 'test',
        authorities: [{ authority: ca.publicBlob, serials: [serial, 99n], keyIds: ['nobody'] }],
      });
      withSshFiles(
        { 'cert.pub': `${line}\n`, 'other.pub': `${other.line}\n`, 'revoked.krl': krl },
        (path) => {
          const listed = runKeygen(keygen!, ['-L', '-f', path('cert.pub')]);
          expect(listed.status, listed.output).toBe(0);
          expect(listed.output).toContain(`Key ID: "key-${type}"`);
          expect(listed.output).toContain(`Serial: ${serial}`);
          expect(listed.output).toContain('deploy@web-01');
          expect(listed.output).toContain(type === 'rsa' ? 'host certificate' : 'user certificate');
          if (type === 'ed25519') expect(listed.output).toContain('force-command /usr/bin/true');
          const revoked = runKeygen(keygen!, ['-Q', '-f', path('revoked.krl'), path('cert.pub')]);
          expect(revoked.output).toContain('REVOKED');
          const fine = runKeygen(keygen!, ['-Q', '-f', path('revoked.krl'), path('other.pub')]);
          expect(fine.status, fine.output).toBe(0);
          expect(fine.output).not.toContain('REVOKED');
        },
      );
    }
  });
});
