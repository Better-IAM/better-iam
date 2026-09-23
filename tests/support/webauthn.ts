import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

/** Minimal CBOR encoder for the COSE key and attestation object a registration carries. */
export function cbor(value: unknown): Buffer {
  const header = (major: number, size: number): Buffer =>
    size < 24
      ? Buffer.from([(major << 5) | size])
      : size < 256
        ? Buffer.from([(major << 5) | 24, size])
        : Buffer.from([(major << 5) | 25, size >> 8, size & 255]);
  if (typeof value === 'number') return header(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([header(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (value instanceof Map)
    return Buffer.concat([
      header(5, value.size),
      ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)]),
    ]);
  throw new Error('Unsupported CBOR test value');
}

/**
 * A virtual platform authenticator for one relying party: it produces real P-256 registration and assertion
 * responses (user-verified, resident) so the verifier runs unmocked.
 */
export class VirtualAuthenticator {
  readonly credentialId = randomBytes(32);
  private readonly key: { publicKey: KeyObject; privateKey: KeyObject };
  private readonly rpHash: Buffer;
  private counter = 0;

  constructor(
    readonly rpId: string,
    readonly origin: string,
  ) {
    this.key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.rpHash = createHash('sha256').update(rpId).digest();
  }

  register(challenge: string) {
    const jwk = this.key.publicKey.export({ format: 'jwk' });
    const cose = cbor(
      new Map<unknown, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x!, 'base64url')],
        [-3, Buffer.from(jwk.y!, 'base64url')],
      ]),
    );
    const authData = Buffer.concat([
      this.rpHash,
      Buffer.from([0x45]),
      Buffer.alloc(4),
      Buffer.alloc(16),
      Buffer.from([0, this.credentialId.length]),
      this.credentialId,
      cose,
    ]);
    const clientData = Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge, origin: this.origin }),
    );
    return {
      id: this.credentialId.toString('base64url'),
      rawId: this.credentialId.toString('base64url'),
      type: 'public-key' as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientData.toString('base64url'),
        attestationObject: cbor(
          new Map<unknown, unknown>([
            ['fmt', 'none'],
            ['attStmt', new Map()],
            ['authData', authData],
          ]),
        ).toString('base64url'),
        transports: ['internal' as const],
      },
    };
  }

  assert(challenge: string, userId: string, origin = this.origin) {
    this.counter += 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const authData = Buffer.concat([this.rpHash, Buffer.from([0x05]), counter]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
    return {
      id: this.credentialId.toString('base64url'),
      rawId: this.credentialId.toString('base64url'),
      type: 'public-key' as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientData.toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: sign(
          'sha256',
          Buffer.concat([authData, createHash('sha256').update(clientData).digest()]),
          this.key.privateKey,
        ).toString('base64url'),
        userHandle: Buffer.from(userId).toString('base64url'),
      },
    };
  }
}
