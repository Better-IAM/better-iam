import { describe, expect, it } from 'vitest';
import {
  legacyRiscSubject,
  parseSubjectIdentifier,
  readSecurityEvent,
  signalEventType,
  signalEventUris,
  SignalFormatError,
  userSubjects,
  type SignalEventType,
  type SubjectIdentifier,
} from '@better-iam/core';

const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';
const ISSUER = 'https://idp.example.com';
const long = 'x'.repeat(513);
const control = `a${String.fromCharCode(0)}b`;

/** The reason `readSecurityEvent` refuses the payload with, or `accepted`. */
function refusal(payload: Record<string, unknown>): string {
  try {
    readSecurityEvent(payload);
    return 'accepted';
  } catch (error) {
    expect(error).toBeInstanceOf(SignalFormatError);
    expect((error as SignalFormatError).name).toBe('SignalFormatError');
    return (error as SignalFormatError).reason;
  }
}

/** A well-formed CAEP session-revoked SET payload; `overrides` replace (or, as undefined, remove) claims. */
function setPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    aud: 'https://iam.example.test/api/iam/signals/push/src-1',
    iat: 1_790_000_000,
    jti: 'set-1',
    sub_id: { format: 'iss_sub', iss: ISSUER, sub: 'user-1' },
    events: {
      [`${CAEP}session-revoked`]: { event_timestamp: 1_789_999_990, initiating_entity: 'policy' },
    },
    ...overrides,
  };
  for (const [key, value] of Object.entries(overrides))
    if (value === undefined) delete payload[key];
  return payload;
}

describe('event types', () => {
  const namespaces: Record<Exclude<SignalEventType, 'unknown'>, string> = {
    'session-revoked': CAEP,
    'credential-change': CAEP,
    'token-claims-change': CAEP,
    'assurance-level-change': CAEP,
    'device-compliance-change': CAEP,
    'risk-level-change': CAEP,
    'account-disabled': RISC,
    'account-enabled': RISC,
    'account-purged': RISC,
    'account-credential-change-required': RISC,
    'credential-compromise': RISC,
    'identifier-changed': RISC,
    'identifier-recycled': RISC,
    'sessions-revoked': RISC,
    verification: SSF,
    'stream-updated': SSF,
  };

  it('names every known event by its CAEP, RISC or SSF URI and maps each URI back', () => {
    expect(Object.keys(signalEventUris).sort()).toEqual(Object.keys(namespaces).sort());
    for (const [type, namespace] of Object.entries(namespaces)) {
      const uri = signalEventUris[type as Exclude<SignalEventType, 'unknown'>];
      expect(uri).toBe(`${namespace}${type}`);
      expect(signalEventType(uri)).toBe(type);
    }
    expect(Object.isFrozen(signalEventUris)).toBe(true);
  });

  it('accepts the legacy RISC sessions-revoked and the pre-1.0 control event URIs', () => {
    expect(signalEventType(`${RISC}sessions-revoked`)).toBe('sessions-revoked');
    expect(signalEventType(`${RISC}verification`)).toBe('verification');
    expect(signalEventType(`${RISC}stream-updated`)).toBe('stream-updated');
    expect(signalEventType('https://schemas.openid.net/secevent/sse/event-type/verification')).toBe(
      'verification',
    );
  });

  it('reads anything else as unknown, matching URIs exactly', () => {
    for (const uri of [
      `${RISC}opt-out-initiated`,
      `${CAEP}session-revoked/`,
      `${CAEP}Session-Revoked`,
      'http://schemas.openid.net/secevent/caep/event-type/session-revoked',
      `${SSF}session-revoked`,
      'session-revoked',
      '',
      'constructor',
      '__proto__',
      'toString',
    ])
      expect(signalEventType(uri)).toBe('unknown');
    expect(signalEventType(42 as unknown as string)).toBe('unknown');
  });
});

describe('parseSubjectIdentifier', () => {
  const simple: SubjectIdentifier[] = [
    { format: 'iss_sub', iss: ISSUER, sub: '00u1abcd' },
    { format: 'email', email: 'Alice@Example.com' },
    { format: 'opaque', id: 'stream-1' },
    { format: 'account', uri: 'acct:alice@example.com' },
    { format: 'phone_number', phone_number: '+12065550100' },
    { format: 'did', url: 'did:example:123456789abcdefghi' },
    { format: 'uri', uri: 'https://example.com/users/alice' },
  ];

  it('reads every simple RFC 9493 format', () => {
    for (const subject of simple) expect(parseSubjectIdentifier(subject)).toEqual(subject);
  });

  it('leaves out members a format does not define and returns a fresh object', () => {
    const input = { format: 'email', email: 'alice@example.com', extra: { deep: true }, iss: 'x' };
    const parsed = parseSubjectIdentifier(input);
    expect(parsed).toEqual({ format: 'email', email: 'alice@example.com' });
    expect(parsed).not.toBe(input);
  });

  it('refuses unknown formats, missing members and values that are not objects', () => {
    for (const value of [
      undefined,
      null,
      'alice@example.com',
      42,
      [{ format: 'email', email: 'alice@example.com' }],
      {},
      { format: 'unknown', id: 'x' },
      { format: 'ISS_SUB', iss: ISSUER, sub: 'x' },
      { format: 'iss-sub', iss: ISSUER, sub: 'x' },
      { subject_type: 'email', email: 'alice@example.com' },
      { format: 'iss_sub', iss: ISSUER },
      { format: 'iss_sub', sub: 'x' },
      { format: 'email' },
      { format: 'opaque' },
      { format: 'account' },
      { format: 'phone_number', phone: '+12065550100' },
      { format: 'did', uri: 'did:example:1' },
      { format: 'uri' },
      Object.create({ format: 'email', email: 'alice@example.com' }),
    ])
      expect(parseSubjectIdentifier(value)).toBeUndefined();
  });

  it('refuses empty, overlong, non-string and control-character strings', () => {
    const bad = ['', long, 42, null, control, `a${String.fromCharCode(0x7f)}`, `a\u0085b`, 'a\nb'];
    for (const value of bad) {
      expect(parseSubjectIdentifier({ format: 'iss_sub', iss: value, sub: 'x' })).toBeUndefined();
      expect(
        parseSubjectIdentifier({ format: 'iss_sub', iss: ISSUER, sub: value }),
      ).toBeUndefined();
      expect(parseSubjectIdentifier({ format: 'opaque', id: value })).toBeUndefined();
      expect(
        parseSubjectIdentifier({ format: 'phone_number', phone_number: value }),
      ).toBeUndefined();
    }
    expect(parseSubjectIdentifier({ format: 'opaque', id: 'x'.repeat(512) })).toEqual({
      format: 'opaque',
      id: 'x'.repeat(512),
    });
  });

  it('checks the shape of email, account, DID and URI values', () => {
    for (const email of [
      'alice',
      '@example.com',
      'alice@',
      'alice smith@example.com',
      `${long}@x.io`,
    ])
      expect(parseSubjectIdentifier({ format: 'email', email })).toBeUndefined();
    for (const uri of ['alice@example.com', 'acct:alice', 'acct:@example.com', 'mailto:a@b.c'])
      expect(parseSubjectIdentifier({ format: 'account', uri })).toBeUndefined();
    expect(parseSubjectIdentifier({ format: 'account', uri: 'ACCT:alice@example.com' })).toEqual({
      format: 'account',
      uri: 'ACCT:alice@example.com',
    });
    for (const url of ['did:', 'did:example', 'did:Example:1', 'https://example.com', 'did:ex:a b'])
      expect(parseSubjectIdentifier({ format: 'did', url })).toBeUndefined();
    for (const uri of ['example.com/alice', '1http://x', 'https:', 'urn:a b'])
      expect(parseSubjectIdentifier({ format: 'uri', uri })).toBeUndefined();
    expect(parseSubjectIdentifier({ format: 'uri', uri: 'urn:uuid:4e5f' })).toEqual({
      format: 'uri',
      uri: 'urn:uuid:4e5f',
    });
  });

  it('reads alias lists of up to ten identifiers, never one inside another', () => {
    const identifiers = simple.slice(0, 3);
    expect(parseSubjectIdentifier({ format: 'aliases', identifiers })).toEqual({
      format: 'aliases',
      identifiers,
    });
    const ten = Array.from({ length: 10 }, (_, index) => ({ format: 'opaque', id: `id-${index}` }));
    expect(parseSubjectIdentifier({ format: 'aliases', identifiers: ten })).toBeDefined();
    expect(
      parseSubjectIdentifier({
        format: 'aliases',
        identifiers: [...ten, { format: 'opaque', id: 'id-10' }],
      }),
    ).toBeUndefined();
    expect(parseSubjectIdentifier({ format: 'aliases', identifiers: [] })).toBeUndefined();
    expect(parseSubjectIdentifier({ format: 'aliases' })).toBeUndefined();
    expect(
      parseSubjectIdentifier({ format: 'aliases', identifiers: { 0: simple[0] } }),
    ).toBeUndefined();
    // One malformed entry refuses the whole list.
    expect(
      parseSubjectIdentifier({ format: 'aliases', identifiers: [simple[0], { format: 'email' }] }),
    ).toBeUndefined();
    expect(
      parseSubjectIdentifier({
        format: 'aliases',
        identifiers: [simple[0], { format: 'aliases', identifiers: [simple[1]] }],
      }),
    ).toBeUndefined();
    // Nor through a complex subject inside the list.
    expect(
      parseSubjectIdentifier({
        format: 'aliases',
        identifiers: [{ format: 'complex', user: { format: 'aliases', identifiers: [simple[1]] } }],
      }),
    ).toBeUndefined();
  });

  it('reads complex subjects by their known members only', () => {
    const complex = {
      format: 'complex',
      user: { format: 'iss_sub', iss: ISSUER, sub: 'user-1' },
      session: { format: 'opaque', id: 'sid-1' },
      device: { format: 'opaque', id: 'device-1' },
      tenant: { format: 'opaque', id: 'tenant-1' },
      group: { format: 'opaque', id: 'group-1' },
      application: { format: 'uri', uri: 'https://app.example.com' },
      org_unit: { format: 'opaque', id: 'ou-1' },
    };
    expect(parseSubjectIdentifier(complex)).toEqual(complex);
    expect(parseSubjectIdentifier({ ...complex, printer: { format: 'opaque', id: 'p' } })).toEqual(
      complex,
    );
    // Only unknown members, or none, name nothing.
    expect(
      parseSubjectIdentifier({ format: 'complex', printer: { format: 'opaque', id: 'p' } }),
    ).toBeUndefined();
    expect(parseSubjectIdentifier({ format: 'complex' })).toBeUndefined();
    // A malformed known member refuses the subject.
    expect(parseSubjectIdentifier({ ...complex, session: { format: 'opaque' } })).toBeUndefined();
    expect(parseSubjectIdentifier({ ...complex, device: null })).toBeUndefined();
    expect(
      parseSubjectIdentifier({ format: 'complex', user: { format: 'complex', user: simple[0] } }),
    ).toBeUndefined();
  });

  it('allows three levels of nesting and no more', () => {
    const threeLevels = {
      format: 'complex',
      user: { format: 'aliases', identifiers: [simple[0], simple[1]] },
    };
    expect(parseSubjectIdentifier(threeLevels)).toEqual(threeLevels);
    const aliasOfComplex = {
      format: 'aliases',
      identifiers: [{ format: 'complex', user: simple[1] }, simple[0]],
    };
    expect(parseSubjectIdentifier(aliasOfComplex)).toEqual(aliasOfComplex);
    expect(
      parseSubjectIdentifier({
        format: 'aliases',
        identifiers: [{ format: 'complex', user: { format: 'aliases', identifiers: [simple[0]] } }],
      }),
    ).toBeUndefined();
    // A deeply nested value is refused without walking it.
    let deep: unknown = simple[0];
    for (let level = 0; level < 5000; level++) deep = { format: 'complex', user: deep };
    expect(parseSubjectIdentifier(deep)).toBeUndefined();
  });
});

describe('legacyRiscSubject', () => {
  it('maps Google RISC subject types to RFC 9493 formats', () => {
    const google = 'https://accounts.google.com/';
    expect(
      legacyRiscSubject({ subject_type: 'iss-sub', iss: google, sub: '7375626A656374' }),
    ).toEqual({ format: 'iss_sub', iss: google, sub: '7375626A656374' });
    expect(legacyRiscSubject({ subject_type: 'iss_sub', iss: google, sub: '1' })).toEqual({
      format: 'iss_sub',
      iss: google,
      sub: '1',
    });
    expect(legacyRiscSubject({ subject_type: 'email', email: 'alice@example.com' })).toEqual({
      format: 'email',
      email: 'alice@example.com',
    });
    expect(legacyRiscSubject({ subject_type: 'phone', phone: '+12065550100' })).toEqual({
      format: 'phone_number',
      phone_number: '+12065550100',
    });
    expect(legacyRiscSubject({ subject_type: 'id_token_claims', iss: google, sub: '1' })).toEqual({
      format: 'iss_sub',
      iss: google,
      sub: '1',
    });
    expect(
      legacyRiscSubject({
        subject_type: 'id_token_claims',
        iss: google,
        sub: '1',
        email: 'alice@example.com',
      }),
    ).toEqual({
      format: 'aliases',
      identifiers: [
        { format: 'iss_sub', iss: google, sub: '1' },
        { format: 'email', email: 'alice@example.com' },
      ],
    });
  });

  it('refuses unknown types and malformed members', () => {
    for (const value of [
      undefined,
      null,
      'iss-sub',
      {},
      { subject_type: 'opaque', id: 'x' },
      { format: 'iss_sub', iss: ISSUER, sub: 'x' },
      { subject_type: 'iss-sub', iss: ISSUER },
      { subject_type: 'iss-sub', iss: ISSUER, sub: long },
      { subject_type: 'email', email: 'alice' },
      { subject_type: 'phone', phone_number: '+12065550100' },
      { subject_type: 'phone', phone: control },
      { subject_type: 'id_token_claims' },
      { subject_type: 'id_token_claims', iss: ISSUER },
      { subject_type: 'id_token_claims', iss: ISSUER, sub: '1', email: 'nope' },
    ])
      expect(legacyRiscSubject(value)).toBeUndefined();
  });
});

describe('readSecurityEvent', () => {
  it('reads a CAEP SET: one audience list, event time in milliseconds, the sub_id subject', () => {
    const claims = readSecurityEvent(setPayload({ txn: 'txn-1' }));
    expect(claims).toEqual({
      iss: ISSUER,
      aud: ['https://iam.example.test/api/iam/signals/push/src-1'],
      iat: 1_790_000_000,
      jti: 'set-1',
      txn: 'txn-1',
      eventUri: `${CAEP}session-revoked`,
      eventType: 'session-revoked',
      event: { event_timestamp: 1_789_999_990, initiating_entity: 'policy' },
      subject: { format: 'iss_sub', iss: ISSUER, sub: 'user-1' },
      eventTimestamp: 1_789_999_990_000,
    });
    expect('txn' in readSecurityEvent(setPayload())).toBe(false);
  });

  it('normalizes audience lists and removes repeats', () => {
    expect(readSecurityEvent(setPayload({ aud: ['a', 'b', 'a'] })).aud).toEqual(['a', 'b']);
    expect(readSecurityEvent(setPayload({ aud: ['only'] })).aud).toEqual(['only']);
  });

  it('reads a legacy Google RISC SET with the subject inside the event', () => {
    const claims = readSecurityEvent({
      iss: 'https://accounts.google.com/',
      aud: '123456789-abc.apps.googleusercontent.com',
      iat: 1_790_000_000,
      jti: '756E69717565206964656E746966696572',
      events: {
        [`${RISC}account-disabled`]: {
          subject: {
            subject_type: 'iss-sub',
            iss: 'https://accounts.google.com/',
            sub: '7375626A',
          },
          reason: 'hijacking',
        },
      },
    });
    expect(claims.eventType).toBe('account-disabled');
    expect(claims.subject).toEqual({
      format: 'iss_sub',
      iss: 'https://accounts.google.com/',
      sub: '7375626A',
    });
    expect(claims.event).toEqual({ reason: 'hijacking' });
    expect(claims.eventTimestamp).toBeUndefined();
  });

  it('reads an RFC 9493 subject inside the event (pre-1.0 CAEP) and the toe claim', () => {
    const claims = readSecurityEvent(
      setPayload({
        sub_id: undefined,
        toe: 1_789_999_000.5,
        events: {
          [`${RISC}credential-compromise`]: {
            subject: { format: 'email', email: 'alice@example.com' },
            credential_type: 'password',
            reason_admin: { en: 'Found in a breach corpus' },
          },
        },
      }),
    );
    expect(claims.eventType).toBe('credential-compromise');
    expect(claims.subject).toEqual({ format: 'email', email: 'alice@example.com' });
    expect(claims.event).toEqual({
      credential_type: 'password',
      reason_admin: { en: 'Found in a breach corpus' },
    });
    expect(claims.eventTimestamp).toBe(1_789_999_000_500);
  });

  it('accepts the same subject in sub_id and the event, and refuses two different ones', () => {
    const subject = { format: 'email', email: 'alice@example.com' };
    const both = (inner: unknown) =>
      setPayload({
        sub_id: subject,
        events: { [`${CAEP}credential-change`]: { subject: inner, change_type: 'update' } },
      });
    expect(
      readSecurityEvent(both({ email: 'alice@example.com', format: 'email' })).subject,
    ).toEqual(subject);
    expect(refusal(both({ format: 'email', email: 'mallory@example.com' }))).toBe('subject');
    expect(refusal(both({ subject_type: 'email', email: 'mallory@example.com' }))).toBe('subject');
  });

  it('reads control events without a subject and unknown events as unknown', () => {
    const verification = readSecurityEvent(
      setPayload({ sub_id: undefined, events: { [`${SSF}verification`]: { state: 'abc' } } }),
    );
    expect(verification.eventType).toBe('verification');
    expect(verification.subject).toBeUndefined();
    expect(verification.event).toEqual({ state: 'abc' });
    const legacy = readSecurityEvent(
      setPayload({ sub_id: undefined, events: { [`${RISC}verification`]: {} } }),
    );
    expect(legacy.eventType).toBe('verification');
    const unknown = readSecurityEvent(
      setPayload({ events: { 'https://vendor.example.com/event/thing': { a: 1 } } }),
    );
    expect(unknown).toMatchObject({
      eventType: 'unknown',
      eventUri: 'https://vendor.example.com/event/thing',
    });
  });

  it('requires exactly one event, as an object', () => {
    expect(refusal(setPayload({ events: {} }))).toBe('events');
    expect(
      refusal(
        setPayload({
          events: { [`${CAEP}session-revoked`]: {}, [`${RISC}account-disabled`]: {} },
        }),
      ),
    ).toBe('events');
    expect(refusal(setPayload({ events: undefined }))).toBe('events');
    expect(refusal(setPayload({ events: [{}] }))).toBe('events');
    expect(refusal(setPayload({ events: 'session-revoked' }))).toBe('events');
    expect(refusal(setPayload({ events: { [`${CAEP}session-revoked`]: 'yes' } }))).toBe('events');
    expect(refusal(setPayload({ events: { [`${CAEP}session-revoked`]: null } }))).toBe('events');
    expect(refusal(setPayload({ events: { [`${CAEP}session-revoked`]: [] } }))).toBe('events');
    expect(refusal(setPayload({ events: { [control]: {} } }))).toBe('events');
  });

  it('refuses a nonce, which only ID tokens carry', () => {
    expect(refusal(setPayload({ nonce: 'n-0S6_WzA2Mj' }))).toBe('nonce');
    expect(refusal(setPayload({ nonce: null }))).toBe('nonce');
    expect(refusal(setPayload({ nonce: '' }))).toBe('nonce');
  });

  it('requires iss, jti, iat and aud', () => {
    expect(refusal(setPayload({ iss: undefined }))).toBe('claims');
    expect(refusal(setPayload({ jti: undefined }))).toBe('claims');
    expect(refusal(setPayload({ iat: undefined }))).toBe('claims');
    expect(refusal(setPayload({ aud: undefined }))).toBe('claims');
    expect(refusal(setPayload({ iss: '' }))).toBe('claims');
    expect(refusal(setPayload({ jti: 42 }))).toBe('claims');
    expect(refusal(setPayload({ jti: control }))).toBe('claims');
    expect(refusal(setPayload({ iat: '1790000000' }))).toBe('claims');
    expect(refusal(setPayload({ iat: 0 }))).toBe('claims');
    expect(refusal(setPayload({ iat: -1 }))).toBe('claims');
    expect(refusal(setPayload({ iat: Number.NaN }))).toBe('claims');
    expect(refusal(setPayload({ iat: 1e12 }))).toBe('claims');
    expect(refusal(setPayload({ aud: [] }))).toBe('claims');
    expect(refusal(setPayload({ aud: '' }))).toBe('claims');
    expect(refusal(setPayload({ aud: 42 }))).toBe('claims');
    expect(refusal(setPayload({ aud: ['a', 42] }))).toBe('claims');
    expect(refusal(setPayload({ txn: 42 }))).toBe('claims');
    expect(refusal(setPayload({ txn: null }))).toBe('claims');
    expect(refusal(null as unknown as Record<string, unknown>)).toBe('claims');
    expect(refusal([] as unknown as Record<string, unknown>)).toBe('claims');
  });

  it('refuses oversized strings and audience lists', () => {
    expect(refusal(setPayload({ iss: long }))).toBe('size');
    expect(refusal(setPayload({ jti: long }))).toBe('size');
    expect(refusal(setPayload({ txn: long }))).toBe('size');
    expect(refusal(setPayload({ aud: long }))).toBe('size');
    expect(refusal(setPayload({ aud: ['a', long] }))).toBe('size');
    expect(refusal(setPayload({ sub: long }))).toBe('size');
    expect(refusal(setPayload({ aud: Array.from({ length: 21 }, (_, i) => `aud-${i}`) }))).toBe(
      'size',
    );
    expect(readSecurityEvent(setPayload({ jti: 'j'.repeat(512) })).jti).toHaveLength(512);
    expect(refusal(setPayload({ events: { [`https://e.example/${long}`]: {} } }))).toBe('size');
    // Oversized subject strings make the subject invalid.
    expect(refusal(setPayload({ sub_id: { format: 'opaque', id: long } }))).toBe('subject');
  });

  it('refuses deeply nested subjects and event claims', () => {
    expect(
      refusal(
        setPayload({
          sub_id: {
            format: 'aliases',
            identifiers: [
              {
                format: 'complex',
                user: { format: 'aliases', identifiers: [{ format: 'opaque', id: 'x' }] },
              },
            ],
          },
        }),
      ),
    ).toBe('subject');
    let nested: unknown = { leaf: true };
    for (let level = 0; level < 10; level++) nested = { nested };
    expect(refusal(setPayload({ events: { [`${CAEP}token-claims-change`]: nested } }))).toBe(
      'size',
    );
    let fine: unknown = { leaf: true };
    for (let level = 0; level < 8; level++) fine = [fine];
    expect(
      readSecurityEvent(
        setPayload({ events: { [`${CAEP}token-claims-change`]: { claims: fine } } }),
      ).eventType,
    ).toBe('token-claims-change');
  });

  it('refuses malformed subjects', () => {
    expect(refusal(setPayload({ sub_id: { format: 'email', email: 'nope' } }))).toBe('subject');
    expect(refusal(setPayload({ sub_id: 'user-1' }))).toBe('subject');
    expect(refusal(setPayload({ sub_id: null }))).toBe('subject');
    const legacy = (subject: unknown) =>
      setPayload({ sub_id: undefined, events: { [`${RISC}account-purged`]: { subject } } });
    expect(refusal(legacy({ subject_type: 'unknown', id: 'x' }))).toBe('subject');
    expect(refusal(legacy('alice@example.com'))).toBe('subject');
    expect(refusal(legacy(null))).toBe('subject');
    expect(refusal(legacy({ format: 'iss_sub', iss: ISSUER }))).toBe('subject');
  });

  it('refuses a sub claim contradicting an iss_sub subject of the same issuer', () => {
    expect(refusal(setPayload({ sub: 'user-2' }))).toBe('subject');
    expect(
      refusal(
        setPayload({
          sub: 'user-2',
          sub_id: {
            format: 'complex',
            user: { format: 'iss_sub', iss: `${ISSUER}/`, sub: 'user-1' },
          },
        }),
      ),
    ).toBe('subject');
    expect(readSecurityEvent(setPayload({ sub: 'user-1' })).subject).toEqual({
      format: 'iss_sub',
      iss: ISSUER,
      sub: 'user-1',
    });
    // Another issuer's subject, or an email, cannot be compared with sub.
    expect(
      readSecurityEvent(
        setPayload({
          sub: 'user-2',
          sub_id: { format: 'iss_sub', iss: 'https://other', sub: 'x' },
        }),
      ).subject,
    ).toBeDefined();
    expect(
      readSecurityEvent(setPayload({ sub: 'user-2', sub_id: { format: 'email', email: 'a@b.c' } }))
        .subject,
    ).toBeDefined();
    expect(refusal(setPayload({ sub: 42 }))).toBe('claims');
  });

  it('refuses a malformed event time', () => {
    const at = (event_timestamp: unknown) =>
      setPayload({ events: { [`${CAEP}session-revoked`]: { event_timestamp } } });
    expect(refusal(at('2026-09-24T00:00:00Z'))).toBe('claims');
    expect(refusal(at(-5))).toBe('claims');
    expect(refusal(at(Number.POSITIVE_INFINITY))).toBe('claims');
    expect(refusal(setPayload({ toe: 'now' }))).toBe('claims');
    // event_timestamp wins over toe.
    expect(readSecurityEvent(setPayload({ toe: 1_700_000_000 })).eventTimestamp).toBe(
      1_789_999_990_000,
    );
  });

  it('reads only its own members', () => {
    const payload = Object.assign(Object.create({ nonce: 'inherited' }), setPayload());
    expect(readSecurityEvent(payload).jti).toBe('set-1');
    const parsed = JSON.parse(
      `{"iss":"${ISSUER}","aud":"a","iat":1790000000,"jti":"j","__proto__":{"nonce":"x"},` +
        `"events":{"${CAEP}session-revoked":{"__proto__":{"polluted":true}}}}`,
    ) as Record<string, unknown>;
    const claims = readSecurityEvent(parsed);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getPrototypeOf(claims.event)).toBe(Object.prototype);
  });
});

describe('userSubjects', () => {
  const issSub: SubjectIdentifier = { format: 'iss_sub', iss: ISSUER, sub: 'user-1' };
  const email: SubjectIdentifier = { format: 'email', email: 'alice@example.com' };

  it('keeps identifiers that may name a person', () => {
    for (const subject of [
      issSub,
      email,
      { format: 'opaque', id: '00u1' },
      { format: 'account', uri: 'acct:alice@example.com' },
      { format: 'phone_number', phone_number: '+12065550100' },
    ] satisfies SubjectIdentifier[])
      expect(userSubjects(subject)).toEqual([subject]);
    expect(userSubjects(undefined)).toEqual([]);
    expect(userSubjects({ format: 'did', url: 'did:example:1' })).toEqual([]);
    expect(userSubjects({ format: 'uri', uri: 'https://example.com/u/1' })).toEqual([]);
  });

  it('expands complex users and alias lists, without repeats', () => {
    expect(
      userSubjects({
        format: 'complex',
        user: { format: 'aliases', identifiers: [issSub, email] },
        session: { format: 'opaque', id: 'sid-1' },
        device: { format: 'opaque', id: 'device-1' },
      }),
    ).toEqual([issSub, email]);
    expect(
      userSubjects({
        format: 'aliases',
        identifiers: [
          email,
          { format: 'complex', user: issSub },
          { format: 'email', email: 'alice@example.com' },
          { format: 'did', url: 'did:example:1' },
        ],
      }),
    ).toEqual([email, issSub]);
  });

  it('leaves out session, device and organization subjects', () => {
    expect(
      userSubjects({
        format: 'complex',
        session: { format: 'opaque', id: 'sid-1' },
        device: { format: 'opaque', id: 'device-1' },
        tenant: { format: 'opaque', id: 'tenant-1' },
        group: { format: 'opaque', id: 'group-1' },
        application: { format: 'opaque', id: 'app-1' },
        org_unit: { format: 'opaque', id: 'ou-1' },
      }),
    ).toEqual([]);
  });
});
