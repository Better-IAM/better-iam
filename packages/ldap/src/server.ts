import { createServer as createTcpServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { createServer as createTlsServer, type TLSSocket, type TlsOptions } from 'node:tls';
import { BerError, readElement } from './ber.js';
import { buildEntries, selectAttributes, type DirectoryData, type DirectoryEntry } from './directory.js';
import { depthBelow, DnError, formatDn, isUnder, normalizeDn, parseDn } from './dn.js';
import { matchFilter } from './filter.js';
import {
  OID,
  ResultCode,
  bindResponse,
  compareResponse,
  decodeMessage,
  extendedResponse,
  genericResponse,
  noticeOfDisconnection,
  pagedResultsControl,
  readPagedResults,
  searchDone,
  searchEntry,
  type LdapMessage,
  type LdapRequest,
} from './protocol.js';

/** What the gateway needs from a `betterIam()` instance (structural, so this package depends on core only). */
export interface LdapIam {
  api: {
    auth: {
      signIn(input: { tenantId: string; email: string; password: string }): Promise<unknown>;
      verifyMfa(input: { tenantId: string; challenge: string; code: string }): Promise<unknown>;
      signOut(credential: { token: string }): Promise<unknown>;
    };
    ldap: {
      directory(credential: { token: string }, input: { tenantId: string }): Promise<DirectoryData>;
    };
  };
  authenticate(credential: { token: string }): Promise<{
    identity: { id: string; tenantId: string; kind: string };
    session: { tenantId: string; kind: string };
  }>;
  auth: {
    withClient<T>(client: { ip?: string; userAgent?: string } | undefined, fn: () => Promise<T>): Promise<T>;
  };
  ldap: {
    tenantForBase(normalizedBaseDn: string): Promise<
      | {
          tenantId: string;
          baseDn: string;
          normalizedBaseDn: string;
          peopleBind: boolean;
          serviceBind: boolean;
          requireTls: boolean;
          mfaSuffix: 'auto' | 'never';
        }
      | undefined
    >;
    resolveBindName(
      tenantId: string,
      kind: 'person' | 'service',
      value: string,
    ): Promise<{ identityId: string; email?: string; mfa?: 'none' | 'totp' | 'unavailable' } | undefined>;
  };
}

export interface LdapServerOptions {
  iam: LdapIam;
  /** Serve LDAPS (TLS from the first byte) with these options (`key`, `cert`, ...). Without them, plain LDAP. */
  tls?: TlsOptions;
  /** The most entries one search returns, and the largest page (default 1000). */
  maxResults?: number;
  /** Connections idle this long are closed (default 5 minutes). */
  idleTimeoutMs?: number;
  /** The largest request accepted (default 64 KiB). */
  maxRequestBytes?: number;
  /** How long a connection reuses a directory snapshot between searches (default 5 seconds). */
  cacheMs?: number;
  /** The most simultaneous connections (default 1000). */
  maxConnections?: number;
  /** Called with errors the gateway could not answer (logging). */
  onError?(error: unknown): void;
}

/** A bound connection: the tenant, the bound DN, and the credential searches use. */
interface Binding {
  tenantId: string;
  baseDn: string;
  normalizedBaseDn: string;
  dn: string;
  credential: { token: string };
  /** The gateway created the session (a person's bind) and signs it out when the binding ends. */
  owned: boolean;
}

interface Connection {
  socket: Socket;
  secure: boolean;
  buffer: Buffer;
  binding?: Binding;
  cache?: { at: number; tenantId: string; entries: DirectoryEntry[]; scope: 'full' | 'self' };
  queue: Promise<void>;
  closed: boolean;
}

const loopback = (address: string | undefined) =>
  !address || address === '::1' || address.startsWith('127.') || address === '::ffff:127.0.0.1';

const credentialOf = (value: unknown): { token: string } | undefined =>
  value && typeof value === 'object' && typeof (value as { token?: unknown }).token === 'string'
    ? { token: (value as { token: string }).token }
    : undefined;

/**
 * A read-only LDAPv3 gateway over Better IAM. Applications bind as a person (`uid={uid},ou=people,{base}` with the
 * password, plus the current one-time code appended when the organization requires MFA) or as a service account
 * (`cn={name},ou=services,{base}` with an API key as the password), then search people, groups and service accounts
 * of the organization whose base DN they use. Binds go through Better IAM sign-in, so rate limits, lockouts, allowed
 * methods, IP rules and sign-in alerts apply; searches are authorized as the bound account (`iam:ldap:read` for the
 * whole directory, otherwise only its own entry). Writes are refused.
 */
export function createLdapServer(options: LdapServerOptions) {
  const { iam } = options;
  const maxResults = options.maxResults ?? 1000;
  const idleTimeoutMs = options.idleTimeoutMs ?? 5 * 60_000;
  const maxRequestBytes = options.maxRequestBytes ?? 65536;
  const cacheMs = options.cacheMs ?? 5000;
  const maxConnections = options.maxConnections ?? 1000;
  const connections = new Set<Connection>();

  const write = (connection: Connection, ...chunks: Buffer[]) => {
    if (!connection.closed && connection.socket.writable) connection.socket.write(Buffer.concat(chunks));
  };

  async function release(binding: Binding | undefined) {
    if (binding?.owned) await iam.api.auth.signOut(binding.credential).catch(() => undefined);
  }

  async function close(connection: Connection, notice?: Buffer) {
    if (connection.closed) return;
    if (notice) write(connection, notice);
    connection.closed = true;
    connections.delete(connection);
    const binding = connection.binding;
    connection.binding = undefined;
    connection.socket.end();
    await release(binding);
  }

  /** The tenant whose base DN `dn` lies under: the longest matching suffix. */
  async function tenantOf(dn: string) {
    const rdns = parseDn(dn);
    for (let start = 0; start < rdns.length; start++) {
      const suffix = normalizeDn(formatDn(rdns.slice(start)));
      const found = await iam.ldap.tenantForBase(suffix);
      if (found) return { ...found, relative: rdns.slice(0, start) };
    }
    return undefined;
  }

  async function bind(connection: Connection, id: number, request: Extract<LdapRequest, { op: 'bind' }>) {
    const previous = connection.binding;
    connection.binding = undefined;
    connection.cache = undefined;
    await release(previous);
    if (request.version !== 3) return write(connection, bindResponse(id, ResultCode.protocolError, 'Only LDAPv3 is supported'));
    if (request.sasl) return write(connection, bindResponse(id, ResultCode.authMethodNotSupported, 'Use a simple bind'));
    const password = request.password?.toString('utf8') ?? '';
    if (!request.name && !password) return write(connection, bindResponse(id, ResultCode.success));
    // RFC 4513 5.1.2: a name with an empty password is an unauthenticated bind; never treat it as signed in.
    if (!password) return write(connection, bindResponse(id, ResultCode.unwillingToPerform, 'Unauthenticated binds are not allowed'));
    const invalid = () => write(connection, bindResponse(id, ResultCode.invalidCredentials, 'Invalid credentials'));
    let target: Awaited<ReturnType<typeof tenantOf>>;
    try {
      target = await tenantOf(request.name);
    } catch {
      return write(connection, bindResponse(id, ResultCode.invalidDNSyntax, 'Invalid DN'));
    }
    if (!target || target.relative.length !== 2) return invalid();
    if (target.requireTls && !connection.secure && !loopback(connection.socket.remoteAddress))
      return write(connection, bindResponse(id, ResultCode.confidentialityRequired, 'Bind over TLS (LDAPS)'));
    const [leaf, container] = target.relative as [{ type: string; value: string }[], { type: string; value: string }[]];
    const ou = container.length === 1 && container[0]!.type.toLowerCase() === 'ou' ? container[0]!.value.toLowerCase() : '';
    const rdn = leaf.length === 1 ? leaf[0]! : undefined;
    const client = { ip: connection.socket.remoteAddress, userAgent: 'better-iam-ldap' };
    const displayDn = request.name;
    try {
      if (ou === 'people' && rdn?.type.toLowerCase() === 'uid' && target.peopleBind) {
        const person = await iam.ldap.resolveBindName(target.tenantId, 'person', rdn.value);
        if (!person?.email) return invalid();
        const credential = await signInPerson(
          target.tenantId,
          { email: person.email, ...(person.mfa ? { mfa: person.mfa } : {}) },
          password,
          target.mfaSuffix,
          client,
        );
        if (!credential) return invalid();
        connection.binding = {
          tenantId: target.tenantId,
          baseDn: target.baseDn,
          normalizedBaseDn: target.normalizedBaseDn,
          dn: displayDn,
          credential,
          owned: true,
        };
        return write(connection, bindResponse(id, ResultCode.success));
      }
      if (ou === 'services' && rdn?.type.toLowerCase() === 'cn' && target.serviceBind) {
        const service = await iam.ldap.resolveBindName(target.tenantId, 'service', rdn.value);
        if (!service) return invalid();
        const principal = await iam.auth.withClient(client, () => iam.authenticate({ token: password }));
        if (
          principal.identity.id !== service.identityId ||
          principal.session.tenantId !== target.tenantId ||
          principal.session.kind !== 'api-key'
        )
          return invalid();
        connection.binding = {
          tenantId: target.tenantId,
          baseDn: target.baseDn,
          normalizedBaseDn: target.normalizedBaseDn,
          dn: displayDn,
          credential: { token: password },
          owned: false,
        };
        return write(connection, bindResponse(id, ResultCode.success));
      }
      return invalid();
    } catch (error) {
      if ((error as { code?: string }).code === 'RATE_LIMITED')
        return write(connection, bindResponse(id, ResultCode.unwillingToPerform, 'Too many attempts; try again later'));
      return invalid();
    }
  }

  /**
   * Signs a person in: with the password, or, when they must use MFA and `mfaSuffix` allows it, with the password
   * followed by the current six-digit authenticator code. Exactly one sign-in attempt per bind, so a person's own
   * binds never count as failed sign-ins.
   */
  async function signInPerson(
    tenantId: string,
    person: { email: string; mfa?: 'none' | 'totp' | 'unavailable' },
    password: string,
    mfaSuffix: 'auto' | 'never',
    client: { ip?: string; userAgent?: string },
  ): Promise<{ token: string } | undefined> {
    const signIn = (secret: string) =>
      iam.auth.withClient(client, () => iam.api.auth.signIn({ tenantId, email: person.email, password: secret }));
    const mfa = person.mfa ?? 'none';
    if (mfa === 'unavailable') return undefined;
    if (mfa === 'none') {
      const direct = credentialOf(await signIn(password));
      return direct;
    }
    if (mfaSuffix !== 'auto' || !/^.+\d{6}$/s.test(password)) return undefined;
    const result = (await signIn(password.slice(0, -6))) as { mfaRequired?: boolean; challenge?: string } | undefined;
    const direct = credentialOf(result);
    // MFA stopped being required in the meantime: the digits were not part of the password.
    if (direct) return void (await iam.api.auth.signOut(direct).catch(() => undefined));
    if (!result?.mfaRequired || !result.challenge) return undefined;
    const verified = await iam.auth.withClient(client, () =>
      iam.api.auth.verifyMfa({ tenantId, challenge: result.challenge!, code: password.slice(-6) }),
    );
    return credentialOf(verified);
  }
  async function entriesFor(connection: Connection): Promise<{ entries: DirectoryEntry[]; scope: 'full' | 'self' }> {
    const binding = connection.binding!;
    const now = Date.now();
    if (connection.cache && connection.cache.tenantId === binding.tenantId && now - connection.cache.at < cacheMs)
      return connection.cache;
    const data = await iam.api.ldap.directory(binding.credential, { tenantId: binding.tenantId });
    connection.cache = { at: now, tenantId: binding.tenantId, entries: buildEntries(data), scope: data.scope };
    return connection.cache;
  }

  const rootDse = () => [
    ['objectClass', ['top', 'extensibleObject']],
    ['supportedLDAPVersion', ['3']],
    ['supportedExtension', [OID.whoAmI]],
    ['supportedControl', [OID.pagedResults]],
    ['supportedSASLMechanisms', []],
    ['vendorName', ['Better IAM']],
  ] as [string, string[]][];

  async function search(connection: Connection, message: LdapMessage, request: Extract<LdapRequest, { op: 'search' }>) {
    const { id } = message;
    if (!request.base && request.scope === 'base') {
      const attributes = rootDse();
      const naming: [string, string[]][] = connection.binding
        ? [['namingContexts', [connection.binding.baseDn]]]
        : [];
      write(connection, searchEntry(id, '', [...attributes, ...naming].filter(([, values]) => values.length), request.typesOnly));
      return write(connection, searchDone(id, ResultCode.success));
    }
    const binding = connection.binding;
    if (!binding) return write(connection, searchDone(id, ResultCode.insufficientAccessRights, 'Bind first'));
    let base: string;
    try {
      base = normalizeDn(request.base);
    } catch {
      return write(connection, searchDone(id, ResultCode.invalidDNSyntax, 'Invalid base DN'));
    }
    // Another organization's tree does not exist for this binding.
    if (!isUnder(base, binding.normalizedBaseDn))
      return write(connection, searchDone(id, ResultCode.noSuchObject, 'No such object'));
    let entries: DirectoryEntry[];
    try {
      ({ entries } = await entriesFor(connection));
    } catch {
      return write(connection, searchDone(id, ResultCode.insufficientAccessRights, 'Access denied'));
    }
    if (!entries.some((item) => item.normalizedDn === base))
      return write(connection, searchDone(id, ResultCode.noSuchObject, 'No such object', binding.normalizedBaseDn));
    const matches = entries.filter((item) => {
      const depth = depthBelow(item.normalizedDn, base);
      const inScope = request.scope === 'base' ? depth === 0 : request.scope === 'one' ? depth === 1 : depth >= 0;
      return inScope && matchFilter(request.filter, item.index);
    });
    const paging = message.controls.find((control) => control.type === OID.pagedResults);
    if (paging) {
      const page = readPagedResults(paging.value);
      const size = Math.min(Math.max(page?.size ?? maxResults, 1), maxResults);
      const offset = page?.cookie.length ? Number.parseInt(page.cookie.toString('utf8'), 10) : 0;
      if (!Number.isSafeInteger(offset) || offset < 0)
        return write(connection, searchDone(id, ResultCode.protocolError, 'Invalid paging cookie'));
      const slice = matches.slice(offset, offset + size);
      for (const item of slice) write(connection, searchEntry(id, item.dn, selectAttributes(item, request.attributes), request.typesOnly));
      const next = offset + size < matches.length ? Buffer.from(String(offset + size)) : Buffer.alloc(0);
      return write(connection, searchDone(id, ResultCode.success, '', '', pagedResultsControl(matches.length, next)));
    }
    const limit = Math.min(request.sizeLimit > 0 ? request.sizeLimit : maxResults, maxResults);
    for (const item of matches.slice(0, limit))
      write(connection, searchEntry(id, item.dn, selectAttributes(item, request.attributes), request.typesOnly));
    write(
      connection,
      matches.length > limit
        ? searchDone(id, ResultCode.sizeLimitExceeded, `More than ${limit} entries match`)
        : searchDone(id, ResultCode.success),
    );
  }

  async function compare(connection: Connection, id: number, request: Extract<LdapRequest, { op: 'compare' }>) {
    const binding = connection.binding;
    if (!binding) return write(connection, compareResponse(id, ResultCode.insufficientAccessRights, 'Bind first'));
    let target: string;
    try {
      target = normalizeDn(request.entry);
    } catch {
      return write(connection, compareResponse(id, ResultCode.invalidDNSyntax, 'Invalid DN'));
    }
    const found = isUnder(target, binding.normalizedBaseDn)
      ? (await entriesFor(connection)).entries.find((item) => item.normalizedDn === target)
      : undefined;
    if (!found) return write(connection, compareResponse(id, ResultCode.noSuchObject, 'No such object'));
    const matched = matchFilter({ type: 'equal', attribute: request.attribute, value: request.value }, found.index);
    write(connection, compareResponse(id, matched ? ResultCode.compareTrue : ResultCode.compareFalse));
  }

  async function handle(connection: Connection, message: LdapMessage) {
    const { id, request } = message;
    switch (request.op) {
      case 'bind':
        return bind(connection, id, request);
      case 'unbind':
        return close(connection);
      case 'search':
        return search(connection, message, request);
      case 'compare':
        return compare(connection, id, request);
      case 'extended':
        if (request.name === OID.whoAmI)
          return write(
            connection,
            extendedResponse(id, ResultCode.success, '', undefined, connection.binding ? `dn:${connection.binding.dn}` : ''),
          );
        return write(connection, extendedResponse(id, ResultCode.protocolError, `Unsupported extended operation ${request.name.slice(0, 64)}`));
      case 'abandon':
        return;
      case 'unsupported':
        return write(connection, genericResponse(id, request.responseTag, ResultCode.unwillingToPerform, 'This directory is read-only'));
    }
  }

  function accept(socket: Socket, secure: boolean) {
    if (connections.size >= maxConnections) {
      socket.end(noticeOfDisconnection(ResultCode.busy, 'Too many connections'));
      return;
    }
    const connection: Connection = { socket, secure, buffer: Buffer.alloc(0), queue: Promise.resolve(), closed: false };
    connections.add(connection);
    socket.setTimeout(idleTimeoutMs, () => void close(connection, noticeOfDisconnection(ResultCode.unavailable, 'Idle timeout')));
    socket.on('error', () => void close(connection));
    socket.on('close', () => void close(connection));
    socket.on('data', (chunk: Buffer) => {
      if (connection.closed) return;
      connection.buffer = Buffer.concat([connection.buffer, chunk]);
      for (;;) {
        let item;
        try {
          item = readElement(connection.buffer, 0, maxRequestBytes);
        } catch (error) {
          void close(connection, noticeOfDisconnection(ResultCode.protocolError, (error as Error).message));
          return;
        }
        if (!item) {
          if (connection.buffer.length > maxRequestBytes + 8)
            void close(connection, noticeOfDisconnection(ResultCode.protocolError, 'Request too large'));
          return;
        }
        connection.buffer = connection.buffer.subarray(item.size);
        let message: LdapMessage;
        try {
          message = decodeMessage(item);
        } catch (error) {
          if (error instanceof BerError || error instanceof DnError) {
            void close(connection, noticeOfDisconnection(ResultCode.protocolError, error.message));
            return;
          }
          throw error;
        }
        // One request at a time per connection, in order.
        connection.queue = connection.queue
          .then(() => (connection.closed ? undefined : handle(connection, message)))
          .catch((error) => {
            options.onError?.(error);
            void close(connection, noticeOfDisconnection(ResultCode.other, 'Internal error'));
          });
      }
    });
  }

  const server: Server = options.tls
    ? createTlsServer(options.tls, (socket: TLSSocket) => accept(socket, true))
    : createTcpServer((socket) => accept(socket, false));

  return {
    server,
    /** Starts listening (port 0 picks a free one); resolves with the bound address. */
    listen(port = options.tls ? 636 : 389, host = '127.0.0.1'): Promise<AddressInfo> {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          resolve(server.address() as AddressInfo);
        });
      });
    },
    /** Stops accepting connections, tells connected clients, and signs out the sessions it created. */
    async close(): Promise<void> {
      await Promise.all([...connections].map((connection) => close(connection, noticeOfDisconnection(ResultCode.unavailable, 'Server shutting down'))));
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
    /** Live connections (for metrics). */
    get connections() {
      return connections.size;
    },
  };
}
