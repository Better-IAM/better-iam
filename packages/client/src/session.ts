import { IamClientError } from './index.js';

/** The minimum client surface the session store needs; `createIamClient` satisfies it. */
export interface SessionClient {
  auth: {
    getSession(options?: unknown): Promise<unknown>;
    signOut(options?: unknown): Promise<unknown>;
  };
}
export type SessionOf<T extends SessionClient> = Awaited<ReturnType<T['auth']['getSession']>>;
export type SessionStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'error';
export interface SessionSnapshot<Session> {
  status: SessionStatus;
  /** The current identity and session, or null when signed out. */
  session: Session | null;
  /** The last transport or authentication error. Unauthenticated states keep the server's error so its code can be shown. */
  error: Error | null;
  updatedAt: number;
}
export interface SessionStore<Session> {
  getSnapshot(): SessionSnapshot<Session>;
  subscribe(listener: () => void): () => void;
  /** Reloads the session from the server. Concurrent calls share one request. */
  refresh(): Promise<SessionSnapshot<Session>>;
  /** Signs out on the server, then clears the local session even if the server call failed. */
  signOut(): Promise<void>;
  /** Replaces the local session, for example right after a sign-in response. */
  set(session: Session | null): void;
}

/** The server answers 401/403 for missing, expired, or step-up-required credentials; anything else is a transport failure. */
export function isUnauthenticated(error: unknown): boolean {
  if (error instanceof IamClientError) return error.status === 401 || error.status === 403;
  // Server-side adapters (Nuxt SSR, tests) call the server in process and see its IamError, which carries `status`.
  const status =
    error && typeof error === 'object' && 'status' in error
      ? (error as { status: unknown }).status
      : undefined;
  return (status === 401 || status === 403) && error instanceof Error && 'code' in error;
}

/**
 * Framework-agnostic session state. The React and Vue bindings subscribe to it;
 * it can also drive other frameworks or plain scripts.
 */
export function createSessionStore<T extends SessionClient>(
  client: T,
  options: { initial?: SessionOf<T> | null } = {},
): SessionStore<SessionOf<T>> {
  type Session = SessionOf<T>;
  const listeners = new Set<() => void>();
  let snapshot: SessionSnapshot<Session> =
    options.initial === undefined
      ? { status: 'loading', session: null, error: null, updatedAt: 0 }
      : {
          status: options.initial === null ? 'unauthenticated' : 'authenticated',
          session: options.initial,
          error: null,
          updatedAt: Date.now(),
        };
  let inflight: Promise<SessionSnapshot<Session>> | undefined;
  const publish = (next: SessionSnapshot<Session>) => {
    snapshot = next;
    for (const listener of [...listeners]) listener();
  };
  const store: SessionStore<Session> = {
    getSnapshot: () => snapshot,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    refresh() {
      inflight ??= (async () => {
        try {
          const session = (await client.auth.getSession()) as Session;
          publish({ status: 'authenticated', session, error: null, updatedAt: Date.now() });
        } catch (error) {
          const failure = error instanceof Error ? error : new Error(String(error));
          publish({
            status: isUnauthenticated(error) ? 'unauthenticated' : 'error',
            session: isUnauthenticated(error) ? null : snapshot.session,
            error: failure,
            updatedAt: Date.now(),
          });
        } finally {
          inflight = undefined;
        }
        return snapshot;
      })();
      return inflight;
    },
    async signOut() {
      try {
        await client.auth.signOut();
      } finally {
        publish({ status: 'unauthenticated', session: null, error: null, updatedAt: Date.now() });
      }
    },
    set(session) {
      publish({
        status: session === null ? 'unauthenticated' : 'authenticated',
        session,
        error: null,
        updatedAt: Date.now(),
      });
    },
  };
  return store;
}
