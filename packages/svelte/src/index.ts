import { getContext, setContext } from 'svelte';
import { get, readable, type Readable } from 'svelte/store';
import {
  createSessionStore,
  type SessionClient,
  type SessionOf,
  type SessionSnapshot,
  type SessionStore,
} from '@better-iam/client/session';

export { createSessionStore, isUnauthenticated } from '@better-iam/client/session';
export type {
  SessionClient,
  SessionOf,
  SessionSnapshot,
  SessionStatus,
  SessionStore,
} from '@better-iam/client/session';

export interface ResourceRef {
  type: string;
  id: string;
}
export interface AuthorizeCheck {
  action: string;
  resource: ResourceRef;
}
export interface AuthorizeResult extends AuthorizeCheck {
  allowed: boolean;
  reason: string;
}
export interface AccessibleResource {
  id: string;
  type: string;
  resourceId: string;
  attributes: Record<string, unknown>;
  ownerId?: string;
  parentType?: string;
  parentId?: string;
}
/** Optional client capabilities the authorization stores use; the typed client provides both. */
export interface AuthorizationClient extends SessionClient {
  authorizeMany?(
    input: { tenantId: string; checks: AuthorizeCheck[] },
    options?: unknown,
  ): Promise<{ results: AuthorizeResult[] }>;
  listAccessible?(
    input: { tenantId: string; action: string; type: string; limit?: number; offset?: number },
    options?: unknown,
  ): Promise<{ resources: AccessibleResource[]; total: number }>;
}
export type QueryStatus = 'idle' | 'loading' | 'ready' | 'error';
/** A plain value or a store of it; stores re-run the query whenever they change. */
export type MaybeReadable<T> = T | Readable<T>;

export interface AuthorizeInput {
  tenantId: string;
  checks: { action: string; resource?: ResourceRef }[];
  enabled?: boolean;
}
export interface AuthorizeState {
  status: QueryStatus;
  results: AuthorizeResult[];
  error: Error | null;
  /** Advisory decision for one check (the tenant itself when no resource is given); false until results arrive. */
  allowed(action: string, resource?: ResourceRef): boolean;
}
export interface CanInput {
  tenantId: string;
  action: string;
  /** Defaults to the tenant (`iam/{tenantId}`). */
  resource?: ResourceRef;
  enabled?: boolean;
}
export interface CanState {
  status: QueryStatus;
  allowed: boolean;
}
export interface AccessibleInput {
  tenantId: string;
  action: string;
  type: string;
  limit?: number;
  offset?: number;
  enabled?: boolean;
}
export interface AccessibleState {
  status: QueryStatus;
  resources: AccessibleResource[];
  total: number;
  error: Error | null;
}
/** A readable store plus a way to re-run its query now. */
export type QueryStore<State> = Readable<State> & { refresh(): Promise<void> };

export interface CreateIamOptions<T extends SessionClient> {
  client: T;
  /** A session from a server load (`iamKit.sessionData`); `null` means known signed-out. Omit to load in the browser. */
  initialSession?: SessionOf<T> | null;
  /** Reload when the tab regains focus or becomes visible (default true). */
  refreshOnFocus?: boolean;
  /** Reload on a fixed interval, in milliseconds. Off by default. */
  refreshIntervalMs?: number;
  /** Force server behaviour (no listeners, no fetching on creation). Detected from `window` by default. */
  server?: boolean;
}
export interface Iam<T extends SessionClient> {
  readonly client: T;
  /** The framework-agnostic store behind `session`. */
  readonly store: SessionStore<SessionOf<T>>;
  /** `$session.status`, `$session.session`, `$session.error`. */
  readonly session: Readable<SessionSnapshot<SessionOf<T>>>;
  /** Reloads the session from the server. */
  refresh(): Promise<SessionSnapshot<SessionOf<T>>>;
  /** Signs out on the server, then clears the local session. */
  signOut(): Promise<void>;
  /** Replaces the local session, for example right after a sign-in response. */
  setSession(session: SessionOf<T> | null): void;
  /**
   * Batched advisory decisions for rendering menus and buttons; the server still enforces every operation. `initial`
   * takes `locals.iam.authorize(...)` results from a server load, so the first render matches the server's.
   */
  authorize(
    input: MaybeReadable<AuthorizeInput>,
    options?: { initial?: AuthorizeResult[] },
  ): QueryStore<AuthorizeState>;
  /** One advisory decision; `$canDelete.allowed` is false while loading or signed out. */
  can(input: MaybeReadable<CanInput>, options?: { initial?: boolean }): QueryStore<CanState>;
  /** The registered resources of a managed type the signed-in principal may act on. */
  accessible(
    input: MaybeReadable<AccessibleInput>,
    options?: { initial?: { resources: AccessibleResource[]; total: number } },
  ): QueryStore<AccessibleState>;
  /** Removes the focus, visibility, and interval listeners. */
  dispose(): void;
}

const isReadable = <T>(value: MaybeReadable<T>): value is Readable<T> =>
  typeof (value as { subscribe?: unknown } | null)?.subscribe === 'function';
const asReadable = <T>(value: MaybeReadable<T>): Readable<T> =>
  isReadable(value) ? value : readable(value);
const checkKey = (action: string, resource: ResourceRef) =>
  `${action}@${resource.type}/${resource.id}`;
function principalKey(session: unknown): string {
  const identity = (session as { identity?: { id?: unknown } } | null)?.identity;
  return typeof identity?.id === 'string' ? identity.id : '';
}
const asError = (error: unknown) => (error instanceof Error ? error : new Error(String(error)));

interface QueryResult<Value> {
  status: QueryStatus;
  value: Value;
  error: Error | null;
}

/**
 * The engine behind `authorize`, `can`, and `accessible`: keyed by the serialized input and the signed-in identity,
 * fetched while subscribed, refetched when either changes. A session refresh for the same identity does not refetch.
 */
function query<Input, Value>(
  session: Readable<SessionSnapshot<unknown>>,
  input: Readable<{ params: Input; enabled: boolean }>,
  load: (params: Input) => Promise<Value>,
  signedOut: (params: Input) => Value,
  empty: Value,
  initial: Value | undefined,
): Readable<QueryResult<Value>> & { refresh(): Promise<void> } {
  let latest: { params: Input; enabled: boolean } | undefined;
  let publish: ((result: QueryResult<Value>) => void) | undefined;
  let state: QueryResult<Value> =
    initial === undefined
      ? { status: 'idle', value: empty, error: null }
      : { status: 'ready', value: initial, error: null };
  let seeded = initial !== undefined;
  let loadedKey: string | undefined;
  let generation = 0;
  const set = (next: QueryResult<Value>) => {
    state = next;
    publish?.(next);
  };
  const run = async (params: Input): Promise<void> => {
    const ticket = ++generation;
    set({ ...state, status: 'loading' });
    try {
      const value = await load(params);
      if (ticket === generation) set({ status: 'ready', value, error: null });
    } catch (error) {
      if (ticket === generation) set({ status: 'error', value: empty, error: asError(error) });
    }
  };
  const store = readable(state, (setValue) => {
    publish = setValue;
    setValue(state);
    let snapshot: SessionSnapshot<unknown> | undefined;
    const evaluate = () => {
      if (!snapshot || !latest || !latest.enabled) return;
      const { params } = latest;
      if (snapshot.status === 'unauthenticated') {
        generation++;
        loadedKey = undefined;
        seeded = false;
        set({ status: 'ready', value: signedOut(params), error: null });
        return;
      }
      if (snapshot.status === 'loading') {
        if (!seeded) set({ status: 'loading', value: empty, error: null });
        return;
      }
      // A transport error keeps the last results; the next successful refresh re-runs the query.
      if (snapshot.status !== 'authenticated') return;
      const key = `${principalKey(snapshot.session)}:${JSON.stringify(params)}`;
      if (seeded) {
        seeded = false;
        loadedKey = key;
        return;
      }
      if (key === loadedKey) return;
      loadedKey = key;
      void run(params);
    };
    const stopSession = session.subscribe((value) => {
      snapshot = value;
      evaluate();
    });
    const stopInput = input.subscribe((value) => {
      latest = value;
      evaluate();
    });
    return () => {
      stopSession();
      stopInput();
      // Results stay cached for a later subscriber with the same key; `refresh()` forces a reload.
      publish = undefined;
    };
  });
  return {
    subscribe: store.subscribe,
    refresh: async () => {
      const current = latest ?? get(input);
      if (current.enabled) await run(current.params);
    },
  };
}

/**
 * One typed client, one session store, and advisory authorization stores for a Svelte 4 or 5 app. Create it once
 * (typically in the root `+layout.svelte`) and share it with `setIamContext` / `getIamContext`.
 *
 * ```svelte
 * <script>
 *   const iam = createIam({ client, initialSession: data.session });
 *   const { session } = iam;
 *   const canManage = iam.can({ tenantId, action: 'projects:manage' });
 * </script>
 * {#if $canManage.allowed}<button>Manage</button>{/if}
 * ```
 */
export function createIam<T extends SessionClient>(options: CreateIamOptions<T>): Iam<T> {
  const server = options.server ?? typeof window === 'undefined';
  const client = options.client as T & AuthorizationClient;
  const store = createSessionStore(
    options.client,
    options.initialSession === undefined ? {} : { initial: options.initialSession },
  );
  const session = readable(store.getSnapshot(), (set) => {
    set(store.getSnapshot());
    return store.subscribe(() => set(store.getSnapshot()));
  });
  const anySession = session as Readable<SessionSnapshot<unknown>>;
  const cleanups: (() => void)[] = [];
  if (!server) {
    if (options.initialSession === undefined) void store.refresh();
    if (options.refreshIntervalMs) {
      const timer = setInterval(() => void store.refresh(), options.refreshIntervalMs);
      cleanups.push(() => clearInterval(timer));
    }
    if (options.refreshOnFocus !== false && typeof document !== 'undefined') {
      const handler = () => {
        if (document.visibilityState === 'visible') void store.refresh();
      };
      window.addEventListener('focus', handler);
      document.addEventListener('visibilitychange', handler);
      cleanups.push(() => {
        window.removeEventListener('focus', handler);
        document.removeEventListener('visibilitychange', handler);
      });
    }
  }

  const authorize: Iam<T>['authorize'] = (input, queryOptions = {}) => {
    const source = asReadable(input);
    let tenant = get(source).tenantId;
    const params = readableMap(source, ({ tenantId, checks, enabled = true }) => {
      tenant = tenantId;
      return {
        params: {
          tenantId,
          checks: checks.map((check) => ({
            action: check.action,
            resource: check.resource ?? { type: 'iam', id: tenantId },
          })),
        },
        enabled,
      };
    });
    const results = query(
      anySession,
      params,
      async (value) => {
        if (!client.authorizeMany) throw new Error('The client does not provide authorizeMany');
        return (await client.authorizeMany(value)).results;
      },
      (value) =>
        value.checks.map((check) => ({ ...check, allowed: false, reason: 'UNAUTHENTICATED' })),
      [] as AuthorizeResult[],
      queryOptions.initial,
    );
    return {
      subscribe: readableMap(results, (result) => ({
        status: result.status,
        results: result.value,
        error: result.error,
        allowed(action: string, resource?: ResourceRef) {
          const target = checkKey(action, resource ?? { type: 'iam', id: tenant });
          return (
            result.value.find((entry) => checkKey(entry.action, entry.resource) === target)
              ?.allowed ?? false
          );
        },
      })).subscribe,
      refresh: results.refresh,
    };
  };

  return {
    client: options.client,
    store,
    session,
    refresh: store.refresh,
    signOut: store.signOut,
    setSession: store.set,
    authorize,
    can(input, queryOptions = {}) {
      const target = readableMap(asReadable(input), (value) => ({
        ...value,
        resource: value.resource ?? { type: 'iam', id: value.tenantId },
      }));
      const current = () => get(target);
      const decisions = authorize(
        readableMap(target, ({ tenantId, action, resource, enabled }) => ({
          tenantId,
          checks: [{ action, resource }],
          ...(enabled === undefined ? {} : { enabled }),
        })),
        queryOptions.initial === undefined
          ? {}
          : {
              initial: [
                {
                  action: current().action,
                  resource: current().resource,
                  allowed: queryOptions.initial,
                  reason: queryOptions.initial ? 'ALLOWED' : 'DENIED',
                },
              ],
            },
      );
      return {
        subscribe: readableMap(decisions, (state) => {
          const { action, resource } = current();
          return { status: state.status, allowed: state.allowed(action, resource) };
        }).subscribe,
        refresh: decisions.refresh,
      };
    },
    accessible(input, queryOptions = {}) {
      const results = query(
        anySession,
        readableMap(asReadable(input), ({ enabled = true, ...params }) => ({ params, enabled })),
        async (params) => {
          if (!client.listAccessible) throw new Error('The client does not provide listAccessible');
          return client.listAccessible(params);
        },
        () => ({ resources: [], total: 0 }),
        { resources: [] as AccessibleResource[], total: 0 },
        queryOptions.initial,
      );
      return {
        subscribe: readableMap(results, (result) => ({
          status: result.status,
          resources: result.value.resources,
          total: result.value.total,
          error: result.error,
        })).subscribe,
        refresh: results.refresh,
      };
    },
    dispose() {
      for (const cleanup of cleanups.splice(0)) cleanup();
    },
  };
}

/** `derived` for one store, without its equality skipping (objects are always new here). */
function readableMap<A, B>(source: Readable<A>, map: (value: A) => B): Readable<B> {
  return {
    subscribe(run, invalidate) {
      return source.subscribe((value) => run(map(value)), invalidate as never);
    },
  };
}

const contextKey = Symbol.for('better-iam.svelte');
/** Shares an `Iam` with descendant components; call during component initialisation. */
export function setIamContext<T extends SessionClient>(iam: Iam<T>): Iam<T> {
  return setContext(contextKey, iam);
}
/** The `Iam` a parent shared with `setIamContext`. */
export function getIamContext<T extends SessionClient = SessionClient>(): Iam<T> {
  const iam = getContext<Iam<T> | undefined>(contextKey);
  if (!iam)
    throw new Error('No Better IAM context: call setIamContext(createIam(...)) in a parent');
  return iam;
}
