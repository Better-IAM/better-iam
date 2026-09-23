import {
  computed,
  defineComponent,
  getCurrentInstance,
  inject,
  onServerPrefetch,
  shallowRef,
  toValue,
  watch,
  type App,
  type ComputedRef,
  type InjectionKey,
  type MaybeRefOrGetter,
  type PropType,
  type Ref,
  type ShallowRef,
  type SlotsType,
  type VNode,
} from 'vue';
import {
  createSessionStore,
  type SessionClient,
  type SessionOf,
  type SessionSnapshot,
  type SessionStatus,
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
/** Optional client capabilities used by the authorization composables; the typed client provides both. */
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

/**
 * Carries query results from server rendering to the browser so hydration renders the same markup. Values are
 * written during SSR and consumed once on the client; Nuxt backs it with the payload, other SSR setups serialize it.
 */
export interface IamHydration {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
  delete(key: string): void;
}
/** A plain object hydration store; serialize `state` into the page and pass the parsed object back on the client. */
export function createHydration(state: Record<string, unknown> = {}): IamHydration & {
  state: Record<string, unknown>;
} {
  return {
    state,
    get: (key) => (Object.hasOwn(state, key) ? state[key] : undefined),
    set: (key, value) => {
      state[key] = value;
    },
    delete: (key) => {
      delete state[key];
    },
  };
}

export interface CreateIamOptions<T extends SessionClient> {
  client: T;
  /** A session rendered on the server; `null` means known signed-out. Omit to load when installed in a browser. */
  initialSession?: SessionOf<T> | null;
  /** Reload when the tab regains focus or becomes visible (default true). */
  refreshOnFocus?: boolean;
  /** Reload on a fixed interval, in milliseconds. Off by default. */
  refreshIntervalMs?: number;
  /** SSR handoff for query results. */
  hydration?: IamHydration;
  /** Register `<IamCan>` globally on install (default true). */
  registerComponents?: boolean;
  /** Force server behaviour (no listeners, queries awaited with `onServerPrefetch`). Detected from `window` by default. */
  server?: boolean;
}
interface IamContext {
  client: AuthorizationClient;
  store: SessionStore<unknown>;
  snapshot: ShallowRef<SessionSnapshot<unknown>>;
  hydration: IamHydration | undefined;
  server: boolean;
}
export interface Iam<T extends SessionClient> {
  readonly client: T;
  readonly store: SessionStore<SessionOf<T>>;
  install(app: App): void;
  /** Removes the focus, visibility, and interval listeners the plugin installed. */
  dispose(): void;
}

const IamKey: InjectionKey<IamContext> = Symbol('better-iam');

/** The Vue plugin: one typed client and one session store for the app. `app.use(createIam({ client }))`. */
export function createIam<T extends SessionClient>(options: CreateIamOptions<T>): Iam<T> {
  const server = options.server ?? typeof window === 'undefined';
  const store = createSessionStore(
    options.client,
    options.initialSession === undefined ? {} : { initial: options.initialSession },
  );
  const snapshot = shallowRef(store.getSnapshot()) as ShallowRef<SessionSnapshot<unknown>>;
  const cleanups: (() => void)[] = [
    store.subscribe(() => {
      snapshot.value = store.getSnapshot();
    }),
  ];
  const context: IamContext = {
    client: options.client as AuthorizationClient,
    store: store as SessionStore<unknown>,
    snapshot,
    hydration: options.hydration,
    server,
  };
  return {
    client: options.client,
    store,
    install(app) {
      app.provide(IamKey, context);
      if (options.registerComponents !== false) app.component('IamCan', IamCan);
      if (server) return;
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
    },
    dispose() {
      for (const cleanup of cleanups.splice(0)) cleanup();
    },
  };
}

function useIamContext(): IamContext {
  const context = inject(IamKey, null);
  if (!context) throw new Error('Better IAM composables need app.use(createIam({ client }))');
  return context;
}

/** The client passed to `createIam`, typed as the caller declares it. */
export function useIamClient<T extends SessionClient = SessionClient>(): T {
  return useIamContext().client as unknown as T;
}

export interface UseSessionResult<Session> {
  status: ComputedRef<SessionStatus>;
  session: ComputedRef<Session | null>;
  error: ComputedRef<Error | null>;
  isAuthenticated: ComputedRef<boolean>;
  refresh(): Promise<SessionSnapshot<Session>>;
  signOut(): Promise<void>;
  /** Replaces the local session, for example right after a sign-in response. */
  setSession(session: Session | null): void;
}

/** Reactive session state plus refresh, sign-out, and manual replacement. */
export function useSession<T extends SessionClient = SessionClient>(): UseSessionResult<
  SessionOf<T>
> {
  const { store, snapshot } = useIamContext();
  return {
    status: computed(() => snapshot.value.status),
    session: computed(() => snapshot.value.session as SessionOf<T> | null),
    error: computed(() => snapshot.value.error),
    isAuthenticated: computed(() => snapshot.value.status === 'authenticated'),
    refresh: store.refresh as () => Promise<SessionSnapshot<SessionOf<T>>>,
    signOut: store.signOut,
    setSession: store.set as (session: SessionOf<T> | null) => void,
  };
}

const checkKey = (action: string, resource: ResourceRef) =>
  `${action}@${resource.type}/${resource.id}`;
function principalKey(session: unknown): string {
  const identity = (session as { identity?: { id?: unknown } } | null)?.identity;
  return typeof identity?.id === 'string' ? identity.id : '';
}
const asError = (error: unknown) => (error instanceof Error ? error : new Error(String(error)));

interface QueryState<Value> {
  status: QueryStatus;
  value: Value;
  error: Error | null;
}

/**
 * Shared engine for the authorization composables: keyed by the serialized input and the signed-in identity, refetched
 * when either changes, awaited during SSR, and seeded from the hydration store on the client.
 */
function useIamQuery<Input, Value>(
  name: string,
  input: () => { params: Input; enabled: boolean },
  load: (client: AuthorizationClient, params: Input) => Promise<Value>,
  signedOut: (params: Input) => Value,
  empty: Value,
) {
  const context = useIamContext();
  const state = shallowRef<QueryState<Value>>({ status: 'idle', value: empty, error: null });
  const key = computed(() => {
    const { params, enabled } = input();
    return {
      id: `better-iam:${name}:${principalKey(context.snapshot.value.session)}:${JSON.stringify(params)}`,
      params,
      enabled,
    };
  });
  let generation = 0;
  let pending: Promise<void> | undefined;
  const run = async (): Promise<void> => {
    const current = key.value;
    const ticket = ++generation;
    state.value = { ...state.value, status: 'loading' };
    try {
      const value = await load(context.client, current.params);
      if (ticket !== generation) return;
      state.value = { status: 'ready', value, error: null };
      if (context.server) context.hydration?.set(current.id, value);
    } catch (error) {
      if (ticket !== generation) return;
      state.value = { status: 'error', value: empty, error: asError(error) };
    }
  };
  // Watch the serialized id, not the key object: a session refresh for the same identity must not refetch.
  watch(
    [() => key.value.id, () => key.value.enabled, () => context.snapshot.value.status],
    ([, enabled, status]) => {
      const current = key.value;
      if (!enabled) return;
      if (status === 'unauthenticated') {
        generation++;
        state.value = { status: 'ready', value: signedOut(current.params), error: null };
        return;
      }
      if (status === 'loading') {
        state.value = { status: 'loading', value: empty, error: null };
        return;
      }
      // A transport error keeps the last results; the next successful refresh re-runs the query.
      if (status !== 'authenticated') return;
      const hydrated = context.server ? undefined : context.hydration?.get(current.id);
      if (hydrated !== undefined) {
        context.hydration?.delete(current.id);
        generation++;
        state.value = { status: 'ready', value: hydrated as Value, error: null };
        return;
      }
      pending = run();
    },
    { immediate: true },
  );
  if (context.server && getCurrentInstance()) onServerPrefetch(() => pending);
  return {
    status: computed(() => state.value.status),
    value: computed(() => state.value.value),
    error: computed(() => state.value.error),
    refresh: run,
  };
}

export interface UseAuthorizeInput {
  tenantId: string;
  checks: AuthorizeCheck[];
  enabled?: boolean;
}
export interface UseAuthorizeResult {
  status: Ref<QueryStatus>;
  results: Ref<AuthorizeResult[]>;
  error: Ref<Error | null>;
  /** Advisory decision for one check (the tenant itself when no resource is given); false until results arrive. */
  allowed(action: string, resource?: ResourceRef): boolean;
  refresh(): Promise<void>;
}

/**
 * Batched advisory decisions for rendering menus and buttons. Accepts a ref or getter so the checks can follow reactive
 * state; the server still enforces every operation.
 */
export function useAuthorize(input: MaybeRefOrGetter<UseAuthorizeInput>): UseAuthorizeResult {
  const query = useIamQuery(
    'authorize',
    () => {
      const { tenantId, checks, enabled = true } = toValue(input);
      return { params: { tenantId, checks }, enabled };
    },
    async (client, params) => {
      if (!client.authorizeMany) throw new Error('The client does not provide authorizeMany');
      return (await client.authorizeMany(params)).results;
    },
    (params) =>
      params.checks.map((check) => ({ ...check, allowed: false, reason: 'UNAUTHENTICATED' })),
    [] as AuthorizeResult[],
  );
  return {
    status: query.status,
    results: query.value,
    error: query.error,
    allowed(action, resource) {
      const target = checkKey(action, resource ?? { type: 'iam', id: toValue(input).tenantId });
      return (
        query.value.value.find((result) => checkKey(result.action, result.resource) === target)
          ?.allowed ?? false
      );
    },
    refresh: query.refresh,
  };
}

export interface UseCanInput {
  tenantId: string;
  action: string;
  /** Defaults to the tenant (`iam/{tenantId}`). */
  resource?: ResourceRef;
  enabled?: boolean;
}
/** One advisory decision as a boolean ref, false while loading or signed out. */
export function useCan(input: MaybeRefOrGetter<UseCanInput>): {
  allowed: ComputedRef<boolean>;
  status: Ref<QueryStatus>;
  refresh(): Promise<void>;
} {
  const target = () => {
    const { tenantId, action, resource, enabled } = toValue(input);
    return {
      tenantId,
      action,
      resource: resource ?? { type: 'iam', id: tenantId },
      ...(enabled === undefined ? {} : { enabled }),
    };
  };
  const decisions = useAuthorize(() => {
    const { tenantId, action, resource, enabled } = target();
    return {
      tenantId,
      checks: [{ action, resource }],
      ...(enabled === undefined ? {} : { enabled }),
    };
  });
  return {
    allowed: computed(() => {
      const { action, resource } = target();
      return decisions.allowed(action, resource);
    }),
    status: decisions.status,
    refresh: decisions.refresh,
  };
}

export interface UseAccessibleInput {
  tenantId: string;
  action: string;
  type: string;
  limit?: number;
  offset?: number;
  enabled?: boolean;
}
export interface UseAccessibleResult {
  status: Ref<QueryStatus>;
  resources: Ref<AccessibleResource[]>;
  total: Ref<number>;
  error: Ref<Error | null>;
  refresh(): Promise<void>;
}

/** The registered resources of a managed type the signed-in principal may act on; refetched when the input or identity changes. */
export function useAccessible(input: MaybeRefOrGetter<UseAccessibleInput>): UseAccessibleResult {
  const query = useIamQuery(
    'accessible',
    () => {
      const { enabled = true, ...params } = toValue(input);
      return { params, enabled };
    },
    async (client, params) => {
      if (!client.listAccessible) throw new Error('The client does not provide listAccessible');
      return client.listAccessible(params);
    },
    () => ({ resources: [], total: 0 }),
    { resources: [] as AccessibleResource[], total: 0 },
  );
  return {
    status: query.status,
    resources: computed(() => query.value.value.resources),
    total: computed(() => query.value.value.total),
    error: query.error,
    refresh: query.refresh,
  };
}

/** An agreement (terms of use) as the signed-in person sees it (`agreements.listMine`). */
export interface MemberAgreement {
  id: string;
  name: string;
  content: string;
  url?: string;
  version: number;
  required: boolean;
  accepted: boolean;
  acceptedAt?: number;
  acceptedVersion?: number;
}
/** One way a denied person could become allowed (`accessPaths.find`). */
export type MemberAccessPath =
  | { kind: 'mfa' }
  | { kind: 'accept-agreements'; agreements: { id: string; name: string; version: number }[] }
  | {
      kind: 'activate';
      bindingId: string;
      role: { id: string; name: string };
      requireApproval: boolean;
      requireJustification: boolean;
      requireMfa: boolean;
      maxActivationMs?: number;
    }
  | {
      kind: 'request-package';
      package: { id: string; name: string; description?: string };
      requireJustification: boolean;
    };
/** Client capabilities used by the self-service composables; the typed client provides them. */
interface SelfServiceClient {
  agreements?: {
    listMine(input: { tenantId: string }): Promise<MemberAgreement[]>;
    accept(input: { tenantId: string; agreementId: string; version: number }): Promise<unknown>;
  };
  accessPaths?: {
    find(input: {
      tenantId: string;
      action: string;
      resource: ResourceRef;
    }): Promise<{ allowed: boolean; reason: string; paths: MemberAccessPath[] }>;
  };
}

export interface UseAgreementsResult {
  status: Ref<QueryStatus>;
  agreements: Ref<MemberAgreement[]>;
  /** Required agreements not accepted in their current version. */
  pending: ComputedRef<MemberAgreement[]>;
  error: Ref<Error | null>;
  /** Records acceptance of the version the person was shown, then reloads. */
  accept(agreement: Pick<MemberAgreement, 'id' | 'version'>): Promise<void>;
  refresh(): Promise<void>;
}

/** The signed-in person's terms of use and a way to accept them; policies can hold back access until they do. */
export function useAgreements(
  input: MaybeRefOrGetter<{ tenantId: string; enabled?: boolean }>,
): UseAgreementsResult {
  const context = useIamContext();
  const api = () => (context.client as SelfServiceClient).agreements;
  const query = useIamQuery(
    'agreements',
    () => {
      const { tenantId, enabled = true } = toValue(input);
      return { params: { tenantId }, enabled };
    },
    async (_client, params) => {
      const agreements = api();
      if (!agreements) throw new Error('The client does not provide agreements');
      return agreements.listMine(params);
    },
    () => [],
    [] as MemberAgreement[],
  );
  return {
    status: query.status,
    agreements: query.value,
    pending: computed(() =>
      query.value.value.filter((agreement) => agreement.required && !agreement.accepted),
    ),
    error: query.error,
    async accept(agreement) {
      const agreements = api();
      if (!agreements) throw new Error('The client does not provide agreements');
      await agreements.accept({
        tenantId: toValue(input).tenantId,
        agreementId: agreement.id,
        version: agreement.version,
      });
      await query.refresh();
    },
    refresh: query.refresh,
  };
}

export interface UseAccessPathsResult {
  status: Ref<QueryStatus>;
  allowed: ComputedRef<boolean>;
  reason: ComputedRef<string>;
  /** What the person could do alone to be allowed; empty means ask an administrator. */
  paths: ComputedRef<MemberAccessPath[]>;
  error: Ref<Error | null>;
  refresh(): Promise<void>;
}

/** Whether the signed-in person may perform an action and, if not, the self-service paths that would allow it. */
export function useAccessPaths(
  input: MaybeRefOrGetter<{
    tenantId: string;
    action: string;
    resource: ResourceRef;
    enabled?: boolean;
  }>,
): UseAccessPathsResult {
  const context = useIamContext();
  const empty = { allowed: false, reason: 'UNAUTHENTICATED', paths: [] as MemberAccessPath[] };
  const query = useIamQuery(
    'accessPaths',
    () => {
      const { tenantId, action, resource, enabled = true } = toValue(input);
      return {
        params: { tenantId, action, resource: { type: resource.type, id: resource.id } },
        enabled,
      };
    },
    async (_client, params) => {
      const paths = (context.client as SelfServiceClient).accessPaths;
      if (!paths) throw new Error('The client does not provide accessPaths');
      return paths.find(params);
    },
    () => empty,
    empty,
  );
  return {
    status: query.status,
    allowed: computed(() => query.value.value.allowed),
    reason: computed(() => query.value.value.reason),
    paths: computed(() => query.value.value.paths),
    error: query.error,
    refresh: query.refresh,
  };
}

/** A team reference as the teams API returns it. */
export interface MemberTeamRef {
  id: string;
  name: string;
  slug: string;
}
/** The signed-in person's teams, join requests, and joinable teams (`teams.listMine`). */
export interface MemberTeams {
  teams: Array<
    MemberTeamRef & {
      description?: string;
      role: 'maintainer' | 'member';
      expiresAt?: number;
      /** Teams above it, whose access the membership also brings. */
      parents: MemberTeamRef[];
    }
  >;
  requests: Array<{
    id: string;
    team: MemberTeamRef;
    status: 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired';
    requestedAt: number;
    expiresAt: number;
    justification?: string;
    note?: string;
  }>;
  joinable: Array<MemberTeamRef & { description?: string; memberCount: number }>;
  /** Open membership reviews of teams the person maintains, soonest due first (older servers omit it). */
  reviews?: Array<{ id: string; team: MemberTeamRef; dueAt: number; undecided: number }>;
}
interface TeamsClient {
  teams?: {
    listMine(input: { tenantId: string }): Promise<MemberTeams>;
    requestToJoin(input: {
      tenantId: string;
      teamId: string;
      justification?: string;
    }): Promise<unknown>;
    cancelRequest(input: { tenantId: string; requestId: string }): Promise<unknown>;
    leave(input: { tenantId: string; teamId: string }): Promise<unknown>;
  };
}

export interface UseTeamsResult {
  status: Ref<QueryStatus>;
  teams: ComputedRef<MemberTeams['teams']>;
  /** The person's pending join requests. */
  pending: ComputedRef<MemberTeams['requests']>;
  /** Teams that take join requests and that the person is not in (and has not asked to join). */
  joinable: ComputedRef<MemberTeams['joinable']>;
  /** Membership reviews waiting for the person as a maintainer. */
  reviews: ComputedRef<NonNullable<MemberTeams['reviews']>>;
  error: Ref<Error | null>;
  /** Asks to join a team whose join policy is `request`; its maintainers decide. */
  requestToJoin(teamId: string, justification?: string): Promise<void>;
  /** Withdraws a pending join request. */
  cancelRequest(requestId: string): Promise<void>;
  /** Leaves a team the person belongs to directly. */
  leave(teamId: string): Promise<void>;
  refresh(): Promise<void>;
}

/** The signed-in person's teams with self-service joining and leaving (`teams.listMine`, `requestToJoin`, `leave`). */
export function useTeams(
  input: MaybeRefOrGetter<{ tenantId: string; enabled?: boolean }>,
): UseTeamsResult {
  const context = useIamContext();
  const api = () => {
    const teams = (context.client as TeamsClient).teams;
    if (!teams) throw new Error('The client does not provide teams');
    return teams;
  };
  const empty: MemberTeams = { teams: [], requests: [], joinable: [], reviews: [] };
  const query = useIamQuery(
    'teams',
    () => {
      const { tenantId, enabled = true } = toValue(input);
      return { params: { tenantId }, enabled };
    },
    async (_client, params) => api().listMine(params),
    () => empty,
    empty,
  );
  const pending = computed(() =>
    query.value.value.requests.filter((request) => request.status === 'pending'),
  );
  const act = async (run: (teams: NonNullable<TeamsClient['teams']>) => Promise<unknown>) => {
    await run(api());
    await query.refresh();
  };
  return {
    status: query.status,
    teams: computed(() => query.value.value.teams),
    pending,
    joinable: computed(() =>
      query.value.value.joinable.filter(
        (team) => !pending.value.some((request) => request.team.id === team.id),
      ),
    ),
    reviews: computed(() => query.value.value.reviews ?? []),
    error: query.error,
    requestToJoin: (teamId, justification) =>
      act((teams) =>
        teams.requestToJoin({
          tenantId: toValue(input).tenantId,
          teamId,
          ...(justification ? { justification } : {}),
        }),
      ),
    cancelRequest: (requestId) =>
      act((teams) => teams.cancelRequest({ tenantId: toValue(input).tenantId, requestId })),
    leave: (teamId) => act((teams) => teams.leave({ tenantId: toValue(input).tenantId, teamId })),
    refresh: query.refresh,
  };
}

/**
 * Renders the default slot only when the advisory decision allows the action, the `fallback` slot otherwise, and the
 * `loading` slot meanwhile. `<IamCan tenant-id="t1" action="projects:delete" :resource="{ type: 'project', id }">`.
 */
export const IamCan = defineComponent({
  name: 'IamCan',
  props: {
    tenantId: { type: String, required: true },
    action: { type: String, required: true },
    resource: { type: Object as PropType<ResourceRef>, default: undefined },
  },
  slots: Object as SlotsType<{
    default?: () => VNode[];
    fallback?: () => VNode[];
    loading?: () => VNode[];
  }>,
  setup(props, { slots }) {
    const { allowed, status } = useCan(() => ({
      tenantId: props.tenantId,
      action: props.action,
      ...(props.resource ? { resource: props.resource } : {}),
    }));
    return () => {
      if (status.value === 'idle' || status.value === 'loading') return slots.loading?.() ?? null;
      return (allowed.value ? slots.default?.() : slots.fallback?.()) ?? null;
    };
  },
});
