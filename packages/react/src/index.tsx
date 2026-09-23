'use client';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import {
  createSessionStore,
  type SessionClient,
  type SessionOf,
  type SessionSnapshot,
  type SessionStore,
} from './store.js';

export { createSessionStore, isUnauthenticated } from './store.js';
export type {
  SessionClient,
  SessionOf,
  SessionSnapshot,
  SessionStatus,
  SessionStore,
} from './store.js';

export interface AuthorizeCheck {
  action: string;
  resource: { type: string; id: string };
}
export interface AuthorizeResult extends AuthorizeCheck {
  allowed: boolean;
  reason: string;
}
/** Optional client capabilities used by the authorization hooks; the typed client provides both. */
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
export interface AccessibleResource {
  id: string;
  type: string;
  resourceId: string;
  attributes: Record<string, unknown>;
  ownerId?: string;
  parentType?: string;
  parentId?: string;
}
type QueryStatus = 'idle' | 'loading' | 'ready' | 'error';

interface ContextValue {
  client: AuthorizationClient;
  store: SessionStore<unknown>;
}
const IamContext = createContext<ContextValue | null>(null);

export interface IamProviderProps<T extends SessionClient> {
  client: T;
  children?: ReactNode;
  /** A session rendered on the server; `null` means known signed-out. Omit to load on mount. */
  initialSession?: SessionOf<T> | null;
  /** Reload when the tab regains focus or becomes visible (default true). */
  refreshOnFocus?: boolean;
  /** Reload on a fixed interval, in milliseconds. Off by default. */
  refreshIntervalMs?: number;
}

/** Holds the typed client and one session store for the tree below. Create the client once, outside render. */
export function IamProvider<T extends SessionClient>({
  client,
  children,
  initialSession,
  refreshOnFocus = true,
  refreshIntervalMs,
}: IamProviderProps<T>) {
  const [store] = useState(() =>
    createSessionStore(client, initialSession === undefined ? {} : { initial: initialSession }),
  );
  useEffect(() => {
    if (initialSession === undefined) void store.refresh();
  }, [store, initialSession]);
  useEffect(() => {
    if (!refreshIntervalMs) return;
    const timer = setInterval(() => {
      void store.refresh();
    }, refreshIntervalMs);
    return () => clearInterval(timer);
  }, [store, refreshIntervalMs]);
  useEffect(() => {
    if (!refreshOnFocus || typeof window === 'undefined') return;
    const handler = () => {
      if (typeof document === 'undefined' || document.visibilityState === 'visible')
        void store.refresh();
    };
    window.addEventListener('focus', handler);
    document.addEventListener('visibilitychange', handler);
    return () => {
      window.removeEventListener('focus', handler);
      document.removeEventListener('visibilitychange', handler);
    };
  }, [store, refreshOnFocus]);
  const value = useMemo<ContextValue>(
    () => ({ client: client as AuthorizationClient, store: store as SessionStore<unknown> }),
    [client, store],
  );
  return <IamContext.Provider value={value}>{children}</IamContext.Provider>;
}

function useIamContext(): ContextValue {
  const context = useContext(IamContext);
  if (!context) throw new Error('Better IAM hooks must be rendered inside <IamProvider>');
  return context;
}

/** The client passed to the provider, typed as the caller declares it. */
export function useIamClient<T extends SessionClient = SessionClient>(): T {
  return useIamContext().client as unknown as T;
}

export interface UseSessionResult<Session> extends SessionSnapshot<Session> {
  isAuthenticated: boolean;
  refresh(): Promise<SessionSnapshot<Session>>;
  signOut(): Promise<void>;
  setSession(session: Session | null): void;
}

/** The current session snapshot plus refresh, sign-out, and manual replacement (after a sign-in response). */
export function useSession<T extends SessionClient = SessionClient>(): UseSessionResult<
  SessionOf<T>
> {
  const { store } = useIamContext();
  const snapshot = useSyncExternalStore(
    store.subscribe,
    store.getSnapshot,
    store.getSnapshot,
  ) as SessionSnapshot<SessionOf<T>>;
  return {
    ...snapshot,
    isAuthenticated: snapshot.status === 'authenticated',
    refresh: store.refresh as () => Promise<SessionSnapshot<SessionOf<T>>>,
    signOut: store.signOut,
    setSession: store.set as (session: SessionOf<T> | null) => void,
  };
}

const checkKey = (action: string, resource: { type: string; id: string }) =>
  `${action}@${resource.type}/${resource.id}`;
function principalKey(session: unknown): string {
  const identity = (session as { identity?: { id?: unknown } } | null)?.identity;
  return typeof identity?.id === 'string' ? identity.id : '';
}

export interface UseAuthorizeInput {
  tenantId: string;
  checks: AuthorizeCheck[];
  enabled?: boolean;
}
export interface UseAuthorizeResult {
  status: QueryStatus;
  results: AuthorizeResult[];
  error: Error | null;
  /** Advisory decision for one check; false until results arrive. */
  allowed(action: string, resource?: { type: string; id: string }): boolean;
  refresh(): Promise<void>;
}

/**
 * Batched advisory decisions for rendering menus and buttons. Re-evaluated when the checks or the signed-in identity change;
 * the server still enforces every operation.
 */
export function useAuthorize({
  tenantId,
  checks,
  enabled = true,
}: UseAuthorizeInput): UseAuthorizeResult {
  const { client, store } = useIamContext();
  const session = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
  const key = JSON.stringify([tenantId, checks]);
  const principal = principalKey(session.session);
  const [state, setState] = useState<{
    key: string;
    principal: string;
    status: QueryStatus;
    results: AuthorizeResult[];
    error: Error | null;
  }>({ key, principal, status: 'idle', results: [], error: null });
  const run = useCallback(async () => {
    if (!client.authorizeMany) throw new Error('The client does not provide authorizeMany');
    const parsed = JSON.parse(key) as [string, AuthorizeCheck[]];
    setState((previous) => ({ ...previous, key, principal, status: 'loading' }));
    try {
      const { results } = await client.authorizeMany({ tenantId: parsed[0], checks: parsed[1] });
      setState({ key, principal, status: 'ready', results, error: null });
    } catch (error) {
      setState({
        key,
        principal,
        status: 'error',
        results: [],
        error: error instanceof Error ? error : new Error(String(error)),
      });
    }
  }, [client, key, principal]);
  useEffect(() => {
    if (!enabled) return;
    if (session.status === 'authenticated') {
      void run();
      return;
    }
    if (session.status === 'unauthenticated')
      setState({
        key,
        principal,
        status: 'ready',
        results: (JSON.parse(key) as [string, AuthorizeCheck[]])[1].map((check) => ({
          ...check,
          allowed: false,
          reason: 'UNAUTHENTICATED',
        })),
        error: null,
      });
  }, [enabled, run, session.status, key, principal]);
  const current =
    state.key === key && state.principal === principal
      ? state
      : { ...state, status: 'loading' as QueryStatus, results: [] };
  const allowed = useCallback(
    (action: string, resource?: { type: string; id: string }) =>
      current.results.find(
        (result) =>
          checkKey(result.action, result.resource) ===
          checkKey(action, resource ?? { type: 'iam', id: tenantId }),
      )?.allowed ?? false,
    [current.results, tenantId],
  );
  return {
    status: current.status,
    results: current.results,
    error: current.error,
    allowed,
    refresh: run,
  };
}

export interface CanProps {
  tenantId: string;
  action: string;
  resource?: { type: string; id: string };
  children?: ReactNode;
  fallback?: ReactNode;
  loading?: ReactNode;
}

/** Renders children only when the advisory decision allows the action; `fallback` otherwise and `loading` meanwhile. */
export function Can({
  tenantId,
  action,
  resource,
  children,
  fallback = null,
  loading = null,
}: CanProps) {
  const target = resource ?? { type: 'iam', id: tenantId };
  const { status, allowed } = useAuthorize({ tenantId, checks: [{ action, resource: target }] });
  if (status === 'idle' || status === 'loading') return <>{loading}</>;
  return <>{allowed(action, target) ? children : fallback}</>;
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
  status: QueryStatus;
  resources: AccessibleResource[];
  total: number;
  error: Error | null;
  refresh(): Promise<void>;
}

/** The registered resources of a managed type the signed-in principal may act on; refetched when the input or identity changes. */
export function useAccessible({
  tenantId,
  action,
  type,
  limit,
  offset,
  enabled = true,
}: UseAccessibleInput): UseAccessibleResult {
  const { client, store } = useIamContext();
  const session = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
  const key = JSON.stringify([tenantId, action, type, limit ?? null, offset ?? null]);
  const principal = principalKey(session.session);
  const [state, setState] = useState<{
    key: string;
    principal: string;
    status: QueryStatus;
    resources: AccessibleResource[];
    total: number;
    error: Error | null;
  }>({ key, principal, status: 'idle', resources: [], total: 0, error: null });
  const run = useCallback(async () => {
    if (!client.listAccessible) throw new Error('The client does not provide listAccessible');
    const [scope, act, kind, max, skip] = JSON.parse(key) as [
      string,
      string,
      string,
      number | null,
      number | null,
    ];
    setState((previous) => ({ ...previous, key, principal, status: 'loading' }));
    try {
      const result = await client.listAccessible({
        tenantId: scope,
        action: act,
        type: kind,
        ...(max === null ? {} : { limit: max }),
        ...(skip === null ? {} : { offset: skip }),
      });
      setState({
        key,
        principal,
        status: 'ready',
        resources: result.resources,
        total: result.total,
        error: null,
      });
    } catch (error) {
      setState({
        key,
        principal,
        status: 'error',
        resources: [],
        total: 0,
        error: error instanceof Error ? error : new Error(String(error)),
      });
    }
  }, [client, key, principal]);
  useEffect(() => {
    if (!enabled) return;
    if (session.status === 'authenticated') void run();
    else if (session.status === 'unauthenticated')
      setState({ key, principal, status: 'ready', resources: [], total: 0, error: null });
  }, [enabled, run, session.status, key, principal]);
  const current =
    state.key === key && state.principal === principal
      ? state
      : { ...state, status: 'loading' as QueryStatus, resources: [], total: 0 };
  return {
    status: current.status,
    resources: current.resources,
    total: current.total,
    error: current.error,
    refresh: run,
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
/** Client capabilities used by the self-service hooks; the typed client provides them. */
interface SelfServiceClient {
  agreements?: {
    listMine(input: { tenantId: string }): Promise<MemberAgreement[]>;
    accept(input: { tenantId: string; agreementId: string; version: number }): Promise<unknown>;
  };
  accessPaths?: {
    find(input: {
      tenantId: string;
      action: string;
      resource: { type: string; id: string };
    }): Promise<{ allowed: boolean; reason: string; paths: MemberAccessPath[] }>;
  };
  features?: {
    evaluate(input: {
      tenantId: string;
      keys?: string[];
    }): Promise<{ tenantId: string; flags: Record<string, boolean> }>;
  };
  delegations?: {
    listMine(input: { tenantId: string }): Promise<MemberDelegation[]>;
    grant(input: DelegationGrantInput & { tenantId: string }): Promise<MemberDelegation>;
    approve(input: {
      tenantId: string;
      delegationId: string;
      scopes?: string[];
      confirm?: string[];
      expiresInSeconds?: number;
    }): Promise<MemberDelegation>;
    deny(input: { tenantId: string; delegationId: string }): Promise<MemberDelegation>;
    revoke(input: { tenantId: string; delegationId: string }): Promise<MemberDelegation>;
    listConfirmations(input: {
      tenantId: string;
      status?: 'pending' | 'approved' | 'rejected';
    }): Promise<MemberConfirmation[]>;
    decideConfirmation(input: {
      tenantId: string;
      confirmationId: string;
      approve: boolean;
    }): Promise<MemberConfirmation>;
  };
  agents?: {
    catalog(input: { tenantId: string }): Promise<CatalogAgent[]>;
  };
  inference?: {
    listMine(input: { tenantId: string }): Promise<MemberModel[]>;
  };
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
  billing?: {
    mySpend(input: { tenantId: string; period?: string; groupBy?: string }): Promise<MemberSpend>;
    check(input: { tenantId: string; meter?: string }): Promise<MemberSpendCheck>;
  };
}
/** A delegation as the person (or the agent) sees it (`delegations.listMine`). */
export interface MemberDelegation {
  id: string;
  status: 'pending' | 'active' | 'denied' | 'revoked';
  expired: boolean;
  agent: { id: string; name: string; model?: string; provider?: string };
  subject: { id: string; name: string; email?: string };
  scopes?: string[];
  confirm?: string[];
  /** `handoff`: another agent handed part of its delegation from the person on to this one. */
  requestedBy: 'subject' | 'agent' | 'handoff';
  reason?: string;
  createdAt: number;
  expiresAt: number;
  requestedSeconds?: number;
  lastUsedAt?: number;
  /** Whether the agent may hand parts of this delegation on to other agents. */
  handoff?: { agents?: string[]; depth: number };
  /** A hand-off: the delegation above it and the agents that handed it on, the person's own delegate first. */
  parentId?: string;
  chain?: { id: string; name: string }[];
  /** The person's cap on AI model use under this delegation, and what the current window has used of it. */
  spend?: {
    period: 'minute' | 'hour' | 'day' | 'month';
    maxTokens?: number;
    maxCostUsd?: number;
    maxRequests?: number;
    usedTokens: number;
    usedCostUsd: number;
    usedRequests: number;
    resetsAt: number;
  };
}
/** What a person grants an agent (`delegations.grant`). */
export interface DelegationGrantInput {
  agentId: string;
  scopes: string[];
  /** Actions the person confirms one call at a time. */
  confirm?: string[];
  expiresInSeconds?: number;
  maxSessionSeconds?: number;
  /** Lets the agent hand parts of the work on to other agents (all, or `agents`), `depth` levels down (1 to 3). */
  handoff?: { agents?: string[]; depth?: number };
  /** Caps what the agent's AI model calls for the person may use per period. */
  spend?: {
    period: 'minute' | 'hour' | 'day' | 'month';
    maxTokens?: number;
    maxCostUsd?: number;
    maxRequests?: number;
  };
}
/** An agent asking the person to confirm one action (`delegations.listConfirmations`). */
export interface MemberConfirmation {
  id: string;
  delegationId: string;
  agent: { id: string; name: string };
  action: string;
  resource: { type: string; id: string };
  reason?: string;
  status: 'pending' | 'approved' | 'rejected';
  expired: boolean;
  createdAt: number;
  expiresAt: number;
  validSeconds: number;
}
/** An agent people of the organization may delegate to (`agents.catalog`). */
export interface CatalogAgent {
  id: string;
  name: string;
  description?: string;
  purpose?: string;
  model?: string;
  provider?: string;
  url?: string;
  protocols?: string[];
  /** Services outside Better IAM it may present a delegation to (with a delegation token). */
  tokenAudiences?: string[];
  sponsorName: string;
}
/** An AI model the signed-in caller may use (`inference.listMine`). */
export interface MemberModel {
  name: string;
  displayName?: string;
  provider: { id: string; name: string; kind: string };
  tier?: string;
  family?: string;
  contextWindow?: number;
  inputPricePerMTok?: number;
  outputPricePerMTok?: number;
}

/**
 * A keyed query that reruns when its key or the signed-in identity changes and settles to `empty` when signed out;
 * the shared shape behind the self-service hooks.
 */
function useSessionQuery<T>(
  key: string,
  empty: T,
  load: (key: string) => Promise<T>,
  enabled: boolean,
) {
  const { store } = useIamContext();
  const session = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
  const principal = principalKey(session.session);
  const [state, setState] = useState<{
    key: string;
    principal: string;
    status: QueryStatus;
    data: T;
    error: Error | null;
  }>({ key, principal, status: 'idle', data: empty, error: null });
  const run = useCallback(async () => {
    setState((previous) => ({ ...previous, key, principal, status: 'loading' }));
    try {
      const data = await load(key);
      setState({ key, principal, status: 'ready', data, error: null });
    } catch (error) {
      setState({
        key,
        principal,
        status: 'error',
        data: empty,
        error: error instanceof Error ? error : new Error(String(error)),
      });
    }
    // `load` and `empty` depend only on the key; callers pass fresh closures every render.
  }, [key, principal]);
  useEffect(() => {
    if (!enabled) return;
    if (session.status === 'authenticated') void run();
    else if (session.status === 'unauthenticated')
      setState({ key, principal, status: 'ready', data: empty, error: null });
  }, [enabled, run, session.status, key, principal]);
  const current =
    state.key === key && state.principal === principal
      ? state
      : { ...state, status: 'loading' as QueryStatus, data: empty };
  return { ...current, refresh: run };
}

export interface UseAgreementsResult {
  status: QueryStatus;
  agreements: MemberAgreement[];
  /** Required agreements not accepted in their current version: show these before anything else. */
  pending: MemberAgreement[];
  error: Error | null;
  /** Records acceptance of the version the person was shown, then reloads. */
  accept(agreement: Pick<MemberAgreement, 'id' | 'version'>): Promise<void>;
  refresh(): Promise<void>;
}

/** The signed-in person's terms of use and a way to accept them; policies can hold back access until they do. */
export function useAgreements({
  tenantId,
  enabled = true,
}: {
  tenantId: string;
  enabled?: boolean;
}): UseAgreementsResult {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).agreements;
  const query = useSessionQuery<MemberAgreement[]>(
    JSON.stringify([tenantId]),
    [],
    async () => {
      if (!api) throw new Error('The client does not provide agreements');
      return api.listMine({ tenantId });
    },
    enabled,
  );
  const accept = useCallback(
    async (agreement: Pick<MemberAgreement, 'id' | 'version'>) => {
      if (!api) throw new Error('The client does not provide agreements');
      await api.accept({ tenantId, agreementId: agreement.id, version: agreement.version });
      await query.refresh();
    },
    [api, tenantId, query],
  );
  return {
    status: query.status,
    agreements: query.data,
    pending: query.data.filter((agreement) => agreement.required && !agreement.accepted),
    error: query.error,
    accept,
    refresh: query.refresh,
  };
}

export interface UseAccessPathsResult {
  status: QueryStatus;
  allowed: boolean;
  reason: string;
  /** What the person could do alone to be allowed; empty means ask an administrator. */
  paths: MemberAccessPath[];
  error: Error | null;
  refresh(): Promise<void>;
}

/**
 * For an action the signed-in person may be denied: whether they are allowed and, if not, the self-service paths
 * (step up to MFA, accept terms, activate an eligible role, request a package) that would allow them.
 */
export function useAccessPaths({
  tenantId,
  action,
  resource,
  enabled = true,
}: {
  tenantId: string;
  action: string;
  resource: { type: string; id: string };
  enabled?: boolean;
}): UseAccessPathsResult {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).accessPaths;
  const empty = { allowed: false, reason: 'UNAUTHENTICATED', paths: [] as MemberAccessPath[] };
  const query = useSessionQuery(
    JSON.stringify([tenantId, action, resource.type, resource.id]),
    empty,
    async () => {
      if (!api) throw new Error('The client does not provide accessPaths');
      return api.find({ tenantId, action, resource: { type: resource.type, id: resource.id } });
    },
    enabled,
  );
  return {
    status: query.status,
    allowed: query.data.allowed,
    reason: query.data.reason,
    paths: query.data.paths,
    error: query.error,
    refresh: query.refresh,
  };
}

export interface UseFeatureFlagsResult {
  status: QueryStatus;
  /** `{ key: value }` for the flags that reach the tenant (`features.evaluate`); missing keys are off. */
  flags: Record<string, boolean>;
  /** Whether a flag is on: `false` while loading, when signed out, and for unknown keys. */
  isEnabled(key: string): boolean;
  error: Error | null;
  refresh(): Promise<void>;
}

/**
 * The tenant's feature flags for the signed-in session, to show or hide UI. `keys` limits the request to those
 * flags. Hiding UI is not enforcement: gate the server side with `iam.features` or a `tenant.features` condition.
 */
export function useFeatureFlags({
  tenantId,
  keys,
  enabled = true,
}: {
  tenantId: string;
  keys?: string[];
  enabled?: boolean;
}): UseFeatureFlagsResult {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).features;
  const query = useSessionQuery<Record<string, boolean>>(
    JSON.stringify([tenantId, keys ? [...new Set(keys)].sort() : null]),
    {},
    async (key) => {
      if (!api) throw new Error('The client does not provide features');
      const [scope, only] = JSON.parse(key) as [string, string[] | null];
      return (await api.evaluate({ tenantId: scope, ...(only ? { keys: only } : {}) })).flags;
    },
    enabled,
  );
  const flags = query.data;
  const isEnabled = useCallback(
    (key: string) => Object.hasOwn(flags, key) && flags[key] === true,
    [flags],
  );
  return { status: query.status, flags, isEnabled, error: query.error, refresh: query.refresh };
}

/** Whether one feature flag is on for the tenant; `value` is `false` until it has loaded. */
export function useFeatureFlag({
  tenantId,
  key,
  enabled = true,
}: {
  tenantId: string;
  key: string;
  enabled?: boolean;
}): { status: QueryStatus; value: boolean; error: Error | null; refresh(): Promise<void> } {
  const query = useFeatureFlags({ tenantId, keys: [key], enabled });
  return {
    status: query.status,
    value: query.isEnabled(key),
    error: query.error,
    refresh: query.refresh,
  };
}

export interface UseDelegationsResult {
  status: QueryStatus;
  delegations: MemberDelegation[];
  /** Agents asking to act for the person, waiting for a decision. */
  requests: MemberDelegation[];
  /** Agents acting for the person right now. */
  active: MemberDelegation[];
  error: Error | null;
  grant(input: DelegationGrantInput): Promise<MemberDelegation>;
  /** Approves a request, optionally narrowing its scopes or adding actions to confirm one at a time. */
  approve(
    delegationId: string,
    changes?: { scopes?: string[]; confirm?: string[]; expiresInSeconds?: number },
  ): Promise<void>;
  deny(delegationId: string): Promise<void>;
  revoke(delegationId: string): Promise<void>;
  refresh(): Promise<void>;
}

/**
 * The AI agents acting (or asking to act) for the signed-in person, and the actions to manage them. Granting and
 * approving need a recent sign-in (`RECENT_AUTH_REQUIRED` otherwise). Agents never get more than the person has.
 */
export function useDelegations({
  tenantId,
  enabled = true,
}: {
  tenantId: string;
  enabled?: boolean;
}): UseDelegationsResult {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).delegations;
  const missing = () => new Error('The client does not provide delegations');
  const query = useSessionQuery<MemberDelegation[]>(
    JSON.stringify([tenantId]),
    [],
    async () => {
      if (!api) throw missing();
      return api.listMine({ tenantId });
    },
    enabled,
  );
  const act = useCallback(
    async <T,>(run: (delegations: NonNullable<SelfServiceClient['delegations']>) => Promise<T>) => {
      if (!api) throw missing();
      const result = await run(api);
      await query.refresh();
      return result;
    },
    [api, query],
  );
  return {
    status: query.status,
    delegations: query.data,
    requests: query.data.filter((item) => item.status === 'pending' && !item.expired),
    active: query.data.filter((item) => item.status === 'active' && !item.expired),
    error: query.error,
    grant: (input) => act((delegations) => delegations.grant({ tenantId, ...input })),
    approve: async (delegationId, changes = {}) => {
      await act((delegations) => delegations.approve({ tenantId, delegationId, ...changes }));
    },
    deny: async (delegationId) => {
      await act((delegations) => delegations.deny({ tenantId, delegationId }));
    },
    revoke: async (delegationId) => {
      await act((delegations) => delegations.revoke({ tenantId, delegationId }));
    },
    refresh: query.refresh,
  };
}

export interface UseConfirmationsResult {
  status: QueryStatus;
  /** Actions agents ask the person to confirm, newest first, still open. */
  pending: MemberConfirmation[];
  error: Error | null;
  approve(confirmationId: string): Promise<void>;
  reject(confirmationId: string): Promise<void>;
  refresh(): Promise<void>;
}

/**
 * The actions AI agents acting for the signed-in person asked them to confirm (delegations with `confirm`), to answer
 * from a notification or an inbox. An approval opens exactly that action on that resource for a few minutes.
 */
export function useConfirmations({
  tenantId,
  enabled = true,
}: {
  tenantId: string;
  enabled?: boolean;
}): UseConfirmationsResult {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).delegations;
  const query = useSessionQuery<MemberConfirmation[]>(
    JSON.stringify([tenantId]),
    [],
    async () => {
      if (!api) throw new Error('The client does not provide delegations');
      return api.listConfirmations({ tenantId, status: 'pending' });
    },
    enabled,
  );
  const decide = useCallback(
    async (confirmationId: string, approve: boolean) => {
      if (!api) throw new Error('The client does not provide delegations');
      await api.decideConfirmation({ tenantId, confirmationId, approve });
      await query.refresh();
    },
    [api, tenantId, query],
  );
  return {
    status: query.status,
    pending: query.data.filter((item) => !item.expired),
    error: query.error,
    approve: (confirmationId) => decide(confirmationId, true),
    reject: (confirmationId) => decide(confirmationId, false),
    refresh: query.refresh,
  };
}

/** The agents the signed-in person may delegate to, with their purpose, model and sponsor (`agents.catalog`). */
export function useAgentCatalog({
  tenantId,
  enabled = true,
}: {
  tenantId: string;
  enabled?: boolean;
}): { status: QueryStatus; agents: CatalogAgent[]; error: Error | null; refresh(): Promise<void> } {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).agents;
  const query = useSessionQuery<CatalogAgent[]>(
    JSON.stringify([tenantId]),
    [],
    async () => {
      if (!api) throw new Error('The client does not provide agents');
      return api.catalog({ tenantId });
    },
    enabled,
  );
  return { status: query.status, agents: query.data, error: query.error, refresh: query.refresh };
}

/** The AI models the signed-in caller may use now (`inference.listMine`), for a model picker. */
export function useModels({ tenantId, enabled = true }: { tenantId: string; enabled?: boolean }): {
  status: QueryStatus;
  models: MemberModel[];
  error: Error | null;
  refresh(): Promise<void>;
} {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).inference;
  const query = useSessionQuery<MemberModel[]>(
    JSON.stringify([tenantId]),
    [],
    async () => {
      if (!api) throw new Error('The client does not provide inference');
      return api.listMine({ tenantId });
    },
    enabled,
  );
  return { status: query.status, models: query.data, error: query.error, refresh: query.refresh };
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

export interface UseTeamsResult {
  status: QueryStatus;
  teams: MemberTeams['teams'];
  /** The person's pending join requests. */
  pending: MemberTeams['requests'];
  /** Teams that take join requests and that the person is not in (and has not asked to join). */
  joinable: MemberTeams['joinable'];
  /** Membership reviews waiting for the person as a maintainer. */
  reviews: NonNullable<MemberTeams['reviews']>;
  error: Error | null;
  /** Asks to join a team whose join policy is `request`; its maintainers decide. */
  requestToJoin(teamId: string, justification?: string): Promise<void>;
  /** Withdraws a pending join request. */
  cancelRequest(requestId: string): Promise<void>;
  /** Leaves a team the person belongs to directly. */
  leave(teamId: string): Promise<void>;
  refresh(): Promise<void>;
}

/** The signed-in person's teams with self-service joining and leaving (`teams.listMine`, `requestToJoin`, `leave`). */
export function useTeams({
  tenantId,
  enabled = true,
}: {
  tenantId: string;
  enabled?: boolean;
}): UseTeamsResult {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).teams;
  const missing = () => new Error('The client does not provide teams');
  const query = useSessionQuery<MemberTeams>(
    JSON.stringify([tenantId]),
    { teams: [], requests: [], joinable: [], reviews: [] },
    async () => {
      if (!api) throw missing();
      return api.listMine({ tenantId });
    },
    enabled,
  );
  const act = useCallback(
    async (run: (teams: NonNullable<SelfServiceClient['teams']>) => Promise<unknown>) => {
      if (!api) throw missing();
      await run(api);
      await query.refresh();
    },
    [api, query],
  );
  const pending = query.data.requests.filter((request) => request.status === 'pending');
  return {
    status: query.status,
    teams: query.data.teams,
    pending,
    joinable: query.data.joinable.filter(
      (team) => !pending.some((request) => request.team.id === team.id),
    ),
    reviews: query.data.reviews ?? [],
    error: query.error,
    requestToJoin: (teamId, justification) =>
      act((teams) =>
        teams.requestToJoin({ tenantId, teamId, ...(justification ? { justification } : {}) }),
      ),
    cancelRequest: (requestId) => act((teams) => teams.cancelRequest({ tenantId, requestId })),
    leave: (teamId) => act((teams) => teams.leave({ tenantId, teamId })),
    refresh: query.refresh,
  };
}

/** One group of a spend report (`billing.mySpend`): money in micros of the deployment currency. */
export interface MemberSpendRow {
  key: string;
  label?: string;
  costMicros: number;
  /** In currency units, rounded to the cent. */
  amount: number;
  /** Percent of the report's total. */
  share: number;
  events: number;
  quantities: Record<string, number>;
}
/** A spend budget with its standing in the current window. */
export interface MemberBudgetStatus {
  budgetId: string;
  name: string;
  subjectType: 'tenant' | 'team' | 'department' | 'identity';
  subjectId: string;
  subjectName?: string;
  period: 'month' | 'quarter' | 'year';
  amountMicros: number;
  spentMicros: number;
  percent: number;
  forecastMicros?: number;
  reached: number[];
  exceeded: boolean;
  enforce: boolean;
}
/** The signed-in person's own spend for a month (their usage and their agents'), with the budgets set on them. */
export interface MemberSpend {
  tenantId: string;
  currency: string;
  period: string;
  groupBy: string;
  rows: MemberSpendRow[];
  total: { costMicros: number; amount: number; events: number };
  forecast?: { costMicros: number; amount: number };
  budgets: MemberBudgetStatus[];
}
/** Whether the caller's usage is within every enforced budget that covers it (`billing.check`). */
export interface MemberSpendCheck {
  allowed: boolean;
  budgets: MemberBudgetStatus[];
  blockedBy?: MemberBudgetStatus;
}

/**
 * The signed-in person's own spend (`billing.mySpend`): what their usage and their agents' cost this month (or
 * `period`), grouped by `meter` (default), `day`, `agent`, `tenant` or `tag:{name}`, with a projection and their budgets.
 */
export function useMySpend({
  tenantId,
  period,
  groupBy,
  enabled = true,
}: {
  tenantId: string;
  period?: string;
  groupBy?: 'meter' | 'day' | 'agent' | 'tenant' | `tag:${string}`;
  enabled?: boolean;
}): {
  status: QueryStatus;
  spend: MemberSpend | null;
  error: Error | null;
  refresh(): Promise<void>;
} {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).billing;
  const query = useSessionQuery<MemberSpend | null>(
    JSON.stringify([tenantId, period ?? null, groupBy ?? null]),
    null,
    async (key) => {
      if (!api) throw new Error('The client does not provide billing');
      const [scope, month, grouping] = JSON.parse(key) as [string, string | null, string | null];
      return api.mySpend({
        tenantId: scope,
        ...(month ? { period: month } : {}),
        ...(grouping ? { groupBy: grouping } : {}),
      });
    },
    enabled,
  );
  return { status: query.status, spend: query.data, error: query.error, refresh: query.refresh };
}

/**
 * Whether the signed-in caller's usage (of `meter`, when given) is within every enforced spend budget that covers it
 * (`billing.check`), to warn before a costly action. `allowed` is `true` until the answer arrives; the server still
 * refuses usage recorded with `enforceBudgets`.
 */
export function useSpendCheck({
  tenantId,
  meter,
  enabled = true,
}: {
  tenantId: string;
  meter?: string;
  enabled?: boolean;
}): {
  status: QueryStatus;
  allowed: boolean;
  blockedBy?: MemberBudgetStatus;
  budgets: MemberBudgetStatus[];
  error: Error | null;
  refresh(): Promise<void>;
} {
  const { client } = useIamContext();
  const api = (client as SelfServiceClient).billing;
  const query = useSessionQuery<MemberSpendCheck>(
    JSON.stringify([tenantId, meter ?? null]),
    { allowed: true, budgets: [] },
    async (key) => {
      if (!api) throw new Error('The client does not provide billing');
      const [scope, only] = JSON.parse(key) as [string, string | null];
      return api.check({ tenantId: scope, ...(only ? { meter: only } : {}) });
    },
    enabled,
  );
  return {
    status: query.status,
    allowed: query.data.allowed,
    ...(query.data.blockedBy ? { blockedBy: query.data.blockedBy } : {}),
    budgets: query.data.budgets,
    error: query.error,
    refresh: query.refresh,
  };
}
