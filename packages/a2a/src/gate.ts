import { IamError, matchPattern, type CredentialInput } from '@better-iam/core';
import type { AgentCard, AgentSkill } from './cards.js';

/**
 * Authorization for Agent2Agent (A2A) servers speaking JSON-RPC over HTTP.
 *
 * `createA2aGate` sits in front of an A2A endpoint (a `Request` → `Response` handler). It serves the agent card at
 * `/.well-known/agent-card.json` without authentication, authenticates every other request (a Better IAM credential:
 * a person's session, an agent's key, or a delegated session in which an agent acts for a person; or an OAuth access
 * token), decides `message/send` and `message/stream` by the skill a message names (its `metadata.skillId`) or the
 * agent-wide message rule, and makes tasks private to the caller who started them: `tasks/get`, `tasks/cancel`,
 * `tasks/resubscribe` and push notification settings for a task another caller started answer "task not found".
 * `agent/getAuthenticatedExtendedCard` lists only the skills the caller may use.
 */

/** A resource the policy engine decides on. */
export interface A2aResourceRef {
  type: string;
  id: string;
}

/** How one skill (or the agent's messages as a whole) is authorized. */
export interface A2aRule {
  /** The Better IAM action a message needs (Better IAM credentials). */
  action?: string;
  /** The resource the message acts on; default `{ type: 'a2a-skill', id: skillId }` (`a2a-agent`/`agent` for `message`). */
  resource?: A2aResourceRef | ((params: Record<string, unknown>) => A2aResourceRef);
  /** Scopes an OAuth access token needs (OAuth callers). */
  scopes?: string[];
  /** Any authenticated caller may send such messages. */
  public?: boolean;
}

/** The part of a Better IAM instance (`betterIam()`) or client the gate needs. */
export interface A2aIam {
  authenticate(credential: CredentialInput): Promise<{
    identity: { id: string; tenantId: string; kind: string };
    session: {
      id: string;
      tenantId: string;
      kind: string;
      agentId?: string;
      delegationId?: string;
    };
  }>;
  authorize(
    request: CredentialInput & { tenantId: string; action: string; resource: A2aResourceRef },
  ): Promise<{ allowed: boolean; reason: string }>;
  authorizeMany(
    request: CredentialInput & {
      tenantId: string;
      checks: { action: string; resource: A2aResourceRef }[];
    },
  ): Promise<{ results: { allowed: boolean; reason: string }[] }>;
  /** Present on a `betterIam()` instance: lets the gate ask a person to confirm an agent's request. */
  api?: {
    delegations?: {
      get(
        credential: CredentialInput,
        input: { tenantId: string; delegationId: string },
      ): Promise<{ confirm?: string[] }>;
      requestConfirmation(
        credential: CredentialInput,
        input: { tenantId: string; action: string; resource: A2aResourceRef; reason: string },
      ): Promise<{ id: string; status: string; expiresAt: number }>;
    };
  };
}

/** The access-token verifier of `@better-iam/oauth` (`createAccessTokenVerifier` or a resource guard's `verifier`). */
export interface A2aOAuthVerifier {
  verifyRequest(
    request: { authorization: string | null; dpop?: string | null; method: string; url: string },
    requirement?: { scopes?: string[] },
  ): Promise<{ subject?: string; clientId: string; tenantId?: string; scopes: string[] }>;
}

/** Who is calling the A2A server. */
export type A2aCaller =
  | {
      kind: 'iam';
      credential: CredentialInput;
      tenantId: string;
      identityId: string;
      identityKind: string;
      sessionKind: string;
      /** The agent behind the credential: its own key, or the agent of a delegated session. */
      agentId?: string;
      delegationId?: string;
    }
  | { kind: 'oauth'; subject?: string; clientId: string; tenantId?: string; scopes: string[] };

/**
 * Who started each task and each conversation (A2A context), by key `task:{id}` or `context:{id}`. The default keeps
 * owners in this process's memory.
 */
export interface A2aTaskOwners {
  get(key: string): Promise<string | undefined> | string | undefined;
  set(key: string, owner: string): Promise<void> | void;
}

/** In-memory owners: at most `maxTasks` entries (default 100000), each kept `ttlMs` (default seven days). */
export function memoryTaskOwners(
  options: { maxTasks?: number; ttlMs?: number; now?: () => number } = {},
): A2aTaskOwners {
  const maxTasks = options.maxTasks ?? 100_000;
  const ttlMs = options.ttlMs ?? 7 * 24 * 3600 * 1000;
  const now = options.now ?? Date.now;
  const owners = new Map<string, { owner: string; until: number }>();
  return {
    get(key) {
      const found = owners.get(key);
      if (!found) return undefined;
      if (found.until <= now()) {
        owners.delete(key);
        return undefined;
      }
      return found.owner;
    },
    set(key, owner) {
      owners.delete(key);
      owners.set(key, { owner, until: now() + ttlMs });
      while (owners.size > maxTasks) owners.delete(owners.keys().next().value!);
    },
  };
}

export interface A2aGateOptions {
  iam: A2aIam;
  /** The rule for every message that names no skill (and for all messages when skills are not used). */
  message: A2aRule;
  /** Rules by skill id, for messages that name a skill (`metadata.skillId`). */
  skills?: Record<string, A2aRule>;
  /** Messages naming a skill without a rule: refused (`deny`, the default) or decided by `message`. */
  unlistedSkills?: 'deny' | 'message';
  /** How a request names its skill (default: `params.message.metadata.skillId`, then `params.metadata.skillId`). */
  skillOf?: (params: Record<string, unknown>) => string | undefined;
  /** The card served at `/.well-known/agent-card.json` (for example from `createCardAttestor`). */
  card?: AgentCard | (() => AgentCard | Promise<AgentCard>);
  /** The card answered to `agent/getAuthenticatedExtendedCard`, with only the skills the caller may use. */
  extendedCard?: AgentCard | (() => AgentCard | Promise<AgentCard>);
  /**
   * Who started each task and conversation; supply a shared store when several instances serve the agent. Unknown
   * tasks and conversations belong to no one, so a restart with the in-memory default ends access to earlier ones.
   */
  tasks?: A2aTaskOwners;
  /** Callers allowed this action on the `message` rule's resource may read and cancel every task (operators). */
  taskAdminAction?: string;
  /** JSON-RPC methods A2A does not define: refused (`deny`, the default) or passed on (`allow`). */
  otherMethods?: 'deny' | 'allow';
  /**
   * HTTP methods other than POST (besides the agent card): refused with 405 (`deny`, the default) or passed on to the
   * server unchecked apart from authentication (`allow`, for servers that serve more than JSON-RPC at this address).
   */
  otherHttpMethods?: 'deny' | 'allow';
  /**
   * The tenant decisions are made in: the organization that runs this agent (required). A function may choose it per
   * caller and returns undefined to refuse the caller. Deciding in each caller's own tenant would let any organization
   * grant itself access.
   */
  tenantId:
    | string
    | ((caller: { identityId: string; sessionTenantId: string }) => string | undefined);
  /**
   * Accepts OAuth access tokens too, decided by each rule's `scopes`. A token naming a tenant other than a fixed
   * `tenantId` is refused.
   */
  oauth?: A2aOAuthVerifier;
  /** Called with unexpected errors before the gate answers JSON-RPC `-32603` (HTTP 500). */
  onError?: (error: unknown) => void;
  /**
   * When an agent acting for a person (a delegated session) sends a message whose action the person confirms one
   * request at a time (the delegation's `confirm`), ask the person (`delegations.requestConfirmation`) and answer with
   * `A2A_CONFIRMATION_REQUESTED`. On by default when `iam.api.delegations` exists; `false` turns it off.
   */
  confirmations?: boolean;
  confirmationReason?: (skill: string | undefined, params: Record<string, unknown>) => string;
  /** Largest accepted JSON-RPC body in bytes (default 4 MiB). */
  maxBodyBytes?: number;
}

/**
 * JSON-RPC error code (HTTP 403) of a message the caller may not send: `error.data.reason` says why (`ACCESS_DENIED`,
 * `UNKNOWN_SKILL`, `NO_RULE_FOR_CALLER`, `INSUFFICIENT_SCOPE`). Tasks of other callers answer A2A's own `-32001`.
 */
export const A2A_ACCESS_DENIED = -32050;
/**
 * JSON-RPC error code (HTTP 403) telling an agent that acts for a person that the person must confirm this request
 * first: a confirmation request was filed (`error.data.confirmationId`, `error.data.expiresAt`); retry once approved.
 */
export const A2A_CONFIRMATION_REQUESTED = -32051;

export interface A2aDecision {
  allowed: boolean;
  /**
   * `ALLOWED`, `PUBLIC`, `ACCESS_DENIED`, `UNKNOWN_SKILL`, `AMBIGUOUS_SKILL`, `NO_RULE_FOR_CALLER`,
   * `INSUFFICIENT_SCOPE`, or `CONFIRMATION_REQUESTED`.
   */
  reason: string;
  confirmation?: { id: string; expiresAt: number };
}

const taskMethods = new Set([
  'tasks/get',
  'tasks/cancel',
  'tasks/resubscribe',
  'tasks/pushNotificationConfig/set',
  'tasks/pushNotificationConfig/get',
  'tasks/pushNotificationConfig/list',
  'tasks/pushNotificationConfig/delete',
]);
const messageMethods = new Set(['message/send', 'message/stream']);
const extendedCardMethod = 'agent/getAuthenticatedExtendedCard';

const plain = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);

/** A rule and, for a skill's own rule, the skill its default resource is named after. */
interface Found {
  rule: A2aRule;
  named?: string;
}

function presented(request: Request): { token: string; scheme: string } | undefined {
  const match = /^(Bearer|DPoP)\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  if (match) return { scheme: match[1]!, token: match[2]! };
  const key = request.headers.get('x-api-key');
  return key ? { scheme: 'Bearer', token: key } : undefined;
}

/** The skill ids a request names: in the message's metadata and in the request's. */
function namedSkills(params: Record<string, unknown>): unknown[] {
  const message = plain(params.message) ? params.message : undefined;
  return [
    plain(message?.metadata) ? message.metadata.skillId : undefined,
    plain(params.metadata) ? params.metadata.skillId : undefined,
  ].filter((value) => value !== undefined);
}

function defaultSkillOf(params: Record<string, unknown>): string | undefined {
  const found = namedSkills(params)[0];
  return typeof found === 'string' ? found : undefined;
}

/**
 * The A2A message metadata key that carries a Better IAM hand-off (`delegations.handoff`) from the calling agent to the
 * agent it calls, so the called agent can act for the same person with `delegations.assume`.
 */
export const handoffMetadataKey = 'better-iam/handoff';

/** Adds a hand-off to an A2A message's metadata (the calling side). */
export function withHandoff<T extends { metadata?: Record<string, unknown> }>(
  message: T,
  delegationId: string,
): T {
  return {
    ...message,
    metadata: { ...(message.metadata ?? {}), [handoffMetadataKey]: delegationId },
  };
}

/**
 * The hand-off an A2A request carries (the called side): the delegation id in the message's metadata, else in the
 * request's. Open a session for it with the called agent's own key (`delegations.assume`), which refuses hand-offs that
 * are not this agent's.
 */
export function handoffOf(params: Record<string, unknown>): string | undefined {
  const message = plain(params.message) ? params.message : undefined;
  const value =
    (plain(message?.metadata) ? message.metadata[handoffMetadataKey] : undefined) ??
    (plain(params.metadata) ? params.metadata[handoffMetadataKey] : undefined);
  return typeof value === 'string' && value ? value : undefined;
}

/** The owner key of a caller: the same person through the same agent (or none), or the same OAuth client and subject. */
export function taskOwnerOf(caller: A2aCaller): string {
  return caller.kind === 'iam'
    ? `iam:${caller.tenantId}:${caller.identityId}:${caller.agentId ?? ''}`
    : `oauth:${caller.clientId}:${caller.subject ?? ''}`;
}

/** Decisions shared by the gate and by handlers written with an A2A SDK. */
export function createA2aAuthorizer(options: A2aGateOptions) {
  const skillOf = options.skillOf ?? defaultSkillOf;
  /** The rule for a skill (or for messages naming none), and the skill its default resource is named after. */
  const ruleFor = (skill: string | undefined): Found | undefined => {
    if (skill !== undefined && options.skills && Object.hasOwn(options.skills, skill))
      return { rule: options.skills[skill]!, named: skill };
    if (skill === undefined || options.unlistedSkills === 'message')
      return { rule: options.message };
    return undefined;
  };
  const resourceOf = (found: Found, params: Record<string, unknown>): A2aResourceRef =>
    typeof found.rule.resource === 'function'
      ? found.rule.resource(params)
      : (found.rule.resource ??
        (found.named !== undefined
          ? { type: 'a2a-skill', id: found.named }
          : { type: 'a2a-agent', id: 'agent' }));

  async function requestConfirmation(
    caller: A2aCaller,
    skill: string | undefined,
    action: string,
    resource: A2aResourceRef,
    params: Record<string, unknown>,
  ): Promise<{ id: string; expiresAt: number } | undefined> {
    const delegations = options.iam.api?.delegations;
    if (
      options.confirmations === false ||
      !delegations ||
      caller.kind !== 'iam' ||
      caller.sessionKind !== 'delegated' ||
      !caller.delegationId
    )
      return undefined;
    try {
      const delegation = await delegations.get(caller.credential, {
        tenantId: caller.tenantId,
        delegationId: caller.delegationId,
      });
      if (!delegation.confirm?.some((pattern) => matchPattern(pattern, action))) return undefined;
      const request = await delegations.requestConfirmation(caller.credential, {
        tenantId: caller.tenantId,
        action,
        resource,
        reason:
          options.confirmationReason?.(skill, params) ??
          (skill
            ? `Your agent wants to use the skill ${skill} of another agent (${action}).`
            : `Your agent wants to send a message to another agent (${action}).`),
      });
      return { id: request.id, expiresAt: request.expiresAt };
    } catch {
      return undefined;
    }
  }

  async function decide(
    caller: A2aCaller,
    found: Found | undefined,
    skill: string | undefined,
    params: Record<string, unknown>,
    confirm: boolean,
  ): Promise<A2aDecision> {
    if (!found) return { allowed: false, reason: 'UNKNOWN_SKILL' };
    const { rule } = found;
    if (rule.public) return { allowed: true, reason: 'PUBLIC' };
    if (caller.kind === 'oauth') {
      if (!rule.scopes?.length) return { allowed: false, reason: 'NO_RULE_FOR_CALLER' };
      return rule.scopes.every((scope) => caller.scopes.includes(scope))
        ? { allowed: true, reason: 'ALLOWED' }
        : { allowed: false, reason: 'INSUFFICIENT_SCOPE' };
    }
    if (!rule.action) return { allowed: false, reason: 'NO_RULE_FOR_CALLER' };
    let resource: A2aResourceRef;
    try {
      resource = resourceOf(found, params);
    } catch {
      return { allowed: false, reason: 'ACCESS_DENIED' };
    }
    const decision = await options.iam.authorize({
      ...caller.credential,
      tenantId: caller.tenantId,
      action: rule.action,
      resource,
    });
    if (decision.allowed) return { allowed: true, reason: 'ALLOWED' };
    const confirmation = confirm
      ? await requestConfirmation(caller, skill, rule.action, resource, params)
      : undefined;
    return confirmation
      ? { allowed: false, reason: 'CONFIRMATION_REQUESTED', confirmation }
      : { allowed: false, reason: 'ACCESS_DENIED' };
  }

  return {
    /** A Better IAM credential first, then (with `oauth`) an OAuth access token; undefined when neither is valid. */
    async authenticate(request: Request): Promise<A2aCaller | undefined> {
      const found = presented(request);
      if (!found) return undefined;
      if (found.scheme.toLowerCase() === 'bearer') {
        const credential: CredentialInput = { token: found.token, headers: request.headers };
        try {
          const principal = await options.iam.authenticate(credential);
          const tenantId =
            typeof options.tenantId === 'function'
              ? options.tenantId({
                  identityId: principal.identity.id,
                  sessionTenantId: principal.session.tenantId,
                })
              : options.tenantId;
          if (typeof tenantId !== 'string' || !tenantId) return undefined;
          const agentId =
            principal.session.kind === 'delegated'
              ? principal.session.agentId
              : principal.identity.kind === 'agent'
                ? principal.identity.id
                : undefined;
          return {
            kind: 'iam',
            credential,
            tenantId,
            identityId: principal.identity.id,
            identityKind: principal.identity.kind,
            sessionKind: principal.session.kind,
            ...(agentId ? { agentId } : {}),
            ...(principal.session.delegationId
              ? { delegationId: principal.session.delegationId }
              : {}),
          };
        } catch (error) {
          if (!(error instanceof Error) || !options.oauth) return undefined;
        }
      }
      if (!options.oauth) return undefined;
      try {
        const token = await options.oauth.verifyRequest({
          authorization: request.headers.get('authorization'),
          dpop: request.headers.get('dpop'),
          method: request.method,
          url: request.url,
        });
        // A token issued for another organization is not a token for this agent.
        if (
          typeof options.tenantId === 'string' &&
          token.tenantId !== undefined &&
          token.tenantId !== options.tenantId
        )
          return undefined;
        return {
          kind: 'oauth',
          clientId: token.clientId,
          scopes: [...token.scopes],
          ...(token.subject ? { subject: token.subject } : {}),
          ...(token.tenantId ? { tenantId: token.tenantId } : {}),
        };
      } catch {
        return undefined;
      }
    },

    /** The skill a `message/send` or `message/stream` request names, if any. */
    skillOf,

    /**
     * Whether the caller may send a message with these params (asking for a confirmation when that applies). A request
     * naming two different skills (in the message's and the request's metadata) is refused as `AMBIGUOUS_SKILL`, so the
     * gate and the server cannot disagree on which skill runs.
     */
    async canSend(caller: A2aCaller, params: Record<string, unknown>): Promise<A2aDecision> {
      if (!options.skillOf && new Set(namedSkills(params)).size > 1)
        return { allowed: false, reason: 'AMBIGUOUS_SKILL' };
      const skill = skillOf(params);
      return decide(caller, ruleFor(skill), skill, params, true);
    },

    /** Whether the caller may read and cancel every task (`taskAdminAction`). */
    async isTaskAdmin(caller: A2aCaller): Promise<boolean> {
      if (!options.taskAdminAction || caller.kind !== 'iam') return false;
      const decision = await decide(
        caller,
        { rule: { ...options.message, action: options.taskAdminAction, public: false } },
        undefined,
        {},
        false,
      );
      return decision.allowed;
    },

    /** The skills the caller may use, in order (checked 50 at a time). */
    async visibleSkills<T extends Pick<AgentSkill, 'id'>>(
      caller: A2aCaller,
      skills: T[],
    ): Promise<T[]> {
      const visible = new Set<string>();
      const checks: { id: string; action: string; resource: A2aResourceRef }[] = [];
      for (const skill of skills) {
        const found = ruleFor(skill.id);
        if (!found) continue;
        const { rule } = found;
        if (rule.public) visible.add(skill.id);
        else if (caller.kind === 'oauth') {
          if (rule.scopes?.length && rule.scopes.every((scope) => caller.scopes.includes(scope)))
            visible.add(skill.id);
        } else if (rule.action) {
          if (typeof rule.resource === 'function') visible.add(skill.id);
          else checks.push({ id: skill.id, action: rule.action, resource: resourceOf(found, {}) });
        }
      }
      if (caller.kind === 'iam')
        for (let index = 0; index < checks.length; index += 50) {
          const batch = checks.slice(index, index + 50);
          const { results } = await options.iam.authorizeMany({
            ...caller.credential,
            tenantId: caller.tenantId,
            checks: batch.map(({ action, resource }) => ({ action, resource })),
          });
          batch.forEach((check, position) => {
            if (results[position]?.allowed) visible.add(check.id);
          });
        }
      return skills.filter((skill) => visible.has(skill.id));
    },
  };
}
export type A2aAuthorizer = ReturnType<typeof createA2aAuthorizer>;

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

const rpcError = (
  id: JsonRpcRequest['id'],
  code: number,
  message: string,
  data?: unknown,
  status = 200,
) =>
  json(
    { jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data ? { data } : {}) } },
    status,
  );

/**
 * The owner keys a JSON-RPC result names: its task (a task's `id`, or the `taskId` of a message or task event) and its
 * conversation (`contextId`).
 */
function ownedKeysOf(result: unknown): string[] {
  if (!plain(result)) return [];
  const keys: string[] = [];
  const taskId = result.kind === 'task' ? result.id : result.taskId;
  if (typeof taskId === 'string' && taskId) keys.push(`task:${taskId}`);
  if (typeof result.contextId === 'string' && result.contextId)
    keys.push(`context:${result.contextId}`);
  return keys;
}

/**
 * The gate: `gate(request, next)` answers the request itself (the agent card, challenges, refusals) or passes it to
 * `next` (the A2A server's handler) with the authenticated caller, recording who started each task on the way back.
 */
export function createA2aGate(options: A2aGateOptions) {
  const authorizer = createA2aAuthorizer(options);
  const owners = options.tasks ?? memoryTaskOwners();
  const maxBodyBytes = options.maxBodyBytes ?? 4 * 1024 * 1024;
  const cardOf = async (source: A2aGateOptions['card']) =>
    typeof source === 'function' ? await source() : source;

  const challenge = (error?: string) =>
    json(
      {
        error: error ?? 'unauthorized',
        error_description: 'Present a Better IAM credential or an OAuth access token',
      },
      401,
      {
        'cache-control': 'no-store',
        'www-authenticate': error ? `Bearer error="${error}"` : 'Bearer',
      },
    );

  async function remember(keys: string[], owner: string): Promise<void> {
    for (const key of keys) if ((await owners.get(key)) === undefined) await owners.set(key, owner);
  }

  /**
   * Records the owner of every task and conversation a response names, in a JSON body or an event stream, without
   * changing it.
   */
  async function observe(response: Response, owner: string): Promise<Response> {
    const type = response.headers.get('content-type') ?? '';
    if (type.includes('application/json')) {
      const text = await response.text();
      try {
        const message = JSON.parse(text) as { result?: unknown };
        await remember(ownedKeysOf(message.result), owner);
      } catch {
        // Not JSON after all: passed on unchanged.
      }
      return new Response(text, { status: response.status, headers: response.headers });
    }
    if (!type.includes('text/event-stream') || !response.body) return response;
    const decoder = new TextDecoder();
    let buffer = '';
    const inspect = async (event: string) => {
      const data = event
        .split(/\r?\n/)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /, ''))
        .join('\n');
      if (!data) return;
      try {
        await remember(ownedKeysOf((JSON.parse(data) as { result?: unknown }).result), owner);
      } catch {
        // Unparseable events are passed on unchanged.
      }
    };
    const body = response.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        async transform(chunk, controller) {
          buffer += decoder.decode(chunk, { stream: true });
          let boundary: RegExpExecArray | null;
          while ((boundary = /\r?\n\r?\n/.exec(buffer))) {
            const event = buffer.slice(0, boundary.index);
            buffer = buffer.slice(boundary.index + boundary[0].length);
            // Recorded before the event reaches the caller, so a follow-up request can already use the task.
            await inspect(event);
          }
          controller.enqueue(chunk);
        },
        async flush() {
          buffer += decoder.decode();
          if (buffer.trim()) await inspect(buffer);
        },
      }),
    );
    return new Response(body, { status: response.status, headers: response.headers });
  }

  /** Whether the caller started the task (or is a task administrator); unknown tasks belong to no one. */
  async function ownsTask(caller: A2aCaller, taskId: unknown): Promise<boolean> {
    if (typeof taskId !== 'string' || !taskId) return false;
    if ((await owners.get(`task:${taskId}`)) === taskOwnerOf(caller)) return true;
    return authorizer.isTaskAdmin(caller);
  }

  /**
   * Whether the caller may add to a conversation: one they started, or as a task administrator. Conversations are
   * started by the server (its answers name them), so an unknown one belongs to no one.
   */
  async function mayJoin(caller: A2aCaller, contextId: unknown): Promise<boolean> {
    if (typeof contextId !== 'string' || !contextId) return false;
    if ((await owners.get(`context:${contextId}`)) === taskOwnerOf(caller)) return true;
    return authorizer.isTaskAdmin(caller);
  }

  const failed = (id: JsonRpcRequest['id'], error: unknown) => {
    options.onError?.(error);
    return rpcError(id, -32603, 'Internal error', undefined, 500);
  };

  return async function gate(
    request: Request,
    next: (request: Request, caller: A2aCaller) => Promise<Response> | Response,
  ): Promise<Response> {
    const url = new URL(request.url);
    if (
      options.card &&
      (url.pathname === '/.well-known/agent-card.json' ||
        url.pathname === '/.well-known/agent.json')
    ) {
      if (request.method === 'OPTIONS')
        return new Response(null, {
          status: 204,
          headers: {
            'access-control-allow-origin': '*',
            'access-control-allow-methods': 'GET, OPTIONS',
          },
        });
      if (request.method !== 'GET' && request.method !== 'HEAD')
        return json({ error: 'method not allowed' }, 405, { allow: 'GET, OPTIONS' });
      try {
        return json(await cardOf(options.card), 200, {
          'access-control-allow-origin': '*',
          'cache-control': 'public, max-age=300',
        });
      } catch (error) {
        options.onError?.(error);
        return json({ error: 'agent card unavailable' }, 503, { 'retry-after': '30' });
      }
    }
    if (!presented(request)) return challenge();
    const caller = await authorizer.authenticate(request);
    if (!caller) return challenge('invalid_token');
    if (request.method !== 'POST')
      return options.otherHttpMethods === 'allow'
        ? next(request, caller)
        : json({ error: 'method not allowed' }, 405, { allow: 'POST' });
    const text = await boundedBody(request, maxBodyBytes);
    if (text === undefined) return json({ error: 'request too large' }, 413);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return rpcError(null, -32700, 'Parse error');
    }
    if (!plain(parsed) || typeof parsed.method !== 'string')
      return rpcError(null, -32600, 'Invalid Request: A2A takes one JSON-RPC request per call');
    const message = parsed as unknown as JsonRpcRequest;
    const params = plain(message.params) ? message.params : {};
    const owner = taskOwnerOf(caller);
    // The server receives the request exactly as the gate read it (no duplicate keys a different parser could pick).
    const headers = new Headers(request.headers);
    headers.delete('content-length');
    const forward = new Request(request.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(parsed),
    });
    try {
      if (messageMethods.has(message.method)) {
        const sent = plain(params.message) ? params.message : {};
        // Continuing a task or a conversation, or pointing at earlier tasks: only whoever started them may.
        if (sent.taskId !== undefined && !(await ownsTask(caller, sent.taskId)))
          return rpcError(message.id, -32001, 'Task not found');
        if (sent.contextId !== undefined && !(await mayJoin(caller, sent.contextId)))
          return rpcError(message.id, -32602, 'Invalid params: unknown context');
        if (sent.referenceTaskIds !== undefined) {
          if (!Array.isArray(sent.referenceTaskIds) || sent.referenceTaskIds.length > 100)
            return rpcError(message.id, -32602, 'Invalid params: referenceTaskIds');
          for (const reference of sent.referenceTaskIds as unknown[])
            if (!(await ownsTask(caller, reference)))
              return rpcError(message.id, -32001, 'Task not found');
        }
        const decision = await authorizer.canSend(caller, params);
        if (!decision.allowed)
          return decision.confirmation
            ? rpcError(
                message.id,
                A2A_CONFIRMATION_REQUESTED,
                'The person you act for must confirm this request first. Retry after they approve it.',
                {
                  reason: decision.reason,
                  confirmationId: decision.confirmation.id,
                  expiresAt: decision.confirmation.expiresAt,
                },
                403,
              )
            : rpcError(
                message.id,
                A2A_ACCESS_DENIED,
                decision.reason === 'UNKNOWN_SKILL'
                  ? 'Unknown skill'
                  : decision.reason === 'AMBIGUOUS_SKILL'
                    ? 'The request names two different skills'
                    : 'Access denied',
                { reason: decision.reason },
                403,
              );
        return observe(await next(forward, caller), owner);
      }
      if (taskMethods.has(message.method)) {
        const taskId =
          message.method === 'tasks/pushNotificationConfig/set' ? params.taskId : params.id;
        if (!(await ownsTask(caller, taskId)))
          return rpcError(message.id, -32001, 'Task not found');
        return next(forward, caller);
      }
      if (message.method === extendedCardMethod) {
        if (options.extendedCard) {
          const card = await cardOf(options.extendedCard);
          return json({
            jsonrpc: '2.0',
            id: message.id ?? null,
            result: {
              ...card,
              skills: await authorizer.visibleSkills(caller, card?.skills ?? []),
            },
          });
        }
        const response = await next(forward, caller);
        if (!(response.headers.get('content-type') ?? '').includes('application/json'))
          return response;
        const body = (await response.json()) as { result?: AgentCard };
        if (plain(body.result) && Array.isArray(body.result.skills))
          body.result = {
            ...body.result,
            skills: await authorizer.visibleSkills(caller, body.result.skills),
          };
        return json(body, response.status);
      }
    } catch (error) {
      if (error instanceof IamError && (error.status === 401 || error.code === 'UNAUTHENTICATED'))
        return challenge('invalid_token');
      return failed(message.id, error);
    }
    return options.otherMethods === 'allow'
      ? next(forward, caller)
      : rpcError(message.id, -32601, 'Method not found');
  };
}

/** The request body as text, or undefined when it is larger than `maxBytes` (read no further than that). */
async function boundedBody(request: Request, maxBytes: number): Promise<string | undefined> {
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > maxBytes) return undefined;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}
export type A2aGate = ReturnType<typeof createA2aGate>;
