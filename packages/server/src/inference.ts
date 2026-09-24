import {
  IamError,
  matchPattern,
  type AuthenticatedPrincipal,
  type IamPlugin,
  type IamStore,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { decryptSecret, encryptSecret, type SafeFetchAddressOptions } from '@better-iam/auth';
import type { ServerContext } from './context.js';
import type { Delegation, DelegationSpend } from './delegations.js';
import type { GroupMember } from './models.js';
import type { ResolvedResource } from './options.js';
import { id } from './utils.js';
import { integer, text } from './validation.js';

/**
 * Inference access control: which people, service accounts and AI agents may call which AI models, how much they may
 * spend, and what they did. Models are defined per tenant and inherited by sub-tenants; each one is a resource of type
 * `model` that policies grant `inference:invoke` on (`model/claude-*`, conditions on `resource.tier`, ...). Upstream
 * provider keys are sealed with the deployment secret and only ever leave storage inside the server (the gateway).
 * Budgets cap tokens and cost per hour, day or month for a tenant, a group or one identity (an agent's budget also
 * covers the sessions in which it acts for people). Every call is metered.
 */

export interface InferenceOptions {
  /**
   * Lets organizations (tenants below the root) point a provider at a custom base URL. Off by default: only a root
   * administrator may, because the gateway sends requests (with the provider key) to that address.
   */
  allowCustomBaseUrls?: boolean;
  /** How long per-request usage records are kept, in days (1 to 3650; 90 by default). */
  usageRetentionDays?: number;
  /** Lets base URLs use http on loopback hosts, for development and tests only. */
  allowInsecureLocalhost?: boolean;
  /**
   * Lets custom base URLs that organizations chose (`allowCustomBaseUrls`) reach private and reserved addresses. Off
   * by default: the gateway returns the upstream response, so without this an organization could read services on
   * the server's own network. Base URLs of the root tenant's providers are never restricted.
   */
  allowPrivateNetworks?: boolean;
}

/** The resource type and action the inference module adds to the permission catalog. */
export const inferenceResourceType = 'model';
export const inferenceAction = 'inference:invoke';
/**
 * Tools the provider runs itself (web search, code execution, remote MCP servers, ...), as resources of this type named
 * by kind (`model-tool/web_search`, `model-tool/mcp:{host}`), checked with `inference:use-tool` for models whose
 * `providerTools` is `policy`.
 */
export const inferenceToolResourceType = 'model-tool';
/** The action decided on each `model-tool/{kind}` a request asks for, for models whose `providerTools` is `policy`. */
export const inferenceToolAction = 'inference:use-tool';

/** What a model allows of provider-run tools: any (the default), none, or those policies allow one by one. */
export type ProviderToolsMode = 'allow' | 'deny' | 'policy';
export const providerToolsModes: readonly ProviderToolsMode[] = ['allow', 'deny', 'policy'];
/** A provider tool id: its kind, or `mcp:{host}` / `mcp:{connector}` for remote MCP servers. */
export const providerToolPattern = /^[a-z0-9][a-z0-9_.:-]{0,254}$/;

/** Upstream API families the gateway can pass requests to. */
export type ProviderKind = 'anthropic' | 'openai' | 'openai-compatible';
export const providerKinds: readonly ProviderKind[] = ['anthropic', 'openai', 'openai-compatible'];
/** The public endpoint of each kind; `openai-compatible` always needs a base URL. */
export const providerBaseUrls: Record<ProviderKind, string | undefined> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
  'openai-compatible': undefined,
};

/** An upstream model provider account. The key is sealed; administrators see only its last four characters. */
export interface InferenceProvider extends StoredRecord {
  name: string;
  kind: ProviderKind;
  baseUrl: string;
  keySealed: string;
  keyHint: string;
  createdAt: number;
  updatedAt: number;
  keyRotatedAt: number;
}

/** A model people may call, under a public name, served by a provider of the same tenant or an ancestor. */
export interface InferenceModel extends StoredRecord {
  /** The public model name (`uniqueKey`), used in requests and in policies as `model/{name}`. */
  name: string;
  providerId: string;
  /** The provider's own model name the gateway sends upstream. */
  upstreamModel: string;
  displayName?: string;
  family?: string;
  /** A free-form tier for policies, such as `frontier` or `small`. */
  tier?: string;
  contextWindow?: number;
  maxOutputTokens?: number;
  /** Prices in US dollars per million tokens; usage cost is metered in micro-dollars. */
  inputPricePerMTok?: number;
  outputPricePerMTok?: number;
  cachedInputPricePerMTok?: number;
  /**
   * Models the gateway tries, in order, when this one's provider is unreachable, rate limited or failing (at most 5):
   * each only if the caller may use it and it speaks the same wire format.
   */
  fallbacks?: string[];
  /**
   * Tools the provider runs itself that a request may ask for (web search, code execution, remote MCP servers, computer
   * use, ...): `allow` (unset) passes them, `deny` refuses any, `policy` checks `inference:use-tool` on each
   * `model-tool/{kind}`. Tools the caller runs itself (functions) are never checked.
   */
  providerTools?: ProviderToolsMode;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
}

/** A budget's window. `minute` budgets are rate limits (requests or tokens per minute). */
export type BudgetPeriod = 'minute' | 'hour' | 'day' | 'month';

/** A spending cap: tokens, cost and/or calls per period, for a tenant, a group or an identity, over some models. */
export interface InferenceBudget extends StoredRecord {
  name: string;
  subjectType: 'tenant' | 'group' | 'identity';
  /** The tenant, group or identity the budget covers. */
  subjectId: string;
  /** `shared`: one pool for everyone covered; `each`: every identity covered gets the full amount. */
  scope: 'shared' | 'each';
  period: BudgetPeriod;
  maxTokens?: number;
  maxCostMicros?: number;
  /** The most calls per window (a rate limit for agents that loop). */
  maxRequests?: number;
  /** Model name patterns the budget counts (every model when absent). */
  models?: string[];
  /** Emits `inference:budget-alert` once per window when usage crosses this share of a limit. */
  alertAtPercent?: number;
  /** Set by a platform (root) administrator: only a platform administrator may change or remove it. */
  platform?: boolean;
  createdAt: number;
  updatedAt: number;
}

/** Usage of one budget pool in one window. */
export interface InferenceCounter extends StoredRecord {
  budgetId: string;
  /** `shared`, or the identity for `each` budgets. */
  subjectKey: string;
  windowStart: number;
  windowEnd: number;
  tokens: number;
  costMicros: number;
  requests: number;
  alerted?: boolean;
  exceeded?: boolean;
  /** When the retention sweep may delete the counter. */
  expiresAt: number;
}

/** One metered model call. */
export interface InferenceUsageRecord extends StoredRecord {
  identityId: string;
  agentId?: string;
  delegationId?: string;
  sessionKind?: string;
  model: string;
  providerId: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  costMicros: number;
  status: 'ok' | 'error';
  requestId?: string;
  latencyMs?: number;
  createdAt: number;
  expiresAt: number;
}

/**
 * Who created an OpenAI Responses API response through the gateway (id `{tenantId}:{responseId}`), so only they may
 * continue it with `previous_response_id`. Kept as long as usage records.
 */
export interface InferenceResponseRecord extends StoredRecord {
  responseId: string;
  identityId: string;
  agentId?: string;
  model: string;
  /** The provider that answered: only a call to the same provider may continue the response. */
  providerId: string;
  createdAt: number;
  expiresAt: number;
}

/** Token counts reported for one call. */
export interface InferenceTokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

/** A budget as a check reports it: how much is left in the current window. */
export interface BudgetStanding {
  budgetId: string;
  name: string;
  period: BudgetPeriod;
  windowStart: number;
  resetsAt: number;
  usedTokens: number;
  usedCostMicros: number;
  /** Calls metered in the window. */
  usedRequests: number;
  remainingTokens?: number;
  remainingCostMicros?: number;
  remainingRequests?: number;
}

/** The outcome of an invocation check (never contains provider secrets). */
export type InvocationCheck =
  | {
      allowed: true;
      model: PublicModel;
      budgets: BudgetStanding[];
    }
  | {
      allowed: false;
      reason: 'ACCESS_DENIED' | 'BUDGET_EXCEEDED' | 'MODEL_DISABLED' | 'TOOL_NOT_ALLOWED';
      model?: PublicModel;
      /** For BUDGET_EXCEEDED: the exhausted budget. */
      budget?: BudgetStanding;
      /** For TOOL_NOT_ALLOWED: the first provider tool refused. */
      tool?: string;
    };

/** A model as callers see it: never the provider key, only which provider serves it. */
export interface PublicModel {
  name: string;
  tenantId: string;
  inherited: boolean;
  provider: { id: string; name: string; kind: ProviderKind };
  upstreamModel: string;
  displayName?: string;
  family?: string;
  tier?: string;
  contextWindow?: number;
  maxOutputTokens?: number;
  inputPricePerMTok?: number;
  outputPricePerMTok?: number;
  cachedInputPricePerMTok?: number;
  fallbacks?: string[];
  /** Provider-run tools: `deny` or `policy` when set (see `InferenceModel.providerTools`). */
  providerTools?: ProviderToolsMode;
  enabled: boolean;
}

/** Reads a list of provider tool ids (at most 64), deduplicated. */
export function providerToolList(value: unknown): string[] {
  if (!Array.isArray(value)) throw new IamError('INVALID_INPUT', 'tools must be a list');
  const tools = [...new Set(value)];
  if (
    tools.length > 64 ||
    tools.some((tool) => typeof tool !== 'string' || !providerToolPattern.test(tool))
  )
    throw new IamError(
      'INVALID_INPUT',
      'tools must list at most 64 provider tool ids (such as web_search or mcp:tools.example.com)',
    );
  return tools as string[];
}

const modelNamePattern = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$/;
const hour = 3_600_000;
const day = 86_400_000;

/** Whether the deployment enabled inference (`inference` option). */
export function inferenceEnabled(ctx: Pick<ServerContext, 'options'>): boolean {
  return Boolean(ctx.options.inference);
}

export function inferenceSettings(ctx: Pick<ServerContext, 'options'>): InferenceOptions {
  const value = ctx.options.inference;
  return typeof value === 'object' && value ? value : {};
}

/** Refuses inference calls on deployments that did not enable it. */
export function assertInference(ctx: Pick<ServerContext, 'options'>): void {
  if (!inferenceEnabled(ctx))
    throw new IamError('FEATURE_DISABLED', 'Inference is not enabled on this deployment', 403);
}

/** The catalog entries the module contributes when enabled: the `model` type and `inference:invoke`. */
export function inferencePlugins(options: { inference?: unknown }): IamPlugin[] {
  if (!options.inference) return [];
  // Validated once, at construction.
  if (typeof options.inference === 'object') {
    const settings = options.inference as InferenceOptions;
    const days = settings.usageRetentionDays;
    if (days !== undefined && (!Number.isSafeInteger(days) || days < 1 || days > 3650))
      throw new IamError('INVALID_CONFIG', 'inference.usageRetentionDays must be 1 to 3650');
    for (const key of [
      'allowCustomBaseUrls',
      'allowInsecureLocalhost',
      'allowPrivateNetworks',
    ] as const)
      if (settings[key] !== undefined && typeof settings[key] !== 'boolean')
        throw new IamError('INVALID_CONFIG', `inference.${key} must be a boolean`);
  } else if (options.inference !== true)
    throw new IamError('INVALID_CONFIG', 'inference must be true or an options object');
  return [
    {
      id: 'better-iam:inference',
      resourceTypes: {
        [inferenceResourceType]: {
          description: 'An AI model callers may invoke through the inference gateway',
          actions: [inferenceAction],
          attributes: {
            provider: 'string',
            providerKind: 'string',
            upstreamModel: 'string',
            family: 'string',
            tier: 'string',
            contextWindow: 'number',
            inputPricePerMTok: 'number',
            outputPricePerMTok: 'number',
            enabled: 'boolean',
          },
        },
        [inferenceToolResourceType]: {
          description:
            'A tool the model provider runs itself (web search, code execution, a remote MCP server, ...)',
          actions: [inferenceToolAction],
          attributes: { kind: 'string', host: 'string' },
        },
      },
    },
  ];
}

/** A public model name. */
export function modelName(value: unknown): string {
  if (typeof value !== 'string' || !modelNamePattern.test(value))
    throw new IamError(
      'INVALID_INPUT',
      'Model names use 1-128 letters, digits or ._:/@+- characters and start with a letter or digit',
    );
  return value;
}

/** A non-negative price in dollars per million tokens (at most 10 000). */
export function price(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 10_000)
    throw new IamError(
      'INVALID_INPUT',
      `${name} must be a price from 0 to 10000 dollars per million tokens`,
    );
  return value;
}

/** The encryption context of a provider's key: binds the ciphertext to its record. */
export const providerKeyContext = (providerId: string) => `inference-provider:${providerId}`;

/** Seals a provider key for storage with the current deployment secret. */
export function sealProviderKey(secret: string, providerId: string, key: string): string {
  return encryptSecret(key, secret, providerKeyContext(providerId));
}

/** Opens a provider's sealed key with the current secret or any previous one (`rotateSecrets` re-seals). */
export function openProviderKey(ctx: ServerContext, provider: InferenceProvider): string {
  return decryptSecret(
    provider.keySealed,
    [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])],
    providerKeyContext(provider.id),
  );
}

/** A provider key: 8 to 4096 printable characters without whitespace. */
export function providerKey(value: unknown): string {
  if (typeof value !== 'string' || value.length < 8 || value.length > 4096 || /\s/.test(value))
    throw new IamError('INVALID_INPUT', 'apiKey must be 8-4096 characters without whitespace');
  return value;
}

/**
 * A provider base URL: https without credentials, query or fragment (http on loopback only with
 * `allowInsecureLocalhost`); the trailing slash is removed.
 */
export function baseUrl(value: unknown, settings: InferenceOptions): string {
  const raw = text(value, 'baseUrl', 2048);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new IamError('INVALID_INPUT', 'baseUrl must be an absolute URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !(
      url.protocol === 'https:' ||
      (url.protocol === 'http:' && loopback && settings.allowInsecureLocalhost)
    )
  )
    throw new IamError(
      'INVALID_INPUT',
      'baseUrl must be an https URL without credentials or query',
    );
  return url.toString().replace(/\/+$/, '');
}

/** The tenant and its ancestors, nearest first, for inherited models and providers. */
async function realmChain(ctx: ServerContext, tx: IamStore, tenantId: string): Promise<Tenant[]> {
  return ctx.ancestry(tx, await ctx.tenant(tx, tenantId));
}

/** A provider visible from a tenant: its own or an ancestor's. */
export async function visibleProvider(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  providerId: string,
): Promise<InferenceProvider | undefined> {
  const provider = await tx.get<InferenceProvider>('inferenceProviders', providerId);
  if (!provider) return undefined;
  const chain = await realmChain(ctx, tx, tenantId);
  return chain.some((realm) => realm.id === provider.tenantId) ? provider : undefined;
}

/** Every provider a tenant may use (its own and its ancestors'), nearest first. */
export async function visibleProviders(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
): Promise<InferenceProvider[]> {
  const providers: InferenceProvider[] = [];
  for (const realm of await realmChain(ctx, tx, tenantId))
    providers.push(
      ...(await tx.find<InferenceProvider>('inferenceProviders', { tenantId: realm.id })),
    );
  return providers;
}

/** The nearest definition of a model name for a tenant (its own, else the closest ancestor's), with its provider. */
export async function resolveModel(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  name: string,
): Promise<{ model: InferenceModel; provider: InferenceProvider | undefined } | undefined> {
  for (const realm of await realmChain(ctx, tx, tenantId)) {
    const model = (
      await tx.find<InferenceModel>('inferenceModels', { tenantId: realm.id, uniqueKey: name })
    )[0];
    if (model)
      return {
        model,
        provider: await visibleProvider(ctx, tx, realm.id, model.providerId),
      };
  }
  return undefined;
}

/** Every model visible from a tenant: its own and inherited ones, the nearest definition of each name winning. */
export async function visibleModels(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
): Promise<{ model: InferenceModel; provider: InferenceProvider | undefined }[]> {
  const seen = new Map<
    string,
    { model: InferenceModel; provider: InferenceProvider | undefined }
  >();
  for (const realm of await realmChain(ctx, tx, tenantId))
    for (const model of await tx.find<InferenceModel>('inferenceModels', { tenantId: realm.id }))
      if (!seen.has(model.name))
        seen.set(model.name, {
          model,
          provider: await visibleProvider(ctx, tx, realm.id, model.providerId),
        });
  return [...seen.values()].sort((a, b) => a.model.name.localeCompare(b.model.name));
}

export function publicModel(
  model: InferenceModel,
  provider: InferenceProvider | undefined,
  tenantId: string,
): PublicModel {
  const result: PublicModel = {
    name: model.name,
    tenantId: model.tenantId,
    inherited: model.tenantId !== tenantId,
    provider: provider
      ? { id: provider.id, name: provider.name, kind: provider.kind }
      : { id: model.providerId, name: '(missing)', kind: 'openai-compatible' },
    upstreamModel: model.upstreamModel,
    enabled: model.enabled && provider !== undefined,
  };
  for (const key of [
    'displayName',
    'family',
    'tier',
    'contextWindow',
    'maxOutputTokens',
    'inputPricePerMTok',
    'outputPricePerMTok',
    'cachedInputPricePerMTok',
  ] as const)
    if (model[key] !== undefined) (result as unknown as Record<string, unknown>)[key] = model[key];
  if (model.fallbacks?.length) result.fallbacks = [...model.fallbacks];
  if (model.providerTools && model.providerTools !== 'allow')
    result.providerTools = model.providerTools;
  return result;
}

/** A model as the policy engine sees it: `resource.provider`, `resource.tier`, `resource.inputPricePerMTok`, ... */
function modelAttributes(
  model: InferenceModel,
  provider: InferenceProvider | undefined,
): Record<string, unknown> {
  const attributes: Record<string, unknown> = {
    provider: provider?.name ?? '',
    providerKind: provider?.kind ?? '',
    upstreamModel: model.upstreamModel,
    enabled: model.enabled && provider !== undefined,
  };
  for (const key of [
    'family',
    'tier',
    'contextWindow',
    'inputPricePerMTok',
    'outputPricePerMTok',
  ] as const)
    if (model[key] !== undefined) attributes[key] = model[key];
  return attributes;
}

/**
 * The decision engine's resolver for `model/{name}` when inference is enabled: the nearest definition's attributes.
 * Undefined for other types (the caller resolves those); NOT_FOUND for a model the tenant cannot see.
 */
export async function resolveModelResource(
  ctx: ServerContext,
  tx: IamStore,
  reference: { tenantId: string; type: string; id: string },
): Promise<ResolvedResource | undefined> {
  // Provider tools are named, not registered: `model-tool/{kind}` or `model-tool/mcp:{host}`.
  if (reference.type === inferenceToolResourceType && inferenceEnabled(ctx)) {
    if (!providerToolPattern.test(reference.id))
      throw new IamError('NOT_FOUND', 'Unknown provider tool', 404);
    const colon = reference.id.indexOf(':');
    return {
      tenantId: reference.tenantId,
      type: inferenceToolResourceType,
      id: reference.id,
      attributes:
        colon > 0
          ? { kind: reference.id.slice(0, colon), host: reference.id.slice(colon + 1) }
          : { kind: reference.id },
    };
  }
  if (reference.type !== inferenceResourceType || !inferenceEnabled(ctx)) return undefined;
  const found = await resolveModel(ctx, tx, reference.tenantId, reference.id);
  if (!found) throw new IamError('NOT_FOUND', 'Model not found', 404);
  return {
    tenantId: reference.tenantId,
    type: inferenceResourceType,
    id: reference.id,
    attributes: modelAttributes(found.model, found.provider),
  };
}

/** The current window of a period (UTC), as [start, end). */
export function budgetWindow(period: BudgetPeriod, now: number): { start: number; end: number } {
  if (period === 'minute') {
    const start = Math.floor(now / 60_000) * 60_000;
    return { start, end: start + 60_000 };
  }
  if (period === 'hour') {
    const start = Math.floor(now / hour) * hour;
    return { start, end: start + hour };
  }
  if (period === 'day') {
    const start = Math.floor(now / day) * day;
    return { start, end: start + day };
  }
  const date = new Date(now);
  return {
    start: Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1),
    end: Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1),
  };
}

/** Cost of a call in micro-dollars: tokens × dollars per million tokens (cached input at its own price when set). */
export function usageCost(model: InferenceModel, usage: InferenceTokenUsage): number {
  const cached = usage.cacheReadTokens ?? 0;
  const input = model.inputPricePerMTok ?? 0;
  const cost =
    usage.inputTokens * input +
    (usage.cacheWriteTokens ?? 0) * input +
    cached * (model.cachedInputPricePerMTok ?? input) +
    usage.outputTokens * (model.outputPricePerMTok ?? 0);
  return Math.round(cost * 1000) / 1000;
}

/** Tokens a budget counts for a call: input (including cache reads and writes) plus output. */
export function usageTokens(usage: InferenceTokenUsage): number {
  return (
    usage.inputTokens +
    usage.outputTokens +
    (usage.cacheReadTokens ?? 0) +
    (usage.cacheWriteTokens ?? 0)
  );
}

/**
 * Who a call is attributed to: the identity, the agent behind the credential, the delegation it acts under, and the
 * identity's groups.
 */
export interface UsageSubject {
  tenantId: string;
  identityId: string;
  agentId?: string;
  delegationId?: string;
  /** For a hand-off: the agents that handed the work on, whose own budgets count the call too. */
  chainAgentIds?: string[];
  groupIds: ReadonlySet<string>;
  /**
   * In a delegated session: the groups of the acting agent (and of the agents that handed the work on), so a group
   * budget on agents counts what they do for people as well as what they do with their own keys.
   */
  agentGroupIds?: ReadonlySet<string>;
}

/** The subject of a principal's calls in `tenantId`. */
export async function usageSubject(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
): Promise<UsageSubject> {
  const groupIds = new Set(
    (await tx.find<GroupMember>('groupMembers', { tenantId, identityId: principal.identity.id }))
      .filter((member) => ctx.liveMembership(member))
      .map((member) => member.groupId),
  );
  const agentId =
    principal.session.kind === 'delegated'
      ? principal.session.agentId
      : principal.identity.kind === 'agent'
        ? principal.identity.id
        : undefined;
  const delegationId =
    principal.session.kind === 'delegated' ? principal.session.delegationId : undefined;
  const chain =
    typeof delegationId === 'string'
      ? (await tx.get<Delegation>('delegations', delegationId))?.chain
      : undefined;
  const agentGroupIds = new Set<string>();
  if (principal.session.kind === 'delegated')
    for (const actingId of [agentId, ...(chain ?? [])])
      if (typeof actingId === 'string')
        for (const member of await tx.find<GroupMember>('groupMembers', {
          tenantId,
          identityId: actingId,
        }))
          if (ctx.liveMembership(member)) agentGroupIds.add(member.groupId);
  return {
    tenantId,
    identityId: principal.identity.id,
    ...(typeof agentId === 'string' ? { agentId } : {}),
    ...(typeof delegationId === 'string' ? { delegationId } : {}),
    ...(chain?.length ? { chainAgentIds: [...chain] } : {}),
    groupIds,
    ...(agentGroupIds.size ? { agentGroupIds } : {}),
  };
}

/**
 * A delegation's spending cap (`Delegation.spend`) as a budget: one shared pool per window, over every model, whose
 * counters are kept under the id `delegation:{delegationId}`.
 */
export function delegationBudget(
  delegation: Delegation & { spend: DelegationSpend },
): InferenceBudget {
  const { spend } = delegation;
  return {
    id: `delegation:${delegation.id}`,
    tenantId: delegation.tenantId,
    name: 'Delegation spending limit',
    subjectType: 'identity',
    subjectId: delegation.subjectId,
    scope: 'shared',
    period: spend.period,
    ...(spend.maxTokens !== undefined ? { maxTokens: spend.maxTokens } : {}),
    ...(spend.maxCostMicros !== undefined ? { maxCostMicros: spend.maxCostMicros } : {}),
    ...(spend.maxRequests !== undefined ? { maxRequests: spend.maxRequests } : {}),
    createdAt: delegation.createdAt,
    updatedAt: delegation.decidedAt ?? delegation.createdAt,
  };
}

/** How much of a delegation's spending cap is used in the current window (undefined without a cap). */
export async function delegationSpendStanding(
  tx: IamStore,
  delegation: Delegation,
  now: number,
): Promise<BudgetStanding | undefined> {
  if (!delegation.spend) return undefined;
  const budget = delegationBudget(delegation as Delegation & { spend: DelegationSpend });
  const window = budgetWindow(budget.period, now);
  const counter = await tx.get<InferenceCounter>(
    'inferenceCounters',
    counterId(budget.id, 'shared', window.start),
  );
  return standingOf(budget, window, counter);
}

/** The budgets that cover a subject's use of a model, with the counter key each one uses. */
async function coveringBudgets(
  tx: IamStore,
  subject: UsageSubject,
  model: string,
): Promise<{ budget: InferenceBudget; subjectKey: string }[]> {
  const covering: { budget: InferenceBudget; subjectKey: string }[] = [];
  for (const budget of await tx.find<InferenceBudget>('inferenceBudgets', {
    tenantId: subject.tenantId,
  })) {
    if (budget.models?.length && !budget.models.some((pattern) => matchPattern(pattern, model)))
      continue;
    const viaAgentGroup =
      budget.subjectType === 'group' &&
      !subject.groupIds.has(budget.subjectId) &&
      (subject.agentGroupIds?.has(budget.subjectId) ?? false);
    const covers =
      budget.subjectType === 'tenant'
        ? budget.subjectId === subject.tenantId
        : budget.subjectType === 'group'
          ? subject.groupIds.has(budget.subjectId) || viaAgentGroup
          : budget.subjectId === subject.identityId ||
            budget.subjectId === subject.agentId ||
            // An agent's budget also counts the work it handed on to other agents.
            (subject.chainAgentIds?.includes(budget.subjectId) ?? false);
    if (!covers) continue;
    // An identity budget on an agent counts everything the agent does, for anyone; a per-identity group budget that
    // covers the call through the agent's group counts it against the agent.
    const subjectKey =
      budget.subjectType === 'identity' || budget.scope === 'shared'
        ? 'shared'
        : viaAgentGroup && subject.agentId
          ? subject.agentId
          : subject.identityId;
    covering.push({ budget, subjectKey });
  }
  // The person's spending caps on the delegation the call is made under and on every delegation above it (hand-offs).
  let delegationId = subject.delegationId;
  for (let depth = 0; delegationId !== undefined && depth <= 3; depth++) {
    const delegation = await tx.get<Delegation>('delegations', delegationId);
    if (!delegation) break;
    if (delegation.spend)
      covering.push({
        budget: delegationBudget(delegation as Delegation & { spend: DelegationSpend }),
        subjectKey: 'shared',
      });
    delegationId = delegation.parentId;
  }
  return covering.sort((a, b) => (a.budget.id < b.budget.id ? -1 : 1));
}

const counterId = (budgetId: string, subjectKey: string, windowStart: number) =>
  `${budgetId}:${subjectKey}:${windowStart}`;

/** A budget's standing in a window, from its counter (absent: nothing used yet). */
export function standingOf(
  budget: InferenceBudget,
  window: { start: number; end: number },
  counter: InferenceCounter | undefined,
): BudgetStanding {
  const usedTokens = counter?.tokens ?? 0;
  const usedCostMicros = counter?.costMicros ?? 0;
  const usedRequests = counter?.requests ?? 0;
  const result: BudgetStanding = {
    budgetId: budget.id,
    name: budget.name,
    period: budget.period,
    windowStart: window.start,
    resetsAt: window.end,
    usedTokens,
    usedCostMicros,
    usedRequests,
  };
  if (budget.maxTokens !== undefined)
    result.remainingTokens = Math.max(0, budget.maxTokens - usedTokens);
  if (budget.maxCostMicros !== undefined)
    result.remainingCostMicros = Math.max(0, budget.maxCostMicros - usedCostMicros);
  if (budget.maxRequests !== undefined)
    result.remainingRequests = Math.max(0, budget.maxRequests - usedRequests);
  return result;
}

/** The standing of every budget covering a subject's use of a model, in the current windows. */
export async function budgetStandings(
  ctx: ServerContext,
  tx: IamStore,
  subject: UsageSubject,
  model: string,
): Promise<{ budget: InferenceBudget; subjectKey: string; standing: BudgetStanding }[]> {
  const now = ctx.now();
  const result = [];
  for (const { budget, subjectKey } of await coveringBudgets(tx, subject, model)) {
    const window = budgetWindow(budget.period, now);
    const counter = await tx.get<InferenceCounter>(
      'inferenceCounters',
      counterId(budget.id, subjectKey, window.start),
    );
    result.push({ budget, subjectKey, standing: standingOf(budget, window, counter) });
  }
  return result;
}

/**
 * Whether a principal may call a model now: the model must be visible and enabled, `inference:invoke` on
 * `model/{name}` must be allowed (denials are audited like any decision), and no covering budget may be exhausted
 * (`estimatedTokens`, when given, must fit in what remains, priced at the model's input price). The first refusal of
 * a budget in a window is audited as `inference:budget-exceeded`.
 */
export async function checkInvocation(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: { tenantId: string; model: string; estimatedTokens?: number; tools?: string[] },
): Promise<InvocationCheck> {
  assertInference(ctx);
  const name = modelName(input.model);
  const estimate =
    input.estimatedTokens === undefined
      ? 0
      : integer(input.estimatedTokens, 'estimatedTokens', 0, 100_000_000);
  const tools = input.tools === undefined ? [] : providerToolList(input.tools);
  const found = await resolveModel(ctx, tx, input.tenantId, name);
  if (!found) throw new IamError('NOT_FOUND', 'Model not found', 404);
  const model = publicModel(found.model, found.provider, input.tenantId);
  const decision = await ctx.operations.recordedDecision(tx, principal, {
    tenantId: input.tenantId,
    action: inferenceAction,
    resource: { type: inferenceResourceType, id: name },
  });
  if (!decision.allowed) return { allowed: false, reason: 'ACCESS_DENIED', model };
  if (!model.enabled) return { allowed: false, reason: 'MODEL_DISABLED', model };
  // Provider-run tools the request asks for, by the model's setting.
  const mode = found.model.providerTools ?? 'allow';
  for (const tool of mode === 'allow' ? [] : tools) {
    let allowed = false;
    if (mode === 'policy')
      allowed = (
        await ctx.operations.recordedDecision(tx, principal, {
          tenantId: input.tenantId,
          action: inferenceToolAction,
          resource: { type: inferenceToolResourceType, id: tool },
        })
      ).allowed;
    // Refused by the model itself: audited like a denied decision.
    else
      await ctx.events.audit(
        tx,
        principal,
        inferenceToolAction,
        input.tenantId,
        `${inferenceToolResourceType}/${tool}`,
        'deny',
        false,
        { model: name, providerTools: 'deny' },
      );
    if (!allowed) return { allowed: false, reason: 'TOOL_NOT_ALLOWED', model, tool };
  }
  const subject = await usageSubject(ctx, tx, principal, input.tenantId);
  const estimateCost = usageCost(found.model, { inputTokens: estimate, outputTokens: 0 });
  const budgets: BudgetStanding[] = [];
  for (const { budget, subjectKey, standing: current } of await budgetStandings(
    ctx,
    tx,
    subject,
    name,
  )) {
    const overTokens =
      budget.maxTokens !== undefined && current.usedTokens + estimate > budget.maxTokens;
    const overCost =
      budget.maxCostMicros !== undefined &&
      current.usedCostMicros + estimateCost > budget.maxCostMicros;
    const exhausted =
      (budget.maxTokens !== undefined && current.usedTokens >= budget.maxTokens) ||
      (budget.maxCostMicros !== undefined && current.usedCostMicros >= budget.maxCostMicros) ||
      (budget.maxRequests !== undefined && current.usedRequests >= budget.maxRequests);
    if (overTokens || overCost || exhausted) {
      await noteExceeded(ctx, tx, principal, budget, subjectKey, current);
      return { allowed: false, reason: 'BUDGET_EXCEEDED', model, budget: current };
    }
    budgets.push(current);
  }
  return { allowed: true, model, budgets };
}

/** Audits the first refusal of a budget in a window (`inference:budget-exceeded`) and marks the counter. */
async function noteExceeded(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  budget: InferenceBudget,
  subjectKey: string,
  current: BudgetStanding,
): Promise<void> {
  const key = counterId(budget.id, subjectKey, current.windowStart);
  const counter = await tx.get<InferenceCounter>('inferenceCounters', key);
  if (counter?.exceeded) return;
  const next: InferenceCounter = counter
    ? { ...counter, exceeded: true }
    : {
        id: key,
        tenantId: budget.tenantId,
        budgetId: budget.id,
        subjectKey,
        windowStart: current.windowStart,
        windowEnd: current.resetsAt,
        tokens: 0,
        costMicros: 0,
        requests: 0,
        exceeded: true,
        expiresAt: current.resetsAt + 35 * day,
      };
  await (counter ? tx.put('inferenceCounters', next) : tx.insert('inferenceCounters', next));
  await ctx.events.audit(
    tx,
    principal,
    'inference:budget-exceeded',
    budget.tenantId,
    budget.id,
    'deny',
    false,
    { budget: budget.name, period: budget.period, windowStart: current.windowStart },
  );
}

/** What a gateway reports after a call. */
export interface InvocationRecord extends InferenceTokenUsage {
  tenantId: string;
  model: string;
  status?: 'ok' | 'error';
  requestId?: string;
  latencyMs?: number;
  /** The provider's Responses API response id, recorded as the caller's (gateway only). */
  responseId?: string;
}

/** The caller a Responses API conversation belongs to: the person or account, and the agent acting, if any. */
function responseOwner(principal: AuthenticatedPrincipal): {
  identityId: string;
  agentId?: string;
} {
  const agentId =
    principal.session.kind === 'delegated'
      ? principal.session.agentId
      : principal.identity.kind === 'agent'
        ? principal.identity.id
        : undefined;
  return {
    identityId: principal.identity.id,
    ...(typeof agentId === 'string' ? { agentId } : {}),
  };
}

const responseRecordId = (tenantId: string, responseId: string) => `${tenantId}:${responseId}`;

/**
 * Whether `responseId` was created through the gateway in `tenantId` by the same caller as `principal`, at the provider
 * `providerId` (so a provider that echoes someone else's response id cannot claim it for another provider's key).
 */
export async function ownsInferenceResponse(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  responseId: string,
  providerId: string,
): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(responseId)) return false;
  const record = await tx.get<InferenceResponseRecord>(
    'inferenceResponses',
    responseRecordId(tenantId, responseId),
  );
  if (
    !record ||
    record.tenantId !== tenantId ||
    record.providerId !== providerId ||
    record.expiresAt <= ctx.now()
  )
    return false;
  const owner = responseOwner(principal);
  return record.identityId === owner.identityId && record.agentId === owner.agentId;
}

/**
 * Meters one call: stores a usage record (cost from the model's prices) and adds it to every covering budget's
 * counter. A counter crossing a budget's `alertAtPercent` is audited once per window as `inference:budget-alert`.
 */
export async function recordInvocation(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: InvocationRecord,
): Promise<InferenceUsageRecord> {
  assertInference(ctx);
  const name = modelName(input.model);
  const usage: InferenceTokenUsage = {
    inputTokens: integer(input.inputTokens, 'inputTokens', 0, 100_000_000),
    outputTokens: integer(input.outputTokens, 'outputTokens', 0, 100_000_000),
  };
  if (input.cacheReadTokens !== undefined)
    usage.cacheReadTokens = integer(input.cacheReadTokens, 'cacheReadTokens', 0, 100_000_000);
  if (input.cacheWriteTokens !== undefined)
    usage.cacheWriteTokens = integer(input.cacheWriteTokens, 'cacheWriteTokens', 0, 100_000_000);
  const found = await resolveModel(ctx, tx, input.tenantId, name);
  if (!found) throw new IamError('NOT_FOUND', 'Model not found', 404);
  const now = ctx.now();
  const subject = await usageSubject(ctx, tx, principal, input.tenantId);
  const retentionDays = inferenceSettings(ctx).usageRetentionDays ?? 90;
  const record: InferenceUsageRecord = {
    id: id(),
    tenantId: input.tenantId,
    identityId: principal.identity.id,
    sessionKind: principal.session.kind,
    model: name,
    providerId: found.model.providerId,
    ...usage,
    costMicros: usageCost(found.model, usage),
    status: input.status === 'error' ? 'error' : 'ok',
    createdAt: now,
    expiresAt: now + retentionDays * day,
  };
  if (subject.agentId) record.agentId = subject.agentId;
  if (typeof principal.session.delegationId === 'string')
    record.delegationId = principal.session.delegationId;
  if (input.requestId !== undefined) record.requestId = text(input.requestId, 'requestId', 128);
  if (input.latencyMs !== undefined)
    record.latencyMs = integer(input.latencyMs, 'latencyMs', 0, 86_400_000);
  await tx.insert<InferenceUsageRecord>('inferenceUsage', record);
  // A Responses API response belongs to whoever created it first; ids are the provider's and never reused.
  if (input.responseId !== undefined && /^[A-Za-z0-9_-]{1,200}$/.test(input.responseId)) {
    const responseId = responseRecordId(input.tenantId, input.responseId);
    if (!(await tx.get<InferenceResponseRecord>('inferenceResponses', responseId)))
      await tx.insert<InferenceResponseRecord>('inferenceResponses', {
        id: responseId,
        tenantId: input.tenantId,
        responseId: input.responseId,
        ...responseOwner(principal),
        model: name,
        providerId: found.model.providerId,
        createdAt: now,
        expiresAt: record.expiresAt,
      });
  }
  // The spend ledger (billing-service.ts), in the same transaction; it never throws and is idempotent on sourceId.
  await ctx.billing?.recordPriced(tx, {
    tenantId: record.tenantId,
    meter: 'inference',
    costMicros: record.costMicros,
    quantity: record.inputTokens + record.outputTokens,
    identityId: record.identityId,
    ...(record.agentId ? { agentId: record.agentId } : {}),
    tags: { model: record.model, provider: record.providerId },
    sourceId: record.id,
  });
  const tokens = usageTokens(usage);
  for (const { budget, subjectKey, standing: current } of await budgetStandings(
    ctx,
    tx,
    subject,
    name,
  )) {
    const key = counterId(budget.id, subjectKey, current.windowStart);
    const counter = await tx.get<InferenceCounter>('inferenceCounters', key);
    const next: InferenceCounter = {
      id: key,
      tenantId: budget.tenantId,
      budgetId: budget.id,
      subjectKey,
      windowStart: current.windowStart,
      windowEnd: current.resetsAt,
      tokens: (counter?.tokens ?? 0) + tokens,
      costMicros: Math.round(((counter?.costMicros ?? 0) + record.costMicros) * 1000) / 1000,
      requests: (counter?.requests ?? 0) + 1,
      expiresAt: current.resetsAt + 35 * day,
      ...(counter?.alerted ? { alerted: true } : {}),
      ...(counter?.exceeded ? { exceeded: true } : {}),
    };
    const threshold = budget.alertAtPercent;
    const crossed =
      threshold !== undefined &&
      !next.alerted &&
      ((budget.maxTokens !== undefined && next.tokens * 100 >= budget.maxTokens * threshold) ||
        (budget.maxCostMicros !== undefined &&
          next.costMicros * 100 >= budget.maxCostMicros * threshold) ||
        (budget.maxRequests !== undefined &&
          next.requests * 100 >= budget.maxRequests * threshold));
    if (crossed) next.alerted = true;
    await (counter ? tx.put('inferenceCounters', next) : tx.insert('inferenceCounters', next));
    if (crossed)
      await ctx.events.audit(
        tx,
        principal,
        'inference:budget-alert',
        budget.tenantId,
        budget.id,
        'allow',
        false,
        {
          budget: budget.name,
          percent: threshold!,
          period: budget.period,
          usedTokens: next.tokens,
          usedCostMicros: next.costMicros,
        },
      );
  }
  return record;
}

/** A provider's secret material for the gateway: its kind, base URL and opened key. Server-side only. */
export interface ProviderCredential {
  id: string;
  kind: ProviderKind;
  baseUrl: string;
  apiKey: string;
  /**
   * Set when an organization (not the platform) owns a provider with a custom base URL: upstream calls must go through
   * the SSRF guard with these address rules, since the organization chose where they go.
   */
  guard?: SafeFetchAddressOptions;
}

export async function providerCredential(
  ctx: ServerContext,
  tx: IamStore,
  provider: InferenceProvider,
): Promise<ProviderCredential> {
  const credential: ProviderCredential = {
    id: provider.id,
    kind: provider.kind,
    baseUrl: provider.baseUrl,
    apiKey: openProviderKey(ctx, provider),
  };
  if (provider.baseUrl !== providerBaseUrls[provider.kind]) {
    const realm = await ctx.tenant(tx, provider.tenantId);
    if (realm.type !== 'root' || realm.parentId !== null) {
      const settings = inferenceSettings(ctx);
      credential.guard = {
        anyPort: true,
        allowInsecureLocalhost: settings.allowInsecureLocalhost === true,
        allowPrivateNetworks: settings.allowPrivateNetworks === true,
      };
    }
  }
  return credential;
}
