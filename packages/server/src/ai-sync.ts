import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Tenant,
} from '@better-iam/core';
import { tokenAudienceList } from './agents.js';
import { agentMutations } from './api/agents.js';
import { inferenceMutations } from './api/inference.js';
import type { ServerContext } from './context.js';
import {
  inferenceEnabled,
  visibleProviders,
  type BudgetPeriod,
  type InferenceBudget,
  type InferenceModel,
  type InferenceProvider,
} from './inference.js';
import type { Group } from './models.js';
import type { ConfigChange, TenantConfig } from './sync.js';
import { integer, object, strings, text } from './validation.js';

/**
 * Configuration as code for AI (the `agents`, `inferenceModels` and `inferenceBudgets` kinds of sync.ts): agents by
 * name with their sponsor by email, the tenant's own models by name with their provider by name, and inference budgets
 * by name with their subject by group name, person email or agent name. API keys, provider keys and delegations are
 * runtime state and never synced. Providers hold secret keys, so they are managed through the API and only named here.
 */

export interface TenantConfigAgent {
  name: string;
  /** The accountable person, by email (an active person of the tenant). */
  sponsor: string;
  description?: string;
  purpose?: string;
  model?: string;
  provider?: string;
  url?: string;
  protocols?: string[];
  /** Default true. */
  delegable?: boolean;
  maxDelegatedSessionSeconds?: number;
  boundary?: PolicyDocument;
  /** Services the agent may present delegations to (`delegations.issueToken`). */
  tokenAudiences?: string[];
}

export interface TenantConfigInferenceModel {
  name: string;
  /** A provider of this tenant or an ancestor, by name. */
  provider: string;
  upstreamModel: string;
  displayName?: string;
  family?: string;
  tier?: string;
  contextWindow?: number;
  maxOutputTokens?: number;
  inputPricePerMTok?: number;
  outputPricePerMTok?: number;
  cachedInputPricePerMTok?: number;
  /** Models the gateway tries, in order, when this one's provider fails. */
  fallbacks?: string[];
  /** Provider-run tools: `deny` or `policy` (`allow`, the default, is left out). */
  providerTools?: 'deny' | 'policy';
  /** Default true. */
  enabled?: boolean;
}

/** A model's `providerTools` in a document: `deny` or `policy`, or undefined for `allow` (the default). */
function providerToolsSetting(value: unknown, label: string): 'deny' | 'policy' | undefined {
  if (value === undefined || value === null || value === 'allow') return undefined;
  if (value === 'deny' || value === 'policy') return value;
  throw new IamError(
    'INVALID_INPUT',
    `${label}: providerTools must be 'allow', 'deny' or 'policy'`,
  );
}

/** Whom a budget covers: the whole tenant, a group by name, a person by email, or an agent by name. */
export type TenantConfigBudgetSubject =
  | 'tenant'
  | { group: string }
  | { identity: string }
  | { agent: string };

export interface TenantConfigInferenceBudget {
  name: string;
  subject: TenantConfigBudgetSubject;
  /** Default `shared` (always shared for a person or an agent). */
  scope?: 'shared' | 'each';
  period: BudgetPeriod;
  maxTokens?: number;
  maxCostUsd?: number;
  maxRequests?: number;
  models?: string[];
  alertAtPercent?: number;
}

/** One desired item next to the record it matches, if any. */
export interface AiPlanned<D, R> {
  change: ConfigChange;
  desired?: D;
  record?: R;
}
export interface AiPlan {
  agents: AiPlanned<TenantConfigAgent, Identity>[];
  models: AiPlanned<TenantConfigInferenceModel, InferenceModel>[];
  budgets: AiPlanned<TenantConfigInferenceBudget, InferenceBudget>[];
}
export interface AiState {
  /** The tenant's agents that are not deleted. */
  agents: Identity[];
  /** The tenant's own models (inherited ones belong to the tenant that defines them). */
  models: InferenceModel[];
  /** Providers the tenant may use, nearest first. */
  providers: InferenceProvider[];
  budgets: InferenceBudget[];
  inference: boolean;
}

const lower = (value: string) => value.trim().toLowerCase();
const periods = new Set(['minute', 'hour', 'day', 'month']);

function optionalText(
  item: Record<string, unknown>,
  key: string,
  label: string,
  max = 512,
): string | undefined {
  const value = item[key];
  return value === undefined || value === null ? undefined : text(value, `${label} ${key}`, max);
}
function optionalNumber(item: Record<string, unknown>, key: string, label: string) {
  const value = item[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0)
    throw new IamError('INVALID_INPUT', `${label}: ${key} must be a non-negative number`);
  return value;
}
function unique<T extends { name: string }>(items: T[], kind: string): T[] {
  const seen = new Set<string>();
  for (const item of items) {
    if (seen.has(lower(item.name)))
      throw new IamError('INVALID_INPUT', `Duplicate ${kind} ${item.name}`);
    seen.add(lower(item.name));
  }
  return items;
}
/** Drops undefined members, so documents and exports compare alike. */
function compact<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as T;
}

export function parseAgentsConfig(items: Record<string, unknown>[]): TenantConfigAgent[] {
  return unique(
    items.map((raw) => {
      const item = object(raw) as Record<string, unknown>;
      const name = text(item.name, 'agent name', 200);
      const label = `Agent ${name}`;
      const sponsor = text(item.sponsor, `${label} sponsor`, 320).toLowerCase();
      if (item.delegable !== undefined && typeof item.delegable !== 'boolean')
        throw new IamError('INVALID_INPUT', `${label}: delegable must be a boolean`);
      if (item.boundary !== undefined && item.boundary !== null) object(item.boundary);
      return compact<TenantConfigAgent>({
        name,
        sponsor,
        description: optionalText(item, 'description', label),
        purpose: optionalText(item, 'purpose', label, 1024),
        model: optionalText(item, 'model', label, 128),
        provider: optionalText(item, 'provider', label, 64)?.toLowerCase(),
        url: optionalText(item, 'url', label, 2048),
        protocols:
          item.protocols === undefined || item.protocols === null
            ? undefined
            : [
                ...new Set(
                  strings(item.protocols, `${label} protocols`).map((p) => p.toLowerCase()),
                ),
              ].sort(),
        delegable: item.delegable === false ? false : undefined,
        maxDelegatedSessionSeconds:
          item.maxDelegatedSessionSeconds === undefined || item.maxDelegatedSessionSeconds === null
            ? undefined
            : integer(
                item.maxDelegatedSessionSeconds,
                `${label} maxDelegatedSessionSeconds`,
                60,
                43_200,
              ),
        boundary:
          item.boundary === undefined || item.boundary === null
            ? undefined
            : (item.boundary as PolicyDocument),
        tokenAudiences:
          item.tokenAudiences === undefined || item.tokenAudiences === null
            ? undefined
            : tokenAudienceList(item.tokenAudiences, `${label} tokenAudiences`),
      });
    }),
    'agent',
  );
}

export function parseModelsConfig(items: Record<string, unknown>[]): TenantConfigInferenceModel[] {
  return unique(
    items.map((raw) => {
      const item = object(raw) as Record<string, unknown>;
      const name = text(item.name, 'model name', 128);
      const label = `Model ${name}`;
      if (item.enabled !== undefined && typeof item.enabled !== 'boolean')
        throw new IamError('INVALID_INPUT', `${label}: enabled must be a boolean`);
      const count = (key: string) => {
        const value = item[key];
        return value === undefined || value === null
          ? undefined
          : integer(value, `${label} ${key}`, 1, 100_000_000);
      };
      return compact<TenantConfigInferenceModel>({
        name,
        provider: text(item.provider, `${label} provider`, 200),
        upstreamModel: text(item.upstreamModel, `${label} upstreamModel`, 256),
        displayName: optionalText(item, 'displayName', label, 128),
        family: optionalText(item, 'family', label, 64),
        tier: optionalText(item, 'tier', label, 64),
        contextWindow: count('contextWindow'),
        maxOutputTokens: count('maxOutputTokens'),
        inputPricePerMTok: optionalNumber(item, 'inputPricePerMTok', label),
        outputPricePerMTok: optionalNumber(item, 'outputPricePerMTok', label),
        cachedInputPricePerMTok: optionalNumber(item, 'cachedInputPricePerMTok', label),
        fallbacks:
          item.fallbacks === undefined || item.fallbacks === null
            ? undefined
            : strings(item.fallbacks, `${label} fallbacks`),
        providerTools: providerToolsSetting(item.providerTools, label),
        enabled: item.enabled === false ? false : undefined,
      });
    }),
    'model',
  );
}

function budgetSubject(value: unknown, label: string): TenantConfigBudgetSubject {
  if (value === 'tenant') return 'tenant';
  const subject = object(value) as Record<string, unknown>;
  const keys = Object.keys(subject);
  if (keys.length === 1 && (keys[0] === 'group' || keys[0] === 'agent'))
    return {
      [keys[0]]: text(subject[keys[0]], `${label} subject`, 200),
    } as TenantConfigBudgetSubject;
  if (keys.length === 1 && keys[0] === 'identity')
    return { identity: text(subject.identity, `${label} subject`, 320).toLowerCase() };
  throw new IamError(
    'INVALID_INPUT',
    `${label}: subject must be 'tenant', { group }, { identity } or { agent }`,
  );
}

export function parseBudgetsConfig(
  items: Record<string, unknown>[],
): TenantConfigInferenceBudget[] {
  return unique(
    items.map((raw) => {
      const item = object(raw) as Record<string, unknown>;
      const name = text(item.name, 'budget name', 100).trim();
      const label = `Budget ${name}`;
      if (typeof item.period !== 'string' || !periods.has(item.period))
        throw new IamError('INVALID_INPUT', `${label}: period must be minute, hour, day or month`);
      if (item.scope !== undefined && item.scope !== 'shared' && item.scope !== 'each')
        throw new IamError('INVALID_INPUT', `${label}: scope must be shared or each`);
      const subject = budgetSubject(item.subject, label);
      const budget = compact<TenantConfigInferenceBudget>({
        name,
        subject,
        scope:
          item.scope === 'each' && (subject === 'tenant' || 'group' in subject)
            ? 'each'
            : undefined,
        period: item.period as BudgetPeriod,
        maxTokens:
          item.maxTokens === undefined || item.maxTokens === null
            ? undefined
            : integer(item.maxTokens, `${label} maxTokens`, 1, 1e15),
        maxCostUsd: optionalNumber(item, 'maxCostUsd', label),
        maxRequests:
          item.maxRequests === undefined || item.maxRequests === null
            ? undefined
            : integer(item.maxRequests, `${label} maxRequests`, 1, 1_000_000_000),
        models:
          item.models === undefined || item.models === null
            ? undefined
            : [...new Set(strings(item.models, `${label} models`))].sort(),
        alertAtPercent:
          item.alertAtPercent === undefined || item.alertAtPercent === null
            ? undefined
            : integer(item.alertAtPercent, `${label} alertAtPercent`, 1, 100),
      });
      if (
        budget.maxTokens === undefined &&
        budget.maxCostUsd === undefined &&
        budget.maxRequests === undefined
      )
        throw new IamError('INVALID_INPUT', `${label}: set maxTokens, maxCostUsd or maxRequests`);
      return budget;
    }),
    'budget',
  );
}

export async function readAiState(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
): Promise<AiState> {
  const byName = (a: { name: string }, b: { name: string }) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  const agents = (await tx.find<Identity>('identities', { tenantId, kind: 'agent' }))
    .filter((agent) => agent.status !== 'deleted')
    .sort(byName);
  const inference = inferenceEnabled(ctx);
  return {
    agents,
    inference,
    models: inference
      ? (await tx.find<InferenceModel>('inferenceModels', { tenantId })).sort(byName)
      : [],
    providers: inference ? await visibleProviders(ctx, tx, tenantId) : [],
    budgets: inference
      ? (await tx.find<InferenceBudget>('inferenceBudgets', { tenantId })).sort(byName)
      : [],
  };
}

interface Names {
  identityEmails: Map<string, string>;
  groupNames: Map<string, string>;
}

function exportedAgent(agent: Identity, names: Names): TenantConfigAgent {
  const profile = agent.agent;
  return compact<TenantConfigAgent>({
    name: agent.name,
    sponsor: names.identityEmails.get(profile?.sponsorId ?? '') ?? profile?.sponsorId ?? '',
    description: agent.description,
    purpose: profile?.purpose,
    model: profile?.model,
    provider: profile?.provider,
    url: profile?.url,
    protocols: profile?.protocols?.length ? [...profile.protocols] : undefined,
    delegable: profile?.delegable === false ? false : undefined,
    maxDelegatedSessionSeconds: profile?.maxDelegatedSessionSeconds,
    boundary: profile?.boundary,
    tokenAudiences: profile?.tokenAudiences?.length ? [...profile.tokenAudiences] : undefined,
  });
}

function exportedModel(
  model: InferenceModel,
  providers: InferenceProvider[],
): TenantConfigInferenceModel {
  return compact<TenantConfigInferenceModel>({
    name: model.name,
    provider:
      providers.find((provider) => provider.id === model.providerId)?.name ?? model.providerId,
    upstreamModel: model.upstreamModel,
    displayName: model.displayName,
    family: model.family,
    tier: model.tier,
    contextWindow: model.contextWindow,
    maxOutputTokens: model.maxOutputTokens,
    inputPricePerMTok: model.inputPricePerMTok,
    outputPricePerMTok: model.outputPricePerMTok,
    cachedInputPricePerMTok: model.cachedInputPricePerMTok,
    fallbacks: model.fallbacks?.length ? [...model.fallbacks] : undefined,
    providerTools:
      model.providerTools === 'deny' || model.providerTools === 'policy'
        ? model.providerTools
        : undefined,
    enabled: model.enabled === false ? false : undefined,
  });
}

function exportedBudget(
  budget: InferenceBudget,
  state: AiState,
  names: Names,
): TenantConfigInferenceBudget {
  let subject: TenantConfigBudgetSubject = 'tenant';
  if (budget.subjectType === 'group')
    subject = { group: names.groupNames.get(budget.subjectId) ?? budget.subjectId };
  else if (budget.subjectType === 'identity') {
    const agent = state.agents.find((item) => item.id === budget.subjectId);
    subject = agent
      ? { agent: agent.name }
      : { identity: names.identityEmails.get(budget.subjectId) ?? budget.subjectId };
  }
  return compact<TenantConfigInferenceBudget>({
    name: budget.name,
    subject,
    scope: budget.scope === 'each' && budget.subjectType !== 'identity' ? 'each' : undefined,
    period: budget.period,
    maxTokens: budget.maxTokens,
    maxCostUsd: budget.maxCostMicros === undefined ? undefined : budget.maxCostMicros / 1_000_000,
    maxRequests: budget.maxRequests,
    models: budget.models?.length ? [...budget.models].sort() : undefined,
    alertAtPercent: budget.alertAtPercent,
  });
}

/** The AI part of an export, each kind only when the tenant has some (so other exports stay unchanged). */
export function exportAi(state: AiState, names: Names): Partial<TenantConfig> {
  const config: Partial<TenantConfig> = {};
  if (state.agents.length) config.agents = state.agents.map((agent) => exportedAgent(agent, names));
  if (state.models.length)
    config.inferenceModels = state.models.map((model) => exportedModel(model, state.providers));
  if (state.budgets.length)
    config.inferenceBudgets = state.budgets.map((budget) => exportedBudget(budget, state, names));
  return config;
}

const same = (a: unknown, b: unknown) =>
  JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, entry]) => [key, sortKeys(entry)]),
    );
  return value;
}
function diffFields(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => !same(before[key], after[key]))
    .sort();
}

/**
 * Plans the AI kinds a document names (a kind the document leaves out is left alone). Sponsors must be people of the
 * tenant now; budget groups must exist after the apply (`groupNamesAfter`); a budget's agent must be an agent now or
 * one this document creates; a model's provider must be visible to the tenant.
 */
export function planAi(
  desired: TenantConfig,
  state: AiState,
  env: Names & {
    identitiesByEmail: Map<string, Identity>;
    groupNamesAfter: Set<string>;
    prune: boolean;
  },
): AiPlan {
  const plan: AiPlan = { agents: [], models: [], budgets: [] };
  if (!state.inference && (desired.inferenceModels || desired.inferenceBudgets))
    throw new IamError(
      'INVALID_INPUT',
      'inferenceModels and inferenceBudgets need the inference option on this deployment',
    );
  const change = <D, R>(
    kind: ConfigChange['kind'],
    name: string,
    before: Record<string, unknown> | undefined,
    after: Record<string, unknown> | undefined,
    desiredItem: D | undefined,
    record: R | undefined,
  ): AiPlanned<D, R> => {
    if (!before) return { change: { kind, name, action: 'create', after }, desired: desiredItem };
    if (!after) return { change: { kind, name, action: 'delete', before }, record };
    const fields = diffFields(before, after);
    return {
      change: fields.length
        ? { kind, name, action: 'update', fields, before, after }
        : { kind, name, action: 'unchanged' },
      desired: desiredItem,
      record,
    };
  };

  if (desired.agents) {
    const existing = new Map<string, Identity>();
    for (const agent of state.agents) {
      if (existing.has(lower(agent.name)))
        throw new IamError(
          'INVALID_INPUT',
          `More than one agent is named ${agent.name}; rename one before syncing agents`,
        );
      existing.set(lower(agent.name), agent);
    }
    for (const agent of desired.agents) {
      const sponsor = env.identitiesByEmail.get(agent.sponsor);
      if (!sponsor || sponsor.kind !== 'user')
        throw new IamError('INVALID_INPUT', `Agent ${agent.name}: no person ${agent.sponsor}`);
      const record = existing.get(lower(agent.name));
      plan.agents.push(
        change(
          'agent',
          agent.name,
          record ? { ...exportedAgent(record, env) } : undefined,
          { ...agent },
          agent,
          record,
        ),
      );
    }
    if (env.prune)
      for (const record of state.agents)
        if (!desired.agents.some((agent) => lower(agent.name) === lower(record.name)))
          plan.agents.push(
            change<TenantConfigAgent, Identity>(
              'agent',
              record.name,
              { ...exportedAgent(record, env) },
              undefined,
              undefined,
              record,
            ),
          );
  }

  if (desired.inferenceModels) {
    const existing = new Map(state.models.map((model) => [model.name, model]));
    for (const model of desired.inferenceModels) {
      if (!state.providers.some((provider) => provider.name === model.provider))
        throw new IamError(
          'INVALID_INPUT',
          `Model ${model.name}: no provider named ${model.provider} (create providers through the API)`,
        );
      const record = existing.get(model.name);
      plan.models.push(
        change(
          'inferenceModel',
          model.name,
          record ? { ...exportedModel(record, state.providers) } : undefined,
          { ...model },
          model,
          record,
        ),
      );
    }
    if (env.prune)
      for (const record of state.models)
        if (!desired.inferenceModels.some((model) => model.name === record.name))
          plan.models.push(
            change<TenantConfigInferenceModel, InferenceModel>(
              'inferenceModel',
              record.name,
              { ...exportedModel(record, state.providers) },
              undefined,
              undefined,
              record,
            ),
          );
  }

  if (desired.inferenceBudgets) {
    const agentsAfter = new Set([
      ...state.agents.map((agent) => lower(agent.name)),
      ...(desired.agents ?? []).map((agent) => lower(agent.name)),
    ]);
    const existing = new Map(state.budgets.map((budget) => [lower(budget.name), budget]));
    for (const budget of desired.inferenceBudgets) {
      const subject = budget.subject;
      if (subject !== 'tenant') {
        if ('group' in subject && !env.groupNamesAfter.has(subject.group))
          throw new IamError('INVALID_INPUT', `Budget ${budget.name}: no group ${subject.group}`);
        if ('identity' in subject && !env.identitiesByEmail.has(subject.identity))
          throw new IamError(
            'INVALID_INPUT',
            `Budget ${budget.name}: no identity ${subject.identity}`,
          );
        if ('agent' in subject && !agentsAfter.has(lower(subject.agent)))
          throw new IamError('INVALID_INPUT', `Budget ${budget.name}: no agent ${subject.agent}`);
      }
      const record = existing.get(lower(budget.name));
      plan.budgets.push(
        change(
          'inferenceBudget',
          budget.name,
          record ? { ...exportedBudget(record, state, env) } : undefined,
          { ...budget },
          budget,
          record,
        ),
      );
    }
    if (env.prune)
      for (const record of state.budgets)
        if (!desired.inferenceBudgets.some((budget) => lower(budget.name) === lower(record.name)))
          plan.budgets.push(
            change<TenantConfigInferenceBudget, InferenceBudget>(
              'inferenceBudget',
              record.name,
              { ...exportedBudget(record, state, env) },
              undefined,
              undefined,
              record,
            ),
          );
  }
  return plan;
}

/**
 * Applies a planned AI change set inside the configuration apply transaction. `upsert` creates and updates (agents
 * first, so budgets can name them), `delete` removes (budgets first, then models and agents); both by default. Every
 * change is authorized like the equivalent API call (`allow`).
 */
export async function applyAi(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  plan: AiPlan,
  env: {
    allow(action: string, resourceId: string, what: string): Promise<void>;
    /** Ordinary group name to ID, including groups this apply created. */
    groupIds: Map<string, string>;
    identitiesByEmail: Map<string, Identity>;
  },
  phase: 'upsert' | 'delete' | 'all' = 'all',
): Promise<void> {
  const tenantId = tenant.id;
  const agents = agentMutations(ctx);
  const inference = inferenceMutations(ctx);
  const personId = (email: string) => {
    const person = env.identitiesByEmail.get(email);
    if (!person) throw new IamError('INVALID_INPUT', `No person ${email}`);
    return person.id;
  };
  const profileOf = (agent: TenantConfigAgent) => ({
    description: agent.description ?? null,
    purpose: agent.purpose ?? null,
    model: agent.model ?? null,
    provider: agent.provider ?? null,
    url: agent.url ?? null,
    protocols: agent.protocols ?? null,
    delegable: agent.delegable !== false,
    maxDelegatedSessionSeconds: agent.maxDelegatedSessionSeconds ?? null,
    boundary: agent.boundary ?? null,
    tokenAudiences: agent.tokenAudiences ?? null,
  });
  const modelInput = (model: TenantConfigInferenceModel, providers: InferenceProvider[]) => ({
    providerId: providers.find((provider) => provider.name === model.provider)!.id,
    upstreamModel: model.upstreamModel,
    displayName: model.displayName ?? null,
    family: model.family ?? null,
    tier: model.tier ?? null,
    contextWindow: model.contextWindow ?? null,
    maxOutputTokens: model.maxOutputTokens ?? null,
    inputPricePerMTok: model.inputPricePerMTok ?? null,
    outputPricePerMTok: model.outputPricePerMTok ?? null,
    cachedInputPricePerMTok: model.cachedInputPricePerMTok ?? null,
    fallbacks: model.fallbacks ?? null,
    providerTools: model.providerTools ?? null,
    enabled: model.enabled !== false,
  });

  if (phase !== 'delete') {
    for (const { change, desired, record } of plan.agents) {
      if (change.action === 'create') {
        await env.allow('iam:agents:create', tenantId, `create agent ${desired!.name}`);
        const { description, ...profile } = profileOf(desired!);
        await agents.createAgent(tx, principal, tenant, {
          name: desired!.name,
          sponsorId: personId(desired!.sponsor),
          ...(description !== null ? { description } : {}),
          ...Object.fromEntries(Object.entries(profile).filter(([, value]) => value !== null)),
        });
      } else if (change.action === 'update') {
        await env.allow('iam:agents:update', record!.id, `update agent ${change.name}`);
        await agents.updateAgent(tx, principal, record!, {
          name: desired!.name,
          sponsorId: personId(desired!.sponsor),
          ...profileOf(desired!),
        });
      }
    }
    const providers = await visibleProviders(ctx, tx, tenantId);
    for (const { change, desired } of plan.models) {
      if (change.action === 'create') {
        await env.allow('iam:inference:manage', tenantId, `create model ${desired!.name}`);
        const input = modelInput(desired!, providers);
        await inference.createModel(tx, tenantId, {
          name: desired!.name,
          ...(Object.fromEntries(
            Object.entries(input).filter(([, value]) => value !== null),
          ) as typeof input & { providerId: string; upstreamModel: string }),
        });
      } else if (change.action === 'update') {
        await env.allow('iam:inference:manage', tenantId, `update model ${change.name}`);
        await inference.updateModel(tx, tenantId, {
          name: desired!.name,
          ...modelInput(desired!, providers),
        });
      }
    }
    const agentIds = new Map(
      (await tx.find<Identity>('identities', { tenantId, kind: 'agent' }))
        .filter((agent) => agent.status !== 'deleted')
        .map((agent) => [lower(agent.name), agent.id]),
    );
    for (const { change, desired, record } of plan.budgets) {
      if (change.action !== 'create' && change.action !== 'update') continue;
      await env.allow('iam:inference:manage', tenantId, `${change.action} budget ${change.name}`);
      const budget = desired!;
      const subject = budget.subject;
      const input = {
        name: budget.name,
        subjectType: (subject === 'tenant'
          ? 'tenant'
          : 'group' in subject
            ? 'group'
            : 'identity') as 'tenant' | 'group' | 'identity',
        ...(subject === 'tenant'
          ? {}
          : {
              subjectId:
                'group' in subject
                  ? (env.groupIds.get(subject.group) ??
                    (await tx.find<Group>('groups', { tenantId })).find(
                      (group) => group.name === subject.group,
                    )?.id ??
                    '')
                  : 'agent' in subject
                    ? (agentIds.get(lower(subject.agent)) ?? '')
                    : personId(subject.identity),
            }),
        scope: budget.scope ?? 'shared',
        period: budget.period,
        maxTokens: budget.maxTokens ?? null,
        maxCostUsd: budget.maxCostUsd ?? null,
        maxRequests: budget.maxRequests ?? null,
        models: budget.models ?? null,
        alertAtPercent: budget.alertAtPercent ?? null,
      };
      await inference.saveBudget(tx, tenantId, input, record);
    }
  }
  if (phase !== 'upsert') {
    for (const { change, record } of plan.budgets)
      if (change.action === 'delete') {
        await env.allow('iam:inference:manage', tenantId, `delete budget ${change.name}`);
        await inference.deleteBudget(tx, record!);
      }
    for (const { change } of plan.models)
      if (change.action === 'delete') {
        await env.allow('iam:inference:manage', tenantId, `delete model ${change.name}`);
        await inference.deleteModel(tx, tenantId, change.name);
      }
    for (const { change, record } of plan.agents)
      if (change.action === 'delete') {
        await env.allow('iam:agents:delete', record!.id, `delete agent ${change.name}`);
        await agents.deleteAgent(tx, principal, record!);
      }
  }
}
