import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Session,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import {
  createInferenceGateway,
  type GatewayRuntime,
  type InferenceGatewayOptions,
} from '../inference-gateway.js';
import {
  assertInference,
  baseUrl,
  budgetStandings,
  budgetWindow,
  checkInvocation,
  inferenceAction,
  inferenceResourceType,
  inferenceSettings,
  modelName,
  ownsInferenceResponse,
  price,
  providerToolsModes,
  type ProviderToolsMode,
  providerBaseUrls,
  providerCredential,
  providerKey,
  providerKinds,
  publicModel,
  recordInvocation,
  resolveModel,
  sealProviderKey,
  standingOf,
  usageSubject,
  visibleModels,
  visibleProvider,
  type BudgetPeriod,
  type BudgetStanding,
  type InferenceBudget,
  type InferenceCounter,
  type InferenceModel,
  type InferenceProvider,
  type InferenceTokenUsage,
  type InferenceUsageRecord,
  type InvocationCheck,
  type InvocationRecord,
  type ProviderCredential,
  type ProviderKind,
  type PublicModel,
} from '../inference.js';
import type { Group } from '../models.js';
import { id, token as newTicket } from '../utils.js';
import { integer, strings, text } from '../validation.js';

/** A provider as administrators see it: never the key, only its last four characters. */
export interface PublicProvider {
  id: string;
  tenantId: string;
  name: string;
  kind: ProviderKind;
  baseUrl: string;
  keyHint: string;
  createdAt: number;
  updatedAt: number;
  keyRotatedAt: number;
  /** Defined by an ancestor tenant. */
  inherited: boolean;
}

export interface ModelInput {
  providerId?: string;
  upstreamModel?: string;
  displayName?: string | null;
  family?: string | null;
  tier?: string | null;
  contextWindow?: number | null;
  maxOutputTokens?: number | null;
  inputPricePerMTok?: number | null;
  outputPricePerMTok?: number | null;
  cachedInputPricePerMTok?: number | null;
  /** Models to try, in order, when this one's provider fails (at most 5; null clears). */
  fallbacks?: string[] | null;
  /** Provider-run tools: `allow` (the default; null too), `deny`, or `policy` (`inference:use-tool` per tool). */
  providerTools?: ProviderToolsMode | null;
  enabled?: boolean;
}

export interface InferenceBudgetInput {
  name: string;
  subjectType: InferenceBudget['subjectType'];
  /** The group or identity; the tenant itself for `tenant` budgets (may be left out). */
  subjectId?: string;
  scope?: InferenceBudget['scope'];
  period: BudgetPeriod;
  maxTokens?: number | null;
  /** A cost cap in US dollars (stored in micro-dollars). */
  maxCostUsd?: number | null;
  /** The most calls per window. */
  maxRequests?: number | null;
  models?: string[] | null;
  alertAtPercent?: number | null;
}

/** A budget with, for shared pools, its standing in the current window (`uniqueKey` is left out). */
export interface InferenceBudgetView extends InferenceBudget {
  maxCostUsd?: number;
  subjectName?: string;
  standing?: BudgetStanding;
}

export interface UsageRow {
  key: string;
  label?: string;
  requests: number;
  errors: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costMicros: number;
  costUsd: number;
}

export interface UsageReport {
  from: number;
  to: number;
  groupBy: 'identity' | 'agent' | 'model' | 'day';
  rows: UsageRow[];
  totals: UsageRow;
}

/** A single-use permit an external gateway redeems with `inference.record` after the call. */
export interface InferenceTicket extends StoredRecord {
  identityId: string;
  sessionId: string;
  /**
   * The caller as the check saw it (session kind, agent, delegation), so `record` meters the call against the same
   * budgets and caps even when the session has ended since.
   */
  sessionKind?: Session['kind'];
  agentId?: string;
  delegationId?: string;
  model: string;
  createdAt: number;
  expiresAt: number;
}

/** The validated, user-controlled fields of a budget. */
type BudgetFields = Pick<
  InferenceBudget,
  | 'uniqueKey'
  | 'name'
  | 'subjectType'
  | 'subjectId'
  | 'scope'
  | 'period'
  | 'maxTokens'
  | 'maxCostMicros'
  | 'maxRequests'
  | 'models'
  | 'alertAtPercent'
>;

const ticketLifetimeMs = 3_600_000;
const tierPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function publicProvider(provider: InferenceProvider, tenantId: string): PublicProvider {
  return {
    id: provider.id,
    tenantId: provider.tenantId,
    name: provider.name,
    kind: provider.kind,
    baseUrl: provider.baseUrl,
    keyHint: provider.keyHint,
    createdAt: provider.createdAt,
    updatedAt: provider.updatedAt,
    keyRotatedAt: provider.keyRotatedAt,
    inherited: provider.tenantId !== tenantId,
  };
}

const keyHint = (key: string) => `…${key.slice(-4)}`;

function emptyRow(key: string, label?: string): UsageRow {
  return {
    key,
    ...(label !== undefined ? { label } : {}),
    requests: 0,
    errors: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    costMicros: 0,
    costUsd: 0,
  };
}

function addUsage(row: UsageRow, record: InferenceUsageRecord): void {
  row.requests++;
  if (record.status === 'error') row.errors++;
  row.inputTokens += record.inputTokens;
  row.outputTokens += record.outputTokens;
  row.cacheReadTokens += record.cacheReadTokens ?? 0;
  row.cacheWriteTokens += record.cacheWriteTokens ?? 0;
  row.costMicros = Math.round((row.costMicros + record.costMicros) * 1000) / 1000;
  row.costUsd = Math.round(row.costMicros) / 1_000_000;
}

/** Aggregates usage records between `from` and `to` by one dimension, largest cost first. */
function aggregate(
  records: InferenceUsageRecord[],
  groupBy: UsageReport['groupBy'],
  from: number,
  to: number,
  labels: Map<string, string>,
): UsageReport {
  const rows = new Map<string, UsageRow>();
  const totals = emptyRow('total');
  for (const record of records) {
    const key =
      groupBy === 'identity'
        ? record.identityId
        : groupBy === 'agent'
          ? (record.agentId ?? '(none)')
          : groupBy === 'model'
            ? record.model
            : new Date(Math.floor(record.createdAt / 86_400_000) * 86_400_000)
                .toISOString()
                .slice(0, 10);
    const row = rows.get(key) ?? emptyRow(key, labels.get(key));
    addUsage(row, record);
    rows.set(key, row);
    addUsage(totals, record);
  }
  return {
    from,
    to,
    groupBy,
    rows: [...rows.values()].sort(
      (a, b) => b.costMicros - a.costMicros || b.requests - a.requests || (a.key < b.key ? -1 : 1),
    ),
    totals,
  };
}

/** The enabled models a principal may invoke in a tenant, decided like `inference:invoke` without recording. */
async function invocableModels(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
): Promise<PublicModel[]> {
  const tenant = await ctx.tenant(tx, tenantId);
  const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, inferenceAction);
  const result: PublicModel[] = [];
  for (const { model, provider } of await visibleModels(ctx, tx, tenantId)) {
    const view = publicModel(model, provider, tenantId);
    if (!view.enabled) continue;
    const resource = await ctx.decisions.resolve(tx, {
      tenantId,
      type: inferenceResourceType,
      id: model.name,
    });
    const decision = 'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource);
    if (decision.allowed) result.push(view);
  }
  return result;
}

/**
 * Model and budget changes without a credential, for the `inference` API (which authorizes first) and for
 * configuration sync (sync.ts, ai-sync.ts). Every function runs inside the caller's transaction.
 */
export function inferenceMutations(ctx: ServerContext) {
  const platformOnly = (what: string) =>
    new IamError('ACCESS_DENIED', `Only a platform administrator can ${what}`, 403);
  /**
   * A model on a parent organization's provider runs on that organization's upstream key, at the prices and limits
   * the model sets: only a platform administrator may publish or change one, so an organization cannot price calls on
   * the platform's account at nothing or lift the platform's caps. Turning such a model off stays open to it.
   */
  async function assertProviderControl(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    providerIds: (string | undefined)[],
  ): Promise<void> {
    for (const providerId of providerIds) {
      if (providerId === undefined) continue;
      const provider = await tx.get<InferenceProvider>('inferenceProviders', providerId);
      if (provider && provider.tenantId !== tenantId && !(await ctx.rootPrincipal(tx, principal)))
        throw platformOnly('publish or change a model on a parent organization’s provider');
    }
  }
  async function ownModel(tx: IamStore, tenantId: string, name: string): Promise<InferenceModel> {
    const model = (
      await tx.find<InferenceModel>('inferenceModels', { tenantId, uniqueKey: modelName(name) })
    )[0];
    if (!model) throw new IamError('NOT_FOUND', 'Model not found in this tenant', 404);
    return model;
  }

  function applyModelFields(next: InferenceModel, input: ModelInput): void {
    const optionalText = (
      key: 'displayName' | 'family' | 'tier',
      value: string | null | undefined,
      max: number,
    ) => {
      if (value === undefined) return;
      if (value === null) delete next[key];
      else {
        const valueText = text(value, key, max);
        if (key !== 'displayName' && !tierPattern.test(valueText))
          throw new IamError('INVALID_INPUT', `${key} must be a short identifier`);
        next[key] = valueText;
      }
    };
    optionalText('displayName', input.displayName, 128);
    optionalText('family', input.family, 64);
    optionalText('tier', input.tier, 64);
    const optionalNumber = (
      key:
        | 'contextWindow'
        | 'maxOutputTokens'
        | 'inputPricePerMTok'
        | 'outputPricePerMTok'
        | 'cachedInputPricePerMTok',
      value: number | null | undefined,
    ) => {
      if (value === undefined) return;
      if (value === null) delete next[key];
      else
        next[key] =
          key === 'contextWindow' || key === 'maxOutputTokens'
            ? integer(value, key, 1, 100_000_000)
            : price(value, key);
    };
    optionalNumber('contextWindow', input.contextWindow);
    optionalNumber('maxOutputTokens', input.maxOutputTokens);
    optionalNumber('inputPricePerMTok', input.inputPricePerMTok);
    optionalNumber('outputPricePerMTok', input.outputPricePerMTok);
    optionalNumber('cachedInputPricePerMTok', input.cachedInputPricePerMTok);
    if (input.upstreamModel !== undefined)
      next.upstreamModel = text(input.upstreamModel, 'upstreamModel', 256);
    if (input.fallbacks === null) delete next.fallbacks;
    else if (input.fallbacks !== undefined) {
      const fallbacks = [...new Set(strings(input.fallbacks, 'fallbacks').map(modelName))];
      if (fallbacks.length > 5)
        throw new IamError('INVALID_INPUT', 'fallbacks may name at most 5 models');
      if (fallbacks.includes(next.name))
        throw new IamError('INVALID_INPUT', 'A model cannot fall back to itself');
      if (fallbacks.length) next.fallbacks = fallbacks;
      else delete next.fallbacks;
    }
    if (input.providerTools === null || input.providerTools === 'allow') delete next.providerTools;
    else if (input.providerTools !== undefined) {
      if (!providerToolsModes.includes(input.providerTools))
        throw new IamError('INVALID_INPUT', "providerTools must be 'allow', 'deny' or 'policy'");
      next.providerTools = input.providerTools;
    }
    if (input.enabled !== undefined) {
      if (typeof input.enabled !== 'boolean')
        throw new IamError('INVALID_INPUT', 'enabled must be a boolean');
      next.enabled = input.enabled;
    }
  }

  async function budgetView(tx: IamStore, budget: InferenceBudget): Promise<InferenceBudgetView> {
    const { uniqueKey: _key, ...rest } = budget;
    const view: InferenceBudgetView = { ...rest };
    if (budget.maxCostMicros !== undefined) view.maxCostUsd = budget.maxCostMicros / 1_000_000;
    if (budget.subjectType === 'group') {
      const group = await tx.get<Group>('groups', budget.subjectId);
      if (group) view.subjectName = group.name;
    } else if (budget.subjectType === 'identity') {
      const identity = await tx.get<Identity>('identities', budget.subjectId);
      if (identity) view.subjectName = identity.email ?? identity.name;
    }
    if (budget.subjectType === 'identity' || budget.scope === 'shared') {
      const window = budgetWindow(budget.period, ctx.now());
      const counter = await tx.get<InferenceCounter>(
        'inferenceCounters',
        `${budget.id}:shared:${window.start}`,
      );
      view.standing = standingOf(budget, window, counter);
    }
    return view;
  }

  async function budgetFields(
    tx: IamStore,
    tenantId: string,
    input: InferenceBudgetInput,
    previous?: InferenceBudget,
  ): Promise<BudgetFields> {
    const name = text(input.name ?? previous?.name, 'name', 100).trim();
    const subjectType = input.subjectType ?? previous?.subjectType;
    if (subjectType !== 'tenant' && subjectType !== 'group' && subjectType !== 'identity')
      throw new IamError('INVALID_INPUT', "subjectType must be 'tenant', 'group' or 'identity'");
    let subjectId: string;
    if (subjectType === 'tenant') subjectId = tenantId;
    else {
      subjectId = text(input.subjectId ?? previous?.subjectId, 'subjectId');
      if (subjectType === 'group') await ctx.scoped<Group>(tx, 'groups', subjectId, tenantId);
      else await ctx.activeIdentity(tx, subjectId, tenantId);
    }
    const scope = input.scope ?? previous?.scope ?? 'shared';
    if (scope !== 'shared' && scope !== 'each')
      throw new IamError('INVALID_INPUT', "scope must be 'shared' or 'each'");
    const period = input.period ?? previous?.period;
    if (period !== 'minute' && period !== 'hour' && period !== 'day' && period !== 'month')
      throw new IamError('INVALID_INPUT', "period must be 'minute', 'hour', 'day' or 'month'");
    const fields: BudgetFields = {
      uniqueKey: `name:${name.toLowerCase()}`,
      name,
      subjectType,
      subjectId,
      scope: subjectType === 'identity' ? 'shared' : scope,
      period,
    };
    const maxTokens =
      input.maxTokens === undefined ? previous?.maxTokens : (input.maxTokens ?? undefined);
    if (maxTokens !== undefined) fields.maxTokens = integer(maxTokens, 'maxTokens', 1, 1e15);
    const maxCost =
      input.maxCostUsd === undefined
        ? previous?.maxCostMicros
        : input.maxCostUsd === null
          ? undefined
          : Math.round(price(input.maxCostUsd, 'maxCostUsd') * 1_000_000);
    if (input.maxCostUsd !== undefined && input.maxCostUsd !== null && input.maxCostUsd <= 0)
      throw new IamError('INVALID_INPUT', 'maxCostUsd must be positive');
    if (maxCost !== undefined) fields.maxCostMicros = maxCost;
    const maxRequests =
      input.maxRequests === undefined ? previous?.maxRequests : (input.maxRequests ?? undefined);
    if (maxRequests !== undefined)
      fields.maxRequests = integer(maxRequests, 'maxRequests', 1, 1_000_000_000);
    if (
      fields.maxTokens === undefined &&
      fields.maxCostMicros === undefined &&
      fields.maxRequests === undefined
    )
      throw new IamError(
        'INVALID_INPUT',
        'A budget needs at least one of maxTokens, maxCostUsd and maxRequests',
      );
    const models = input.models === undefined ? previous?.models : (input.models ?? undefined);
    if (models !== undefined) {
      const list = [...new Set(strings(models, 'models'))];
      for (const pattern of list)
        if (!/^[A-Za-z0-9*?][A-Za-z0-9._:/@+*?-]{0,127}$/.test(pattern))
          throw new IamError('INVALID_INPUT', `Invalid model pattern ${pattern}`);
      if (list.length) fields.models = list;
    }
    const alert =
      input.alertAtPercent === undefined
        ? previous?.alertAtPercent
        : (input.alertAtPercent ?? undefined);
    if (alert !== undefined) fields.alertAtPercent = integer(alert, 'alertAtPercent', 1, 100);
    return fields;
  }

  async function createModel(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    input: ModelInput & { name: string; providerId: string; upstreamModel: string },
  ): Promise<PublicModel> {
    const name = modelName(input.name);
    if ((await tx.find('inferenceModels', { tenantId, uniqueKey: name })).length)
      throw new IamError('CONFLICT', 'A model with this name exists in this tenant', 409);
    const provider = await visibleProvider(ctx, tx, tenantId, text(input.providerId, 'providerId'));
    if (!provider) throw new IamError('NOT_FOUND', 'Provider not found', 404);
    await assertProviderControl(tx, principal, tenantId, [provider.id]);
    const now = ctx.now();
    const model: InferenceModel = {
      id: id(),
      tenantId,
      uniqueKey: name,
      name,
      providerId: provider.id,
      upstreamModel: text(input.upstreamModel, 'upstreamModel', 256),
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };
    applyModelFields(model, input);
    await tx.insert<InferenceModel>('inferenceModels', model);
    return publicModel(model, provider, tenantId);
  }

  async function updateModel(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    input: ModelInput & { name: string },
  ): Promise<PublicModel> {
    const model = await ownModel(tx, tenantId, input.name);
    const next: InferenceModel = { ...model, updatedAt: ctx.now() };
    if (input.providerId !== undefined) {
      const provider = await visibleProvider(
        ctx,
        tx,
        tenantId,
        text(input.providerId, 'providerId'),
      );
      if (!provider) throw new IamError('NOT_FOUND', 'Provider not found', 404);
      next.providerId = provider.id;
    }
    applyModelFields(next, input);
    // Turning a model off never needs more than managing the tenant's models.
    const onlyDisables =
      next.enabled === false &&
      JSON.stringify({ ...next, enabled: model.enabled, updatedAt: 0 }) ===
        JSON.stringify({ ...model, updatedAt: 0 });
    if (!onlyDisables)
      await assertProviderControl(tx, principal, tenantId, [model.providerId, next.providerId]);
    const saved = await tx.put<InferenceModel>('inferenceModels', next);
    return publicModel(saved, await visibleProvider(ctx, tx, tenantId, saved.providerId), tenantId);
  }

  async function deleteModel(tx: IamStore, tenantId: string, name: string): Promise<void> {
    const model = await ownModel(tx, tenantId, name);
    await tx.delete('inferenceModels', model.id);
  }

  /** Creates a budget, or replaces `previous`; names are unique regardless of case. */
  async function saveBudget(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    input: InferenceBudgetInput,
    previous?: InferenceBudget,
  ): Promise<InferenceBudget> {
    // A cap the platform put on an organization binds the organization's own administrators.
    const platform = await ctx.rootPrincipal(tx, principal);
    if (previous?.platform && !platform) throw platformOnly('change a budget the platform set');
    const fields = await budgetFields(tx, tenantId, input, previous);
    const clash = (
      await tx.find<InferenceBudget>('inferenceBudgets', { tenantId, uniqueKey: fields.uniqueKey })
    ).some((other) => other.id !== previous?.id);
    if (clash) throw new IamError('CONFLICT', 'A budget with this name exists', 409);
    const now = ctx.now();
    const budget: InferenceBudget = previous
      ? { ...fields, id: previous.id, tenantId, createdAt: previous.createdAt, updatedAt: now }
      : { ...fields, id: id(), tenantId, createdAt: now, updatedAt: now };
    if (platform) budget.platform = true;
    else delete budget.platform;
    await (previous ? tx.put('inferenceBudgets', budget) : tx.insert('inferenceBudgets', budget));
    return budget;
  }

  /** Deletes a budget and its counters. */
  async function deleteBudget(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    budget: InferenceBudget,
  ): Promise<void> {
    if (budget.platform && !(await ctx.rootPrincipal(tx, principal)))
      throw platformOnly('remove a budget the platform set');
    await tx.delete('inferenceBudgets', budget.id);
    for (const counter of await tx.find('inferenceCounters', { budgetId: budget.id }))
      await tx.delete('inferenceCounters', counter.id);
  }

  return {
    ownModel,
    applyModelFields,
    budgetView,
    budgetFields,
    createModel,
    updateModel,
    deleteModel,
    saveBudget,
    deleteBudget,
  };
}

/**
 * The `inference` group: AI model access for people, service accounts and agents. Administrators with
 * `iam:inference:manage` register upstream providers (keys are sealed and never returned), the models callers use,
 * and budgets; `iam:inference:read` reads them and the usage reports. Access to a model is an ordinary policy
 * decision: `inference:invoke` on `model/{name}`. Callers check their own access (`check`, `listMine`) and see their
 * own usage (`myUsage`); an external gateway redeems the ticket a check returns with `record`
 * (`iam:inference:record`). Requires the `inference` option.
 */
export function createInferenceApi(ctx: ServerContext) {
  const { auth, store } = ctx;
  const { operation } = ctx.operations;
  const settings = () => inferenceSettings(ctx);
  const mutations = inferenceMutations(ctx);
  const { budgetView } = mutations;

  /** Wraps an operation so it fails with FEATURE_DISABLED when inference is off. */
  const enabled = <T>(fn: () => Promise<T>): Promise<T> => {
    try {
      assertInference(ctx);
    } catch (error) {
      return Promise.reject(error);
    }
    return fn();
  };

  async function ownProvider(tx: IamStore, providerId: string, tenantId: string) {
    return ctx.scoped<InferenceProvider>(tx, 'inferenceProviders', providerId, tenantId);
  }

  /** Custom base URLs point the gateway (and the provider key) somewhere else: root, or opted in by the deployment. */
  async function allowedBaseUrl(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    kind: ProviderKind,
    value: unknown,
  ): Promise<string> {
    const fallback = providerBaseUrls[kind];
    if (value === undefined) {
      if (!fallback)
        throw new IamError('INVALID_INPUT', 'An openai-compatible provider needs a baseUrl');
      return fallback;
    }
    const url = baseUrl(value, settings());
    if (
      url !== fallback &&
      !settings().allowCustomBaseUrls &&
      !(await ctx.rootPrincipal(tx, principal))
    )
      throw new IamError(
        'ACCESS_DENIED',
        'Only a root administrator can point a provider at a custom base URL on this deployment',
        403,
      );
    return url;
  }

  function usageRange(input: { from?: number; to?: number }) {
    const now = ctx.now();
    const to = input.to !== undefined ? integer(input.to, 'to', 0, Number.MAX_SAFE_INTEGER) : now;
    const from =
      input.from !== undefined
        ? integer(input.from, 'from', 0, Number.MAX_SAFE_INTEGER)
        : budgetWindow('month', now).start;
    if (from > to) throw new IamError('INVALID_INPUT', 'from must not be after to');
    return { from, to };
  }

  async function records(
    tx: IamStore,
    filter: Record<string, unknown>,
    from: number,
    to: number,
  ): Promise<InferenceUsageRecord[]> {
    return (await tx.find<InferenceUsageRecord>('inferenceUsage', filter)).filter(
      (record) => record.createdAt >= from && record.createdAt <= to,
    );
  }

  async function labelsFor(tx: IamStore, ids: Iterable<string>): Promise<Map<string, string>> {
    const labels = new Map<string, string>();
    for (const key of ids) {
      const identity = await tx.get<Identity>('identities', key);
      if (identity) labels.set(key, identity.email ?? identity.name);
    }
    return labels;
  }

  return {
    /**
     * Registers an upstream provider account. `kind` is `anthropic`, `openai` or `openai-compatible` (which needs a
     * `baseUrl`); the key is sealed with the deployment secret and only its last four characters are ever shown. A
     * custom base URL needs a root administrator unless the deployment sets `inference.allowCustomBaseUrls`. Models
     * of this tenant and of its sub-tenants may use the provider. Needs `iam:inference:manage` and a recent sign-in.
     */
    createProvider: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        kind: ProviderKind;
        apiKey: string;
        baseUrl?: string;
      },
    ): Promise<PublicProvider> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          input.tenantId,
          async ({ tx, principal, tenant }) => {
            auth.requireRecent(principal);
            const name = text(input.name, 'name', 100).trim();
            if (!providerKinds.includes(input.kind))
              throw new IamError(
                'INVALID_INPUT',
                `kind must be one of ${providerKinds.join(', ')}`,
              );
            const apiKey = providerKey(input.apiKey);
            const uniqueKey = `name:${name.toLowerCase()}`;
            if ((await tx.find('inferenceProviders', { tenantId: tenant.id, uniqueKey })).length)
              throw new IamError('CONFLICT', 'A provider with this name exists', 409);
            const now = ctx.now();
            const providerId = id();
            const provider: InferenceProvider = {
              id: providerId,
              tenantId: tenant.id,
              uniqueKey,
              name,
              kind: input.kind,
              baseUrl: await allowedBaseUrl(tx, principal, input.kind, input.baseUrl),
              keySealed: sealProviderKey(ctx.options.secret, providerId, apiKey),
              keyHint: keyHint(apiKey),
              createdAt: now,
              updatedAt: now,
              keyRotatedAt: now,
            };
            await tx.insert<InferenceProvider>('inferenceProviders', provider);
            return publicProvider(provider, tenant.id);
          },
        ),
      ),

    /** Renames a provider, moves its base URL, or replaces its key (`apiKey`). Needs `iam:inference:manage` and a recent sign-in. */
    updateProvider: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        providerId: string;
        name?: string;
        apiKey?: string;
        baseUrl?: string;
      },
    ): Promise<PublicProvider> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          text(input.providerId, 'providerId'),
          async ({ tx, principal, tenant }) => {
            auth.requireRecent(principal);
            const provider = await ownProvider(tx, input.providerId, tenant.id);
            const next: InferenceProvider = { ...provider, updatedAt: ctx.now() };
            if (input.name !== undefined) {
              next.name = text(input.name, 'name', 100).trim();
              next.uniqueKey = `name:${next.name.toLowerCase()}`;
              const clash = (
                await tx.find<InferenceProvider>('inferenceProviders', {
                  tenantId: tenant.id,
                  uniqueKey: next.uniqueKey,
                })
              ).some((other) => other.id !== provider.id);
              if (clash) throw new IamError('CONFLICT', 'A provider with this name exists', 409);
            }
            if (input.baseUrl !== undefined)
              next.baseUrl = await allowedBaseUrl(tx, principal, provider.kind, input.baseUrl);
            // The sealed key is write-only: pointing the provider somewhere else must not send it along, so a new base
            // URL needs the key again.
            if (next.baseUrl !== provider.baseUrl && input.apiKey === undefined)
              throw new IamError(
                'INVALID_INPUT',
                'Changing the base URL needs the provider key (apiKey) again',
              );
            if (input.apiKey !== undefined) {
              const apiKey = providerKey(input.apiKey);
              next.keySealed = sealProviderKey(ctx.options.secret, provider.id, apiKey);
              next.keyHint = keyHint(apiKey);
              next.keyRotatedAt = next.updatedAt;
            }
            return publicProvider(await tx.put('inferenceProviders', next), tenant.id);
          },
        ),
      ),

    /** Deletes a provider no model uses (RESOURCE_IN_USE otherwise). Needs `iam:inference:manage`. */
    deleteProvider: (
      credential: CredentialInput,
      input: { tenantId: string; providerId: string },
    ) =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          text(input.providerId, 'providerId'),
          async ({ tx, tenant }) => {
            const provider = await ownProvider(tx, input.providerId, tenant.id);
            if ((await tx.find('inferenceModels', { providerId: provider.id })).length)
              throw new IamError('RESOURCE_IN_USE', 'Models still use this provider', 409);
            await tx.delete('inferenceProviders', provider.id);
            return { deleted: true };
          },
        ),
      ),

    /** The providers models of this tenant may use: its own and its ancestors'. Needs `iam:inference:read`. */
    listProviders: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<PublicProvider[]> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:read',
          input.tenantId,
          async ({ tx, tenant }) => {
            const result: PublicProvider[] = [];
            for (const realm of await ctx.ancestry(tx, tenant))
              for (const provider of await tx.find<InferenceProvider>('inferenceProviders', {
                tenantId: realm.id,
              }))
                result.push(publicProvider(provider, tenant.id));
            return result.sort(
              (a, b) => Number(a.inherited) - Number(b.inherited) || a.name.localeCompare(b.name),
            );
          },
        ),
      ),

    /**
     * Publishes a model under a public `name` (letters, digits, `._:/@+-`), served by a provider of this tenant or an
     * ancestor as `upstreamModel`. Prices (dollars per million tokens) drive cost metering and budgets; `tier` and
     * `family` are free-form attributes for policies. Sub-tenants inherit the model; a sub-tenant's own model of the
     * same name takes precedence there. Needs `iam:inference:manage`.
     */
    createModel: (
      credential: CredentialInput,
      input: ModelInput & {
        tenantId: string;
        name: string;
        providerId: string;
        upstreamModel: string;
      },
    ): Promise<PublicModel> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          input.tenantId,
          async ({ tx, principal, tenant }) =>
            mutations.createModel(tx, principal, tenant.id, input),
        ),
      ),

    /** Changes a model of this tenant (null clears an optional field); `enabled: false` stops every call at once. */
    updateModel: (
      credential: CredentialInput,
      input: ModelInput & { tenantId: string; name: string },
    ): Promise<PublicModel> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          input.tenantId,
          async ({ tx, principal, tenant }) =>
            mutations.updateModel(tx, principal, tenant.id, input),
        ),
      ),

    /** Removes a model of this tenant (an inherited model of the same name becomes visible again). */
    deleteModel: (credential: CredentialInput, input: { tenantId: string; name: string }) =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          input.tenantId,
          async ({ tx, tenant }) => {
            await mutations.deleteModel(tx, tenant.id, input.name);
            return { deleted: true };
          },
        ),
      ),

    /** Every model visible to the tenant (own and inherited). Needs `iam:inference:read`. */
    listModels: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<PublicModel[]> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:read',
          input.tenantId,
          async ({ tx, tenant }) =>
            (await visibleModels(ctx, tx, tenant.id)).map(({ model, provider }) =>
              publicModel(model, provider, tenant.id),
            ),
        ),
      ),

    /**
     * The enabled models the caller may invoke in the tenant (for a model picker), evaluated like `inference:invoke`
     * decisions without recording them. Any credential of the tenant; needs no permission.
     */
    listMine: (credential: CredentialInput, input: { tenantId: string }): Promise<PublicModel[]> =>
      enabled(async () => {
        const tenantId = text(input.tenantId, 'tenantId');
        const authenticated = await ctx.principals.authenticate(credential);
        return store.transaction(async (tx) =>
          invocableModels(
            ctx,
            tx,
            await ctx.principals.currentPrincipal(tx, authenticated),
            tenantId,
          ),
        );
      }),

    /**
     * Creates or (with `budgetId`) replaces a budget: `maxTokens` and/or `maxCostUsd` per `period` for the tenant, a
     * group or one identity (an agent's covers everything it does, for anyone), `shared` as one pool or for `each`
     * identity, optionally only over some `models` (name patterns). `alertAtPercent` audits `inference:budget-alert`
     * once per window. Calls that would exceed a budget are refused with BUDGET_EXCEEDED. Needs `iam:inference:manage`.
     */
    setBudget: (
      credential: CredentialInput,
      input: InferenceBudgetInput & { tenantId: string; budgetId?: string },
    ): Promise<InferenceBudgetView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          input.tenantId,
          async ({ tx, principal, tenant }) => {
            const previous =
              input.budgetId !== undefined
                ? await ctx.scoped<InferenceBudget>(
                    tx,
                    'inferenceBudgets',
                    input.budgetId,
                    tenant.id,
                  )
                : undefined;
            return budgetView(
              tx,
              await mutations.saveBudget(tx, principal, tenant.id, input, previous),
            );
          },
        ),
      ),

    deleteBudget: (credential: CredentialInput, input: { tenantId: string; budgetId: string }) =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:manage',
          text(input.budgetId, 'budgetId'),
          async ({ tx, principal, tenant }) => {
            const budget = await ctx.scoped<InferenceBudget>(
              tx,
              'inferenceBudgets',
              input.budgetId,
              tenant.id,
            );
            await mutations.deleteBudget(tx, principal, budget);
            return { deleted: true };
          },
        ),
      ),

    /** The tenant's budgets, with the current window's standing of each shared pool. Needs `iam:inference:read`. */
    listBudgets: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<InferenceBudgetView[]> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:read',
          input.tenantId,
          async ({ tx, tenant }) => {
            const budgets = (
              await tx.find<InferenceBudget>('inferenceBudgets', { tenantId: tenant.id })
            ).sort((a, b) => a.name.localeCompare(b.name));
            return Promise.all(budgets.map((budget) => budgetView(tx, budget)));
          },
        ),
      ),

    /**
     * Usage between `from` (default: start of this month, UTC) and `to` (default: now), optionally for one identity,
     * agent or model, grouped by `identity`, `agent`, `model` or `day`. Needs `iam:inference:read`.
     */
    usage: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        from?: number;
        to?: number;
        identityId?: string;
        agentId?: string;
        model?: string;
        groupBy?: UsageReport['groupBy'];
      },
    ): Promise<UsageReport> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:read',
          input.tenantId,
          async ({ tx, tenant }) => {
            const { from, to } = usageRange(input);
            const groupBy = input.groupBy ?? 'model';
            if (!['identity', 'agent', 'model', 'day'].includes(groupBy))
              throw new IamError(
                'INVALID_INPUT',
                "groupBy must be 'identity', 'agent', 'model' or 'day'",
              );
            const filter: Record<string, unknown> = { tenantId: tenant.id };
            if (input.identityId !== undefined)
              filter.identityId = text(input.identityId, 'identityId');
            if (input.agentId !== undefined) filter.agentId = text(input.agentId, 'agentId');
            if (input.model !== undefined) filter.model = modelName(input.model);
            const found = await records(tx, filter, from, to);
            const labels =
              groupBy === 'identity' || groupBy === 'agent'
                ? await labelsFor(
                    tx,
                    new Set(
                      found.flatMap((record) => {
                        const key = groupBy === 'identity' ? record.identityId : record.agentId;
                        return key ? [key] : [];
                      }),
                    ),
                  )
                : new Map<string, string>();
            return aggregate(found, groupBy, from, to, labels);
          },
        ),
      ),

    /**
     * The caller's own usage by model between `from` and `to`, plus the standing of every budget that covers them for
     * each model they used or may use. Any credential of the tenant; needs no permission.
     */
    myUsage: (
      credential: CredentialInput,
      input: { tenantId: string; from?: number; to?: number },
    ): Promise<UsageReport & { budgets: BudgetStanding[] }> =>
      enabled(async () => {
        const tenantId = text(input.tenantId, 'tenantId');
        const { from, to } = usageRange(input);
        const authenticated = await ctx.principals.authenticate(credential);
        return store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          if (principal.session.tenantId !== tenantId)
            throw new IamError(
              'ACCESS_DENIED',
              'Usage is read in the credential’s own tenant',
              403,
            );
          const found = await records(
            tx,
            { tenantId, identityId: principal.identity.id },
            from,
            to,
          );
          const report = aggregate(found, 'model', from, to, new Map());
          const subject = await usageSubject(ctx, tx, principal, tenantId);
          const seen = new Map<string, BudgetStanding>();
          const names = new Set([
            ...found.map((record) => record.model),
            ...(await visibleModels(ctx, tx, tenantId)).map((item) => item.model.name),
          ]);
          for (const name of names)
            for (const { standing } of await budgetStandings(ctx, tx, subject, name))
              seen.set(standing.budgetId, standing);
          return { ...report, budgets: [...seen.values()] };
        });
      }),

    /**
     * Whether the caller may invoke `model` now (access, enabled, budgets with an optional `estimatedTokens`, and the
     * provider-run `tools` the request asks for, by the model's `providerTools`). Allowed checks carry a single-use
     * `ticket` (valid one hour) an external gateway redeems with `record` after the call. Denials are audited like any
     * decision.
     */
    check: (
      credential: CredentialInput,
      input: { tenantId: string; model: string; estimatedTokens?: number; tools?: string[] },
    ): Promise<InvocationCheck & { ticket?: string }> =>
      enabled(async () => {
        const tenantId = text(input.tenantId, 'tenantId');
        const authenticated = await ctx.principals.authenticate(credential);
        return store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          const result = await checkInvocation(ctx, tx, principal, {
            tenantId,
            model: input.model,
            ...(input.estimatedTokens !== undefined
              ? { estimatedTokens: input.estimatedTokens }
              : {}),
            ...(input.tools !== undefined ? { tools: input.tools } : {}),
          });
          if (!result.allowed) return result;
          const ticket = newTicket();
          const now = ctx.now();
          const agentId =
            principal.session.kind === 'delegated'
              ? principal.session.agentId
              : principal.identity.kind === 'agent'
                ? principal.identity.id
                : undefined;
          await tx.insert<InferenceTicket>('inferenceTickets', {
            id: ticket,
            tenantId,
            identityId: principal.identity.id,
            sessionId: principal.session.id,
            sessionKind: principal.session.kind,
            ...(typeof agentId === 'string' ? { agentId } : {}),
            ...(typeof principal.session.delegationId === 'string'
              ? { delegationId: principal.session.delegationId }
              : {}),
            model: result.model.name,
            createdAt: now,
            expiresAt: now + ticketLifetimeMs,
          });
          return { ...result, ticket };
        });
      }),

    /**
     * An external gateway meters a call it made after `check`: the ticket names the caller as the check saw them
     * (their session may have ended since: the call is metered all the same, against the same budgets and delegation
     * caps) and the model; token counts come from the provider's response. Single use. Needs `iam:inference:record` (a
     * gateway's service account).
     */
    record: (
      credential: CredentialInput,
      input: InferenceTokenUsage & {
        tenantId: string;
        ticket: string;
        status?: 'ok' | 'error';
        requestId?: string;
        latencyMs?: number;
      },
    ): Promise<{ recorded: true; costMicros: number }> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:inference:record',
          input.tenantId,
          async ({ tx, tenant }) => {
            const ticket = await tx.get<InferenceTicket>(
              'inferenceTickets',
              text(input.ticket, 'ticket'),
            );
            if (!ticket || ticket.tenantId !== tenant.id || ticket.expiresAt <= ctx.now())
              throw new IamError(
                'INVALID_TICKET',
                'Unknown, used or expired inference ticket',
                400,
              );
            await tx.delete('inferenceTickets', ticket.id);
            // Metered as the caller the check saw, not re-authenticated: an ended session (or a deleted caller) must
            // not let a call it was allowed escape the budgets it counts against.
            const identity =
              (await tx.get<Identity>('identities', ticket.identityId)) ??
              ({
                id: ticket.identityId,
                tenantId: tenant.id,
                kind: 'user',
                name: ticket.identityId,
                status: 'deleted',
                emailVerified: false,
                owner: false,
                rootAdmin: false,
                createdAt: ticket.createdAt,
              } as Identity);
            const stored = await tx.get<Session>('sessions', ticket.sessionId);
            const session: Session = {
              ...(stored ?? {
                id: ticket.sessionId,
                tenantId: tenant.id,
                identityId: ticket.identityId,
                createdAt: ticket.createdAt,
                lastSeenAt: ticket.createdAt,
                expiresAt: ticket.expiresAt,
                mfa: false,
              }),
              kind: ticket.sessionKind ?? stored?.kind ?? 'user',
            } as Session;
            if (ticket.agentId !== undefined && session.kind === 'delegated')
              session.agentId = ticket.agentId;
            if (ticket.delegationId !== undefined) session.delegationId = ticket.delegationId;
            const caller = { identity, session } as AuthenticatedPrincipal;
            const record = await recordInvocation(ctx, tx, caller, {
              tenantId: tenant.id,
              model: ticket.model,
              inputTokens: input.inputTokens,
              outputTokens: input.outputTokens,
              ...(input.cacheReadTokens !== undefined
                ? { cacheReadTokens: input.cacheReadTokens }
                : {}),
              ...(input.cacheWriteTokens !== undefined
                ? { cacheWriteTokens: input.cacheWriteTokens }
                : {}),
              ...(input.status !== undefined ? { status: input.status } : {}),
              ...(input.requestId !== undefined ? { requestId: input.requestId } : {}),
              ...(input.latencyMs !== undefined ? { latencyMs: input.latencyMs } : {}),
            });
            return { recorded: true as const, costMicros: record.costMicros };
          },
        ),
      ),
  };
}

/** A checked call the in-process gateway may make: the caller, the model and the provider credential. */
export interface GatewayPermit {
  principal: AuthenticatedPrincipal;
  tenantId: string;
  check: Extract<InvocationCheck, { allowed: true }>;
  upstreamModel: string;
  provider: ProviderCredential;
}

/**
 * `iam.inference`: the server-side half of inference, for the gateway and for applications that call models
 * themselves. `authorize` checks a credential for a model and returns the opened provider credential (never expose
 * it); `record` meters a call; `gateway` builds the HTTP gateway.
 */
export function createInferenceRuntime(ctx: ServerContext) {
  const runtime: GatewayRuntime & {
    authorize: GatewayRuntime['authorize'];
    gateway(options?: InferenceGatewayOptions): (request: Request) => Promise<Response>;
    record(
      permit: Pick<GatewayPermit, 'principal' | 'tenantId'>,
      usage: Omit<InvocationRecord, 'tenantId'>,
    ): Promise<InferenceUsageRecord>;
  } = {
    /** The enabled models a credential may invoke in its session's tenant (or `tenantId`). */
    async models(credential: CredentialInput, tenantId?: string): Promise<PublicModel[]> {
      assertInference(ctx);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        return invocableModels(ctx, tx, principal, tenantId ?? principal.session.tenantId);
      });
    },
    /**
     * The HTTP inference gateway (a `Request` → `Response` handler): Anthropic `POST /v1/messages` (and
     * `/v1/messages/count_tokens`), OpenAI `POST /v1/chat/completions`, `/v1/responses` and `/v1/embeddings`, and
     * `GET /v1/models`, authorized and metered per caller. Mount it on any route.
     */
    gateway: (options?: InferenceGatewayOptions) => createInferenceGateway(runtime, options),
    /**
     * Authenticates `credential`, checks `model` for it in the credential's tenant (or `tenantId`), with the provider-run
     * `tools` the request asks for, and on success returns the permit with the provider's opened key. Throws
     * FEATURE_DISABLED when inference is off.
     */
    async authorize(
      credential: CredentialInput,
      input: { model: string; tenantId?: string; estimatedTokens?: number; tools?: string[] },
    ): Promise<GatewayPermit | { denied: Exclude<InvocationCheck, { allowed: true }> }> {
      assertInference(ctx);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenantId = input.tenantId ?? principal.session.tenantId;
        const check = await checkInvocation(ctx, tx, principal, {
          tenantId,
          model: input.model,
          ...(input.estimatedTokens !== undefined
            ? { estimatedTokens: input.estimatedTokens }
            : {}),
          ...(input.tools !== undefined ? { tools: input.tools } : {}),
        });
        if (!check.allowed) return { denied: check };
        const found = await resolveModel(ctx, tx, tenantId, check.model.name);
        if (!found?.provider) throw new IamError('NOT_FOUND', 'Model provider not found', 404);
        return {
          principal,
          tenantId,
          check,
          upstreamModel: found.model.upstreamModel,
          provider: await providerCredential(ctx, tx, found.provider),
        };
      });
    },
    /** Whether a Responses API response was created through the gateway by the permit's caller, at its provider. */
    ownsResponse(
      permit: Pick<GatewayPermit, 'principal' | 'tenantId' | 'provider'>,
      responseId: string,
    ): Promise<boolean> {
      return ctx.store.transaction((tx) =>
        ownsInferenceResponse(
          ctx,
          tx,
          permit.principal,
          permit.tenantId,
          responseId,
          permit.provider.id,
        ),
      );
    },
    /** Meters a call made under a permit. */
    record(
      permit: Pick<GatewayPermit, 'principal' | 'tenantId'>,
      usage: Omit<InvocationRecord, 'tenantId'>,
    ): Promise<InferenceUsageRecord> {
      return ctx.store.transaction((tx) =>
        recordInvocation(ctx, tx, permit.principal, { ...usage, tenantId: permit.tenantId }),
      );
    },
  };
  return runtime;
}
export type InferenceRuntime = ReturnType<typeof createInferenceRuntime>;
