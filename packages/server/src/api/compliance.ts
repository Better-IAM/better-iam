import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import {
  IamError,
  canonicalJson,
  type AuditChainHead,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import {
  checkById,
  checkParams,
  checkpointId,
  complianceChecks,
  complianceFrameworks,
  effectiveParams,
  exceptionActive,
  frameworkById,
  type CheckFinding,
  type CheckStatus,
  type ComplianceCheckpoint,
  type ComplianceControl,
  type ComplianceException,
  type ComplianceResult,
  type ComplianceRun,
} from '../compliance.js';
import type { ServerContext } from '../context.js';
import { id, sameHash } from '../utils.js';
import { integer, object, strings, text } from '../validation.js';

export interface ControlInput {
  key: string;
  name: string;
  description?: string;
  checkId: string;
  params?: Record<string, number>;
  mappings?: string[];
  enabled?: boolean;
}
/** A finding as readers see it: with the subject's current name when they may read the directory. */
export type FindingView = CheckFinding & { excepted?: boolean; name?: string };
export interface ResultView extends ComplianceResult {
  findings: FindingView[];
  /** Older than three days: the scheduled evaluation has not run (or failed) since. */
  stale: boolean;
}
export type RequirementStatus = CheckStatus | 'not-evaluated' | 'disabled' | 'no-control';
export interface FrameworkStatus {
  framework: { id: string; name: string };
  total: number;
  /** Requirements with at least one control (enabled or not), and how many of those pass. */
  covered: number;
  passing: number;
  requirements: Array<{
    id: string;
    title: string;
    /** The worst of its controls: a disabled, stale or never-evaluated control keeps a requirement from passing. */
    status: RequirementStatus;
    controls: Array<{
      key: string;
      name: string;
      enabled: boolean;
      status?: CheckStatus;
      evaluatedAt?: number;
      stale?: boolean;
    }>;
  }>;
}
export interface EvidencePack {
  format: 'better-iam.compliance-evidence';
  version: 2;
  generatedAt: string;
  tenant: { id: string; name: string };
  framework?: { id: string; name: string };
  controls: Array<{
    key: string;
    name: string;
    checkId: string;
    params: Record<string, number>;
    mappings: string[];
    enabled: boolean;
    result?: Pick<
      ResultView,
      | 'runId'
      | 'status'
      | 'rawStatus'
      | 'summary'
      | 'metrics'
      | 'findings'
      | 'findingsTotal'
      | 'excepted'
      | 'evaluatedAt'
      | 'stale'
    >;
  }>;
  /** Every exception of the included controls, including pending, revoked and expired ones. */
  exceptions: Array<
    Pick<
      ComplianceException,
      | 'controlKey'
      | 'subject'
      | 'reason'
      | 'expiresAt'
      | 'createdBy'
      | 'createdAt'
      | 'approvedBy'
      | 'approvedAt'
      | 'revokedBy'
      | 'revokedAt'
    > & { status: 'pending' | 'approved' | 'revoked' }
  >;
  runs: Array<Pick<ComplianceRun, 'id' | 'evaluatedAt' | 'counts' | 'digest'>>;
  /** The audit chain head at export time: the evaluations' audit events are covered by it. */
  auditHead?: { sequence: number; hash: string };
  /** SHA-256 (base64url) of the canonical JSON of every field above; also recorded in the audit chain at export. */
  digest: string;
  /** Ed25519 over `digest`, by the key `evidenceKeys` publishes. */
  signature: { alg: 'EdDSA'; kid: string; value: string };
}
export interface EvidenceKey {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  alg: 'EdDSA';
  use: 'sig';
}
export interface ComplianceJobResult {
  evaluated: Array<{ tenantId: string; runId: string; counts: Record<CheckStatus, number> }>;
  /** Tenants whose evaluation failed (their controls keep their last results, shown as stale after three days). */
  failed: Array<{ tenantId: string; code: string; message: string }>;
}

const maxControls = 200;
const resultRetentionMs = 400 * 86_400_000;
const staleAfterMs = 3 * 86_400_000;
/** Manual evaluations per tenant: at most one a minute (the scheduled job is not limited). */
const manualIntervalMs = 60_000;

/** Ed25519 keys derived from the deployment secret, so every instance signs alike and rotation keeps old packs valid. */
const keyCache = new Map<
  string,
  { privateKey: KeyObject; publicKey: KeyObject; jwk: EvidenceKey }
>();
function evidenceKey(secret: string) {
  const cached = keyCache.get(secret);
  if (cached) return cached;
  const seed = createHash('sha256')
    .update(`better-iam:compliance-evidence:ed25519:${secret}`)
    .digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
  // RFC 7638 thumbprint: the required members in lexicographic order.
  const kid = createHash('sha256')
    .update(canonicalJson({ crv: 'Ed25519', kty: 'OKP', x }))
    .digest('base64url');
  const entry = {
    privateKey,
    publicKey,
    jwk: { kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig' } as const,
  };
  keyCache.set(secret, entry);
  return entry;
}
const packDigest = (body: unknown) =>
  createHash('sha256').update(canonicalJson(body)).digest('base64url');
/** Version 1 packs (HMAC-SHA256 under the deployment secret) still verify on the deployment that made them. */
const legacySignature = (secret: string, body: unknown) =>
  createHmac(
    'sha256',
    createHash('sha256').update(`better-iam:compliance-evidence:${secret}`).digest(),
  )
    .update(canonicalJson(body))
    .digest('base64url');

/**
 * Verifies an evidence pack offline, with the deployment's published evidence keys (`compliance.evidenceKeys`): the
 * digest must match the pack's content and the signature must verify with the key it names. Needs no server.
 */
export function verifyEvidencePack(
  pack: unknown,
  keys: EvidenceKey[] | { keys: EvidenceKey[] },
): { valid: boolean; kid?: string; reason?: string } {
  if (!pack || typeof pack !== 'object') return { valid: false, reason: 'not a pack' };
  const { digest, signature, ...body } = pack as EvidencePack;
  if (
    typeof digest !== 'string' ||
    !signature ||
    typeof signature !== 'object' ||
    typeof signature.value !== 'string'
  )
    return { valid: false, reason: 'unsigned' };
  if (packDigest(body) !== digest) return { valid: false, reason: 'digest mismatch' };
  const list = Array.isArray(keys) ? keys : keys.keys;
  const key = list.find((item) => item.kid === signature.kid);
  if (!key) return { valid: false, reason: 'unknown key' };
  try {
    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: key.x },
      format: 'jwk',
    });
    return verify(null, Buffer.from(digest), publicKey, Buffer.from(signature.value, 'base64url'))
      ? { valid: true, kid: key.kid }
      : { valid: false, reason: 'bad signature' };
  } catch {
    return { valid: false, reason: 'bad signature' };
  }
}

function controlKey(value: unknown): string {
  const key = text(value, 'key', 64);
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(key))
    throw new IamError(
      'INVALID_INPUT',
      'Control keys use lowercase letters, digits, dots, underscores or hyphens',
    );
  return key;
}
function mappings(value: unknown): string[] {
  if (value === undefined) return [];
  const list = [
    ...new Set(strings(value, 'mappings').map((item) => text(item, 'mappings', 64).trim())),
  ];
  if (list.length > 50) throw new IamError('INVALID_INPUT', 'At most 50 mappings');
  return list.sort();
}
const emptyCounts = (): Record<CheckStatus, number> => ({
  pass: 0,
  fail: 0,
  warn: 0,
  'not-applicable': 0,
});
/** Worst first: a requirement is as good as its worst control. */
const severity: Record<RequirementStatus, number> = {
  fail: 6,
  disabled: 5,
  'not-evaluated': 4,
  'no-control': 3,
  warn: 2,
  pass: 1,
  'not-applicable': 0,
};
/** Whether a finding names this person (an exception for it would be their own). */
const namesIdentity = (subject: string, identityId: string) =>
  subject === `identity:${identityId}` || subject.startsWith(`identity:${identityId}:`);
const exceptionStatus = (exception: ComplianceException) => exception.status ?? 'approved';

/**
 * Runs a tenant's enabled controls (or the named ones) and records the results, a run, and an audit event. The checks
 * read outside any transaction; only the results are written, in one short transaction.
 */
export async function evaluateCompliance(
  ctx: ServerContext,
  tenantId: string,
  triggeredBy: string,
  keys?: string[],
  options: { minIntervalMs?: number } = {},
): Promise<{ run: ComplianceRun; results: ComplianceResult[] }> {
  const store = ctx.store;
  const tenant = await ctx.tenant(store, tenantId);
  const now = ctx.now();
  if (options.minIntervalMs) {
    const last = (await store.find<ComplianceRun>('complianceRuns', { tenantId })).reduce(
      (latest, run) => Math.max(latest, run.evaluatedAt),
      0,
    );
    if (last > now - options.minIntervalMs)
      throw new IamError('RATE_LIMITED', 'The controls were evaluated less than a minute ago', 429);
  }
  const controls = (await store.find<ComplianceControl>('complianceControls', { tenantId }))
    .filter((control) => control.enabled && (!keys || keys.includes(control.key)))
    .sort((a, b) => (a.key < b.key ? -1 : 1));
  const exceptions = (
    await store.find<ComplianceException>('complianceExceptions', { tenantId })
  ).filter((exception) => exceptionActive(exception, now));
  const runId = id();
  const evaluated: Array<{ control: ComplianceControl; result: ComplianceResult }> = [];
  let checkpoint: { sequence: number; hash: string } | undefined;
  for (const control of controls) {
    const check = checkById.get(control.checkId);
    if (!check) continue;
    const excepted = new Set(
      check.noExceptions
        ? []
        : exceptions.filter((item) => item.controlKey === control.key).map((item) => item.subject),
    );
    let status: CheckStatus;
    let rawStatus: CheckStatus;
    let summary: string;
    let metrics: Record<string, number> = {};
    let findings: ComplianceResult['findings'] = [];
    try {
      const outcome = await check.evaluate(
        ctx,
        store,
        tenant,
        effectiveParams(check, control.params),
        now,
      );
      metrics = outcome.metrics;
      findings = outcome.findings.map((finding) =>
        excepted.has(finding.subject) ? { ...finding, excepted: true } : finding,
      );
      rawStatus = outcome.judge(outcome.findings).status;
      ({ status, summary } = outcome.judge(findings.filter((finding) => !finding.excepted)));
      if (outcome.checkpoint) checkpoint = outcome.checkpoint;
    } catch (error) {
      // A check that cannot run fails, visibly, rather than passing by omission.
      rawStatus = status = 'fail';
      summary =
        `The check could not run: ${error instanceof Error ? error.message : String(error)}`.slice(
          0,
          300,
        );
    }
    evaluated.push({
      control,
      result: {
        id: id(),
        tenantId,
        runId,
        controlId: control.id,
        controlKey: control.key,
        checkId: control.checkId,
        status,
        rawStatus,
        summary,
        metrics,
        findings: findings.slice(0, 200),
        findingsTotal: findings.length,
        excepted: findings.filter((finding) => finding.excepted).length,
        evaluatedAt: now,
        expiresAt: now + resultRetentionMs,
      },
    });
  }
  return store.transaction(async (tx) => {
    const results: ComplianceResult[] = [];
    const counts = emptyCounts();
    for (const { control: read, result } of evaluated) {
      // The control may have changed or gone while the checks ran; results follow the stored one.
      const control = await tx.get<ComplianceControl>('complianceControls', read.id);
      if (!control || control.tenantId !== tenantId || control.key !== read.key) continue;
      counts[result.status]++;
      await tx.insert('complianceResults', result);
      results.push(result);
      const { status, summary } = result;
      if (control.lastStatus !== status && (status === 'fail' || control.lastStatus === 'fail'))
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: triggeredBy,
          action: status === 'fail' ? 'compliance:control:fail' : 'compliance:control:recover',
          resourceId: control.id,
          timestamp: now,
          outcome: status === 'fail' ? 'deny' : 'allow',
          metadata: {
            key: control.key,
            checkId: control.checkId,
            status,
            ...(control.lastStatus ? { previous: control.lastStatus } : {}),
            summary,
          },
        });
      await tx.put<ComplianceControl>('complianceControls', {
        ...control,
        lastStatus: status,
        lastEvaluatedAt: now,
        lastResultId: result.id,
      });
    }
    if (checkpoint) {
      const saved = await tx.get<ComplianceCheckpoint>(
        'complianceCheckpoints',
        checkpointId(tenantId),
      );
      const record: ComplianceCheckpoint = {
        id: checkpointId(tenantId),
        tenantId,
        sequence: checkpoint.sequence,
        hash: checkpoint.hash,
        verifiedAt: now,
      };
      if (!saved) await tx.insert('complianceCheckpoints', record);
      else if (saved.sequence < checkpoint.sequence) await tx.put('complianceCheckpoints', record);
    }
    const digest = createHash('sha256')
      .update(
        canonicalJson(
          results.map((result) => ({
            control: result.controlKey,
            status: result.status,
            findings: result.findingsTotal,
            excepted: result.excepted,
            metrics: result.metrics,
          })),
        ),
      )
      .digest('hex');
    const run: ComplianceRun = {
      id: runId,
      tenantId,
      evaluatedAt: now,
      counts,
      digest,
      triggeredBy,
      expiresAt: now + resultRetentionMs,
    };
    await tx.insert('complianceRuns', run);
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: triggeredBy,
      action: 'compliance:evaluate',
      resourceId: runId,
      timestamp: now,
      outcome: 'allow',
      metadata: { ...counts, digest },
    });
    return { run, results };
  });
}

/** The newest result of each control, by its pointer (controls evaluated before pointers fall back to a lookup). */
async function latestResults(
  tx: IamStore,
  tenantId: string,
  controls: ComplianceControl[],
): Promise<Map<string, ComplianceResult>> {
  const latest = new Map<string, ComplianceResult>();
  for (const control of controls) {
    if (control.lastResultId) {
      const result = await tx.get<ComplianceResult>('complianceResults', control.lastResultId);
      if (result?.tenantId === tenantId) latest.set(control.key, result);
      continue;
    }
    if (control.lastEvaluatedAt === undefined) continue;
    for (const result of await tx.find<ComplianceResult>('complianceResults', {
      tenantId,
      controlKey: control.key,
    }))
      if ((latest.get(control.key)?.evaluatedAt ?? -1) < result.evaluatedAt)
        latest.set(control.key, result);
  }
  return latest;
}

/**
 * The compliance center: turn the built-in checks into controls (by adopting SOC 2, ISO 27001, NIST 800-53 or GDPR
 * mappings, or one by one), evaluate them (the scheduler job `iam.compliance.evaluateAll`, or `evaluate`), grant
 * time-boxed exceptions for accepted findings (a second person approves each), see each framework requirement's
 * status, and export signed evidence. Reading needs `iam:compliance:read`, running evaluations
 * `iam:compliance:evaluate`, the rest `iam:compliance:manage`. Findings name people only for callers who may read the
 * directory (`iam:identities:read`).
 */
export function createComplianceApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  /** May the caller see people's names and addresses (`iam:identities:read`)? */
  const directory = async (tx: IamStore, principal: AuthenticatedPrincipal, tenantId: string) =>
    (
      await ctx.decisions.decide(
        tx,
        principal,
        { tenantId, action: 'iam:identities:read', resource: { type: 'iam', id: tenantId } },
        true,
      )
    ).allowed;
  /** Results as readers see them: names added for directory readers, staleness marked. */
  const views = async (
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    results: ComplianceResult[],
  ): Promise<ResultView[]> => {
    const names = new Map<string, string>();
    if (await directory(tx, principal, tenantId)) {
      const ids = new Set<string>();
      for (const result of results)
        for (const finding of result.findings) {
          const match = /^identity:([^:]+)/.exec(finding.subject);
          if (match) ids.add(match[1]!);
        }
      for (const identityId of ids) {
        const identity = await tx.get<Identity>('identities', identityId);
        if (identity?.tenantId === tenantId) names.set(identityId, identity.email ?? identity.name);
      }
    }
    const now = ctx.now();
    return results.map((result) => ({
      ...result,
      stale: result.evaluatedAt < now - staleAfterMs,
      findings: result.findings.map((finding) => {
        const name = names.get(/^identity:([^:]+)/.exec(finding.subject)?.[1] ?? '');
        return name ? { ...finding, name } : finding;
      }),
    }));
  };
  const audit = (
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    metadata: Record<string, import('@better-iam/core').Json>,
  ) => ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);
  const controlState = (control: ComplianceControl) => ({
    name: control.name,
    params: control.params,
    mappings: control.mappings,
    enabled: control.enabled,
  });
  return {
    /** The built-in checks (with their parameters) and framework mappings. */
    catalog: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:compliance:read', input.tenantId, async () => ({
        checks: complianceChecks.map(
          ({ id: checkId, title, description, params, noExceptions }) => ({
            id: checkId,
            title,
            description,
            params,
            ...(noExceptions ? { noExceptions } : {}),
          }),
        ),
        frameworks: complianceFrameworks,
      })),
    /**
     * Adopts a framework: one control per check its requirements use. A control already running that check (the one
     * keyed by the check's ID first, else the first by key) gains the framework's mappings instead. Returns the
     * controls it created or extended.
     */
    adoptFramework: async (
      credential: CredentialInput,
      input: { tenantId: string; framework: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const framework = frameworkById.get(text(input.framework, 'framework', 32));
          if (!framework)
            throw new IamError(
              'INVALID_INPUT',
              `framework must be one of ${complianceFrameworks.map((item) => item.id).join(', ')}`,
            );
          const now = ctx.now();
          const controls = (
            await tx.find<ComplianceControl>('complianceControls', { tenantId: tenant.id })
          ).sort((a, b) => (a.key < b.key ? -1 : 1));
          const touched: ComplianceControl[] = [];
          const byCheck = new Map<string, string[]>();
          for (const requirement of framework.requirements)
            for (const checkId of requirement.checks)
              byCheck.set(checkId, [
                ...(byCheck.get(checkId) ?? []),
                `${framework.id}:${requirement.id}`,
              ]);
          for (const [checkId, refs] of byCheck) {
            const check = checkById.get(checkId)!;
            const existing =
              controls.find((control) => control.key === checkId) ??
              controls.find((control) => control.checkId === checkId);
            if (existing) {
              const merged = [...new Set([...existing.mappings, ...refs])].sort();
              touched.push(
                await tx.put<ComplianceControl>('complianceControls', {
                  ...existing,
                  mappings: merged,
                  updatedAt: now,
                }),
              );
              continue;
            }
            if (controls.length + touched.length >= maxControls)
              throw new IamError('LIMIT_EXCEEDED', `At most ${maxControls} controls`, 409);
            if (controls.some((control) => control.key === checkId))
              throw new IamError('CONFLICT', `A control keyed ${checkId} runs another check`, 409);
            touched.push(
              await tx.insert<ComplianceControl>('complianceControls', {
                id: id(),
                tenantId: tenant.id,
                uniqueKey: `key:${checkId}`,
                key: checkId,
                name: check.title,
                description: check.description,
                checkId,
                params: checkParams(check, undefined),
                mappings: refs.sort(),
                enabled: true,
                createdAt: now,
                updatedAt: now,
              }),
            );
          }
          await audit(tx, principal, 'compliance:framework:adopt', tenant.id, tenant.id, {
            framework: framework.id,
            controls: touched.map((control) => control.key),
          });
          return { framework: framework.id, controls: touched };
        },
      ),
    createControl: async (
      credential: CredentialInput,
      input: ControlInput & { tenantId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const key = controlKey(input.key);
          const check = checkById.get(text(input.checkId, 'checkId', 64));
          if (!check) throw new IamError('INVALID_INPUT', `Unknown check ${input.checkId}`);
          const controls = await tx.find<ComplianceControl>('complianceControls', {
            tenantId: tenant.id,
          });
          if (controls.some((control) => control.key === key))
            throw new IamError('CONFLICT', 'A control with this key exists', 409);
          if (controls.length >= maxControls)
            throw new IamError('LIMIT_EXCEEDED', `At most ${maxControls} controls`, 409);
          if (input.enabled !== undefined && typeof input.enabled !== 'boolean')
            throw new IamError('INVALID_INPUT', 'enabled must be a boolean');
          const now = ctx.now();
          const control = await tx.insert<ComplianceControl>('complianceControls', {
            id: id(),
            tenantId: tenant.id,
            uniqueKey: `key:${key}`,
            key,
            name: text(input.name, 'name', 120).trim(),
            ...(input.description
              ? { description: text(input.description, 'description', 1000) }
              : {}),
            checkId: check.id,
            params: checkParams(check, input.params),
            mappings: mappings(input.mappings),
            enabled: input.enabled ?? true,
            createdAt: now,
            updatedAt: now,
          });
          await audit(tx, principal, 'compliance:control:create', tenant.id, control.id, {
            key,
            checkId: check.id,
            ...controlState(control),
          });
          return control;
        },
      ),
    /** Changes a control; audited as `compliance:control:update` with its state before and after. */
    updateControl: async (
      credential: CredentialInput,
      input: Partial<Omit<ControlInput, 'key' | 'checkId'>> & {
        tenantId: string;
        controlId: string;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        text(input.controlId, 'controlId'),
        async ({ tx, tenant, principal }) => {
          const control = await ctx.scoped<ComplianceControl>(
            tx,
            'complianceControls',
            input.controlId,
            tenant.id,
          );
          const check = checkById.get(control.checkId)!;
          if (input.enabled !== undefined && typeof input.enabled !== 'boolean')
            throw new IamError('INVALID_INPUT', 'enabled must be a boolean');
          const updated = await tx.put<ComplianceControl>('complianceControls', {
            ...control,
            ...(input.name !== undefined ? { name: text(input.name, 'name', 120).trim() } : {}),
            ...(input.description !== undefined
              ? { description: text(input.description, 'description', 1000) }
              : {}),
            ...(input.params !== undefined ? { params: checkParams(check, input.params) } : {}),
            ...(input.mappings !== undefined ? { mappings: mappings(input.mappings) } : {}),
            ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
            updatedAt: ctx.now(),
          });
          await audit(tx, principal, 'compliance:control:update', tenant.id, control.id, {
            key: control.key,
            before: controlState(control),
            after: controlState(updated),
          });
          return updated;
        },
      ),
    /** Deletes a control; its exceptions end (kept as revoked history) and its past results stay until they expire. */
    deleteControl: async (
      credential: CredentialInput,
      input: { tenantId: string; controlId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        text(input.controlId, 'controlId'),
        async ({ tx, tenant, principal }) => {
          const control = await ctx.scoped<ComplianceControl>(
            tx,
            'complianceControls',
            input.controlId,
            tenant.id,
          );
          const now = ctx.now();
          for (const exception of await tx.find<ComplianceException>('complianceExceptions', {
            tenantId: tenant.id,
            controlKey: control.key,
          }))
            if (exceptionStatus(exception) !== 'revoked')
              await tx.put<ComplianceException>('complianceExceptions', {
                ...exception,
                status: 'revoked',
                revokedBy: principal.identity.id,
                revokedAt: now,
              });
          await tx.delete('complianceControls', control.id);
          await audit(tx, principal, 'compliance:control:delete', tenant.id, control.id, {
            key: control.key,
            checkId: control.checkId,
            before: controlState(control),
          });
          return { deleted: true };
        },
      ),
    listControls: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const controls = (
            await tx.find<ComplianceControl>('complianceControls', { tenantId: tenant.id })
          ).sort((a, b) => a.name.localeCompare(b.name));
          const latest = await latestResults(tx, tenant.id, controls);
          const shown = await views(tx, principal, tenant.id, [...latest.values()]);
          const byKey = new Map(shown.map((result) => [result.controlKey, result]));
          return controls.map((control) => ({ ...control, latest: byKey.get(control.key) }));
        },
      ),
    /**
     * Runs the enabled controls (or `controlKeys`) now, at most once a minute per tenant. Audited as
     * `compliance:evaluate` with the run's digest. Returns the run and each control's status and counts; the findings
     * are read with `listResults` (which needs `iam:compliance:read`).
     */
    evaluate: async (
      credential: CredentialInput,
      input: { tenantId: string; controlKeys?: string[] },
    ) => {
      const keys =
        input.controlKeys === undefined ? undefined : strings(input.controlKeys, 'controlKeys');
      const caller = await operation(
        credential,
        input.tenantId,
        'iam:compliance:evaluate',
        input.tenantId,
        async ({ principal }) => principal.identity.id,
      );
      const { run, results } = await evaluateCompliance(
        ctx,
        text(input.tenantId, 'tenantId'),
        caller,
        keys,
        {
          minIntervalMs: manualIntervalMs,
        },
      );
      return {
        run,
        results: results.map(
          ({ controlKey: key, checkId, status, rawStatus, summary, findingsTotal, excepted }) => ({
            controlKey: key,
            checkId,
            status,
            rawStatus,
            summary,
            findingsTotal,
            excepted,
          }),
        ),
      };
    },
    /** Each framework's requirements with the latest status of the controls that evidence them. */
    status: async (
      credential: CredentialInput,
      input: { tenantId: string; framework?: string },
    ): Promise<FrameworkStatus[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tx, tenant }) => {
          const selected =
            input.framework === undefined
              ? undefined
              : frameworkById.get(text(input.framework, 'framework', 32));
          if (input.framework !== undefined && !selected)
            throw new IamError('INVALID_INPUT', 'Unknown framework');
          const controls = await tx.find<ComplianceControl>('complianceControls', {
            tenantId: tenant.id,
          });
          const latest = await latestResults(tx, tenant.id, controls);
          const now = ctx.now();
          const frameworks = selected
            ? [selected]
            : complianceFrameworks.filter((framework) =>
                controls.some((control) =>
                  control.mappings.some((ref) => ref.startsWith(`${framework.id}:`)),
                ),
              );
          return frameworks.map((framework) => {
            const requirements = framework.requirements.map((requirement) => {
              const ref = `${framework.id}:${requirement.id}`;
              const mapped = controls
                .filter((control) => control.mappings.includes(ref))
                .sort((a, b) => (a.key < b.key ? -1 : 1))
                .map((control) => {
                  const result = latest.get(control.key);
                  return {
                    key: control.key,
                    name: control.name,
                    enabled: control.enabled,
                    ...(result
                      ? {
                          status: result.status,
                          evaluatedAt: result.evaluatedAt,
                          stale: result.evaluatedAt < now - staleAfterMs,
                        }
                      : {}),
                  };
                });
              const statuses: RequirementStatus[] = mapped.map((control) =>
                !control.enabled
                  ? 'disabled'
                  : control.status === undefined || control.stale
                    ? 'not-evaluated'
                    : control.status,
              );
              const status: RequirementStatus = !mapped.length
                ? 'no-control'
                : statuses.reduce((worst, item) =>
                    severity[item] > severity[worst] ? item : worst,
                  );
              return { id: requirement.id, title: requirement.title, status, controls: mapped };
            });
            const covered = requirements.filter((item) => item.status !== 'no-control');
            return {
              framework: { id: framework.id, name: framework.name },
              total: requirements.length,
              covered: covered.length,
              passing: covered.filter(
                (item) => item.status === 'pass' || item.status === 'not-applicable',
              ).length,
              requirements,
            };
          });
        },
      ),
    listRuns: async (credential: CredentialInput, input: { tenantId: string; limit?: number }) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tx, tenant }) =>
          (await tx.find<ComplianceRun>('complianceRuns', { tenantId: tenant.id }))
            .sort((a, b) => b.evaluatedAt - a.evaluatedAt)
            .slice(0, integer(input.limit ?? 30, 'limit', 1, 500)),
      ),
    /** Results, newest first: of one control (its history), of one run, or the latest of every control. */
    listResults: async (
      credential: CredentialInput,
      input: { tenantId: string; controlKey?: string; runId?: string; limit?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          if (input.controlKey === undefined && input.runId === undefined) {
            const controls = await tx.find<ComplianceControl>('complianceControls', {
              tenantId: tenant.id,
            });
            return views(
              tx,
              principal,
              tenant.id,
              [...(await latestResults(tx, tenant.id, controls)).values()].sort((a, b) =>
                a.controlKey < b.controlKey ? -1 : 1,
              ),
            );
          }
          const filter: Record<string, unknown> = { tenantId: tenant.id };
          if (input.controlKey !== undefined)
            filter.controlKey = text(input.controlKey, 'controlKey', 64);
          if (input.runId !== undefined) filter.runId = text(input.runId, 'runId');
          return views(
            tx,
            principal,
            tenant.id,
            (await tx.find<ComplianceResult>('complianceResults', filter))
              .sort(
                (a, b) => b.evaluatedAt - a.evaluatedAt || (a.controlKey < b.controlKey ? -1 : 1),
              )
              .slice(0, limit),
          );
        },
      ),
    /**
     * Proposes accepting a finding for a while (a compensating control, a planned fix). It covers the finding only once
     * a second person approves it (`approveException`), until `expiresAt` (at most a year). `subject` is the finding's
     * subject exactly (`identity:{id}`, `tenant:{id}:mfa-optional`, ...). Nobody may propose or approve an exception for
     * a finding about themselves, and audit-integrity findings cannot be excepted.
     */
    createException: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        controlKey: string;
        subject: string;
        reason: string;
        expiresAt: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const key = controlKey(input.controlKey);
          const [control] = await tx.find<ComplianceControl>('complianceControls', {
            tenantId: tenant.id,
            key,
          });
          if (!control) throw new IamError('NOT_FOUND', 'Control not found', 404);
          if (checkById.get(control.checkId)?.noExceptions)
            throw new IamError(
              'INVALID_INPUT',
              `Findings of ${control.checkId} cannot be excepted`,
            );
          const subject = text(input.subject, 'subject', 300);
          if (namesIdentity(subject, principal.identity.id))
            throw new IamError(
              'ACCESS_DENIED',
              'An exception for your own finding needs someone else',
              403,
            );
          const now = ctx.now();
          const expiresAt = integer(
            input.expiresAt,
            'expiresAt',
            now + 60_000,
            now + 366 * 86_400_000,
          );
          const exception: ComplianceException = {
            id: id(),
            tenantId: tenant.id,
            controlKey: key,
            subject,
            reason: text(input.reason, 'reason', 1000),
            expiresAt,
            createdBy: principal.identity.id,
            createdAt: now,
            status: 'pending',
          };
          await tx.insert('complianceExceptions', exception);
          await audit(tx, principal, 'compliance:exception', tenant.id, exception.id, {
            controlKey: key,
            subject,
            expiresAt,
            status: 'pending',
          });
          return exception;
        },
      ),
    /** Approves a pending exception: someone other than its author, and not the subject of the finding. */
    approveException: async (
      credential: CredentialInput,
      input: { tenantId: string; exceptionId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        text(input.exceptionId, 'exceptionId'),
        async ({ tx, tenant, principal }) => {
          const exception = await ctx.scoped<ComplianceException>(
            tx,
            'complianceExceptions',
            input.exceptionId,
            tenant.id,
          );
          if (exceptionStatus(exception) !== 'pending')
            throw new IamError('CONFLICT', 'The exception is not pending', 409);
          if (exception.expiresAt <= ctx.now())
            throw new IamError('CONFLICT', 'The exception has expired', 409);
          if (exception.createdBy === principal.identity.id)
            throw new IamError('ACCESS_DENIED', 'A second person approves an exception', 403);
          if (namesIdentity(exception.subject, principal.identity.id))
            throw new IamError(
              'ACCESS_DENIED',
              'An exception for your own finding needs someone else',
              403,
            );
          const approved = await tx.put<ComplianceException>('complianceExceptions', {
            ...exception,
            status: 'approved',
            approvedBy: principal.identity.id,
            approvedAt: ctx.now(),
          });
          await audit(tx, principal, 'compliance:exception:approve', tenant.id, exception.id, {
            controlKey: exception.controlKey,
            subject: exception.subject,
            createdBy: exception.createdBy,
            expiresAt: exception.expiresAt,
          });
          return approved;
        },
      ),
    /** Ends an exception (or withdraws a pending one); the record stays as history. */
    revokeException: async (
      credential: CredentialInput,
      input: { tenantId: string; exceptionId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:manage',
        text(input.exceptionId, 'exceptionId'),
        async ({ tx, tenant, principal }) => {
          const exception = await ctx.scoped<ComplianceException>(
            tx,
            'complianceExceptions',
            input.exceptionId,
            tenant.id,
          );
          if (exceptionStatus(exception) === 'revoked') return { revoked: true };
          await tx.put<ComplianceException>('complianceExceptions', {
            ...exception,
            status: 'revoked',
            revokedBy: principal.identity.id,
            revokedAt: ctx.now(),
          });
          await audit(tx, principal, 'compliance:exception:revoke', tenant.id, exception.id, {
            controlKey: exception.controlKey,
            subject: exception.subject,
          });
          return { revoked: true };
        },
      ),
    /** Every exception with its status; `active` ones cover findings now. Records are kept 400 days after expiry. */
    listExceptions: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tx, tenant }) => {
          const now = ctx.now();
          return (
            await tx.find<ComplianceException>('complianceExceptions', { tenantId: tenant.id })
          )
            .map((exception) => ({
              ...exception,
              status: exceptionStatus(exception),
              active: exceptionActive(exception, now),
            }))
            .sort((a, b) => a.expiresAt - b.expiresAt);
        },
      ),
    /** The public keys evidence packs are signed with (JWKS; the current key first), for auditors' offline checks. */
    evidenceKeys: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:compliance:read', input.tenantId, async () => ({
        keys: [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])].map(
          (secret) => evidenceKey(secret).jwk,
        ),
      })),
    /**
     * An evidence pack for auditors: the controls (of one framework, or all; disabled ones included and marked), their
     * latest results with findings (stale ones marked), every exception with its history, recent runs, and the audit
     * chain head. Signed with the deployment's Ed25519 evidence key; the pack's digest is recorded in the audit chain
     * (`compliance:evidence-export`), so a pack made later cannot pass for this one. Findings name people only when the
     * caller may read the directory.
     */
    exportEvidence: async (
      credential: CredentialInput,
      input: { tenantId: string; framework?: string },
    ): Promise<EvidencePack> =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const framework =
            input.framework === undefined
              ? undefined
              : frameworkById.get(text(input.framework, 'framework', 32));
          if (input.framework !== undefined && !framework)
            throw new IamError('INVALID_INPUT', 'Unknown framework');
          const now = ctx.now();
          const controls = (
            await tx.find<ComplianceControl>('complianceControls', { tenantId: tenant.id })
          )
            .filter(
              (control) =>
                !framework || control.mappings.some((ref) => ref.startsWith(`${framework.id}:`)),
            )
            .sort((a, b) => (a.key < b.key ? -1 : 1));
          const shown = new Map(
            (
              await views(tx, principal, tenant.id, [
                ...(await latestResults(tx, tenant.id, controls)).values(),
              ])
            ).map((result) => [result.controlKey, result]),
          );
          const keys = new Set(controls.map((control) => control.key));
          const head = await tx.get<AuditChainHead>('auditChains', tenant.id);
          const body: Omit<EvidencePack, 'signature' | 'digest'> = {
            format: 'better-iam.compliance-evidence',
            version: 2,
            generatedAt: new Date(now).toISOString(),
            tenant: { id: tenant.id, name: (tenant as Tenant).name },
            ...(framework ? { framework: { id: framework.id, name: framework.name } } : {}),
            controls: controls.map((control) => {
              const result = shown.get(control.key);
              return {
                key: control.key,
                name: control.name,
                checkId: control.checkId,
                params: control.params,
                mappings: control.mappings,
                enabled: control.enabled,
                ...(result
                  ? {
                      result: {
                        runId: result.runId,
                        status: result.status,
                        rawStatus: result.rawStatus,
                        summary: result.summary,
                        metrics: result.metrics,
                        findings: result.findings,
                        findingsTotal: result.findingsTotal,
                        excepted: result.excepted,
                        evaluatedAt: result.evaluatedAt,
                        stale: result.stale,
                      },
                    }
                  : {}),
              };
            }),
            exceptions: (
              await tx.find<ComplianceException>('complianceExceptions', { tenantId: tenant.id })
            )
              .filter((exception) => keys.has(exception.controlKey))
              .sort((a, b) => a.createdAt - b.createdAt)
              .map((exception) => ({
                controlKey: exception.controlKey,
                subject: exception.subject,
                reason: exception.reason,
                expiresAt: exception.expiresAt,
                createdBy: exception.createdBy,
                createdAt: exception.createdAt,
                status: exceptionStatus(exception),
                ...(exception.approvedBy
                  ? { approvedBy: exception.approvedBy, approvedAt: exception.approvedAt }
                  : {}),
                ...(exception.revokedBy
                  ? { revokedBy: exception.revokedBy, revokedAt: exception.revokedAt }
                  : {}),
              })),
            runs: (await tx.find<ComplianceRun>('complianceRuns', { tenantId: tenant.id }))
              .sort((a, b) => b.evaluatedAt - a.evaluatedAt)
              .slice(0, 30)
              .map(({ id: runId, evaluatedAt, counts, digest }) => ({
                id: runId,
                evaluatedAt,
                counts,
                digest,
              })),
            ...(head ? { auditHead: { sequence: head.sequence, hash: head.hash } } : {}),
          };
          const digest = packDigest(body);
          const key = evidenceKey(ctx.options.secret);
          await audit(tx, principal, 'compliance:evidence-export', tenant.id, tenant.id, {
            ...(framework ? { framework: framework.id } : {}),
            controls: controls.length,
            digest,
            kid: key.jwk.kid,
          });
          return {
            ...body,
            digest,
            signature: {
              alg: 'EdDSA',
              kid: key.jwk.kid,
              value: sign(null, Buffer.from(digest), key.privateKey).toString('base64url'),
            },
          };
        },
      ),
    /**
     * Whether an evidence pack is unaltered and was signed by this deployment (current or previous secret). Pass the
     * `pack`, or only its `digest` and `signature` when the pack is too large to send (check the digest yourself, or
     * verify offline with `verifyEvidencePack`).
     */
    verifyEvidence: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        pack?: EvidencePack;
        digest?: string;
        signature?: EvidencePack['signature'];
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:compliance:read',
        input.tenantId,
        async ({ tenant }) => {
          const secrets = [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])];
          const jwks = secrets.map((secret) => evidenceKey(secret).jwk);
          if (input.pack === undefined) {
            const digest = text(input.digest, 'digest', 100);
            const signature = object(input.signature) as unknown as EvidencePack['signature'];
            const key = jwks.find((item) => item.kid === signature.kid);
            if (!key || typeof signature.value !== 'string') return { valid: false };
            const publicKey = createPublicKey({
              key: { kty: 'OKP', crv: 'Ed25519', x: key.x },
              format: 'jwk',
            });
            try {
              return {
                valid: verify(
                  null,
                  Buffer.from(digest),
                  publicKey,
                  Buffer.from(signature.value, 'base64url'),
                ),
              };
            } catch {
              return { valid: false };
            }
          }
          const pack = object(input.pack) as unknown as
            | EvidencePack
            | (Omit<EvidencePack, 'signature' | 'version'> & {
                version: 1;
                signature: string;
              });
          if (pack.tenant?.id !== tenant.id) return { valid: false };
          if (pack.version === 1 && typeof pack.signature === 'string') {
            const { signature, ...body } = pack;
            return {
              valid: secrets.some((secret) => sameHash(legacySignature(secret, body), signature)),
            };
          }
          return { valid: verifyEvidencePack(pack, jwks).valid };
        },
      ),
  };
}

/** Compliance for the deployment's own code (`iam.compliance`): the scheduler job `evaluateAll` (daily). */
export function createComplianceRuntime(ctx: ServerContext) {
  return {
    /**
     * Evaluates every active tenant (or one) that has enabled controls, one after another. A tenant's failure is
     * reported in `failed` and never stops the others.
     */
    evaluateAll: async (input: { tenantId?: string } = {}): Promise<ComplianceJobResult> => {
      const filter =
        input.tenantId === undefined ? {} : { tenantId: text(input.tenantId, 'tenantId') };
      const controls = await ctx.store.find<ComplianceControl>('complianceControls', filter);
      const tenants = [
        ...new Set(
          controls.filter((control) => control.enabled).map((control) => control.tenantId),
        ),
      ].sort();
      const result: ComplianceJobResult = { evaluated: [], failed: [] };
      for (const tenantId of tenants) {
        const tenant = await ctx.store.get<Tenant>('tenants', tenantId);
        if (tenant?.status !== 'active') continue;
        try {
          const { run } = await evaluateCompliance(ctx, tenantId, 'deployment-operator');
          result.evaluated.push({ tenantId, runId: run.id, counts: run.counts });
        } catch (error) {
          result.failed.push({
            tenantId,
            code: error instanceof IamError ? error.code : 'INTERNAL_ERROR',
            message: (error instanceof Error ? error.message : String(error)).slice(0, 300),
          });
        }
      }
      return result;
    },
  };
}
