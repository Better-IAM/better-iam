import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
} from '@better-iam/core';
import { acceptanceCurrent, type Agreement, type AgreementAcceptance } from '../agreements.js';
import type { ServerContext } from '../context.js';
import { actsInOwnRight } from '../session-kinds.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';

export interface AgreementInput {
  name: string;
  content: string;
  url?: string;
  required?: boolean;
  reacceptAfterDays?: number;
}
/** An agreement as the signed-in person sees it. */
export interface MyAgreement {
  id: string;
  name: string;
  content: string;
  url?: string;
  version: number;
  required: boolean;
  /** Accepted in the current version and not lapsed. */
  accepted: boolean;
  acceptedAt?: number;
  acceptedVersion?: number;
}
export interface AgreementStatus {
  agreement: { id: string; name: string; version: number; required: boolean };
  accepted: { identity: { id: string; name: string }; version: number; acceptedAt: number }[];
  /** Active people without a current acceptance (outdated version, lapsed, or never accepted). */
  pending: { identity: { id: string; name: string }; acceptedVersion?: number }[];
}

const maxAgreements = 50;

/** Agreement text: up to 50 000 characters over several lines (tabs and line breaks allowed, other controls not). */
function body(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > 50_000 ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  )
    throw new IamError('INVALID_INPUT', 'Invalid content');
  return value;
}

/** Agreements are the caller's own business: refused for role sessions, session tokens and unknown kinds. */
function selfSession(principal: AuthenticatedPrincipal, tenantId: string): void {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.tenantId !== tenantId ||
    principal.identity.tenantId !== tenantId
  )
    throw new IamError(
      'ACCESS_DENIED',
      'Agreements are accepted from an ordinary session of their tenant',
      403,
    );
}

/**
 * Publishes (without `previous`) or edits an agreement after validating it; `newVersion` asks everyone to accept
 * again. Shared by the `agreements` API and configuration apply.
 */
export async function saveAgreement(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: Partial<Omit<AgreementInput, 'reacceptAfterDays'>> & { reacceptAfterDays?: number | null },
  previous?: Agreement,
  newVersion = false,
): Promise<Agreement> {
  const values = fields(input as Partial<AgreementInput>, previous);
  const others = (await tx.find<Agreement>('agreements', { tenantId })).filter(
    (agreement) => agreement.id !== previous?.id,
  );
  if (others.some((agreement) => agreement.uniqueKey === values.uniqueKey))
    throw new IamError('CONFLICT', 'An agreement with this name exists', 409);
  const now = ctx.now();
  if (previous) {
    const { url: _url, reacceptAfterDays: _reaccept, ...kept } = previous;
    return tx.put<Agreement>('agreements', {
      ...kept,
      ...values,
      version: previous.version + (newVersion ? 1 : 0),
      updatedAt: now,
    });
  }
  if (others.length >= maxAgreements)
    throw new IamError('LIMIT_EXCEEDED', `At most ${maxAgreements} agreements`, 409);
  return tx.insert<Agreement>('agreements', {
    ...values,
    id: id(),
    tenantId,
    version: 1,
    createdAt: now,
    updatedAt: now,
  });
}

/** Deletes an agreement with every acceptance of it. */
export async function deleteAgreement(tx: IamStore, agreement: Agreement): Promise<void> {
  for (const acceptance of await tx.find<AgreementAcceptance>('agreementAcceptances', {
    tenantId: agreement.tenantId,
    agreementId: agreement.id,
  }))
    await tx.delete('agreementAcceptances', acceptance.id);
  await tx.delete('agreements', agreement.id);
}

function fields(input: Partial<AgreementInput>, previous?: Agreement) {
  const name = text(input.name ?? previous?.name, 'name', 100).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  const content = body(input.content ?? previous?.content);
  const url =
    input.url === undefined ? previous?.url : input.url ? text(input.url, 'url', 2048) : undefined;
  if (url !== undefined && !/^https?:\/\//.test(url))
    throw new IamError('INVALID_INPUT', 'url must be an http(s) URL');
  const required = input.required ?? previous?.required ?? true;
  if (typeof required !== 'boolean')
    throw new IamError('INVALID_INPUT', 'required must be a boolean');
  const reaccept =
    input.reacceptAfterDays === undefined
      ? previous?.reacceptAfterDays
      : input.reacceptAfterDays === null
        ? undefined
        : integer(input.reacceptAfterDays, 'reacceptAfterDays', 1, 3650);
  return {
    uniqueKey: `name:${name.toLowerCase()}`,
    name,
    content,
    ...(url ? { url } : {}),
    required,
    ...(reaccept !== undefined ? { reacceptAfterDays: reaccept } : {}),
  };
}

/**
 * Terms of use: versioned agreements a tenant asks its members to accept. Policies see `principal.agreements` (names
 * accepted in their current version) and `principal.pendingAgreements` (required ones still owed), so a deny
 * statement can hold back access until people accept. Managing needs `iam:agreements:manage`, reporting
 * `iam:agreements:read`; members list and accept their own without a permission.
 */
export function createAgreementsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  return {
    /** Publishes a new agreement at version 1 (required by default). */
    create: async (credential: CredentialInput, input: AgreementInput & { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:agreements:manage',
        input.tenantId,
        async ({ tx, tenant }) => saveAgreement(ctx, tx, tenant.id, input),
      ),
    /**
     * Edits an agreement. `newVersion: true` publishes the change as the next version, so everyone must accept
     * again; without it the edit (a typo fix, a new link) keeps existing acceptances valid.
     */
    update: async (
      credential: CredentialInput,
      input: Partial<Omit<AgreementInput, 'reacceptAfterDays'>> & {
        tenantId: string;
        agreementId: string;
        newVersion?: boolean;
        reacceptAfterDays?: number | null;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:agreements:manage',
        text(input.agreementId, 'agreementId'),
        async ({ tx, tenant }) => {
          const previous = await ctx.scoped<Agreement>(
            tx,
            'agreements',
            input.agreementId,
            tenant.id,
          );
          return saveAgreement(ctx, tx, tenant.id, input, previous, input.newVersion === true);
        },
      ),
    /** Deletes an agreement and its acceptances. */
    delete: async (credential: CredentialInput, input: { tenantId: string; agreementId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:agreements:manage',
        text(input.agreementId, 'agreementId'),
        async ({ tx, tenant }) => {
          const agreement = await ctx.scoped<Agreement>(
            tx,
            'agreements',
            input.agreementId,
            tenant.id,
          );
          await deleteAgreement(tx, agreement);
          return { deleted: true };
        },
      ),
    list: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:agreements:read',
        input.tenantId,
        async ({ tx, tenant }) =>
          (await tx.find<Agreement>('agreements', { tenantId: tenant.id })).sort((a, b) =>
            a.name.localeCompare(b.name),
          ),
      ),
    /** Who accepted the current version and which active people still owe it. */
    status: async (
      credential: CredentialInput,
      input: { tenantId: string; agreementId: string },
    ): Promise<AgreementStatus> =>
      operation(
        credential,
        input.tenantId,
        'iam:agreements:read',
        text(input.agreementId, 'agreementId'),
        async ({ tx, tenant }) => {
          const agreement = await ctx.scoped<Agreement>(
            tx,
            'agreements',
            input.agreementId,
            tenant.id,
          );
          const acceptances = new Map(
            (
              await tx.find<AgreementAcceptance>('agreementAcceptances', {
                tenantId: tenant.id,
                agreementId: agreement.id,
              })
            ).map((acceptance) => [acceptance.identityId, acceptance]),
          );
          const now = ctx.now();
          const result: AgreementStatus = {
            agreement: {
              id: agreement.id,
              name: agreement.name,
              version: agreement.version,
              required: agreement.required,
            },
            accepted: [],
            pending: [],
          };
          const people = (await tx.find<Identity>('identities', { tenantId: tenant.id }))
            .filter((identity) => identity.kind === 'user' && identity.status === 'active')
            .sort((a, b) => (a.email ?? a.name).localeCompare(b.email ?? b.name));
          for (const identity of people) {
            const ref = { id: identity.id, name: identity.email ?? identity.name };
            const acceptance = acceptances.get(identity.id);
            if (acceptanceCurrent(agreement, acceptance, now))
              result.accepted.push({
                identity: ref,
                version: acceptance!.version,
                acceptedAt: acceptance!.acceptedAt,
              });
            else
              result.pending.push({
                identity: ref,
                ...(acceptance ? { acceptedVersion: acceptance.version } : {}),
              });
          }
          return result;
        },
      ),
    /** The caller's agreements with their acceptance state; needs only an ordinary session of the tenant. */
    listMine: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<MyAgreement[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        selfSession(principal, tenantId);
        const acceptances = new Map(
          (
            await tx.find<AgreementAcceptance>('agreementAcceptances', {
              tenantId,
              identityId: principal.identity.id,
            })
          ).map((acceptance) => [acceptance.agreementId, acceptance]),
        );
        const now = ctx.now();
        return (await tx.find<Agreement>('agreements', { tenantId }))
          .map((agreement) => {
            const acceptance = acceptances.get(agreement.id);
            return {
              id: agreement.id,
              name: agreement.name,
              content: agreement.content,
              ...(agreement.url ? { url: agreement.url } : {}),
              version: agreement.version,
              required: agreement.required,
              accepted: acceptanceCurrent(agreement, acceptance, now),
              ...(acceptance
                ? { acceptedAt: acceptance.acceptedAt, acceptedVersion: acceptance.version }
                : {}),
            };
          })
          .sort(
            (a, b) =>
              Number(a.accepted) - Number(b.accepted) ||
              Number(b.required) - Number(a.required) ||
              a.name.localeCompare(b.name),
          );
      });
    },
    /**
     * Records that the caller accepts `version` of an agreement (which must be the current one, so nobody accepts
     * text they were not shown). Impersonating administrators cannot accept on someone's behalf. Audited as
     * `agreement:accept`.
     */
    accept: async (
      credential: CredentialInput,
      input: { tenantId: string; agreementId: string; version: number },
    ) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const agreementId = text(input.agreementId, 'agreementId');
      const version = integer(input.version, 'version', 1, 1_000_000);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        selfSession(principal, tenantId);
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Agreements cannot be accepted while impersonating',
            403,
          );
        if (principal.identity.kind !== 'user')
          throw new IamError('INVALID_INPUT', 'Only people accept agreements');
        const agreement = await ctx.scoped<Agreement>(tx, 'agreements', agreementId, tenantId);
        if (agreement.version !== version)
          throw new IamError(
            'VERSION_CONFLICT',
            'The agreement changed; review the current version before accepting',
            409,
          );
        const acceptance: AgreementAcceptance = {
          id: `${agreement.id}:${principal.identity.id}`,
          tenantId,
          agreementId: agreement.id,
          identityId: principal.identity.id,
          version,
          acceptedAt: ctx.now(),
        };
        await ((await tx.get('agreementAcceptances', acceptance.id))
          ? tx.put('agreementAcceptances', acceptance)
          : tx.insert('agreementAcceptances', acceptance));
        await ctx.events.audit(
          tx,
          principal,
          'agreement:accept',
          tenantId,
          agreement.id,
          'allow',
          false,
          { name: agreement.name, version },
        );
        return { accepted: true, version, acceptedAt: acceptance.acceptedAt };
      });
    },
  };
}
