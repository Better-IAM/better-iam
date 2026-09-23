import type { IamStore, StoredRecord } from '@better-iam/core';

/**
 * A tenant's terms of use (acceptable-use policy, NDA, data-handling rules). Publishing a new version asks
 * everyone to accept again. Names are unique per tenant (uniqueKey `name:{lowercase}`).
 */
export interface Agreement extends StoredRecord {
  name: string;
  /** The text people accept (plain text or Markdown, at most 50 000 characters). */
  content: string;
  /** Optional link to the canonical document. */
  url?: string;
  version: number;
  /** Required agreements count toward `principal.pendingAgreements` until accepted. */
  required: boolean;
  /** Acceptance lapses this many days after it was given (annual re-acceptance, for example). */
  reacceptAfterDays?: number;
  createdAt: number;
  updatedAt: number;
}
/** One person's latest acceptance of one agreement; the ID is `{agreementId}:{identityId}`. */
export interface AgreementAcceptance extends StoredRecord {
  agreementId: string;
  identityId: string;
  version: number;
  acceptedAt: number;
}

/** Whether an acceptance covers the agreement's current version and has not lapsed. */
export function acceptanceCurrent(
  agreement: Agreement,
  acceptance: AgreementAcceptance | undefined,
  now: number,
): boolean {
  if (!acceptance || acceptance.version !== agreement.version) return false;
  return (
    agreement.reacceptAfterDays === undefined ||
    now - acceptance.acceptedAt < agreement.reacceptAfterDays * 86_400_000
  );
}

/**
 * Policy context for a person in their own tenant: `principal.agreements` lists the names of agreements they have
 * accepted in their current version, and `principal.pendingAgreements` counts required ones they still owe. Service
 * accounts and agents cannot accept anything, so nothing is pending for them.
 */
export async function agreementContext(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  kind: 'user' | 'service' | 'agent',
  now: number,
): Promise<{ 'principal.agreements': string[]; 'principal.pendingAgreements': number }> {
  const agreements = await tx.find<Agreement>('agreements', { tenantId });
  if (!agreements.length) return { 'principal.agreements': [], 'principal.pendingAgreements': 0 };
  const acceptances = new Map(
    (await tx.find<AgreementAcceptance>('agreementAcceptances', { tenantId, identityId })).map(
      (acceptance) => [acceptance.agreementId, acceptance],
    ),
  );
  const accepted: string[] = [];
  let pending = 0;
  for (const agreement of agreements)
    if (acceptanceCurrent(agreement, acceptances.get(agreement.id), now))
      accepted.push(agreement.name);
    else if (agreement.required && kind === 'user') pending++;
  return { 'principal.agreements': accepted.sort(), 'principal.pendingAgreements': pending };
}
