import type { Tone } from '@/components/ui';

/** Labels and badge tones shared by the console's privacy pages. */
export const requestTypeLabels: Record<string, string> = {
  access: 'Access',
  portability: 'Portability',
  erasure: 'Erasure',
  rectification: 'Rectification',
  restriction: 'Restriction',
  objection: 'Objection',
  'opt-out': 'Opt-out',
};
export const requestTypeOptions = Object.entries(requestTypeLabels).map(([value, label]) => ({
  value,
  label,
}));
export const legalBasisLabels: Record<string, string> = {
  consent: 'Consent',
  contract: 'Contract',
  'legal-obligation': 'Legal obligation',
  'vital-interests': 'Vital interests',
  'public-task': 'Public task',
  'legitimate-interests': 'Legitimate interests',
};
export const regulationOptions = [
  { value: 'gdpr', label: 'GDPR' },
  { value: 'uk-gdpr', label: 'UK GDPR' },
  { value: 'ccpa', label: 'CCPA / CPRA' },
  { value: 'lgpd', label: 'LGPD' },
  { value: 'pipeda', label: 'PIPEDA' },
  { value: 'other', label: 'Other' },
];
export const rejectionOptions = [
  { value: 'unverified', label: 'Identity could not be confirmed' },
  { value: 'unfounded', label: 'Manifestly unfounded' },
  { value: 'excessive', label: 'Excessive or repetitive' },
  { value: 'exempt', label: 'Exempt (legal obligation, legal claims, …)' },
  { value: 'duplicate', label: 'Duplicate of another request' },
  { value: 'no-data', label: 'We hold no personal data about them' },
  { value: 'other', label: 'Other' },
];
/** What a person reads next to a purpose's current state. */
export const consentReasonLabels: Record<string, string> = {
  CONSENT_GIVEN: 'You agreed',
  NOT_OPTED_OUT: 'On until you opt out',
  LEGITIMATE_INTERESTS: 'On until you object',
  LEGAL_BASIS: 'Needed to provide the service',
  NO_CONSENT: 'Off: you have not agreed',
  CONSENT_WITHDRAWN: 'Off: you withdrew',
  CONSENT_EXPIRED: 'Off: your consent lapsed',
  CONSENT_OUTDATED: 'Off: the purpose changed, please decide again',
  OBJECTED: 'Off: you objected',
  RESTRICTED: 'Paused: processing is restricted',
  ERASED: 'Off: your data was erased',
  PURPOSE_ARCHIVED: 'No longer used',
};

export function requestStatusTone(status: string, overdue: boolean): Tone {
  if (overdue) return 'danger';
  return status === 'open'
    ? 'accent'
    : status === 'pending-verification'
      ? 'warning'
      : status === 'completed'
        ? 'success'
        : 'neutral';
}
