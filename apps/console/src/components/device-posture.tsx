import type { ComplianceResult, DeviceAssurance } from 'better-iam';
import { Badge } from '@/components/ui';
import {
  assuranceHelp,
  assuranceLabels,
  assuranceTone,
  complianceState,
  deviceStatusTone,
  shownReasons,
  type DeviceStatus,
} from '@/lib/device-posture';

/** What a proof from the device is worth to policies (`request.deviceAssurance`), with its meaning on hover. */
export function AssuranceBadge({ assurance }: { assurance: DeviceAssurance }) {
  return (
    <span title={assuranceHelp[assurance]}>
      <Badge tone={assuranceTone(assurance)}>{assuranceLabels[assurance]}</Badge>
    </span>
  );
}

/** Compliant, non-compliant (with the reasons), or unmanaged. */
export function ComplianceBadge({ compliance }: { compliance: ComplianceResult }) {
  const state = complianceState(compliance);
  const reasons = shownReasons(compliance);
  return (
    <span className="stack" style={{ gap: 4 }}>
      <span>
        <Badge tone={state.tone}>{state.label}</Badge>
      </span>
      {reasons.length > 0 && <span className="small muted">{reasons.join(' · ')}</span>}
    </span>
  );
}

export function DeviceStatusBadge({ status }: { status: DeviceStatus }) {
  return <Badge tone={deviceStatusTone(status)}>{status}</Badge>;
}
