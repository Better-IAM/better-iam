import Link from 'next/link';
import type { LicenseSeatView } from 'better-iam/server';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, Table, Time } from '@/components/ui';
import {
  assignableProducts,
  memberAssignFields,
  seatLabel,
  seatStatusTone,
  usageRatio,
  usageTone,
} from '@/lib/licenses';
import { can, key, type OrgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/** How much of a product's capacity active seats take. */
export function UsageMeter({
  usage,
}: {
  usage: { capacity: number; active: number; waiting: number };
}) {
  const ratio = usageRatio(usage);
  const tone = usageTone(usage);
  return (
    <div
      className={`meter ${tone === 'neutral' ? '' : tone}`}
      role="meter"
      aria-label={`${usage.active} of ${usage.capacity} seats in use`}
      aria-valuemin={0}
      aria-valuemax={usage.capacity}
      aria-valuenow={Math.min(usage.active, usage.capacity)}
    >
      <span style={{ width: `${Math.max(2, Math.round(ratio * 100))}%` }} />
    </div>
  );
}

export function SeatBadge({ seat }: { seat: Pick<LicenseSeatView, 'status' | 'position'> }) {
  return <Badge tone={seatStatusTone(seat.status)}>{seatLabel(seat)}</Badge>;
}

const assignmentsResource = { type: 'iam', id: 'licenses/assignments' };

/**
 * The member page's Licenses card: the person's seats (active, or their place on a waiting list) with how they hold
 * each one, and giving or taking back a product directly. Hidden when licenses are not readable, and in organizations
 * that have no products.
 */
export async function MemberLicenses({
  page,
  identityId,
  active,
}: {
  page: OrgPage;
  identityId: string;
  /** Only active people can be given a product. */
  active: boolean;
}) {
  const { iam, auth, tenantId, base } = page;
  const [seats, assignments, products, groups, allowed] = await Promise.all([
    tryRead(() => iam.api.licenses.listSeats(auth, { tenantId, identityId, limit: 1000 })),
    tryRead(() =>
      iam.api.licenses.listAssignments(auth, {
        tenantId,
        subjectType: 'identity',
        subjectId: identityId,
        limit: 1000,
      }),
    ),
    tryRead(() => iam.api.licenses.listProducts(auth, { tenantId, status: 'active' })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    can(page, [{ action: 'iam:licenses:assign', resource: assignmentsResource }]),
  ]);
  if (!seats || (!seats.total && !assignments?.total && !products?.products.length)) return null;
  const mayAssign = allowed[key('iam:licenses:assign', assignmentsResource)] === true;
  const direct = new Set((assignments?.assignments ?? []).map((item) => item.productId));
  const groupName = (groupId: string) =>
    groups?.find((group) => group.id === groupId)?.name ?? groupId;
  const options = assignableProducts(products?.products ?? [], direct);
  // A direct assignment whose seat is gone (the product was retired) is still listed, so it can be removed.
  const seatless = (assignments?.assignments ?? []).filter(
    (assignment) => !seats.seats.some((seat) => seat.productId === assignment.productId),
  );
  return (
    <Card
      title="Licenses"
      description="Seats this person holds or waits for. Policies read the products of active seats as principal.licenses; birthright rules on identity.licenses grant what a product includes."
      actions={
        <Link className="btn small secondary" href={`${base}/licenses`}>
          All licenses
        </Link>
      }
      flush
    >
      <Table
        head={['Product', 'Seat', 'Through', 'Since', '']}
        rows={[
          ...seats.seats.map((seat) => [
            <Link key="p" href={`${base}/licenses/${seat.productId}`}>
              {seat.productName}
            </Link>,
            <SeatBadge key="s" seat={seat} />,
            <span key="t" className="small">
              {seat.direct && 'direct'}
              {seat.direct && seat.groupIds.length > 0 && ', '}
              {seat.groupIds.map((groupId, index) => (
                <span key={groupId}>
                  {index > 0 && ', '}
                  group <Link href={`${base}/groups/${groupId}`}>{groupName(groupId)}</Link>
                </span>
              ))}
            </span>,
            <Time key="a" value={seat.activatedAt ?? seat.assignedAt} />,
            seat.direct && mayAssign ? (
              <ApiButton
                key="r"
                path="licenses/unassign"
                body={{
                  tenantId,
                  productId: seat.productId,
                  subjectType: 'identity',
                  subjectId: identityId,
                }}
                label="Remove"
                tone="danger"
                confirm={
                  seat.groupIds.length
                    ? `Remove the direct assignment of ${seat.productName}? The seat stays while a group still gives it.`
                    : `Take ${seat.productName} away? The seat goes to the next person waiting.`
                }
                tenantId={tenantId}
              />
            ) : (
              ''
            ),
          ]),
          ...seatless.map((assignment) => [
            <Link key="p" href={`${base}/licenses/${assignment.productId}`}>
              {assignment.productName}
            </Link>,
            <Badge key="s">no seat</Badge>,
            <span key="t" className="small">
              direct
            </span>,
            <Time key="a" value={assignment.assignedAt} />,
            mayAssign ? (
              <ApiButton
                key="r"
                path="licenses/unassign"
                body={{ tenantId, assignmentId: assignment.id }}
                label="Remove"
                tone="danger"
                tenantId={tenantId}
              />
            ) : (
              ''
            ),
          ]),
        ]}
        empty="No licenses."
      />
      {mayAssign && active && (
        <div className="card-body">
          {options.length ? (
            <ApiForm
              path="licenses/assign"
              tenantId={tenantId}
              submitLabel="Give license"
              compact
              successMessage="Assigned."
              fields={memberAssignFields(tenantId, identityId, options)}
            />
          ) : (
            products && (
              <Alert tone="info">Every active product is already assigned to this person.</Alert>
            )
          )}
        </div>
      )}
    </Card>
  );
}
