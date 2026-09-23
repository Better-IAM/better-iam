import Link from 'next/link';
import type { ReactNode } from 'react';
import { Alert, Badge, Card, PageHeader, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

interface Attention {
  tone: Tone;
  label: string;
  detail: string;
  href: string;
}

function Tile({
  title,
  status,
  figure,
  unit,
  children,
  meter,
  links,
  locked,
}: {
  title: string;
  status?: { tone: Tone; label: string };
  figure?: ReactNode;
  unit?: string;
  children?: ReactNode;
  meter?: { value: number; tone?: Tone };
  links: { href: string; label: string }[];
  locked?: string;
}) {
  return (
    <section className="card tile">
      <div className="tile-head">
        <h2>{title}</h2>
        {status && <Badge tone={status.tone}>{status.label}</Badge>}
      </div>
      {locked ? (
        <p>
          Requires <code>{locked}</code>.
        </p>
      ) : (
        <>
          {figure !== undefined && (
            <div className="figure">
              {figure}
              {unit && <small>{unit}</small>}
            </div>
          )}
          {meter && (
            <div
              className={`meter ${meter.tone ?? ''}`}
              role="meter"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(meter.value * 100)}
            >
              <span style={{ width: `${Math.max(2, Math.min(100, meter.value * 100))}%` }} />
            </div>
          )}
          {children}
        </>
      )}
      <div className="tile-foot">
        {links.map((link) => (
          <Link key={link.href} href={link.href}>
            {link.label} →
          </Link>
        ))}
      </div>
    </section>
  );
}

export default async function Governance({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  // Each read is independent and permission-gated; a missing permission hides only its tile's figures.
  const [
    findings,
    invariants,
    mining,
    sizing,
    agreements,
    campaigns,
    sod,
    bindingApprovals,
    packageApprovals,
  ] = await Promise.all([
    tryRead(() => iam.api.analysis.findings(auth, { tenantId })),
    tryRead(() => iam.api.invariants.run(auth, { tenantId })),
    tryRead(() => iam.api.roleMining.suggest(auth, { tenantId, limit: 1 })),
    tryRead(() => iam.api.roleMining.rightSize(auth, { tenantId })),
    tryRead(() => iam.api.agreements.list(auth, { tenantId })),
    tryRead(() => iam.api.certifications.list(auth, { tenantId, status: 'open' })),
    tryRead(() => iam.api.sod.violations(auth, { tenantId })),
    tryRead(() => iam.api.bindings.listApprovals(auth, { tenantId })),
    tryRead(() => iam.api.packages.listApprovals(auth, { tenantId })),
  ]);
  const agreementStatus = agreements
    ? await Promise.all(
        agreements.map((agreement) =>
          tryRead(() => iam.api.agreements.status(auth, { tenantId, agreementId: agreement.id })),
        ),
      )
    : [];
  const now = Date.now();

  const brokenEnforced =
    invariants?.results.filter((result) => !result.passed && result.invariant.mode === 'enforce') ??
    [];
  const brokenMonitored =
    invariants?.results.filter((result) => !result.passed && result.invariant.mode === 'monitor') ??
    [];
  const unused = sizing?.entries.filter((entry) => entry.status === 'unused') ?? [];
  const partial = sizing?.entries.filter((entry) => entry.status === 'partial') ?? [];
  const pendingAcceptances = agreementStatus.reduce(
    (count, status) => count + (status?.agreement.required ? status.pending.length : 0),
    0,
  );
  const acceptedTotal = agreementStatus.reduce(
    (count, status) => count + (status?.accepted.length ?? 0),
    0,
  );
  const overdue = campaigns?.filter((campaign) => campaign.dueAt && campaign.dueAt < now) ?? [];
  const reviewTotal =
    campaigns?.reduce((count, campaign) => count + campaign.progress.total, 0) ?? 0;
  const reviewDecided =
    campaigns?.reduce((count, campaign) => count + campaign.progress.decided, 0) ?? 0;
  const approvals = (bindingApprovals?.length ?? 0) + (packageApprovals?.length ?? 0);
  const simplifications = mining
    ? mining.summary['redundant-binding'] +
      mining.summary['group-binding'] +
      mining.summary['duplicate-roles'] +
      mining.summary.bundle
    : 0;

  const attention: Attention[] = [];
  if (findings?.summary.high)
    attention.push({
      tone: 'danger',
      label: `${findings.summary.high} high-severity finding${findings.summary.high === 1 ? '' : 's'}`,
      detail: 'Administrators without MFA, unrestricted policies, conflicting duties.',
      href: `${base}/findings`,
    });
  if (brokenEnforced.length)
    attention.push({
      tone: 'danger',
      label: `${brokenEnforced.length} enforced invariant${brokenEnforced.length === 1 ? ' is' : 's are'} broken`,
      detail: 'Violations that predate enforcement; new changes are already refused.',
      href: `${base}/invariants`,
    });
  if (sod?.length)
    attention.push({
      tone: 'danger',
      label: `${sod.length} separation-of-duties conflict${sod.length === 1 ? '' : 's'}`,
      detail: 'People who hold roles that must not be held together.',
      href: `${base}/separation-of-duties`,
    });
  if (approvals)
    attention.push({
      tone: 'warning',
      label: `${approvals} request${approvals === 1 ? '' : 's'} waiting for your approval`,
      detail: 'Just-in-time activations and access-package requests.',
      href: `${base}/elevate`,
    });
  if (overdue.length)
    attention.push({
      tone: 'warning',
      label: `${overdue.length} certification campaign${overdue.length === 1 ? ' is' : 's are'} overdue`,
      detail: `${reviewTotal - reviewDecided} item(s) still undecided across open campaigns.`,
      href: `${base}/certifications`,
    });
  if (brokenMonitored.length)
    attention.push({
      tone: 'warning',
      label: `${brokenMonitored.length} monitored invariant${brokenMonitored.length === 1 ? ' is' : 's are'} broken`,
      detail: 'Guardrails in monitor mode report but do not block.',
      href: `${base}/invariants`,
    });
  if (findings?.summary.medium)
    attention.push({
      tone: 'warning',
      label: `${findings.summary.medium} medium-severity finding${findings.summary.medium === 1 ? '' : 's'}`,
      detail: 'Dormant access, stale API keys, broad wildcards, standing admin access.',
      href: `${base}/findings`,
    });
  if (sizing?.complete && unused.length)
    attention.push({
      tone: 'info',
      label: `${unused.length} role assignment${unused.length === 1 ? '' : 's'} unused for ${sizing.unusedDays} days`,
      detail: 'Candidates to remove under least privilege.',
      href: `${base}/role-mining`,
    });
  if (pendingAcceptances)
    attention.push({
      tone: 'info',
      label: `${pendingAcceptances} required agreement acceptance${pendingAcceptances === 1 ? '' : 's'} outstanding`,
      detail: 'Members see a banner until they accept.',
      href: `${base}/agreements`,
    });
  if (mining && (mining.summary['redundant-binding'] || mining.summary['group-binding']))
    attention.push({
      tone: 'info',
      label: `${mining.summary['redundant-binding'] + mining.summary['group-binding']} binding cleanup${mining.summary['redundant-binding'] + mining.summary['group-binding'] === 1 ? '' : 's'} can be applied in one click`,
      detail: 'Redundant direct bindings and roles to move onto a group.',
      href: `${base}/role-mining`,
    });

  const findingsTotal = findings
    ? findings.summary.high + findings.summary.medium + findings.summary.low
    : 0;

  return (
    <>
      <PageHeader
        title="Governance"
        description="The health of who can do what: risks found in the configuration, guardrails and their status, access nobody uses, reviews in progress, and terms people have accepted. Each tile opens the page that fixes it."
      />
      <div className="stack">
        <Card
          title="Needs attention"
          description={
            attention.length
              ? 'Most urgent first.'
              : 'Nothing needs attention with the permissions you hold.'
          }
          flush
        >
          {attention.length ? (
            <div className="attention">
              {attention.map((item) => (
                <Link key={item.label} href={item.href}>
                  <Badge tone={item.tone}>
                    {item.tone === 'danger' ? 'urgent' : item.tone === 'warning' ? 'soon' : 'tidy'}
                  </Badge>
                  <span>
                    <strong>{item.label}</strong>
                    <span className="small muted" style={{ display: 'block' }}>
                      {item.detail}
                    </span>
                  </span>
                  <span className="go">Review →</span>
                </Link>
              ))}
            </div>
          ) : (
            <div className="empty">All clear.</div>
          )}
        </Card>

        <h2 className="section-title">Risk</h2>
        <div className="tiles">
          <Tile
            title="Security findings"
            locked={findings ? undefined : 'iam:analysis:read'}
            status={
              findings
                ? findings.summary.high
                  ? { tone: 'danger', label: `${findings.summary.high} high` }
                  : findings.summary.medium
                    ? { tone: 'warning', label: `${findings.summary.medium} medium` }
                    : { tone: 'success', label: 'no high or medium' }
                : undefined
            }
            figure={findingsTotal}
            unit="open"
            links={[{ href: `${base}/findings`, label: 'Findings' }]}
          >
            {findings && (
              <p>
                {findings.summary.low} low, {findings.summary.suppressed} suppressed as accepted
                risk.
              </p>
            )}
          </Tile>
          <Tile
            title="Invariants"
            locked={invariants ? undefined : 'iam:invariants:read'}
            status={
              invariants
                ? invariants.summary.failed + invariants.summary.errors
                  ? { tone: brokenEnforced.length ? 'danger' : 'warning', label: 'broken' }
                  : invariants.results.length
                    ? { tone: 'success', label: 'all hold' }
                    : { tone: 'neutral', label: 'none yet' }
                : undefined
            }
            figure={invariants ? `${invariants.summary.passed}/${invariants.results.length}` : '—'}
            unit="hold"
            meter={
              invariants?.results.length
                ? {
                    value: invariants.summary.passed / invariants.results.length,
                    tone: invariants.summary.failed ? 'danger' : 'success',
                  }
                : undefined
            }
            links={[
              { href: `${base}/invariants`, label: 'Invariants' },
              { href: `${base}/impact`, label: 'Preview a change' },
            ]}
          >
            {invariants && (
              <p>
                {invariants.results.filter((result) => result.invariant.mode === 'enforce').length}{' '}
                enforced; {invariants.summary.errors} cannot be evaluated.
              </p>
            )}
          </Tile>
          <Tile
            title="Separation of duties"
            locked={sod ? undefined : 'iam:sod:read'}
            status={
              sod
                ? sod.length
                  ? { tone: 'danger', label: 'conflicts' }
                  : { tone: 'success', label: 'no conflicts' }
                : undefined
            }
            figure={sod?.length ?? '—'}
            unit="conflicting people"
            links={[{ href: `${base}/separation-of-duties`, label: 'Rules' }]}
          />
        </div>

        <h2 className="section-title">Least privilege</h2>
        <div className="tiles">
          <Tile
            title="Unused access"
            locked={sizing ? undefined : 'iam:analysis:read'}
            status={
              sizing
                ? !sizing.tracking
                  ? { tone: 'neutral', label: 'tracking off' }
                  : sizing.complete
                    ? unused.length
                      ? { tone: 'warning', label: `${unused.length} unused` }
                      : { tone: 'success', label: 'all used' }
                    : { tone: 'info', label: 'collecting' }
                : undefined
            }
            figure={sizing?.tracking ? unused.length : '—'}
            unit={sizing?.tracking ? `unused, ${partial.length} partly used` : undefined}
            links={[{ href: `${base}/role-mining`, label: 'Least privilege' }]}
          >
            {sizing && !sizing.tracking && (
              <p>Enable the accessUsage option to record which actions people use.</p>
            )}
            {sizing?.tracking && !sizing.complete && (
              <p>
                Usage recorded for less than {sizing.unusedDays} days; "unused" is not conclusive
                yet.
              </p>
            )}
          </Tile>
          <Tile
            title="Role mining"
            locked={mining ? undefined : 'iam:analysis:read'}
            status={
              mining
                ? simplifications
                  ? { tone: 'info', label: `${simplifications} suggestions` }
                  : { tone: 'success', label: 'tidy' }
                : undefined
            }
            figure={mining ? simplifications : '—'}
            unit="ways to simplify"
            links={[{ href: `${base}/role-mining`, label: 'Suggestions' }]}
          >
            {mining && (
              <p>
                {mining.summary['redundant-binding']} redundant, {mining.summary['group-binding']}{' '}
                to move onto groups, {mining.summary['duplicate-roles']} duplicate roles,{' '}
                {mining.summary.bundle} bundles.
              </p>
            )}
          </Tile>
        </div>

        <h2 className="section-title">Reviews and approvals</h2>
        <div className="tiles">
          <Tile
            title="Certifications"
            locked={campaigns ? undefined : 'iam:certifications:read'}
            status={
              campaigns
                ? overdue.length
                  ? { tone: 'warning', label: `${overdue.length} overdue` }
                  : campaigns.length
                    ? { tone: 'info', label: `${campaigns.length} open` }
                    : { tone: 'neutral', label: 'none open' }
                : undefined
            }
            figure={reviewTotal ? `${Math.round((reviewDecided / reviewTotal) * 100)}%` : '—'}
            unit={reviewTotal ? `of ${reviewTotal} decided` : undefined}
            meter={
              reviewTotal
                ? {
                    value: reviewDecided / reviewTotal,
                    tone: overdue.length ? 'warning' : undefined,
                  }
                : undefined
            }
            links={[{ href: `${base}/certifications`, label: 'Campaigns' }]}
          />
          <Tile
            title="Approvals"
            status={
              bindingApprovals || packageApprovals
                ? approvals
                  ? { tone: 'warning', label: 'waiting' }
                  : { tone: 'success', label: 'inbox empty' }
                : undefined
            }
            locked={
              bindingApprovals || packageApprovals
                ? undefined
                : 'iam:bindings:approve or iam:packages:approve'
            }
            figure={approvals}
            unit="waiting for you"
            links={[{ href: `${base}/elevate`, label: 'Approvals' }]}
          >
            <p>
              {bindingApprovals?.length ?? 0} activation request(s), {packageApprovals?.length ?? 0}{' '}
              package request(s).
            </p>
          </Tile>
          <Tile
            title="Terms of use"
            locked={agreements ? undefined : 'iam:agreements:read'}
            status={
              agreements
                ? !agreements.length
                  ? { tone: 'neutral', label: 'none published' }
                  : pendingAcceptances
                    ? { tone: 'warning', label: `${pendingAcceptances} outstanding` }
                    : { tone: 'success', label: 'all accepted' }
                : undefined
            }
            figure={agreements?.length ?? '—'}
            unit="agreements"
            meter={
              acceptedTotal + pendingAcceptances
                ? {
                    value: acceptedTotal / (acceptedTotal + pendingAcceptances),
                    tone: pendingAcceptances ? 'warning' : 'success',
                  }
                : undefined
            }
            links={[{ href: `${base}/agreements`, label: 'Agreements' }]}
          />
        </div>

        {!findings && !invariants && !mining && (
          <Alert tone="info">
            Governance views need read permissions such as <code>iam:analysis:read</code>,{' '}
            <code>iam:invariants:read</code>, and <code>iam:certifications:read</code>. Ask an owner
            to grant them.
          </Alert>
        )}
      </div>
    </>
  );
}
