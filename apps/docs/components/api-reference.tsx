import Link from 'next/link';
import {
  RiBookOpenLine,
  RiGlobalLine,
  RiKey2Line,
  RiLock2Line,
  RiLockUnlockLine,
  RiServerLine,
} from 'react-icons/ri';
import { CopyText } from '@/components/copy-text';
import { apiUsage } from '@/lib/api-usage';
import { cx } from '@/utils/cx';

const basePath = '/api/iam';

/** Who may call a route, told apart by weight: credential-gated is solid ink, public outlined, server-only muted. */
function credentialBadge(credential: string) {
  if (credential === 'none')
    return {
      icon: RiLockUnlockLine,
      label: 'Public',
      title: 'Callable without a credential',
      className: 'border border-text-primary text-text-primary',
    };
  if (credential === 'required')
    return {
      icon: RiLock2Line,
      label: 'Credential',
      title: 'Requires a session, API key, or assumed-role credential',
      className: 'bg-text-primary text-background-full',
    };
  return {
    icon: RiServerLine,
    label: 'Server only',
    title: 'Not exposed over HTTP; call it from trusted server code',
    className: 'bg-background-secondary-default text-text-secondary',
  };
}

/**
 * The HTTP route, credential requirement, and browser-client call of one API method, plus the guides that use it
 * (found by scanning every guide for calls and reference links; see `lib/api-usage.ts`).
 */
export async function ApiEndpoint({
  group,
  method,
  http,
  credential,
}: {
  group: string;
  method: string;
  http?: string;
  credential: string;
}) {
  const badge = credentialBadge(http ? credential : 'server');
  const path = http ? `${basePath}${http.replace(/^POST /, '')}` : undefined;
  const guides = (await apiUsage()).usedIn.get(`${group}.${method}`) ?? [];
  return (
    <>
      <Endpoint group={group} method={method} http={http} path={path} badge={badge} />
      {guides.length ? (
        <p className="not-prose -mt-2 mb-4 flex flex-wrap items-center gap-x-2 gap-y-1 text-caption-1-regular text-text-secondary">
          <RiBookOpenLine className="size-3.5" aria-hidden />
          <span>Used in</span>
          {guides.slice(0, 6).map((guide, index) => (
            <span key={guide.url}>
              <Link
                href={guide.url}
                className="text-text-primary underline-offset-2 hover:underline"
              >
                {guide.title}
              </Link>
              {index < Math.min(guides.length, 6) - 1 ? ',' : ''}
            </span>
          ))}
          {guides.length > 6 ? <span>and {guides.length - 6} more</span> : null}
        </p>
      ) : null}
    </>
  );
}

function Endpoint({
  group,
  method,
  http,
  path,
  badge,
}: {
  group: string;
  method: string;
  http?: string;
  path?: string;
  badge: ReturnType<typeof credentialBadge>;
}) {
  return (
    <div className="not-prose my-4 flex flex-col gap-2 rounded-2xl border border-border-button-default bg-surface-sunken p-2 text-body-regular sm:flex-row sm:items-center">
      {path ? (
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-border-button-default bg-background-primary-default px-2 py-1.5 shadow-xs">
          <span className="rounded-md bg-text-primary px-1.5 py-0.5 font-mono text-[0.7rem] font-semibold text-background-full">
            POST
          </span>
          <code className="min-w-0 flex-1 truncate font-mono text-[0.8rem]">{path}</code>
          <CopyText text={path} label="Copy route" />
        </div>
      ) : (
        <div className="flex flex-1 items-center gap-2 px-2 py-1.5 text-text-secondary">
          <RiServerLine className="size-4" aria-hidden />
          <span>
            Call{' '}
            <code className="font-mono text-[0.8rem] text-text-primary">{`iam.api.${group}.${method}()`}</code>{' '}
            from server code.
          </span>
        </div>
      )}
      <div className="flex items-center gap-2">
        {http ? (
          <span
            title="Browser client call"
            className="inline-flex items-center gap-1.5 rounded-lg border border-border-button-default bg-background-primary-default px-2 py-1 font-mono text-[0.75rem] text-text-secondary"
          >
            <RiGlobalLine className="size-3.5" aria-hidden />
            {`client.${group}.${method}()`}
          </span>
        ) : null}
        <span
          title={badge.title}
          className={cx(
            'inline-flex items-center gap-1 rounded-lg px-2 py-1 text-caption-1-medium',
            badge.className,
          )}
        >
          <badge.icon className="size-3.5" aria-hidden />
          {badge.label}
        </span>
      </div>
    </div>
  );
}

export function ApiGroupSummary({
  group,
  methods,
  routed,
}: {
  group: string;
  methods: number;
  routed: boolean;
}) {
  const items = [
    { icon: RiKey2Line, label: 'Server', value: `iam.api.${group}` },
    ...(routed
      ? [
          { icon: RiGlobalLine, label: 'Client', value: `client.${group}` },
          { icon: RiServerLine, label: 'HTTP', value: `POST ${basePath}/${group}/*` },
        ]
      : []),
  ];
  return (
    <div className="not-prose my-6 grid gap-px overflow-hidden rounded-2xl border border-border-button-default bg-separator-border sm:grid-cols-4">
      <div className="flex flex-col gap-1 bg-background-primary-default p-3">
        <span className="text-caption-1-regular text-text-secondary">Methods</span>
        <span className="text-title-2-semibold tabular-nums">{methods}</span>
      </div>
      {items.map((item) => (
        <div
          key={item.label}
          className="flex min-w-0 flex-col gap-1 bg-background-primary-default p-3"
        >
          <span className="inline-flex items-center gap-1 text-caption-1-regular text-text-secondary">
            <item.icon className="size-3.5" aria-hidden />
            {item.label}
          </span>
          <code className="truncate font-mono text-[0.8rem]">{item.value}</code>
        </div>
      ))}
      {!routed ? (
        <div className="col-span-2 flex items-center bg-background-primary-default p-3 text-caption-1-regular text-text-secondary">
          This group has no HTTP routes; call it from trusted server code.
        </div>
      ) : null}
    </div>
  );
}
