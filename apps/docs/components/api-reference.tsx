import Link from 'next/link';
import { BookOpen, Globe, KeyRound, Lock, LockOpen, Server } from 'lucide-react';
import { CopyText } from '@/components/copy-text';
import { apiUsage } from '@/lib/api-usage';
import { cn } from '@/lib/cn';

const basePath = '/api/iam';

function credentialBadge(credential: string) {
  if (credential === 'none')
    return {
      icon: LockOpen,
      label: 'Public',
      title: 'Callable without a credential',
      className: 'text-sky-600 ring-sky-500/25 bg-sky-500/10 dark:text-sky-400',
    };
  if (credential === 'required')
    return {
      icon: Lock,
      label: 'Credential',
      title: 'Requires a session, API key, or assumed-role credential',
      className: 'text-fd-primary ring-fd-primary/25 bg-fd-primary/10',
    };
  return {
    icon: Server,
    label: 'Server only',
    title: 'Not exposed over HTTP; call it from trusted server code',
    className: 'text-fd-muted-foreground ring-fd-border bg-fd-muted',
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
        <p className="not-prose -mt-2 mb-4 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fd-muted-foreground">
          <BookOpen className="size-3.5" />
          <span>Used in</span>
          {guides.slice(0, 6).map((guide, index) => (
            <span key={guide.url}>
              <Link
                href={guide.url}
                className="text-fd-foreground hover:text-fd-primary hover:underline"
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
    <div className="not-prose my-4 flex flex-col gap-2 rounded-xl border bg-fd-card p-2 text-sm sm:flex-row sm:items-center">
      {path ? (
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-lg bg-fd-background px-2 py-1.5 ring-1 ring-fd-border">
          <span className="rounded-md bg-emerald-500/12 px-1.5 py-0.5 font-mono text-[0.7rem] font-semibold text-emerald-700 dark:text-emerald-400">
            POST
          </span>
          <code className="min-w-0 flex-1 truncate font-mono text-[0.8rem]">{path}</code>
          <CopyText text={path} label="Copy route" />
        </div>
      ) : (
        <div className="flex flex-1 items-center gap-2 px-2 py-1.5 text-fd-muted-foreground">
          <Server className="size-4" />
          <span>
            Call{' '}
            <code className="font-mono text-[0.8rem] text-fd-foreground">{`iam.api.${group}.${method}()`}</code>{' '}
            from server code.
          </span>
        </div>
      )}
      <div className="flex items-center gap-2">
        {http ? (
          <span
            title="Browser client call"
            className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-[0.75rem] text-fd-muted-foreground ring-1 ring-fd-border ring-inset"
          >
            <Globe className="size-3.5" />
            {`client.${group}.${method}()`}
          </span>
        ) : null}
        <span
          title={badge.title}
          className={cn(
            'inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset',
            badge.className,
          )}
        >
          <badge.icon className="size-3.5" />
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
    { icon: KeyRound, label: 'Server', value: `iam.api.${group}` },
    ...(routed
      ? [
          { icon: Globe, label: 'Client', value: `client.${group}` },
          { icon: Server, label: 'HTTP', value: `POST ${basePath}/${group}/*` },
        ]
      : []),
  ];
  return (
    <div className="not-prose my-6 grid gap-px overflow-hidden rounded-xl border bg-fd-border sm:grid-cols-4">
      <div className="flex flex-col gap-1 bg-fd-card p-3">
        <span className="text-xs text-fd-muted-foreground">Methods</span>
        <span className="text-xl font-semibold tabular-nums">{methods}</span>
      </div>
      {items.map((item) => (
        <div key={item.label} className="flex min-w-0 flex-col gap-1 bg-fd-card p-3">
          <span className="inline-flex items-center gap-1 text-xs text-fd-muted-foreground">
            <item.icon className="size-3.5" />
            {item.label}
          </span>
          <code className="truncate font-mono text-[0.8rem]">{item.value}</code>
        </div>
      ))}
      {!routed ? (
        <div className="col-span-2 flex items-center bg-fd-card p-3 text-xs text-fd-muted-foreground">
          This group has no HTTP routes; call it from trusted server code.
        </div>
      ) : null}
    </div>
  );
}
