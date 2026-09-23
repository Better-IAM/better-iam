'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { motion } from 'motion/react';
import { RequestTraceView, stages } from './request-trace-view';
import { ease } from './motion';

/**
 * The pipeline told one stage at a time. On wide screens the trace stays pinned while the reader scrolls through the
 * stages, and the stage in the middle of the viewport lights up; on narrow screens the trace plays by itself above
 * the text. The wording follows "The request pipeline" in guides/concepts.
 */
const chapters: { title: string; body: ReactNode; note?: string }[] = [
  {
    title: 'Resolve the credential',
    body: 'The session cookie, bearer token, or API key becomes an identity and a session. When the call carries request headers, the client’s address comes from them too, so network rules judge the address that actually presented the credential.',
  },
  {
    title: 'Re-validate inside the transaction',
    body: 'An administrator may have disabled the person or ended the session a moment ago. So before anything is used, the transaction re-reads the identity and session and checks every revocation condition again: status, expiry, tenant ancestry, idle timeout, MFA, and network rules.',
  },
  {
    title: 'Authorize the operation',
    body: 'Every provisioning operation is itself an action on a resource, evaluated like any product action against roles, policies, boundaries, and grant authorities. A denial commits only a deny audit event, and the caller receives a typed error.',
    note: 'ACCESS_DENIED · 403',
  },
  {
    title: 'Apply the change',
    body: 'Plugin hooks run around the change itself, then separation-of-duties rules and access invariants are checked. Any failure rolls the whole transaction back, so a change that breaks a rule never becomes visible.',
    note: 'INVARIANT_VIOLATION · 409',
  },
  {
    title: 'Append the audit event',
    body: 'One event joins the tenant’s hash chain in the same transaction. Each event includes the hash of the one before, so altering, reordering, or removing a record is detectable.',
  },
  {
    title: 'Fan out after commit',
    body: 'Subscribers, plugin afterAudit hooks, and signed webhooks are queued in the transaction and dispatched once it commits. Nothing is emitted for a change that rolled back.',
  },
];

function useWide() {
  const [wide, setWide] = useState(false);
  useEffect(() => {
    const query = window.matchMedia('(min-width: 1024px)');
    const update = () => setWide(query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  return wide;
}

export function PipelineStory({ code }: { code: ReactNode }) {
  const wide = useWide();
  const [active, setActive] = useState(0);
  const items = useRef<(HTMLLIElement | null)[]>([]);

  useEffect(() => {
    if (!wide) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setActive(Number((entry.target as HTMLElement).dataset.index));
        }
      },
      { rootMargin: '-45% 0px -50% 0px' },
    );
    for (const item of items.current) if (item) observer.observe(item);
    return () => observer.disconnect();
  }, [wide]);

  return (
    <div className="grid gap-10 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)] lg:gap-14">
      <div className="min-w-0 lg:sticky lg:top-32 lg:self-start">
        <RequestTraceView code={code} step={wide ? active : undefined} stacked={wide} />
      </div>
      <ol className="flex flex-col gap-9 lg:gap-0 lg:py-[18vh]">
        {chapters.map((chapter, index) => {
          const lit = index === Math.min(active, chapters.length - 1);
          const current = !wide || lit;
          return (
            <li
              key={chapter.title}
              ref={(element) => {
                items.current[index] = element;
              }}
              data-index={index}
              className="relative lg:min-h-[34vh] lg:py-6"
            >
              <motion.div
                className="relative flex flex-col gap-2 border-s ps-6"
                animate={{ opacity: current ? 1 : 0.38 }}
                transition={{ duration: 0.35, ease }}
              >
                {/* The rule beside the stage in view turns to the brand color. */}
                <motion.span
                  aria-hidden
                  className="absolute -start-px top-0 h-full w-px origin-top bg-fd-primary"
                  initial={false}
                  animate={{ scaleY: wide && lit ? 1 : 0 }}
                  transition={{ duration: 0.45, ease }}
                />
                <span className="font-mono text-xs tabular-nums text-fd-muted-foreground">
                  {String(index + 1).padStart(2, '0')} · {stages[index]!.label}
                </span>
                <h3 className="text-lg font-medium leading-snug">{chapter.title}</h3>
                <p className="text-[0.9375rem] leading-7 text-fd-muted-foreground">
                  {chapter.body}
                </p>
                {chapter.note ? (
                  <span className="mt-1 w-fit rounded-md border bg-fd-card px-2 py-0.5 font-mono text-[0.6875rem] text-fd-muted-foreground">
                    {chapter.note}
                  </span>
                ) : null}
              </motion.div>
            </li>
          );
        })}
        {/* Past the last stage the trace completes: "Allowed · committed". */}
        <li
          aria-hidden
          ref={(element) => {
            items.current[chapters.length] = element;
          }}
          data-index={chapters.length}
          className="hidden h-px lg:block"
        />
      </ol>
    </div>
  );
}
