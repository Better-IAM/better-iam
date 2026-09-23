'use client';

import { useEffect, useState } from 'react';
import { ThumbsDown, ThumbsUp } from 'lucide-react';
import { cn } from '@/lib/cn';
import { newIssueUrl } from '@/lib/shared';

type Opinion = 'good' | 'bad';

const storageKey = (url: string) => `better-iam-docs:feedback:${url}`;

/**
 * "Was this page helpful?" Answers are remembered per page in this browser only; a negative answer offers a
 * prefilled issue so the reader can say what was missing.
 */
export function PageFeedback({ url }: { url: string }) {
  const [opinion, setOpinion] = useState<Opinion | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(storageKey(url));
      setOpinion(saved === 'good' || saved === 'bad' ? saved : null);
    } catch {
      setOpinion(null);
    }
  }, [url]);

  function choose(next: Opinion) {
    setOpinion(next);
    try {
      localStorage.setItem(storageKey(url), next);
    } catch {
      // Storage can be unavailable (private windows); the answer still shows for this visit.
    }
  }

  const issueUrl = newIssueUrl(
    `Docs feedback: ${url}`,
    `Page: ${url}\n\nWhat were you looking for, and what was missing or unclear?\n`,
  );

  return (
    <div className="mt-10 flex flex-col gap-3 rounded-xl border bg-fd-card p-4 text-sm sm:flex-row sm:items-center">
      <p className="font-medium">
        {opinion ? 'Thanks for the feedback.' : 'Was this page helpful?'}
      </p>
      <div className="flex items-center gap-2 sm:ms-auto">
        {(
          [
            ['good', ThumbsUp, 'Yes'],
            ['bad', ThumbsDown, 'No'],
          ] as const
        ).map(([value, Icon, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={opinion === value}
            onClick={() => choose(value)}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 transition-colors',
              opinion === value
                ? 'border-fd-primary/50 bg-fd-primary/10 text-fd-primary'
                : 'hover:bg-fd-accent hover:text-fd-accent-foreground',
            )}
          >
            <Icon className="size-3.5" />
            {label}
          </button>
        ))}
        {opinion === 'bad' && issueUrl ? (
          <a
            href={issueUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="rounded-lg px-2 py-1.5 text-fd-primary underline-offset-4 hover:underline"
          >
            Tell us what was missing
          </a>
        ) : null}
      </div>
    </div>
  );
}
