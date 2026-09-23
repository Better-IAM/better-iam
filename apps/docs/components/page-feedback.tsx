'use client';

import { useEffect, useState } from 'react';
import { RiThumbDownLine, RiThumbUpLine } from 'react-icons/ri';
import { buttonStyles } from '@/components/base/buttons/button';
import { newIssueUrl } from '@/lib/shared';
import { cx } from '@/utils/cx';

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
    <div className="mt-10 flex flex-col gap-3 rounded-2xl border border-border-button-default bg-surface-sunken p-4 sm:flex-row sm:items-center sm:ps-5">
      <p className="text-body-medium">
        {opinion ? 'Thanks for the feedback.' : 'Was this page helpful?'}
      </p>
      <div className="flex items-center gap-2 sm:ms-auto">
        {(
          [
            ['good', RiThumbUpLine, 'Yes'],
            ['bad', RiThumbDownLine, 'No'],
          ] as const
        ).map(([value, Icon, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={opinion === value}
            onClick={() => choose(value)}
            className={cx(
              buttonStyles.base,
              buttonStyles.size.small,
              opinion === value ? buttonStyles.variant.primary : buttonStyles.variant.secondary,
              'gap-1.5 px-2.5',
            )}
          >
            <Icon className="size-4" aria-hidden />
            <span className={buttonStyles.label.small}>{label}</span>
          </button>
        ))}
        {opinion === 'bad' && issueUrl ? (
          <a
            href={issueUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="rounded-lg px-2 py-1.5 text-body-medium underline-offset-4 hover:underline"
          >
            Tell us what was missing
          </a>
        ) : null}
      </div>
    </div>
  );
}
