'use client';

import { RiCheckLine, RiFileCopyLine } from 'react-icons/ri';
import { useCopyButton } from 'fumadocs-ui/utils/use-copy-button';
import { cx } from '@/utils/cx';

export function CopyText({
  text,
  className,
  label = 'Copy',
}: {
  text: string;
  className?: string;
  label?: string;
}) {
  const [checked, onClick] = useCopyButton(() => navigator.clipboard.writeText(text));
  return (
    <button
      type="button"
      aria-label={checked ? 'Copied' : label}
      title={checked ? 'Copied' : label}
      onClick={onClick}
      className={cx(
        'inline-flex size-6 shrink-0 items-center justify-center rounded-md text-foreground-icon-secondary transition-colors hover:bg-background-secondary-default hover:text-foreground-icon-primary',
        className,
      )}
    >
      {checked ? (
        <RiCheckLine className="size-3.5" aria-hidden />
      ) : (
        <RiFileCopyLine className="size-3.5" aria-hidden />
      )}
    </button>
  );
}
