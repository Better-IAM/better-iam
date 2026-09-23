'use client';

import { Check, Copy } from 'lucide-react';
import { useCopyButton } from 'fumadocs-ui/utils/use-copy-button';
import { cn } from '@/lib/cn';

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
      className={cn(
        'inline-flex size-6 shrink-0 items-center justify-center rounded-md text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-accent-foreground',
        className,
      )}
    >
      {checked ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  );
}
