'use client';

import { Check, Copy, Terminal } from 'lucide-react';
import { useCopyButton } from 'fumadocs-ui/utils/use-copy-button';

export function InstallCommand({ command = 'npm i better-iam' }: { command?: string }) {
  const [checked, onClick] = useCopyButton(() => navigator.clipboard.writeText(command));
  return (
    <button
      type="button"
      onClick={onClick}
      className="group inline-flex h-11 items-center gap-3 rounded-xl border bg-fd-card/80 px-4 font-mono text-sm backdrop-blur transition-colors hover:border-fd-primary/40"
      aria-label={`Copy ${command}`}
    >
      <Terminal className="size-4 text-fd-muted-foreground" />
      <span>
        <span className="text-fd-muted-foreground">$ </span>
        {command}
      </span>
      {checked ? (
        <Check className="size-4 text-fd-primary" />
      ) : (
        <Copy className="size-4 text-fd-muted-foreground transition-colors group-hover:text-fd-foreground" />
      )}
    </button>
  );
}
