import Link from 'next/link';
import { FlaskConical, Sparkles } from 'lucide-react';
import { version } from '@/lib/shared';

export function SidebarFooter() {
  return (
    <div className="flex flex-col gap-2 pt-2">
      <Link
        href="/playground"
        className="group flex items-center gap-2 rounded-lg border bg-fd-card px-3 py-2 text-sm transition-colors hover:border-fd-primary/40 hover:bg-fd-accent"
      >
        <FlaskConical className="size-4 text-fd-primary" />
        <span className="flex-1">Policy playground</span>
        <span className="text-fd-muted-foreground transition-transform group-hover:translate-x-0.5">
          →
        </span>
      </Link>
      <div className="flex items-center gap-2 px-1 text-xs text-fd-muted-foreground">
        <Sparkles className="size-3.5" />
        <span>
          v{version} ·{' '}
          <Link href="/docs/reference/changelog" className="hover:text-fd-foreground">
            Changelog
          </Link>{' '}
          ·{' '}
          <Link href="/docs/reference/ai" className="hover:text-fd-foreground">
            Use with AI
          </Link>
        </span>
      </div>
    </div>
  );
}
