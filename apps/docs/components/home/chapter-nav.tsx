'use client';

import { useEffect, useRef, useState } from 'react';
import { motion, useScroll, useSpring } from 'motion/react';
import { cn } from '@/lib/cn';

export const chapters = [
  { id: 'pipeline', label: 'Pipeline' },
  { id: 'build', label: 'Build' },
  { id: 'sign-in', label: 'Sign-in' },
  { id: 'decisions', label: 'Decisions' },
  { id: 'tenancy', label: 'Tenancy' },
  { id: 'elevation', label: 'Elevation' },
  { id: 'audit', label: 'Audit' },
  { id: 'federation', label: 'Federation' },
  { id: 'reference', label: 'Reference' },
] as const;

/** Sticky chapter list under the site header: highlights the section in view and shows how far down the page you are. */
export function ChapterNav() {
  const [active, setActive] = useState<string>();
  const list = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 200, damping: 40, restDelta: 0.001 });

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting);
        if (visible.length) setActive(visible[0]!.target.id);
      },
      { rootMargin: '-40% 0px -55% 0px' },
    );
    for (const chapter of chapters) {
      const element = document.getElementById(chapter.id);
      if (element) observer.observe(element);
    }
    return () => observer.disconnect();
  }, []);

  // Keep the active chapter visible in the horizontally scrolling list on small screens.
  useEffect(() => {
    const container = list.current;
    const item = container?.querySelector<HTMLElement>(`[data-chapter="${active}"]`);
    if (!container || !item) return;
    const left = item.offsetLeft - container.clientWidth / 2 + item.clientWidth / 2;
    container.scrollTo({ left, behavior: 'smooth' });
  }, [active]);

  return (
    <nav
      aria-label="On this page"
      className="sticky top-14 z-30 border-y bg-fd-background/80 backdrop-blur-lg"
    >
      <div
        ref={list}
        className="mx-auto flex w-full max-w-6xl items-center gap-1 overflow-x-auto px-5 py-2 [scrollbar-width:none] sm:px-6"
      >
        {chapters.map((chapter, index) => (
          <a
            key={chapter.id}
            href={`#${chapter.id}`}
            data-chapter={chapter.id}
            aria-current={active === chapter.id ? 'location' : undefined}
            className={cn(
              'relative isolate inline-flex h-8 shrink-0 items-center gap-2 rounded-lg px-3 text-[0.8125rem] transition-colors',
              active === chapter.id
                ? 'text-fd-foreground'
                : 'text-fd-muted-foreground hover:text-fd-foreground',
            )}
          >
            {active === chapter.id ? (
              <motion.span
                layoutId="chapter-active"
                className="absolute inset-0 -z-10 rounded-lg bg-fd-accent"
                transition={{ type: 'spring', stiffness: 450, damping: 38 }}
              />
            ) : null}
            <span className="font-mono text-[0.6875rem] tabular-nums text-fd-muted-foreground">
              {String(index + 1).padStart(2, '0')}
            </span>
            {chapter.label}
          </a>
        ))}
      </div>
      <motion.div
        aria-hidden
        className="absolute inset-x-0 -bottom-px h-px origin-left bg-fd-primary"
        style={{ scaleX: progress }}
      />
    </nav>
  );
}
