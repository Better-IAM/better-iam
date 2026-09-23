import type { ReactNode } from 'react';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { cn } from '@/lib/cn';
import { Reveal } from './motion';

/** Content column shared by every landing section, so left edges line up from hero to footer. */
export function Container({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn('mx-auto w-full max-w-6xl px-5 sm:px-6', className)}>{children}</div>;
}

export function Section({
  id,
  className,
  children,
}: {
  id?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className={cn('scroll-mt-28 py-20 md:py-28', className)}>
      <Container>{children}</Container>
    </section>
  );
}

/** Eyebrow, heading, and a short lede: the same reading order at the top of every section. */
export function SectionHeader({
  eyebrow,
  title,
  children,
  align = 'start',
  className,
}: {
  eyebrow: string;
  title: ReactNode;
  children?: ReactNode;
  align?: 'start' | 'center';
  className?: string;
}) {
  return (
    <header
      className={cn(
        'flex max-w-2xl flex-col gap-4',
        align === 'center' && 'mx-auto items-center text-center',
        className,
      )}
    >
      <p className="eyebrow">{eyebrow}</p>
      <h2 className="text-balance text-3xl font-medium leading-[1.12] tracking-tight md:text-[2.5rem]">
        {title}
      </h2>
      {children ? (
        <p className="text-pretty text-base leading-7 text-fd-muted-foreground md:text-[1.0625rem]">
          {children}
        </p>
      ) : null}
    </header>
  );
}

export interface Point {
  lead: string;
  body: ReactNode;
}

/** Three or four short claims, each a bold lead-in and one sentence: easy to scan, hard to misread. */
export function Points({ points, className }: { points: Point[]; className?: string }) {
  return (
    <ul className={cn('flex flex-col gap-4', className)}>
      {points.map((point) => (
        <li key={point.lead} className="flex gap-3 text-[0.9375rem] leading-6">
          <span aria-hidden className="mt-[0.6875rem] h-px w-3 shrink-0 bg-fd-primary" />
          <span className="text-fd-muted-foreground">
            <span className="font-medium text-fd-foreground">{point.lead}</span> {point.body}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function GuideLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="group inline-flex w-fit items-center gap-1.5 text-sm font-medium text-fd-primary underline-offset-4 hover:underline"
    >
      {children}
      <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
    </Link>
  );
}

interface ExplainerProps {
  id: string;
  eyebrow: string;
  title: ReactNode;
  lede: ReactNode;
  points: Point[];
  href: string;
  linkLabel: string;
  visual: ReactNode;
  className?: string;
}

/** Text beside a diagram. `reverse` puts the diagram first on wide screens. */
export function SplitExplainer({
  reverse = false,
  ...props
}: ExplainerProps & { reverse?: boolean }) {
  return (
    <Section id={props.id} className={props.className}>
      <div
        className={cn(
          'grid items-center gap-12 lg:gap-16',
          reverse
            ? 'lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]'
            : 'lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]',
        )}
      >
        <div className={cn('flex flex-col gap-8', reverse && 'lg:order-2')}>
          <SectionHeader eyebrow={props.eyebrow} title={props.title}>
            {props.lede}
          </SectionHeader>
          <Points points={props.points} />
          <GuideLink href={props.href}>{props.linkLabel}</GuideLink>
        </div>
        <Reveal className={cn('min-w-0', reverse && 'lg:order-1')}>{props.visual}</Reveal>
      </div>
    </Section>
  );
}

/** Heading and claims side by side, with a full-width diagram below. */
export function StackedExplainer(props: ExplainerProps) {
  return (
    <Section id={props.id} className={props.className}>
      <div className="grid gap-8 lg:grid-cols-2 lg:gap-16">
        <SectionHeader eyebrow={props.eyebrow} title={props.title}>
          {props.lede}
        </SectionHeader>
        <div className="flex flex-col gap-6 lg:pt-9">
          <Points points={props.points} />
          <GuideLink href={props.href}>{props.linkLabel}</GuideLink>
        </div>
      </div>
      <Reveal className="mt-12 min-w-0">{props.visual}</Reveal>
    </Section>
  );
}
