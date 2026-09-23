import type { Metadata } from 'next';
import Link from 'next/link';
import { RiArrowRightLine, RiSearchEyeLine } from 'react-icons/ri';
import { Kbd } from '@/components/base/kbd/kbd';
import { Band, gutter } from '@/components/site/frame';
import { SiteFooter } from '@/components/site/site-footer';
import { SiteHeader } from '@/components/site/site-header';
import { SmoothScroll } from '@/components/site/smooth-scroll';
import { cx } from '@/utils/cx';

// Next.js adds `noindex` to every 404 response on its own.
export const metadata: Metadata = { title: 'Page not found' };

const destinations: [string, string, string][] = [
  ['Guides', '/docs/guides', 'Concepts, sign-in, decisions, and the access lifecycle'],
  ['Frameworks', '/docs/frameworks', 'Next.js, Nuxt, SvelteKit, NestJS, and more'],
  ['API reference', '/docs/reference/api', 'Every method with its route and signature'],
  ['Playground', '/playground', 'Write policies and watch the engine decide'],
];

export default function NotFound() {
  return (
    <SmoothScroll>
      <div className="site flex min-h-screen flex-1 flex-col">
        <SiteHeader />
        <main className="flex flex-1 flex-col">
          <Band frameClassName="overflow-hidden">
            <div
              aria-hidden
              className="grid-lines pointer-events-none absolute inset-x-0 top-0 h-80"
            />
            <div className={cx('relative flex flex-col items-start gap-5 py-20 md:py-28', gutter)}>
              <span className="flex size-11 items-center justify-center rounded-2lg border border-border-button-default bg-background-primary-default shadow-xs">
                <RiSearchEyeLine className="size-5 text-foreground-icon-primary" aria-hidden />
              </span>
              <p className="eyebrow">404 · Not found</p>
              <h1 className="max-w-2xl text-display-3-semibold tracking-[-0.03em] text-balance md:text-display-2-semibold md:leading-[1.08]">
                This page does not exist
              </h1>
              <p className="max-w-xl text-headline-regular leading-7 text-text-secondary">
                It may have moved when the guides were reorganized. Search with{' '}
                <Kbd className="bg-background-secondary-default text-text-secondary">Ctrl K</Kbd>,
                or start from one of these:
              </p>
            </div>
          </Band>
          <Band marks={false}>
            <ul className="grid gap-px bg-separator-border sm:grid-cols-2 lg:grid-cols-4">
              {destinations.map(([label, href, body]) => (
                <li key={href} className="bg-background-full">
                  <Link
                    href={href}
                    className="group relative flex h-full flex-col gap-2 overflow-hidden p-6 transition-colors duration-200 hover:bg-background-secondary-default sm:p-8"
                  >
                    <span
                      aria-hidden
                      className="hatch pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100"
                    />
                    <span className="relative flex items-center gap-1.5 text-headline-medium">
                      {label}
                      <RiArrowRightLine
                        className="size-4 text-foreground-icon-tertiary transition-[color,transform] duration-300 group-hover:translate-x-1 group-hover:text-foreground-icon-primary"
                        aria-hidden
                      />
                    </span>
                    <span className="relative text-body-regular leading-6 text-text-secondary">
                      {body}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </Band>
        </main>
        <SiteFooter />
      </div>
    </SmoothScroll>
  );
}
