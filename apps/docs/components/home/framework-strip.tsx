import type { IconType } from 'react-icons';
import Link from 'next/link';
import { RiArrowRightLine } from 'react-icons/ri';
import {
  SiExpress,
  SiFastify,
  SiHono,
  SiNestjs,
  SiNextdotjs,
  SiNuxt,
  SiReact,
  SiReactrouter,
  SiSvelte,
  SiVuedotjs,
} from 'react-icons/si';
import { TextLink } from '@/components/site/action';
import { Band, gutter } from '@/components/site/frame';
import { StaggerChild, StaggerList } from '@/components/site/motion-text';
import { cx } from '@/utils/cx';

const frameworks: [name: string, logo: IconType, href: string][] = [
  ['Next.js', SiNextdotjs, '/docs/frameworks/nextjs'],
  ['React', SiReact, '/docs/frameworks/react'],
  ['Vue', SiVuedotjs, '/docs/frameworks/vue'],
  ['Nuxt', SiNuxt, '/docs/frameworks/nuxt'],
  ['SvelteKit', SiSvelte, '/docs/frameworks/sveltekit'],
  ['React Router', SiReactrouter, '/docs/frameworks/react-router'],
  ['NestJS', SiNestjs, '/docs/frameworks/nestjs'],
  ['Express', SiExpress, '/docs/frameworks/node'],
  ['Hono', SiHono, '/docs/frameworks/node'],
  ['Fastify', SiFastify, '/docs/frameworks/node'],
];

const corners = [
  'top-3 left-3 -translate-x-1 -translate-y-1 border-t border-l',
  'top-3 right-3 translate-x-1 -translate-y-1 border-t border-r',
  'bottom-3 left-3 -translate-x-1 translate-y-1 border-b border-l',
  'right-3 bottom-3 translate-x-1 translate-y-1 border-r border-b',
];

/** The frameworks Better IAM ships integrations for, as their own logos (Simple Icons) in one hairline grid. */
export function FrameworkStrip() {
  return (
    <Band aria-label="Framework integrations">
      <div
        className={cx(
          'flex flex-wrap items-center justify-between gap-3 border-b border-separator-border py-4',
          gutter,
        )}
      >
        <p className="eyebrow">Works with the stack you already run</p>
        <TextLink
          href="/docs/frameworks"
          trailingIcon={RiArrowRightLine}
          className="text-body-2-medium"
        >
          All integrations
        </TextLink>
      </div>
      <StaggerList className="grid grid-cols-2 gap-px bg-separator-border sm:grid-cols-5 xl:grid-cols-10">
        {frameworks.map(([name, Logo, href]) => (
          <li key={name} className="bg-background-full">
            <StaggerChild>
              <Link
                href={href}
                className="group relative flex h-24 flex-col items-center justify-center gap-2.5 transition-colors duration-200 hover:bg-background-secondary-default"
              >
                {/* Corner brackets close in on the logo under the pointer. */}
                {corners.map((corner) => (
                  <span
                    key={corner}
                    aria-hidden
                    className={cx(
                      'absolute size-2.5 border-text-primary opacity-0 transition-[opacity,transform] duration-300 ease-out group-hover:translate-x-0 group-hover:translate-y-0 group-hover:opacity-100 group-focus-visible:opacity-100',
                      corner,
                    )}
                  />
                ))}
                <Logo
                  className="size-6 text-foreground-icon-secondary transition-[color,transform] duration-300 ease-out group-hover:-translate-y-0.5 group-hover:scale-110 group-hover:text-foreground-icon-primary"
                  aria-hidden
                />
                <span className="text-caption-1-medium text-text-secondary transition-colors group-hover:text-text-primary">
                  {name}
                </span>
              </Link>
            </StaggerChild>
          </li>
        ))}
      </StaggerList>
    </Band>
  );
}
