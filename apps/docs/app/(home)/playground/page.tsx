import type { Metadata } from 'next';
import { RiFlaskLine } from 'react-icons/ri';
import { PolicyPlayground } from '@/components/playground/policy-playground';
import { TextLink } from '@/components/site/action';
import { Band, gutter } from '@/components/site/frame';
import { pageMetadata, siteImages } from '@/lib/metadata';
import { cx } from '@/utils/cx';

export const metadata: Metadata = pageMetadata({
  title: 'Policy playground',
  description:
    'Write Better IAM policy documents and evaluate requests in your browser with the real policy engine from @better-iam/core.',
  path: '/playground',
  image: siteImages.playground,
  keywords: [
    'policy playground',
    'policy engine',
    'policy simulator',
    'access policy',
    'ABAC',
    'RBAC',
    'Better IAM',
    '@better-iam/core',
  ],
});

/** Inline links inside the lede: the lede's own size, underlined so they read as links in running text. */
const inlineLink =
  'inline text-[length:inherit] font-medium underline decoration-text-tertiary transition-colors hover:decoration-text-primary';

export default function PlaygroundPage() {
  return (
    <main className="relative flex flex-1 flex-col overflow-x-clip">
      <Band frameClassName="overflow-hidden">
        <div
          aria-hidden
          className="grid-lines pointer-events-none absolute inset-x-0 top-0 h-full"
        />
        <header
          className={cx('relative flex flex-col items-start pt-14 pb-12 md:pt-20 md:pb-14', gutter)}
        >
          <span className="animate-float-in inline-flex max-w-full items-center gap-2 rounded-2xl border border-border-button-default bg-background-primary-default py-1 ps-1 pe-3 text-caption-1-medium text-text-secondary shadow-xs sm:rounded-full">
            <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-text-primary text-background-full">
              <RiFlaskLine className="size-3" aria-hidden />
            </span>
            <span>
              Runs <code className="font-mono text-text-primary">evaluatePolicy</code> from{' '}
              <code className="font-mono text-text-primary">@better-iam/core</code> in your browser
            </span>
          </span>
          <h1 className="animate-blur-in mt-7 max-w-2xl text-display-4-semibold tracking-[-0.025em] text-balance [animation-delay:80ms] md:text-display-3-semibold md:leading-[1.12]">
            Policy playground
          </h1>
          <p className="animate-float-in mt-5 max-w-2xl text-headline-regular leading-7 text-pretty text-text-secondary [animation-delay:180ms] md:text-[1.0625rem]">
            Edit grant and boundary documents, describe a request, and watch the decision and its
            statement-by-statement trace update as you type. Nothing leaves this page; share a
            scenario with a link. Learn the model in{' '}
            <TextLink href="/docs/guides/authorization/policies" className={inlineLink}>
              Policies
            </TextLink>{' '}
            and{' '}
            <TextLink href="/docs/guides/authorization/conditions" className={inlineLink}>
              Conditions
            </TextLink>
            .
          </p>
        </header>
      </Band>

      <Band frameClassName="bg-surface-sunken" marks={false}>
        <div className={cx('animate-float-in py-8 [animation-delay:260ms] md:py-12', gutter)}>
          <PolicyPlayground />
        </div>
      </Band>
    </main>
  );
}
