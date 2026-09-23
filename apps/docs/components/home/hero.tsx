import { Fragment } from 'react';
import Link from 'next/link';
import { highlight } from 'fumadocs-core/highlight';
import { RiArrowRightLine, RiArrowRightUpLine } from 'react-icons/ri';
import { ActionLink } from '@/components/site/action';
import { Band, gutter } from '@/components/site/frame';
import { codeThemes } from '@/lib/code-themes';
import { version } from '@/lib/shared';
import { cx } from '@/utils/cx';
import { CreatorCredit } from '@/components/site/creator-credit';
import { WordReveal } from '@/components/site/motion-text';
import { HeroGrid } from './hero-grid';
import { HeroWindow } from './hero-window';
import { InstallCommand } from './install-command';

/** Checked against the real APIs (guides/authentication/passkeys, the code tour, and @better-iam/core). */
const snippets = [
  `import { startAuthentication } from 'better-iam/client/passkeys';

const { challengeId, options } =
  await client.auth.beginPasskeyAuthentication({
    tenantId,
    email: 'olivia@acme.test',
  });
const response = await startAuthentication({
  optionsJSON: options,
});

// The session has already passed MFA.
await client.auth.finishPasskeyAuthentication({
  tenantId,
  challengeId,
  response,
});`,
  `// Authorized as iam:identities:create on iam/{tenantId}.
await iam.api.identities.invite(
  { headers: request.headers },
  { tenantId, email: 'alice@acme.test' },
);

// Your own actions go through the same evaluator.
await iam.require({
  headers: request.headers,
  tenantId,
  action: 'invoices:approve',
  resource: { type: 'invoice', id: invoice.id },
});`,
  `import { verifyAuditChain } from '@better-iam/core';

// Every operation appended an event to the tenant's
// SHA-256 hash chain. Verify an export anywhere,
// without the server that wrote it.
const result = await verifyAuditChain(events);

// → { valid: true, checked: 3 }`,
];

export async function Hero() {
  // Keyed, because the array itself crosses to the client component.
  const code = await Promise.all(
    snippets.map(async (source, index) => (
      <Fragment key={index}>
        {await highlight(source, { lang: 'ts', themes: codeThemes, defaultColor: false })}
      </Fragment>
    )),
  );

  return (
    <Band frameClassName="overflow-hidden">
      <HeroGrid />

      <div className={cx('relative pt-14 pb-12 md:pt-20 md:pb-14', gutter)}>
        <Link
          href="/docs/reference/changelog"
          className="animate-float-in group inline-flex items-center gap-2 rounded-full border border-border-button-default bg-background-primary-default py-1 ps-1 pe-3 text-caption-1-medium text-text-secondary shadow-xs transition-colors hover:border-border-button-hover hover:text-text-primary"
        >
          <span className="rounded-full bg-text-primary px-2 py-0.5 font-mono text-background-full">
            v{version}
          </span>
          Read the changelog
          <RiArrowRightLine
            className="size-3.5 transition-transform group-hover:translate-x-0.5"
            aria-hidden
          />
        </Link>

        <h1 className="mt-7 max-w-[15ch] text-[2.5rem] leading-[1.04] font-semibold tracking-[-0.045em] text-balance sm:text-[3.5rem] lg:max-w-[17ch] lg:text-[4.5rem]">
          <WordReveal text="Identity and access management" immediate delay={0.08} />{' '}
          <WordReveal
            text="that lives in your codebase"
            immediate
            delay={0.26}
            className="text-text-secondary"
          />
        </h1>

        <div className="mt-10 grid gap-8 lg:grid-cols-12 lg:items-end">
          <div className="animate-float-in flex flex-col gap-5 [animation-delay:220ms] lg:col-span-6">
            <p className="text-headline-regular leading-7 text-pretty text-text-secondary md:text-[1.0625rem]">
              Better IAM is an embeddable TypeScript platform for multi-tenant authentication,
              fine-grained authorization, access governance, and enterprise federation. It runs in
              your process, on your database, behind one typed API.
            </p>
            <CreatorCredit />
          </div>
          <div className="animate-float-in flex flex-col gap-4 [animation-delay:300ms] lg:col-span-6 lg:col-start-7 lg:items-end">
            <div className="flex flex-wrap items-center gap-2.5 lg:justify-end">
              <ActionLink href="/docs/guides/quickstart" trailingIcon={RiArrowRightLine}>
                Get started
              </ActionLink>
              <InstallCommand />
              <ActionLink
                href="/playground"
                variant="ghost"
                trailingIcon={RiArrowRightUpLine}
                className="bg-transparent"
              >
                Playground
              </ActionLink>
            </div>
            <p className="text-caption-1-regular text-text-secondary">
              Node.js 22.12+ <Dot /> PostgreSQL, SQLite, or libSQL <Dot /> ESM with TypeScript types
            </p>
          </div>
        </div>
      </div>

      <div className={cx('relative pb-10 md:pb-14', gutter)}>
        <HeroWindow code={code} />
      </div>
    </Band>
  );
}

function Dot() {
  return (
    <span className="mx-1.5 inline-block size-[3px] rounded-full bg-text-tertiary align-middle" />
  );
}
