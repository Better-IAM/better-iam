import type { ComponentType } from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import {
  RiArrowRightLine,
  RiArrowRightUpLine,
  RiBookOpenLine,
  RiBracesLine,
  RiFlaskLine,
  RiLayoutGridLine,
  RiPlugLine,
  RiScales3Line,
  RiServerLine,
  RiVerifiedBadgeLine,
} from 'react-icons/ri';
import stats from '@/generated/stats.json';
import { AuditChain } from '@/components/home/audit-chain';
import { ChapterNav } from '@/components/home/chapter-nav';
import { CodeTour } from '@/components/home/code-tour';
import { CountUp } from '@/components/home/count-up';
import { DecisionDemo } from '@/components/home/decision-demo';
import { ElevationTimeline } from '@/components/home/elevation-timeline';
import { FederationMap } from '@/components/home/federation-map';
import { FrameworkStrip } from '@/components/home/framework-strip';
import { Hero } from '@/components/home/hero';
import { MotionProvider, Reveal } from '@/components/home/motion';
import { Pipeline } from '@/components/home/pipeline';
import { SplitExplainer, StackedExplainer } from '@/components/home/section';
import { SignInFlow } from '@/components/home/sign-in-flow';
import { TenantTree } from '@/components/home/tenant-tree';
import { LogoMark } from '@/components/logo';
import { ActionLink, TextLink } from '@/components/site/action';
import { CreatorCredit } from '@/components/site/creator-credit';
import { Band, SectionHeading, gutter } from '@/components/site/frame';
import { StaggerChild, StaggerList } from '@/components/site/motion-text';
import { JsonLd } from '@/components/json-ld';
import { pageMetadata, siteDescription, siteImages, siteJsonLd, siteTitle } from '@/lib/metadata';
import { cx } from '@/utils/cx';

type Icon = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>;

export const metadata: Metadata = pageMetadata({
  title: siteTitle,
  absolute: true,
  description: siteDescription,
  path: '/',
  image: siteImages.home,
});

export default function HomePage() {
  return (
    <MotionProvider>
      <main className="relative flex flex-1 flex-col overflow-x-clip">
        <JsonLd data={siteJsonLd()} />
        <Hero />
        <FrameworkStrip />
        {/* The chapter bar stays pinned only while the chapters (01 to 09) are on screen. */}
        <div>
          <ChapterNav />
          <Pipeline />

          <StackedExplainer
            id="build"
            index="02"
            eyebrow="Build"
            sunken
            title="One typed API, from the database to the button"
            lede="Configure one instance, enforce decisions on the server, and guard pages, routes, and UI in the framework you already use. Every call is typed end to end from that same instance."
            points={[
              {
                lead: 'Typed end to end.',
                body: 'Inputs, results, and errors come from one instance, on the server and in the browser client.',
              },
              {
                lead: 'Stable errors.',
                body: `Every failure carries one of ${stats.errorCodes} documented codes with its HTTP status.`,
              },
              {
                lead: 'Your framework.',
                body: 'Guards for Next.js, Nuxt, SvelteKit, React Router, and NestJS; middleware for Express, Hono, and Fastify.',
              },
            ]}
            href="/docs/guides/quickstart"
            linkLabel="Start the quickstart"
            visual={<CodeTour />}
          />

          <StackedExplainer
            id="sign-in"
            index="03"
            eyebrow="Sign-in"
            title="Every sign-in method, one session model"
            lede="Passwords with policy and history, passkeys, magic links, email and SMS codes, TOTP with recovery codes, and federated sign-in all end in the same kind of session, checked against each organization's own rules."
            points={[
              {
                lead: 'Per-organization policy.',
                body: 'Allowed methods, required MFA, session lifetime, idle timeout, and IP allowlists, set by each tenant.',
              },
              {
                lead: 'Trusted devices.',
                body: 'A remembered device can stand in for the second factor for as many days as the tenant allows.',
              },
              {
                lead: 'Visible to policies.',
                body: 'How someone signed in reaches every decision as principal.authMethod and principal.mfa.',
              },
            ]}
            href="/docs/guides/authentication"
            linkLabel="Read the authentication guide"
            visual={<SignInFlow />}
          />

          <StackedExplainer
            id="decisions"
            index="04"
            eyebrow="Decisions"
            sunken
            title="Decisions you can explain"
            lede="Roles, versioned JSON policies, and boundaries meet in one evaluator. Flip the switches: this is the real evaluator from @better-iam/core, running in your browser."
            points={[
              { lead: 'Deny wins.', body: 'A matching deny statement overrides every allow.' },
              {
                lead: 'Grants are a union.',
                body: 'One matching allow from any role or policy is enough.',
              },
              {
                lead: 'Boundaries only take away.',
                body: 'Each boundary is an independent ceiling. None of them ever grants.',
              },
              {
                lead: '21 condition operators.',
                body: 'With variables such as ${principal.id} and request context such as the source IP.',
              },
            ]}
            href="/docs/guides/authorization"
            linkLabel="How a decision is made"
            visual={<DecisionDemo />}
          />

          <SplitExplainer
            id="tenancy"
            index="05"
            eyebrow="Tenancy"
            reverse
            title="Tenants all the way down"
            lede="Mirror how your customers are organized: the platform at the root, organizations below it, and projects or workspaces below those. Every level is a full tenant with its own members and access model."
            points={[
              {
                lead: 'Isolated directories.',
                body: 'People belong to one tenant, and membership in a parent grants nothing in a child.',
              },
              {
                lead: 'Your hierarchy.',
                body: 'Define your own tenant types and depth, eight levels by default.',
              },
              {
                lead: 'Suspension cascades.',
                body: 'Suspend a tenant and its whole subtree stops, sessions included.',
              },
              {
                lead: 'Domains and limits.',
                body: 'Verified domains route people to their organization; plan limits cap usage.',
              },
            ]}
            href="/docs/guides/concepts/tenants-and-identities"
            linkLabel="Tenants and identities"
            visual={<TenantTree />}
          />

          <SplitExplainer
            id="elevation"
            index="06"
            eyebrow="Elevation"
            sunken
            title="Privileged access that expires on its own"
            lede="Make powerful roles eligible instead of standing. People activate them for a bounded time, with a reason, MFA, and approval when you require it, and the access ends by itself."
            points={[
              {
                lead: 'Two-person control.',
                body: 'An approver group or the requester’s manager decides. Nobody approves their own request.',
              },
              {
                lead: 'Access packages.',
                body: 'Bundle roles and groups into packages people request, or that rules assign automatically.',
              },
              {
                lead: 'Configuration as code.',
                body: 'Export, plan, and apply roles, policies, and bindings, with drift detection in CI.',
              },
            ]}
            href="/docs/guides/privileged-access/elevation"
            linkLabel="Just-in-time elevation"
            visual={<ElevationTimeline />}
          />

          <StackedExplainer
            id="audit"
            index="07"
            eyebrow="Audit"
            title="A record nobody can quietly rewrite"
            lede="Every operation, allowed or denied, appends an event to its tenant's SHA-256 hash chain. Try to change history below: the real verifier from @better-iam/core catches every attempt."
            points={[
              {
                lead: 'Verifiable anywhere.',
                body: 'verifyAuditChain runs on exported events, outside the server that wrote them.',
              },
              {
                lead: 'Export and archive.',
                body: 'JSON Lines export, and continuous archiving to storage you control.',
              },
              {
                lead: 'Signed webhooks.',
                body: 'After commit, events fan out to signed webhooks and in-process subscribers.',
              },
            ]}
            href="/docs/guides/events/audit-chain"
            linkLabel="How the audit chain works"
            visual={<AuditChain />}
          />

          <StackedExplainer
            id="federation"
            index="08"
            eyebrow="Federation"
            sunken
            title="Fluent in every enterprise identity protocol"
            lede="Sign people in with any OIDC or SAML identity provider, act as the OAuth provider for your own apps and MCP servers, provision users in and out with SCIM, and transmit Shared Signals."
            points={[
              {
                lead: 'Standards, not adapters.',
                body: 'OIDC, OAuth 2.0, SAML 2.0, SCIM 2.0, WebAuthn, DPoP, PAR, and RFC 8693 token exchange.',
              },
              {
                lead: 'Ready for MCP.',
                body: 'Dynamic client registration and protected resource metadata (RFC 9728) for AI agents.',
              },
              {
                lead: 'Enterprise onboarding.',
                body: 'Verified domains send people to their own company’s identity provider.',
              },
            ]}
            href="/docs/federation"
            linkLabel="Federation overview"
            visual={<FederationMap />}
          />

          <MoreSection />
          <ReferenceSection />
        </div>
        <FinalCta />
      </main>
    </MotionProvider>
  );
}

function MoreSection() {
  const cards: { icon: Icon; title: string; href: string; items: string[] }[] = [
    {
      icon: RiScales3Line,
      title: 'Governance',
      href: '/docs/guides/governance',
      items: [
        'Certification campaigns with reviewer suggestions',
        'Separation-of-duties rules, enforced on every grant',
        'Role mining and usage-based right-sizing',
        'Access invariants and change-impact previews',
        'Terms of use that people accept',
      ],
    },
    {
      icon: RiServerLine,
      title: 'Operations',
      href: '/docs/operations',
      items: [
        'PostgreSQL, SQLite, and libSQL adapters with migrations',
        'Prometheus metrics, health checks, and tracing spans',
        'Retention sweeps, snapshots, and secret rotation',
        `A CLI with ${stats.cliCommands} commands for jobs and diagnostics`,
      ],
    },
    {
      icon: RiPlugLine,
      title: 'Integrations',
      href: '/docs/frameworks',
      items: [
        'Next.js, Nuxt, SvelteKit, and React Router',
        'React and Vue hooks with batched checks',
        'NestJS guards and decorators',
        'Express, Hono, and Fastify middleware',
      ],
    },
  ];
  return (
    <Band id="more">
      <div className={cx('py-16 md:py-20', gutter)}>
        <SectionHeading eyebrow="And more" title="The rest of the platform">
          Governance, operations, and integrations share the same tenant model, the same pipeline,
          and the same audit log as everything above.
        </SectionHeading>
      </div>
      <StaggerList className="grid gap-px border-t border-separator-border bg-separator-border md:grid-cols-3">
        {cards.map(({ icon: CardIcon, ...card }) => (
          <li key={card.title} className="bg-background-full">
            <StaggerChild className="h-full">
              <Link href={card.href} className={cellLink}>
                <HoverHatch />
                <span className="relative flex items-center gap-3">
                  <IconTile icon={CardIcon} />
                  <span className="text-title-3-semibold">{card.title}</span>
                  <CellArrow className="ms-auto" />
                </span>
                <ul className="relative flex flex-col gap-2.5">
                  {card.items.map((item, index) => (
                    <li
                      key={item}
                      className="flex gap-2.5 text-body-regular leading-6 text-text-secondary transition-colors duration-300 group-hover:text-text-primary"
                      style={{ transitionDelay: `${index * 40}ms` }}
                    >
                      <span
                        aria-hidden
                        className="mt-[0.7rem] h-px w-2.5 shrink-0 bg-text-tertiary transition-[width,background-color] duration-300 group-hover:w-4 group-hover:bg-text-primary"
                        style={{ transitionDelay: `${index * 40}ms` }}
                      />
                      {item}
                    </li>
                  ))}
                </ul>
              </Link>
            </StaggerChild>
          </li>
        ))}
      </StaggerList>
    </Band>
  );
}

function ReferenceSection() {
  const numbers = [
    {
      value: stats.methods,
      label: 'typed API methods',
      detail: `in ${stats.groups} groups, with routes and signatures`,
      href: '/docs/reference/api',
    },
    {
      value: stats.errorCodes,
      label: 'stable error codes',
      detail: 'each with its HTTP status and meaning',
      href: '/docs/reference/errors',
    },
    {
      value: stats.cliCommands,
      label: 'CLI commands',
      detail: 'migrations, jobs, audits, and diagnostics',
      href: '/docs/reference/cli',
    },
    {
      value: stats.packages,
      label: 'packages',
      detail: `${stats.exports} runtime exports, from one umbrella package or only what you need`,
      href: '/docs/reference/packages',
    },
  ];
  const resources: [string, string][] = [
    ['OpenAPI 3.1 spec', '/openapi.json'],
    ['llms.txt', '/llms.txt'],
    ['Exports', '/docs/reference/exports'],
    ['Glossary', '/docs/reference/glossary'],
    ['Types', '/docs/reference/types'],
  ];
  return (
    <Band id="reference" frameClassName="bg-surface-sunken">
      <div className={cx('grid gap-8 py-16 md:py-20 lg:grid-cols-12', gutter)}>
        <SectionHeading
          index="09"
          eyebrow="Reference"
          title="Generated from the source"
          className="lg:col-span-6"
        >
          The reference is extracted from the repository every time this site is built, so every
          count and signature on it matches the code.
        </SectionHeading>
        <div className="flex flex-wrap content-end gap-2 lg:col-span-5 lg:col-start-8 lg:justify-end">
          {resources.map(([label, href]) => (
            <ActionLink
              key={href}
              href={href}
              variant="secondary"
              size="small"
              trailingIcon={RiArrowRightUpLine}
              className="font-mono text-caption-1-regular"
            >
              {label}
            </ActionLink>
          ))}
        </div>
      </div>
      <StaggerList className="grid gap-px border-t border-separator-border bg-separator-border sm:grid-cols-2 lg:grid-cols-4">
        {numbers.map((item) => (
          <li key={item.label} className="bg-surface-sunken">
            <StaggerChild className="h-full">
              <Link href={item.href} className={cx(cellLink, 'gap-2')}>
                <HoverHatch />
                <CountUp
                  value={item.value}
                  className="relative text-display-2-medium tracking-[-0.04em] tabular-nums transition-transform duration-300 ease-out group-hover:-translate-y-1"
                />
                <span className="relative text-body-medium">{item.label}</span>
                <span className="relative text-body-2-regular text-text-secondary">
                  {item.detail}
                </span>
                <CellArrow className="relative mt-3" />
              </Link>
            </StaggerChild>
          </li>
        ))}
      </StaggerList>
    </Band>
  );
}

function FinalCta() {
  const paths: { icon: Icon; title: string; body: string; href: string }[] = [
    {
      icon: RiBookOpenLine,
      title: 'Read the guides',
      body: 'Concepts first, then sign-in, decisions, and the access lifecycle.',
      href: '/docs/guides',
    },
    {
      icon: RiLayoutGridLine,
      title: 'Pick your framework',
      body: 'Full-stack, client, and server integrations.',
      href: '/docs/frameworks',
    },
    {
      icon: RiBracesLine,
      title: 'Browse the API',
      body: `${stats.methods} methods with routes and TypeScript signatures.`,
      href: '/docs/reference/api',
    },
    {
      icon: RiFlaskLine,
      title: 'Open the playground',
      body: 'Write policies and watch the engine decide.',
      href: '/playground',
    },
  ];
  return (
    <Band marks={false}>
      <div className="grid lg:grid-cols-2">
        <div
          className={cx(
            'relative flex flex-col items-start gap-6 overflow-hidden border-b border-separator-border py-16 md:py-20 lg:border-e lg:border-b-0',
            gutter,
          )}
        >
          <div
            aria-hidden
            className="hatch hatch-drift pointer-events-none absolute inset-0 opacity-60"
          />
          <Reveal className="relative flex flex-col items-start gap-6">
            <LogoMark className="size-10 text-text-primary" />
            <h2 className="max-w-md text-display-4-semibold tracking-[-0.03em] text-balance md:text-display-3-semibold md:leading-[1.12]">
              Own your identity layer, with the guarantees of a platform
            </h2>
            <p className="max-w-md text-headline-regular leading-7 text-pretty text-text-secondary">
              Start with SQLite on your laptop, ship on PostgreSQL, and keep every decision,
              session, and audit event in your own database.
            </p>
            <CreatorCredit label="Built and maintained by" />
            <div className="mt-2 flex flex-wrap gap-2.5">
              <ActionLink href="/docs/guides/quickstart" trailingIcon={RiArrowRightLine}>
                Start the quickstart
              </ActionLink>
              <ActionLink
                href="/docs/operations"
                variant="secondary"
                leadingIcon={RiVerifiedBadgeLine}
              >
                Production checklist
              </ActionLink>
            </div>
          </Reveal>
        </div>
        <StaggerList className="grid gap-px bg-separator-border sm:grid-cols-2">
          {paths.map(({ icon: PathIcon, ...path }) => (
            <li key={path.title} className="bg-background-full">
              <StaggerChild className="h-full">
                <Link href={path.href} className={cx(cellLink, 'gap-2')}>
                  <HoverHatch />
                  <IconTile icon={PathIcon} className="relative" />
                  <span className="relative mt-2 flex items-center gap-1.5 text-headline-medium">
                    {path.title}
                    <CellArrow />
                  </span>
                  <span className="relative text-body-regular leading-6 text-text-secondary">
                    {path.body}
                  </span>
                </Link>
              </StaggerChild>
            </li>
          ))}
        </StaggerList>
      </div>
      <p
        className={cx(
          'border-t border-separator-border py-5 text-body-regular text-text-secondary',
          gutter,
        )}
      >
        New to identity and access management?{' '}
        <TextLink
          href="/docs/guides/concepts"
          trailingIcon={RiArrowRightLine}
          className="inline-flex"
        >
          Start with the concepts
        </TextLink>
      </p>
    </Band>
  );
}

/** Grid cell links in the closing sections: full-cell hit area, press feedback, and a hatched hover fill. */
const cellLink =
  'group relative flex h-full flex-col gap-5 overflow-hidden p-6 transition-colors duration-200 hover:bg-background-secondary-default active:bg-background-secondary-hover sm:p-8';

function HoverHatch() {
  return (
    <span
      aria-hidden
      className="hatch pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100"
    />
  );
}

/** A BoardUI icon tile that inverts to solid ink when its cell is hovered. */
function IconTile({ icon: TileIcon, className }: { icon: Icon; className?: string }) {
  return (
    <span
      className={cx(
        'flex size-9 shrink-0 items-center justify-center rounded-2lg border border-border-button-default bg-background-primary-default text-foreground-icon-primary shadow-xs transition-[background-color,border-color,color,transform] duration-300 group-hover:-rotate-6 group-hover:border-text-primary group-hover:bg-text-primary group-hover:text-background-full',
        className,
      )}
    >
      <TileIcon className="size-[18px]" aria-hidden />
    </span>
  );
}

function CellArrow({ className }: { className?: string }) {
  return (
    <RiArrowRightLine
      className={cx(
        'size-4 shrink-0 text-foreground-icon-tertiary transition-[color,transform] duration-300 group-hover:translate-x-1 group-hover:text-foreground-icon-primary',
        className,
      )}
      aria-hidden
    />
  );
}
