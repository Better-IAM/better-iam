import type { ReactNode } from 'react';
import Link from 'next/link';
import {
  ArrowRight,
  BadgeCheck,
  Blocks,
  BookOpen,
  FlaskConical,
  Link2,
  Scale,
  Server,
  Workflow,
} from 'lucide-react';
import stats from '@/generated/stats.json';
import { AuditChain } from '@/components/home/audit-chain';
import { ChapterNav } from '@/components/home/chapter-nav';
import { CodeTour } from '@/components/home/code-tour';
import { CountUp } from '@/components/home/count-up';
import { DecisionDemo } from '@/components/home/decision-demo';
import { ElevationTimeline } from '@/components/home/elevation-timeline';
import { FederationMap } from '@/components/home/federation-map';
import { HeroShowcase } from '@/components/home/hero-showcase';
import { InstallCommand } from '@/components/home/install-command';
import { MotionProvider, Reveal } from '@/components/home/motion';
import { RequestTrace } from '@/components/home/request-trace';
import {
  Container,
  GuideLink,
  Section,
  SectionHeader,
  SplitExplainer,
  StackedExplainer,
} from '@/components/home/section';
import { SignInFlow } from '@/components/home/sign-in-flow';
import { SiteFooter } from '@/components/home/site-footer';
import { TenantTree } from '@/components/home/tenant-tree';
import { LogoMark } from '@/components/logo';
import { version } from '@/lib/shared';

const frameworks = [
  ['Next.js', '/docs/frameworks/nextjs'],
  ['React', '/docs/frameworks/react'],
  ['Vue', '/docs/frameworks/vue'],
  ['Nuxt', '/docs/frameworks/nuxt'],
  ['SvelteKit', '/docs/frameworks/sveltekit'],
  ['React Router', '/docs/frameworks/react-router'],
  ['NestJS', '/docs/frameworks/nestjs'],
  ['Express', '/docs/frameworks/node'],
  ['Hono', '/docs/frameworks/node'],
  ['Fastify', '/docs/frameworks/node'],
] as const;

export default function HomePage() {
  return (
    <MotionProvider>
      <main className="landing relative flex flex-1 flex-col overflow-x-clip">
        <Hero />
        <FrameworkStrip />
        <ChapterNav />

        <StackedExplainer
          id="pipeline"
          eyebrow="01 · Pipeline"
          title="Every call runs the same pipeline"
          lede="Whether a call comes from a browser, a server action, the CLI, or a SCIM connector, it resolves its credential, re-validates inside a serialized transaction, is authorized, applies its change, and appends an audit event."
          points={[
            {
              lead: 'Nothing skips it.',
              body: 'A permission check, a revocation, or an audit rule in the pipeline cannot be bypassed by calling the API another way.',
            },
            {
              lead: 'No permission cache.',
              body: 'Tokens, roles, and policies are checked on every use, so a revocation applies to the very next request.',
            },
            {
              lead: 'All or nothing.',
              body: 'A change that breaks a rule rolls back whole, and nothing is emitted for it.',
            },
          ]}
          href="/docs/guides/concepts"
          linkLabel="Read the architecture overview"
          visual={<RequestTrace />}
        />

        <StackedExplainer
          id="build"
          className="border-y bg-fd-card/40"
          eyebrow="02 · Build"
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
          eyebrow="03 · Sign-in"
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
          className="border-y bg-fd-card/40"
          eyebrow="04 · Decisions"
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
          reverse
          eyebrow="05 · Tenancy"
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
          className="border-y bg-fd-card/40"
          eyebrow="06 · Elevation"
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
          eyebrow="07 · Audit"
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
          className="border-y bg-fd-card/40"
          eyebrow="08 · Federation"
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
        <FinalCta />
      </main>
      <SiteFooter />
    </MotionProvider>
  );
}

function Hero() {
  return (
    <section className="relative isolate">
      {/* Backdrop: a masked grid, two slow aurora lights, and film grain so the gradients never band. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[56rem] overflow-hidden"
      >
        <div className="bg-grid hero-grid-mask absolute inset-0 opacity-60" />
        <div className="aurora aurora-a absolute right-[-10rem] top-[-12rem] h-[34rem] w-[46rem] rounded-full" />
        <div className="aurora aurora-b absolute left-[-14rem] top-[8rem] h-[26rem] w-[38rem] rounded-full" />
        <div className="grain absolute inset-0" />
      </div>

      <Container className="pb-20 pt-12 md:pb-28 md:pt-20">
        <HeroShowcase
          intro={
            <div className="flex flex-col items-start">
              <Link
                href="/docs/reference/changelog"
                className="animate-float-in inline-flex items-center gap-2 rounded-full border bg-fd-card/80 py-1 pe-3 ps-1 text-xs text-fd-muted-foreground backdrop-blur transition-colors hover:text-fd-foreground"
              >
                <span className="rounded-full bg-fd-primary/10 px-2 py-0.5 font-mono font-medium text-fd-primary">
                  v{version}
                </span>
                Read the changelog
                <ArrowRight className="size-3" />
              </Link>
              <h1 className="animate-blur-in mt-7 text-[2.25rem] font-semibold leading-[1.04] tracking-[-0.04em] [animation-delay:80ms] sm:text-[3.25rem] xl:text-[3.375rem]">
                Identity and access management{' '}
                <span className="text-gradient">that lives in your codebase</span>
              </h1>
              <p className="animate-float-in mt-6 max-w-xl text-pretty text-base leading-7 text-fd-muted-foreground [animation-delay:260ms] md:text-[1.0625rem] md:leading-8">
                Better IAM is an embeddable TypeScript platform for multi-tenant authentication,
                fine-grained authorization, access governance, and enterprise federation. It runs in
                your process, on your database, behind one typed API.
              </p>
              <div className="animate-float-in mt-8 flex flex-wrap items-center gap-3 [animation-delay:320ms]">
                <Link
                  href="/docs/guides/quickstart"
                  className="btn-primary inline-flex h-11 items-center gap-2 rounded-xl px-5 text-sm font-medium"
                >
                  Get started <ArrowRight className="size-4" />
                </Link>
                <InstallCommand />
              </div>
              <p className="animate-float-in mt-5 text-xs text-fd-muted-foreground [animation-delay:380ms]">
                Node.js 22.12+ <Dot /> PostgreSQL, SQLite, or libSQL <Dot /> ESM with TypeScript
                types
              </p>
            </div>
          }
        />
      </Container>
    </section>
  );
}

function Dot() {
  return (
    <span className="mx-1.5 inline-block size-[3px] rounded-full bg-fd-muted-foreground/50 align-middle" />
  );
}

function FrameworkStrip() {
  return (
    <div className="pb-12 md:pb-16">
      <Container className="flex flex-col items-center gap-4">
        <p className="eyebrow eyebrow-muted">Works with the stack you already run</p>
        <ul className="flex flex-wrap items-center justify-center gap-x-1 gap-y-1">
          {frameworks.map(([name, href], index) => (
            <li key={name}>
              <Reveal delay={index * 0.04}>
                <Link
                  href={href}
                  className="rounded-lg px-3 py-1.5 text-[0.9375rem] font-medium text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
                >
                  {name}
                </Link>
              </Reveal>
            </li>
          ))}
        </ul>
      </Container>
    </div>
  );
}

function MoreSection() {
  return (
    <Section id="more">
      <SectionHeader eyebrow="And more" title="The rest of the platform">
        Governance, operations, and integrations share the same tenant model, the same pipeline, and
        the same audit log as everything above.
      </SectionHeader>
      <div className="mt-12 grid gap-4 md:grid-cols-3">
        <MoreCard
          icon={<Scale />}
          title="Governance"
          href="/docs/guides/governance"
          items={[
            'Certification campaigns with reviewer suggestions',
            'Separation-of-duties rules, enforced on every grant',
            'Role mining and usage-based right-sizing',
            'Access invariants and change-impact previews',
            'Terms of use that people accept',
          ]}
        />
        <MoreCard
          icon={<Server />}
          title="Operations"
          href="/docs/operations"
          items={[
            'PostgreSQL, SQLite, and libSQL adapters with migrations',
            'Prometheus metrics, health checks, and tracing spans',
            'Retention sweeps, snapshots, and secret rotation',
            `A CLI with ${stats.cliCommands} commands for jobs and diagnostics`,
          ]}
        />
        <MoreCard
          icon={<Workflow />}
          title="Integrations"
          href="/docs/frameworks"
          items={[
            'Next.js, Nuxt, SvelteKit, and React Router',
            'React and Vue hooks with batched checks',
            'NestJS guards and decorators',
            'Express, Hono, and Fastify middleware',
          ]}
        />
      </div>
    </Section>
  );
}

function MoreCard({
  icon,
  title,
  href,
  items,
}: {
  icon: ReactNode;
  title: string;
  href: string;
  items: string[];
}) {
  return (
    <Reveal>
      <Link
        href={href}
        className="group flex h-full flex-col gap-5 rounded-2xl border bg-fd-card p-6 transition-colors hover:border-fd-primary/40"
      >
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-xl border bg-fd-card text-fd-primary [&_svg]:size-[1.125rem]">
            {icon}
          </span>
          <h3 className="text-lg font-medium">{title}</h3>
          <ArrowRight className="ms-auto size-4 text-fd-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:text-fd-foreground" />
        </div>
        <ul className="flex flex-col gap-2.5">
          {items.map((item) => (
            <li key={item} className="flex gap-2.5 text-sm leading-6 text-fd-muted-foreground">
              <span aria-hidden className="mt-[0.6875rem] h-px w-2.5 shrink-0 bg-fd-primary/70" />
              {item}
            </li>
          ))}
        </ul>
      </Link>
    </Reveal>
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
    <Section id="reference">
      <div className="grid gap-8 lg:grid-cols-2 lg:gap-16">
        <SectionHeader eyebrow="09 · Reference" title="Generated from the source">
          The reference is extracted from the repository every time this site is built, so every
          count and signature on it matches the code.
        </SectionHeader>
        <div className="flex flex-wrap content-end gap-2 lg:justify-end">
          {resources.map(([label, href]) => (
            <a
              key={href}
              href={href}
              className="inline-flex h-9 items-center gap-2 rounded-lg border bg-fd-card px-3 font-mono text-xs text-fd-muted-foreground transition-colors hover:border-fd-primary/40 hover:text-fd-foreground"
            >
              {label}
              <ArrowRight className="size-3" />
            </a>
          ))}
        </div>
      </div>
      <div className="mt-12 grid gap-px overflow-hidden rounded-2xl border bg-fd-border sm:grid-cols-2 lg:grid-cols-4">
        {numbers.map((item) => (
          <Link
            key={item.label}
            href={item.href}
            className="group flex flex-col gap-2 bg-fd-card p-6 transition-colors hover:bg-fd-accent/60"
          >
            <CountUp
              value={item.value}
              className="text-4xl font-normal tabular-nums tracking-tight text-fd-foreground md:text-5xl"
            />
            <span className="text-sm font-medium">{item.label}</span>
            <span className="text-[0.8125rem] leading-5 text-fd-muted-foreground">
              {item.detail}
            </span>
            <ArrowRight className="mt-2 size-4 text-fd-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:text-fd-primary" />
          </Link>
        ))}
      </div>
    </Section>
  );
}

function FinalCta() {
  const paths = [
    {
      icon: <BookOpen />,
      title: 'Read the guides',
      body: 'Concepts first, then sign-in, decisions, and the access lifecycle.',
      href: '/docs/guides',
    },
    {
      icon: <Blocks />,
      title: 'Pick your framework',
      body: 'Full-stack, client, and server integrations.',
      href: '/docs/frameworks',
    },
    {
      icon: <Link2 />,
      title: 'Browse the API',
      body: `${stats.methods} methods with routes and TypeScript signatures.`,
      href: '/docs/reference/api',
    },
    {
      icon: <FlaskConical />,
      title: 'Open the playground',
      body: 'Write policies and watch the engine decide.',
      href: '/playground',
    },
  ];
  return (
    <Section className="pt-4 md:pt-8">
      <div className="relative overflow-hidden rounded-3xl border bg-fd-card">
        <div
          aria-hidden
          className="bg-grid mask-radial pointer-events-none absolute inset-0 opacity-40"
        />
        <div className="relative grid gap-10 p-8 md:p-12 lg:grid-cols-2 lg:gap-14">
          <div className="flex flex-col items-start gap-5">
            <LogoMark className="size-10 text-fd-primary" />
            <h2 className="text-balance text-3xl font-medium leading-[1.12] tracking-tight md:text-[2.5rem]">
              Own your identity layer, with the guarantees of a platform
            </h2>
            <p className="max-w-md text-pretty leading-7 text-fd-muted-foreground">
              Start with SQLite on your laptop, ship on PostgreSQL, and keep every decision,
              session, and audit event in your own database.
            </p>
            <div className="mt-2 flex flex-wrap gap-3">
              <Link
                href="/docs/guides/quickstart"
                className="btn-primary inline-flex h-11 items-center gap-2 rounded-xl px-5 text-sm font-medium"
              >
                Start the quickstart <ArrowRight className="size-4" />
              </Link>
              <Link
                href="/docs/operations"
                className="inline-flex h-11 items-center gap-2 rounded-xl border bg-fd-background px-5 text-sm font-medium transition-colors hover:bg-fd-accent"
              >
                <BadgeCheck className="size-4 text-fd-primary" /> Production checklist
              </Link>
            </div>
          </div>
          <ul className="grid gap-3 sm:grid-cols-2">
            {paths.map((path) => (
              <li key={path.title}>
                <Link
                  href={path.href}
                  className="group flex h-full flex-col gap-2 rounded-2xl border bg-fd-background/80 p-5 backdrop-blur transition-colors hover:border-fd-primary/40"
                >
                  <span className="text-fd-primary [&_svg]:size-5">{path.icon}</span>
                  <span className="flex items-center gap-1.5 font-medium">
                    {path.title}
                    <ArrowRight className="size-3.5 text-fd-muted-foreground transition-transform group-hover:translate-x-0.5" />
                  </span>
                  <span className="text-sm leading-6 text-fd-muted-foreground">{path.body}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <p className="mt-8 text-center text-sm text-fd-muted-foreground">
        New to identity and access management?{' '}
        <GuideLink href="/docs/guides/concepts">Start with the concepts</GuideLink>
      </p>
    </Section>
  );
}
