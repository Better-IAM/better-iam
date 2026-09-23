import { highlight } from 'fumadocs-core/highlight';
import { CodeTourView, type TourStep } from './code-tour-view';

/** Checked against the real APIs; keep lines under ~84 characters so the panel never scrolls sideways. */
const steps: (Omit<TourStep, 'code' | 'raw'> & { lang: string; source: string })[] = [
  {
    id: 'configure',
    title: 'Configure the instance',
    summary: 'Storage, the deployment secret, and the resource types your product protects.',
    file: 'lib/iam.ts',
    lang: 'ts',
    source: `import { betterIam } from 'better-iam';
import { postgresAdapter } from 'better-iam/adapter-postgres';

export const iam = betterIam({
  database: postgresAdapter({ connectionString: process.env.DATABASE_URL! }),
  secret: process.env.BETTER_IAM_SECRET!,
  baseURL: 'https://identity.example.com',
  permissions: {
    resourceTypes: {
      invoice: {
        actions: ['invoices:read', 'invoices:approve'],
        attributes: { amount: 'number' },
      },
    },
  },
});`,
  },
  {
    id: 'enforce',
    title: 'Enforce on the server',
    summary: 'One call right before the protected operation. Denials throw a typed 403.',
    file: 'routes/invoices.ts',
    lang: 'ts',
    source: `import { iam } from '@/lib/iam';

export async function approveInvoice(request: Request, invoice: Invoice) {
  // Throws ACCESS_DENIED (403) unless the caller may approve this invoice.
  await iam.require({
    headers: request.headers,
    tenantId: invoice.tenantId,
    action: 'invoices:approve',
    resource: { type: 'invoice', id: invoice.id },
  });

  // ...only reached when the decision allowed it
}`,
  },
  {
    id: 'pages',
    title: 'Guard pages and routes',
    summary: 'Framework guards redirect signed-out visitors and refuse members without access.',
    file: 'app/projects/page.tsx',
    lang: 'tsx',
    source: `import { createIamNext } from 'better-iam/next';
import { iam } from '@/lib/iam';

export const iamNext = createIamNext(iam, { loginPath: '/login' });

// Signed-out visitors go to /login; members without projects:read get a 403.
export default iamNext.page(
  async (props, { session }) => <Dashboard session={session} />,
  { authorize: { action: 'projects:read' } },
);`,
  },
  {
    id: 'ui',
    title: 'Render permission-aware UI',
    summary: 'Hooks and components batch advisory checks, so a page asks once.',
    file: 'components/team.tsx',
    lang: 'tsx',
    source: `import { useSession, Can } from 'better-iam/react';

export function Team({ tenantId }: { tenantId: string }) {
  const { session } = useSession();
  return (
    <section>
      <h2>Signed in as {session?.identity.name}</h2>
      {/* One batched, advisory decision for the whole page. */}
      <Can tenantId={tenantId} action="iam:identities:create">
        <InviteButton />
      </Can>
    </section>
  );
}`,
  },
  {
    id: 'policies',
    title: 'Write policies as data',
    summary: 'Versioned JSON with conditions and variables, evaluated on every request.',
    file: 'approve-own-region.json',
    lang: 'json',
    source: `{
  "version": 1,
  "statements": [
    {
      "sid": "ApproveInOwnRegion",
      "effect": "allow",
      "actions": ["invoices:approve"],
      "resources": ["invoice/*"],
      "conditions": {
        "StringEquals": { "resource.region": "\${principal.region}" },
        "NumericLessThanEquals": { "resource.amount": 50000 },
        "Bool": { "principal.mfa": true }
      }
    }
  ]
}`,
  },
  {
    id: 'nestjs',
    title: 'Decorate controllers',
    summary: 'The same checks as NestJS guards and decorators, resolved from route params.',
    file: 'projects.controller.ts',
    lang: 'ts',
    source: `import { IamModule, Authorize, CurrentIdentity } from 'better-iam/nestjs';

@Module({ imports: [IamModule.forRoot({ iam, guard: true, mount: true })] })
export class AppModule {}

@Controller('projects')
export class ProjectsController {
  @Post(':id/archive')
  @Authorize('projects:manage', { resource: { type: 'project', id: { param: 'id' } } })
  archive(@Param('id') id: string, @CurrentIdentity() identity: Identity) {
    return this.projects.archive(id, identity.id);
  }
}`,
  },
];

export async function CodeTour() {
  const rendered: TourStep[] = await Promise.all(
    steps.map(async ({ lang, source, ...step }) => ({
      ...step,
      raw: source,
      code: await highlight(source, {
        lang,
        themes: { light: 'github-light', dark: 'github-dark' },
        defaultColor: false,
      }),
    })),
  );
  return <CodeTourView steps={rendered} />;
}
