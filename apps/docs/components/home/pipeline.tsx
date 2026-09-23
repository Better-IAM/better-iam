import { highlight } from 'fumadocs-core/highlight';
import { RiArrowRightLine } from 'react-icons/ri';
import { TextLink } from '@/components/site/action';
import { Band, SectionHeading, gutter } from '@/components/site/frame';
import { codeThemes } from '@/lib/code-themes';
import { cx } from '@/utils/cx';
import { PipelineCarousel } from './pipeline-carousel';
import { Points } from './section';

const code = `// The caller's session cookie or bearer token.
const credential = { headers: request.headers };

await iam.api.identities.invite(credential, {
  tenantId,
  email: 'alice@acme.test',
  roleIds: [editorRoleId],
});`;

const points = [
  {
    lead: 'Nothing skips it.',
    body: 'A permission check, a revocation, or an audit rule cannot be bypassed by calling the API another way.',
  },
  {
    lead: 'No permission cache.',
    body: 'Tokens, roles, and policies are checked on every use, so a revocation applies to the very next request.',
  },
  {
    lead: 'All or nothing.',
    body: 'A change that breaks a rule rolls back whole, and nothing is emitted for it.',
  },
];

/** Chapter 01: one real API call and the pipeline it runs through (see "The request pipeline" in guides/concepts). */
export async function Pipeline() {
  const highlighted = await highlight(code, {
    lang: 'ts',
    themes: codeThemes,
    defaultColor: false,
  });
  return (
    <Band id="pipeline">
      <div className={cx('grid gap-10 py-16 md:py-20 lg:grid-cols-12', gutter)}>
        <SectionHeading
          index="01"
          eyebrow="Pipeline"
          title="Every call runs the same pipeline"
          className="lg:col-span-6"
        >
          Whether a call comes from a browser, a server action, the CLI, or a SCIM connector, it
          resolves its credential, re-validates inside a serialized transaction, is authorized,
          applies its change, and appends an audit event.
        </SectionHeading>
        <div className="flex flex-col gap-5 lg:col-span-5 lg:col-start-8 lg:pt-10">
          <Points points={points} />
          <TextLink href="/docs/guides/concepts" trailingIcon={RiArrowRightLine}>
            Read the architecture overview
          </TextLink>
        </div>
      </div>
      <PipelineCarousel code={highlighted} />
    </Band>
  );
}
