import { highlight } from 'fumadocs-core/highlight';
import { PipelineStory } from './pipeline-story';

/**
 * The Pipeline chapter: one real API call next to the pipeline it runs through (see "The request pipeline" in
 * guides/concepts). The code is highlighted on the server; the trace and the scroll story run on the client.
 */
const code = `// The caller's session cookie or bearer token.
const credential = { headers: request.headers };

await iam.api.identities.invite(credential, {
  tenantId,
  email: 'alice@acme.test',
  roleIds: [editorRoleId],
});`;

export async function RequestTrace() {
  const highlighted = await highlight(code, {
    lang: 'ts',
    themes: { light: 'github-light', dark: 'github-dark' },
    defaultColor: false,
  });
  return <PipelineStory code={highlighted} />;
}
