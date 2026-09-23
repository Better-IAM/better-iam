import { docsLlms } from '@/lib/source';
import { appDescription, appName, creator } from '@/lib/shared';

export const revalidate = false;

export async function GET() {
  const header = `# ${appName}\n\n> ${appDescription} Created by ${creator}.\n\n`;
  return new Response(header + (await docsLlms.full()), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
