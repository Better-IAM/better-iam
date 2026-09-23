import { getIam } from '@/lib/iam';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** The public keys agents' A2A cards are signed with (`a2a.jwksUrl`), for other agents verifying those cards. */
export async function GET(): Promise<Response> {
  return (await getIam()).a2a.jwksResponse();
}
