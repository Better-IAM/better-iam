import { authenticator } from 'otplib';

/** Demo tenant and member, created once when DEMO_SEED=1. The root TOTP secret is discarded: never do this for real. */
export const demo: { tenantId?: string } = {};

export default defineNitroPlugin(async () => {
  if (process.env.DEMO_SEED !== '1') return;
  const iam = await useIam();
  const password = 'demo root password for the nuxt example';
  let tenantId: string;
  try {
    const root = await iam.bootstrap({ email: 'root@example.test', name: 'Root', password });
    tenantId = root.tenant.id;
  } catch (error) {
    if ((error as { code?: string }).code !== 'ALREADY_INITIALIZED') throw error;
    return;
  }
  const challenge = await iam.api.auth.signIn({ tenantId, email: 'root@example.test', password });
  if (!('mfaRequired' in challenge)) throw new Error('Root sign-in must require MFA');
  const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  await iam.api.identities.create(
    { token: session.token },
    {
      tenantId,
      email: 'member@example.test',
      name: 'Mia Member',
      password: 'demo member password for nuxt',
    },
  );
  demo.tenantId = tenantId;
});
