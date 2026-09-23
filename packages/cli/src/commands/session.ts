import type { CallerIdentity } from '@better-iam/server';
import { CliError, usageError } from '../errors.js';
import {
  defineCommand,
  describeProfileTarget,
  type CommandContext,
  type FlagSpecs,
} from '../framework.js';
import { formatResult, type OutputFormat } from '../output.js';
import type { StoredProfile } from '../profiles.js';
import { localTransport, remoteTransport, sameEndpoint, type ApiTransport } from '../transport.js';

interface SignInResult {
  token?: string;
  session?: { expiresAt?: number };
  mfaRequired?: boolean;
  challenge?: string;
  enrollmentRequired?: boolean;
  emailCodeAvailable?: boolean;
}

async function ask(
  context: CommandContext<FlagSpecs>,
  question: string,
  hidden: boolean,
  missing: string,
): Promise<string> {
  if (!context.io.prompt)
    throw new CliError('MISSING_ENV', missing, 'Run it in a terminal, or set the variable.');
  const answer = (await context.io.prompt(question, { hidden })).trim();
  if (!answer) throw usageError(`${question.replace(/[:?]\s*$/, '')} is required`);
  return answer;
}

/** The deployment a saved profile belongs to, as a transport carrying its token (never any other deployment). */
async function profileTransport(
  context: CommandContext<FlagSpecs>,
  profile: StoredProfile,
): Promise<ApiTransport | undefined> {
  if (profile.url) return remoteTransport(profile.url, profile.token, context.io.fetch);
  if (profile.config)
    return localTransport(await context.open(profile.config), profile.config, profile.token);
  if (profile.envConfig)
    return localTransport(await context.open(), 'BETTER_IAM_DATABASE_URL', profile.token);
  return undefined;
}

type ProfileTarget = Pick<StoredProfile, 'url' | 'config' | 'envConfig'>;

/** Where this command's calls go, in the form a profile records it. */
async function targetOf(
  context: CommandContext<FlagSpecs>,
  transport: ApiTransport,
): Promise<ProfileTarget> {
  if (transport.mode === 'remote') return { url: transport.target };
  const where = await context.configPath();
  return where ? { config: where.path } : { envConfig: true };
}

function sameTarget(profile: ProfileTarget, target: ProfileTarget): boolean {
  if (target.url) return profile.url !== undefined && sameEndpoint(profile.url, target.url);
  if (target.config) return profile.config === target.config;
  return profile.envConfig === true && !profile.url && !profile.config;
}

export const sessionCommands = [
  defineCommand({
    name: 'login',
    group: 'Session',
    summary: 'Sign in once and save the session for later commands',
    description:
      'login signs in with an email and password (and an authenticator or emailed code when MFA is required) and saves the session in the credentials file as a profile (--profile, default the current profile or "default"; a profile that holds a session for another deployment is only replaced when named with --profile), so later token commands need no BETTER_IAM_TOKEN. The password comes from BETTER_IAM_PASSWORD or a hidden prompt and the code from BETTER_IAM_MFA_CODE or a prompt, never from flags. --with-token saves a token read from standard input instead (an API key for CI, or a session from elsewhere) after checking it. The profile remembers the server (--url) or configuration it was created with, and --tenant/--org sets the default tenant of later commands.',
    usage:
      'better-iam login [--config better-iam.config.mjs | --url URL] [--tenant TENANT_ID | --org SLUG] [--email EMAIL] [--email-code] [--with-token] [--profile NAME]',
    target: 'token',
    flags: {
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        env: 'BETTER_IAM_TENANT',
        description: 'Organization to sign in to',
      },
      org: {
        type: 'string',
        value: 'SLUG',
        description: 'Organization to sign in to, by its slug',
      },
      email: {
        type: 'string',
        value: 'EMAIL',
        env: 'BETTER_IAM_EMAIL',
        description: 'Account email (prompted when absent)',
      },
      'email-code': {
        type: 'boolean',
        description: 'Email a one-time code for MFA instead of using an authenticator',
      },
      'with-token': {
        type: 'boolean',
        description: 'Save a token read from standard input instead of signing in',
      },
    },
    examples: [
      'better-iam login --url https://iam.example.com --org acme --email me@acme.test',
      'echo "$API_KEY" | better-iam login --with-token --url https://iam.example.com --profile ci',
    ],
    // Only flags typed on the command line conflict; BETTER_IAM_TENANT / BETTER_IAM_EMAIL are defaults that yield.
    validate(_flags, _args, explicit) {
      if (explicit.has('tenant') && explicit.has('org'))
        throw usageError('Give --tenant or --org, not both');
      if (
        explicit.has('with-token') &&
        ['tenant', 'org', 'email', 'email-code'].some((name) => explicit.has(name))
      )
        throw usageError('--with-token takes no sign-in flags (the token names its tenant)');
    },
    async run(context) {
      const { flags, io, env, profiles } = context;
      const anonymous = await context.api({ authenticated: false });
      // Refuse before signing in, so a new session never silently replaces one saved for another deployment.
      const where = await targetOf(context, anonymous);
      const name = await profiles.currentName(flags.profile);
      const existing = await profiles.get(name);
      if (existing && !flags.profile && !sameTarget(existing, where))
        throw new CliError(
          'PROFILE_IN_USE',
          `Profile ${name} holds a session for ${describeProfileTarget(existing)}`,
          'Pass --profile NAME to save this session under another name, or run better-iam logout first.',
        );
      let token: string;
      let signedInEmail: string | undefined;
      if (flags['with-token']) {
        if (!io.stdin) throw usageError('--with-token reads the token from standard input');
        token = (await io.stdin()).trim();
        if (!token) throw usageError('Standard input held no token');
      } else {
        // --org is always typed on the command line, so it wins over a BETTER_IAM_TENANT default.
        let tenantId = flags.org ? undefined : flags.tenant;
        if (!tenantId) {
          const slug =
            flags.org ??
            (await ask(context, 'Organization (slug): ', false, 'Pass --tenant ID or --org SLUG'));
          tenantId = (await anonymous.call<{ tenantId: string }>('tenants/lookup', { slug }))
            .tenantId;
        }
        const email =
          flags.email ??
          (await ask(context, 'Email: ', false, 'Pass --email or set BETTER_IAM_EMAIL'));
        signedInEmail = email;
        const password =
          env.BETTER_IAM_PASSWORD ||
          (await ask(
            context,
            'Password: ',
            true,
            'Set BETTER_IAM_PASSWORD (passwords are never flags)',
          ));
        let result = await anonymous.call<SignInResult>('auth/signIn', {
          tenantId,
          email,
          password,
        });
        if (result.mfaRequired) {
          const challenge = result.challenge!;
          if (flags['email-code']) {
            if (!result.emailCodeAvailable)
              throw new CliError(
                'MFA_EMAIL_UNAVAILABLE',
                'This organization does not offer emailed codes',
              );
            await anonymous.call('auth/requestMfaCode', { tenantId, challenge });
            context.note(`A one-time code was sent to ${email}.`);
          } else if (result.enrollmentRequired)
            throw new CliError(
              'MFA_ENROLLMENT_REQUIRED',
              'This account must enroll an authenticator before it can sign in',
              result.emailCodeAvailable
                ? 'Enroll one in the console, or pass --email-code to receive a one-time code.'
                : 'Enroll one in the console first.',
            );
          const code =
            env.BETTER_IAM_MFA_CODE ||
            (await ask(
              context,
              flags['email-code'] ? 'Emailed code: ' : 'Authenticator code: ',
              false,
              'Set BETTER_IAM_MFA_CODE',
            ));
          result = await anonymous.call<SignInResult>('auth/verifyMfa', {
            tenantId,
            challenge,
            code,
          });
        }
        if (!result.token)
          throw new CliError('SIGN_IN_INCOMPLETE', 'Sign-in did not return a session');
        token = result.token;
      }
      const transport = await context.api({ token });
      const caller = await transport.call<CallerIdentity & Record<string, unknown>>(
        'sts/getCallerIdentity',
      );
      const expiresAt = typeof caller.expiresAt === 'number' ? caller.expiresAt : undefined;
      await profiles.save(name, {
        ...where,
        token,
        tenantId: caller.tenantId,
        identityId: caller.identityId,
        ...(signedInEmail ? { email: signedInEmail } : {}),
        ...(typeof caller.sessionKind === 'string' ? { kind: caller.sessionKind } : {}),
        ...(expiresAt !== undefined ? { expiresAt } : {}),
        savedAt: Date.now(),
      });
      return {
        profile: name,
        ...where,
        tenantId: caller.tenantId,
        identityId: caller.identityId,
        ...(expiresAt !== undefined ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
        credentials: profiles.path,
      };
    },
  }),
  defineCommand({
    name: 'logout',
    group: 'Session',
    summary: 'Sign out and forget a saved session',
    description:
      'logout signs a saved user session out on the server (best effort; API keys and other machine credentials saved with --with-token are only forgotten, never revoked) and removes the profile from the credentials file.',
    target: 'token',
    async run(context) {
      const { profiles, flags } = context;
      const name = await profiles.currentName(flags.profile);
      const saved = await profiles.get(name);
      if (!saved)
        throw new CliError(
          'NOT_FOUND',
          `No saved session named ${name}`,
          'Run better-iam profiles to list them.',
        );
      let revoked = false;
      if (!saved.kind || saved.kind === 'user') {
        try {
          const transport = await profileTransport(context, saved);
          if (transport) {
            await transport.call('auth/signOut');
            revoked = true;
          }
        } catch {
          /* An expired or already revoked session is gone either way. */
        }
      }
      await profiles.remove(name);
      return { profile: name, revoked, forgotten: true };
    },
  }),
  defineCommand({
    name: 'profiles',
    group: 'Session',
    summary: 'List saved sessions, or choose or remove one',
    description:
      'profiles lists the sessions saved by login (never their tokens) and marks the current one; profiles use NAME makes NAME current, and profiles remove NAME forgets one without signing it out.',
    usage: 'better-iam profiles [use NAME | remove NAME]',
    args: [
      { name: 'action', description: 'use or remove' },
      { name: 'name', description: 'The profile' },
    ],
    flags: {
      profile: {
        type: 'string',
        value: 'NAME',
        env: 'BETTER_IAM_PROFILE',
        hidden: true,
        description: 'Treat NAME as current',
      },
    },
    async run({ args, profiles, flags, io }) {
      const [action, name] = args;
      if (!action) {
        const list = await profiles.list(flags.profile);
        io.out(
          formatResult(
            list.map((entry) => ({
              ...entry,
              ...(entry.expiresAt ? { expiresAt: new Date(entry.expiresAt).toISOString() } : {}),
              savedAt: new Date(entry.savedAt).toISOString(),
            })),
            (flags.format as OutputFormat | undefined) ?? 'table',
            flags.query,
          ),
        );
        return;
      }
      if (!name || !['use', 'remove'].includes(action))
        throw usageError('Use: better-iam profiles, profiles use NAME, or profiles remove NAME');
      if (action === 'use') {
        await profiles.use(name);
        return { current: name };
      }
      if (!(await profiles.remove(name)))
        throw new CliError('NOT_FOUND', `No saved profile named ${name}`);
      return { removed: name };
    },
  }),
  defineCommand({
    name: 'token',
    group: 'Session',
    summary: 'Print the token commands act as, for scripts',
    description:
      "token prints the bearer token token commands would use (BETTER_IAM_TOKEN, else the saved profile's), for scripts and other tools: export BETTER_IAM_TOKEN=$(better-iam token). It is a secret; do not log it.",
    target: 'token',
    output: 'text',
    async run({ token }) {
      return token();
    },
  }),
];
