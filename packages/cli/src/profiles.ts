import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { CliError, usageError } from './errors.js';

/**
 * A signed-in session saved by `better-iam login`, so later commands act as it without `BETTER_IAM_TOKEN`. It
 * belongs to one deployment: a remote endpoint (`url`) or the configuration it was created with (`config`).
 */
export interface StoredProfile {
  /** The IAM endpoint (`https://host/api/iam`) the session was issued by, for remote commands. */
  url?: string;
  /** The configuration module the session was issued through, for in-process commands. */
  config?: string;
  /** The session was issued through the environment-only deployment (`BETTER_IAM_DATABASE_URL`, no file). */
  envConfig?: boolean;
  tenantId?: string;
  identityId?: string;
  email?: string;
  /** Session kind: `user`, `api-key`, `role`, or `session-token`. */
  kind?: string;
  /** The bearer token. The file is written with owner-only permissions; treat it like a password. */
  token: string;
  /** When the session ends (epoch ms), when known. */
  expiresAt?: number;
  savedAt: number;
}

/** A profile as listed by `better-iam profiles`: everything except the token. */
export type ProfileSummary = Omit<StoredProfile, 'token'> & { name: string; current: boolean };

interface CredentialsFile {
  version: 1;
  current?: string;
  profiles: Record<string, StoredProfile>;
}

const profileName = /^[A-Za-z0-9._-]{1,64}$/;
export const defaultProfile = 'default';

/**
 * Where saved sessions live: `BETTER_IAM_CREDENTIALS`, else `%APPDATA%\better-iam\credentials.json` on Windows, else
 * `$XDG_CONFIG_HOME/better-iam/credentials.json` or `~/.config/better-iam/credentials.json`. Read only from the
 * given environment, so an embedding program (and every test) decides whether a profile can be found at all.
 */
export function credentialsPath(env: NodeJS.ProcessEnv): string | undefined {
  if (env.BETTER_IAM_CREDENTIALS) return resolve(env.BETTER_IAM_CREDENTIALS);
  if (process.platform === 'win32' && env.APPDATA)
    return join(env.APPDATA, 'better-iam', 'credentials.json');
  const home = env.HOME || env.USERPROFILE;
  const base = env.XDG_CONFIG_HOME || (home ? join(home, '.config') : undefined);
  return base ? join(base, 'better-iam', 'credentials.json') : undefined;
}

export function assertProfileName(name: string): string {
  if (!profileName.test(name))
    throw usageError('Profile names use letters, digits, dot, dash, and underscore (at most 64)');
  return name;
}

/** Reads and writes the saved-session file. Every write replaces the file atomically with mode 0600. */
export interface ProfileStore {
  /** The file in use, or undefined when the environment names no home or config directory. */
  readonly path: string | undefined;
  /** `--profile`, else `BETTER_IAM_PROFILE`, else the file's current profile, else `default`. */
  currentName(explicit?: string): Promise<string>;
  get(name: string): Promise<StoredProfile | undefined>;
  list(explicit?: string): Promise<ProfileSummary[]>;
  save(name: string, profile: StoredProfile, makeCurrent?: boolean): Promise<void>;
  remove(name: string): Promise<boolean>;
  use(name: string): Promise<void>;
}

/**
 * Opens the saved-session file that `login`, `logout`, `profiles`, and token commands use, located from `env` (see
 * `credentialsPath`), so tools can list, save, or switch profiles the same way the CLI does.
 */
export function createProfileStore(env: NodeJS.ProcessEnv): ProfileStore {
  const path = credentialsPath(env);
  const read = async (): Promise<CredentialsFile> => {
    if (!path) return { version: 1, profiles: {} };
    let raw: string;
    try {
      raw = await readFile(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, profiles: {} };
      throw error;
    }
    try {
      const parsed = JSON.parse(raw) as CredentialsFile;
      if (parsed?.version !== 1 || !parsed.profiles || typeof parsed.profiles !== 'object')
        throw new Error('shape');
      return {
        version: 1,
        ...(typeof parsed.current === 'string' ? { current: parsed.current } : {}),
        profiles: Object.assign(Object.create(null), parsed.profiles),
      };
    } catch {
      throw new CliError(
        'INVALID_CREDENTIALS_FILE',
        `${path} is not a Better IAM credentials file`,
        'Delete it or point BETTER_IAM_CREDENTIALS at another file, then run better-iam login.',
      );
    }
  };
  const write = async (file: CredentialsFile): Promise<void> => {
    if (!path)
      throw new CliError(
        'NO_CREDENTIALS_FILE',
        'No place to save sessions: HOME, APPDATA, and XDG_CONFIG_HOME are all unset',
        'Set BETTER_IAM_CREDENTIALS to a file path.',
      );
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temporary = `${path}.${randomBytes(6).toString('hex')}.tmp`;
    try {
      await writeFile(temporary, JSON.stringify(file, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      await rename(temporary, path);
      await chmod(path, 0o600).catch(() => undefined);
    } catch (error) {
      await rm(temporary, { force: true }).catch(() => undefined);
      throw error;
    }
  };
  const currentName = async (explicit?: string) =>
    assertProfileName(
      explicit || env.BETTER_IAM_PROFILE || (await read()).current || defaultProfile,
    );
  return {
    path,
    currentName,
    async get(name) {
      const file = await read();
      return Object.hasOwn(file.profiles, name) ? file.profiles[name] : undefined;
    },
    async list(explicit) {
      const file = await read();
      const current = await currentName(explicit);
      return Object.entries(file.profiles)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, { token: _token, ...rest }]) => ({
          name,
          current: name === current,
          ...rest,
        }));
    },
    async save(name, profile, makeCurrent = true) {
      assertProfileName(name);
      const file = await read();
      file.profiles[name] = profile;
      if (makeCurrent) file.current = name;
      await write(file);
    },
    async remove(name) {
      const file = await read();
      if (!Object.hasOwn(file.profiles, name)) return false;
      delete file.profiles[name];
      if (file.current === name) delete file.current;
      await write(file);
      return true;
    },
    async use(name) {
      const file = await read();
      if (!Object.hasOwn(file.profiles, assertProfileName(name)))
        throw new CliError(
          'NOT_FOUND',
          `No saved profile named ${name}`,
          'Run better-iam profiles to list them.',
        );
      file.current = name;
      await write(file);
    },
  };
}
