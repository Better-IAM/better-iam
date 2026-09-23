import type { BetterIamOptions } from './options.js';
import type { TenantConfig } from './sync.js';

/** What a configuration factory receives when the `better-iam` CLI (or your code) calls it. */
export interface IamConfigContext {
  /** The CLI command being run (`migrate`, `api`, a project command); absent when your server calls the factory. */
  command?: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
}
/** A deployment configuration computed on demand, so importing the module has no side effects (no database opened). */
export type IamConfigFactory = (
  context?: IamConfigContext,
) => BetterIamOptions | Promise<BetterIamOptions>;

/**
 * Types a deployment configuration for `better-iam.config.{mjs,ts}`: options, or a factory of them that receives
 * `{ command, env, cwd }` from the CLI. It returns its argument unchanged; the value is autocompletion and checking.
 *
 * ```ts
 * export default defineConfig(({ env = process.env } = {}) => ({
 *   database: sqliteAdapter({ filename: env.BETTER_IAM_DATABASE ?? './iam.db' }),
 *   secret: env.BETTER_IAM_SECRET!,
 *   baseURL: env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
 * }));
 * // In the server: const iam = betterIam(await configOptions(config));
 * ```
 */
export function defineConfig(config: BetterIamOptions): BetterIamOptions;
export function defineConfig(factory: IamConfigFactory): IamConfigFactory;
export function defineConfig(
  config: BetterIamOptions | IamConfigFactory,
): BetterIamOptions | IamConfigFactory {
  return config;
}

/**
 * The options a `defineConfig` value stands for: a factory is called with `context` (default: this process's
 * environment and working directory), plain options are returned as they are.
 */
export async function configOptions(
  config: BetterIamOptions | IamConfigFactory,
  context: IamConfigContext = { env: process.env, cwd: process.cwd() },
): Promise<BetterIamOptions> {
  return typeof config === 'function' ? config(context) : config;
}

/** What a tenant-configuration factory receives from `config-plan` / `config-apply`. */
export interface TenantConfigFactoryContext {
  /** The tenant being planned or applied (`--tenant`). */
  tenantId?: string;
  env: NodeJS.ProcessEnv;
}

/**
 * Types a tenant's configuration as code (roles, policies, groups, bindings, packages, invariants, agreements) for
 * `better-iam config-plan|config-apply --input tenant.config.ts`, or a factory that computes it per tenant and
 * environment. Returns its argument unchanged; `iam.api.config.apply(credential, { tenantId, config })` applies the
 * same value from code.
 */
export function defineTenantConfig(config: TenantConfig): TenantConfig;
export function defineTenantConfig(
  factory: (context: TenantConfigFactoryContext) => TenantConfig | Promise<TenantConfig>,
): (context: TenantConfigFactoryContext) => TenantConfig | Promise<TenantConfig>;
export function defineTenantConfig(
  config:
    | TenantConfig
    | ((context: TenantConfigFactoryContext) => TenantConfig | Promise<TenantConfig>),
): unknown {
  return config;
}
