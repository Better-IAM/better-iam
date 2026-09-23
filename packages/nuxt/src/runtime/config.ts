/** The public runtime config the module writes under `runtimeConfig.public.betterIam`. */
export interface IamPublicConfig {
  apiPath: string;
  loginPath: string;
  /** Every route needs a session unless its page meta sets `iam: false`. */
  requireAuth: boolean;
  /** Load the session during server rendering so the first paint is authenticated. */
  ssrSession: boolean;
  /** Query parameter that carries the original path to the login page (empty string disables it). */
  nextParam: string;
}

export interface IamRouteLike {
  path: string;
  fullPath: string;
  params: Record<string, unknown>;
  query: Record<string, unknown>;
  meta: Record<string, unknown>;
}
export interface IamResourceRef {
  type: string;
  id: string;
}

/**
 * Page-level access declared with `definePageMeta({ iam: … })`: `false` opts a page out of `requireAuth`, `true` needs a
 * session, and an object needs a session plus an advisory decision (the server still enforces every operation).
 */
export type IamPageMeta =
  | boolean
  | {
      action: string;
      /** Defaults to the tenant (`iam/{tenantId}`). A function receives the target route. */
      resource?: IamResourceRef | ((route: IamRouteLike) => IamResourceRef);
      /** Defaults to the signed-in session's tenant. */
      tenantId?: string | ((route: IamRouteLike, session: unknown) => string);
      /** Where to send a denied visitor; without it navigation aborts with a 403 error. */
      redirectTo?: string;
    };

export const defaultPublicConfig: IamPublicConfig = {
  apiPath: '/api/iam',
  loginPath: '/login',
  requireAuth: false,
  ssrSession: true,
  nextParam: 'next',
};
