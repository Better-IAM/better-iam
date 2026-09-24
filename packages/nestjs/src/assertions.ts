import {
  Inject,
  Injectable,
  Module,
  SetMetadata,
  createParamDecorator,
  type CanActivate,
  type DynamicModule,
  type ExecutionContext,
  type Provider,
} from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { verifyAssertion, type AssertionClaims } from '@better-iam/server/assertions';
import {
  ASSERTION_KEY,
  IAM_ASSERTION_OPTIONS,
  PUBLIC_KEY,
  headersOf,
  iamHttpError,
  isIamError,
  requestOf,
  toHttpException,
} from './context.js';

export interface IamAssertionOptions {
  /**
   * The derived verification key from `iam.assertionKey()` (64 hex characters), or the list from
   * `iam.assertionKeys()` while the deployment secret rotates.
   */
  key: string | readonly string[];
  /** This service's audience; assertions issued for any other audience are rejected. */
  audience: string;
  /** The IAM server's origin (`iss`); checked when set. */
  issuer?: string;
  /** Clock skew allowance (default 30 seconds). */
  toleranceSeconds?: number;
  /** Header carrying the assertion (default `authorization` with the `Bearer ` scheme). */
  header?: string;
}
export interface ClaimRequirements {
  /** At least one of these role ids. */
  roles?: string[];
  /** At least one of these group ids. */
  groups?: string[];
  /** The asserted session completed multi-factor authentication. */
  mfa?: boolean;
  /** Accepted credential kinds. */
  kinds?: AssertionClaims['kind'][];
}

const claimsByRequest = new WeakMap<object, AssertionClaims>();

/** Requirements the verified assertion must meet in addition to signature, audience, and lifetime. */
export const RequireClaims = (requirements: ClaimRequirements) =>
  SetMetadata(ASSERTION_KEY, requirements);

/** The verified assertion claims (`sub`, `tid`, `roles`, `groups`, `ext`, ...), or null on a `@Public()` handler. */
export const AssertionClaimsParam = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AssertionClaims | null => {
    const found = requestOf(context);
    return (found && claimsByRequest.get(found.key)) ?? null;
  },
);

/**
 * For downstream services that receive stateless assertions from a Better IAM deployment: verifies the token without
 * a database or network round trip and exposes its claims. It never contacts the IAM server, so revocation takes
 * effect when the (short-lived) assertion expires.
 */
@Injectable()
export class IamAssertionGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(IAM_ASSERTION_OPTIONS) private readonly options: IamAssertionOptions,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getHandler(), context.getClass()];
    const required = this.reflector.getAllAndOverride<ClaimRequirements | undefined>(
      ASSERTION_KEY,
      targets,
    );
    // `@RequireClaims` needs claims to check, so `@Public()` admits callers without an assertion only when absent.
    const anonymousAllowed =
      this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, targets) === true && !required;
    const found = requestOf(context);
    const raw = found ? headersOf(found.request).get(this.options.header ?? 'authorization') : null;
    // The scheme is case-insensitive (RFC 9110), as the IAM server's own credential parsing is.
    const token =
      raw && (this.options.header ? raw : /^bearer /i.test(raw) ? raw.slice(7) : null);
    if (!found || !token) {
      if (anonymousAllowed) return true;
      throw iamHttpError('UNAUTHENTICATED', 'An IAM assertion is required', 401);
    }
    let claims: AssertionClaims;
    try {
      claims = verifyAssertion(token, this.options);
    } catch (error) {
      if (anonymousAllowed) return true;
      throw isIamError(error) ? toHttpException(error) : error;
    }
    claimsByRequest.set(found.key, claims);
    if (required) {
      const denied =
        (required.mfa && !claims.mfa) ||
        (required.kinds && !required.kinds.includes(claims.kind)) ||
        (required.roles && !required.roles.some((role) => claims.roles.includes(role))) ||
        (required.groups && !required.groups.some((group) => claims.groups.includes(group)));
      if (denied) throw iamHttpError('ACCESS_DENIED', 'Access denied', 403);
    }
    return true;
  }
}

/** Configures `IamAssertionGuard` for a service that trusts assertions from a Better IAM deployment. */
@Module({})
export class IamAssertionModule {
  static forRoot(
    options: IamAssertionOptions & { global?: boolean; guard?: boolean },
  ): DynamicModule {
    const { global, guard, ...rest } = options;
    const keys = typeof rest.key === 'string' ? [rest.key] : rest.key;
    if (
      !Array.isArray(keys) ||
      !keys.length ||
      keys.some((key) => typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key))
    )
      throw new Error(
        'Better IAM: the assertion key must be the 64-hex value of iam.assertionKey() (or a list of them)',
      );
    if (!rest.audience) throw new Error('Better IAM: an assertion audience is required');
    const providers: Provider[] = [
      { provide: IAM_ASSERTION_OPTIONS, useValue: rest },
      IamAssertionGuard,
    ];
    if (guard) providers.push({ provide: APP_GUARD, useExisting: IamAssertionGuard });
    return {
      module: IamAssertionModule,
      global: global !== false,
      providers,
      exports: [IAM_ASSERTION_OPTIONS, IamAssertionGuard],
    };
  }
}

export type { AssertionClaims };
