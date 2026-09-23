import {
  Inject,
  Injectable,
  SetMetadata,
  UseInterceptors,
  applyDecorators,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { from, mergeMap, type Observable } from 'rxjs';
import {
  IAM_OPTIONS,
  credentialOf,
  isIamError,
  requestOf,
  resolveTenant,
  stateOf,
  toHttpException,
} from './context.js';
import type { IamModuleOptions, ValueSource } from './types.js';

const FILTER_KEY = 'better-iam:filter-accessible';

export interface FilterAccessibleOptions<Item = unknown> {
  /** The managed resource type the items are registered as. */
  type: string;
  /** The item's resource id (default `item.id`). */
  id?: (item: Item) => string;
  /** Property of the response object holding the array (default: the response is the array). */
  path?: string;
  /** Overrides the module's tenant resolution. */
  tenant?: ValueSource;
}
type FilterRule = FilterAccessibleOptions & { action: string };

/**
 * Drops items the caller may not perform `action` on from a list response, using the reverse query `listAccessible`
 * over the registered resources of a managed type (one query per page of 1000, never one decision per item, so the
 * audit log is not flooded with denials). Requires `IamGuard` to have authenticated the request.
 *
 * ```ts
 * @Get() @FilterAccessible('projects:read', { type: 'project' })
 * list() { return this.projects.findAll(); }
 * ```
 */
export function FilterAccessible<Item = { id: string }>(
  action: string,
  options: FilterAccessibleOptions<Item>,
) {
  return applyDecorators(
    SetMetadata(FILTER_KEY, { action, ...options } as FilterRule),
    UseInterceptors(IamFilterInterceptor),
  );
}

@Injectable()
export class IamFilterInterceptor implements NestInterceptor {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(IAM_OPTIONS) private readonly options: IamModuleOptions,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const rule = this.reflector.get<FilterRule | undefined>(FILTER_KEY, context.getHandler());
    const found = requestOf(context);
    if (!rule || !found) return next.handle();
    return next.handle().pipe(mergeMap((value) => from(this.filter(rule, found, value))));
  }

  private async filter(
    rule: FilterRule,
    { request, key, args }: NonNullable<ReturnType<typeof requestOf>>,
    value: unknown,
  ): Promise<unknown> {
    const items = rule.path ? (value as Record<string, unknown> | null)?.[rule.path] : value;
    if (!Array.isArray(items) || items.length === 0) return value;
    const principal = stateOf(key)?.principal;
    if (!principal) return rule.path ? { ...(value as object), [rule.path]: [] } : [];
    const tenantId = await resolveTenant(
      rule.tenant,
      this.options.tenant,
      request,
      principal,
      args,
    );
    const accessible = new Set<string>();
    try {
      for (let offset = 0; ; offset += 1000) {
        const page = await this.options.iam.listAccessible({
          ...credentialOf(request),
          tenantId,
          action: rule.action,
          type: rule.type,
          limit: 1000,
          offset,
        });
        for (const resource of page.resources) accessible.add(resource.resourceId);
        if (offset + 1000 >= page.total) break;
      }
    } catch (error) {
      throw isIamError(error) ? toHttpException(error) : error;
    }
    const idOf = rule.id ?? ((item: unknown) => (item as { id: string }).id);
    const kept = items.filter((item) => accessible.has(idOf(item)));
    return rule.path ? { ...(value as object), [rule.path]: kept } : kept;
  }
}
