import { IamError } from '@better-iam/core';

export type SpanKind =
  | 'operation'
  | 'authorize'
  | 'authorizeMany'
  | 'listAccessible'
  | 'auth'
  | 'http';
/** One timed unit of work: an operation, an authorization query, an authentication call, or an HTTP request. */
export interface IamSpan {
  kind: SpanKind;
  /** The action, authentication method, or request path. */
  name: string;
  tenantId?: string;
  outcome: 'ok' | 'denied' | 'error';
  /** The IamError code for denied and error outcomes. */
  code?: string;
  /** HTTP status for `http` spans. */
  status?: number;
  /** The caller's `X-Request-Id` on `http` spans, so latency and outcomes join your request logs. */
  requestId?: string;
  durationMs: number;
}
export interface ObservabilityOptions {
  /** Receives every span after it completes. Must not throw; failures are ignored so they can never affect requests. */
  onSpan?(span: IamSpan): void;
  /**
   * Keeps Prometheus-style counters and latency histograms from the spans (`iam.metrics`). With a `bearerToken`, the
   * HTTP handler also serves them at `GET {basePath}/metrics`.
   */
  metrics?: boolean | import('./metrics.js').MetricsOptions;
}
export interface Observer {
  /** Times `fn`, then reports the span; `outcomeOf` classifies a successful result (for advisory denials). */
  span<T>(
    kind: SpanKind,
    name: string,
    tenantId: string | undefined,
    fn: () => Promise<T>,
    outcomeOf?: (value: T) => Partial<Pick<IamSpan, 'outcome' | 'status' | 'code'>>,
    extra?: Pick<IamSpan, 'requestId'>,
  ): Promise<T>;
  enabled: boolean;
}

/** Authentication and authorization refusals (401, 403, 429) are `denied`; everything else that throws is an `error`. */
export const deniedStatuses: ReadonlySet<number> = new Set([401, 403, 429]);

export function createObserver(options: ObservabilityOptions | undefined): Observer {
  const handler = options?.onSpan;
  const emit = (span: IamSpan) => {
    try {
      handler?.(span);
    } catch {
      /* Observability never interferes with the request. */
    }
  };
  return {
    enabled: Boolean(handler),
    async span(kind, name, tenantId, fn, outcomeOf, extra) {
      if (!handler) return fn();
      const started = performance.now();
      try {
        const value = await fn();
        emit({
          kind,
          name,
          tenantId,
          ...extra,
          outcome: 'ok',
          ...outcomeOf?.(value),
          durationMs: performance.now() - started,
        });
        return value;
      } catch (error) {
        const known = error instanceof IamError;
        emit({
          kind,
          name,
          tenantId,
          ...extra,
          outcome: known && deniedStatuses.has(error.status) ? 'denied' : 'error',
          code: known ? error.code : 'INTERNAL_ERROR',
          durationMs: performance.now() - started,
        });
        throw error;
      }
    },
  };
}
