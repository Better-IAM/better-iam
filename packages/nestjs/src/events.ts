import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import type { AuditEvent } from '@better-iam/core';
import { EVENT_KEY, IAM_OPTIONS } from './context.js';
import type { IamModuleOptions } from './types.js';

/**
 * Subscribes every `@OnIamEvent` provider method to the IAM event stream at bootstrap and, when
 * `dispatchIntervalMs` is set, drives `iam.events.dispatch()` until shutdown.
 */
@Injectable()
export class IamEventsExplorer implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger('BetterIam');
  private readonly unsubscribers: (() => void)[] = [];
  private timer: ReturnType<typeof setInterval> | undefined;
  private running: Promise<unknown> | undefined;

  constructor(
    @Inject(IAM_OPTIONS) private readonly options: IamModuleOptions,
    @Inject(DiscoveryService) private readonly discovery: DiscoveryService,
    @Inject(MetadataScanner) private readonly scanner: MetadataScanner,
    @Inject(Reflector) private readonly reflector: Reflector,
  ) {}

  onApplicationBootstrap(): void {
    for (const wrapper of this.discovery.getProviders()) {
      const instance = wrapper.instance as Record<string, unknown> | undefined;
      if (!instance || typeof instance !== 'object' || !wrapper.isDependencyTreeStatic()) continue;
      const prototype = Object.getPrototypeOf(instance) as object | null;
      if (!prototype) continue;
      for (const name of this.scanner.getAllMethodNames(prototype)) {
        const method = instance[name];
        if (typeof method !== 'function') continue;
        const pattern = this.reflector.get<string | string[] | undefined>(EVENT_KEY, method);
        if (!pattern) continue;
        this.unsubscribers.push(
          this.options.iam.events.subscribe(
            pattern,
            (event: AuditEvent) =>
              (method as (event: AuditEvent) => unknown).call(instance, event) as Promise<void>,
          ),
        );
      }
    }
    const interval = this.options.dispatchIntervalMs;
    if (interval !== undefined) {
      if (!Number.isInteger(interval) || interval < 100)
        throw new Error('Better IAM: dispatchIntervalMs must be an integer of at least 100');
      this.timer = setInterval(() => void this.dispatch(), interval);
      this.timer.unref?.();
    }
  }

  /** Delivers queued events now; concurrent calls share one run. */
  dispatch(): Promise<unknown> {
    this.running ??= this.options.iam.events
      .dispatch()
      .catch((error: unknown) => {
        this.logger.error(`Event dispatch failed: ${(error as Error).message}`);
      })
      .finally(() => {
        this.running = undefined;
      });
    return this.running;
  }

  async onApplicationShutdown(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.running;
    for (const unsubscribe of this.unsubscribers.splice(0)) unsubscribe();
  }
}
