import {
  Inject,
  Module,
  RequestMethod,
  type DynamicModule,
  type MiddlewareConsumer,
  type ModuleMetadata,
  type NestModule,
  type Provider,
} from '@nestjs/common';
import { APP_FILTER, APP_GUARD, DiscoveryModule } from '@nestjs/core';
import { IAM_INSTANCE, IAM_OPTIONS } from './context.js';
import { IamEventsExplorer } from './events.js';
import { IamExceptionFilter } from './filter.js';
import { IamGuard } from './guard.js';
import { IamHttpMiddleware } from './middleware.js';
import { IamService } from './service.js';
import type { IamModuleOptions } from './types.js';

const IAM_MOUNT = 'BETTER_IAM_MOUNT';

/** Structural choices that must be known when the module graph is built, shared by `forRoot` and `forRootAsync`. */
export interface IamModuleFeatures {
  /** Registers the module globally so `IamService` and `IamGuard` are injectable everywhere (default true). */
  global?: boolean;
  /** Installs `IamGuard` as a global guard: every route needs a session unless marked `@Public()` (default false). */
  guard?: boolean;
  /** Installs `IamExceptionFilter` globally so `IamError`s render with their status (default true). */
  filter?: boolean;
  /** Serves the IAM HTTP API at `mountPath` from this application (default false). */
  mount?: boolean;
}
/** A provider that builds the module options, for `forRootAsync({ useClass })` or `{ useExisting }`. */
export interface IamOptionsFactory {
  createIamOptions(): IamModuleOptions | Promise<IamModuleOptions>;
}
type Token = string | symbol | (abstract new (...args: never[]) => unknown);
export interface IamModuleAsyncOptions extends IamModuleFeatures, Pick<ModuleMetadata, 'imports'> {
  inject?: Token[];
  useFactory?(...args: never[]): IamModuleOptions | Promise<IamModuleOptions>;
  /** A class implementing `IamOptionsFactory`, instantiated inside this module. */
  useClass?: new (...args: never[]) => IamOptionsFactory;
  /** An `IamOptionsFactory` provider already available through `imports` (or globally). */
  useExisting?: Token;
}

/**
 * Better IAM for NestJS: provides `IamService`, `IamGuard`, and the exception filter; optionally installs the guard
 * globally, mounts the IAM HTTP API, and binds `@OnIamEvent` handlers.
 *
 * ```ts
 * @Module({ imports: [IamModule.forRoot({ iam, guard: true, mount: true })] })
 * export class AppModule {}
 * ```
 */
@Module({})
export class IamModule implements NestModule {
  constructor(
    @Inject(IAM_OPTIONS) private readonly options: IamModuleOptions,
    @Inject(IAM_MOUNT) private readonly mount: boolean,
  ) {}

  static forRoot(options: IamModuleOptions & IamModuleFeatures): DynamicModule {
    const { global, guard, filter, mount, ...rest } = options;
    return IamModule.build({ global, guard, filter, mount }, [
      { provide: IAM_OPTIONS, useValue: rest },
    ]);
  }

  static forRootAsync(options: IamModuleAsyncOptions): DynamicModule {
    const { global, guard, filter, mount, imports, inject, useFactory, useClass, useExisting } =
      options;
    const fromFactory = (factory: IamOptionsFactory) => factory.createIamOptions();
    let optionProviders: Provider[];
    if (useFactory) optionProviders = [{ provide: IAM_OPTIONS, useFactory, inject: inject ?? [] }];
    else if (useClass)
      optionProviders = [
        useClass,
        { provide: IAM_OPTIONS, useFactory: fromFactory, inject: [useClass] },
      ];
    else if (useExisting)
      optionProviders = [{ provide: IAM_OPTIONS, useFactory: fromFactory, inject: [useExisting] }];
    else throw new Error('Better IAM: forRootAsync needs useFactory, useClass, or useExisting');
    return IamModule.build({ global, guard, filter, mount }, optionProviders, imports);
  }

  private static build(
    features: IamModuleFeatures,
    optionProviders: Provider[],
    imports: ModuleMetadata['imports'] = [],
  ): DynamicModule {
    const providers: Provider[] = [
      ...optionProviders,
      {
        provide: IAM_INSTANCE,
        useFactory: (options: IamModuleOptions) => {
          if (!options?.iam) throw new Error('Better IAM: IamModule options must include `iam`');
          return options.iam;
        },
        inject: [IAM_OPTIONS],
      },
      { provide: IAM_MOUNT, useValue: features.mount === true },
      IamService,
      IamGuard,
      IamEventsExplorer,
    ];
    if (features.guard) providers.push({ provide: APP_GUARD, useExisting: IamGuard });
    if (features.filter !== false)
      providers.push({ provide: APP_FILTER, useClass: IamExceptionFilter });
    return {
      module: IamModule,
      global: features.global !== false,
      imports: [...imports, DiscoveryModule],
      providers,
      exports: [IAM_INSTANCE, IAM_OPTIONS, IamService, IamGuard],
    };
  }

  configure(consumer: MiddlewareConsumer): void {
    if (!this.mount) return;
    const path = (
      this.options.mountPath ??
      this.options.iam.endpoint?.basePath ??
      '/api/iam'
    ).replace(/\/+$/, '');
    if (!/^\/[\w/-]*$/.test(path)) throw new Error('Better IAM: invalid mountPath');
    consumer
      .apply(IamHttpMiddleware)
      .forRoutes({ path: `${path}/*path`, method: RequestMethod.ALL });
  }
}
