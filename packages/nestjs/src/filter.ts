import { Catch, Inject, type ArgumentsHost, type ExceptionFilter } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { IamError } from '@better-iam/core';
import { throwError } from 'rxjs';
import { toHttpException } from './context.js';

/**
 * Renders `IamError`s thrown from handlers and providers (for example `IamService.require` or direct `iam.api.*`
 * calls) as the IAM server's `{ error: { code, message } }` body with the error's status instead of a 500.
 * GraphQL receives an `HttpException`, WebSocket clients an `exception` event, and RPC callers an error payload.
 */
@Catch(IamError)
export class IamExceptionFilter implements ExceptionFilter<IamError> {
  constructor(@Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost) {}

  catch(error: IamError, host: ArgumentsHost): unknown {
    const payload = { error: { code: error.code, message: error.message } };
    const type = host.getType<string>();
    if (type === 'http') {
      const { httpAdapter } = this.adapterHost;
      const response = host.switchToHttp().getResponse<unknown>();
      httpAdapter.setHeader(response, 'cache-control', 'no-store');
      httpAdapter.reply(response, payload, error.status);
      return undefined;
    }
    if (type === 'ws') {
      host
        .switchToWs()
        .getClient<{ emit?(event: string, data: unknown): void }>()
        .emit?.('exception', { status: error.status, ...payload.error });
      return undefined;
    }
    if (type === 'rpc') return throwError(() => ({ status: error.status, ...payload.error }));
    return toHttpException(error);
  }
}
