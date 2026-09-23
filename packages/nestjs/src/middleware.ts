import type { IncomingMessage, ServerResponse } from 'node:http';
import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import { IAM_OPTIONS } from './context.js';
import type { IamInstance, IamModuleOptions } from './types.js';

type NodeRequest = IncomingMessage & { originalUrl?: string; rawBody?: unknown; body?: unknown };
const maxBody = 2097152;

function flatten(value: unknown, prefix = '', into = new URLSearchParams()): URLSearchParams {
  if (value && typeof value === 'object' && !Array.isArray(value))
    for (const [key, item] of Object.entries(value))
      flatten(item, prefix ? `${prefix}[${key}]` : key, into);
  else if (Array.isArray(value)) for (const item of value) flatten(item, prefix, into);
  else if (value !== undefined && value !== null) into.append(prefix, String(value));
  return into;
}

/**
 * The request body as bytes. Nest's Express adapter parses JSON and form bodies before middleware runs, so the raw
 * body (`NestFactory.create(App, { rawBody: true })`) is used when present, then the parsed body re-serialised, and
 * otherwise the untouched stream (Fastify, or content types no parser claimed).
 */
async function bodyOf(req: NodeRequest): Promise<Buffer | undefined> {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined;
  if (Buffer.isBuffer(req.rawBody)) return req.rawBody;
  if (req.readableEnded || req.body !== undefined) {
    const body = req.body;
    if (body === undefined || body === null) return Buffer.alloc(0);
    if (Buffer.isBuffer(body)) return body;
    if (typeof body === 'string') return Buffer.from(body);
    const type = String(req.headers['content-type'] ?? '').toLowerCase();
    return Buffer.from(
      type.startsWith('application/x-www-form-urlencoded')
        ? flatten(body).toString()
        : JSON.stringify(body),
    );
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > maxBody) throw Object.assign(new Error('Request too large'), { status: 413 });
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * A Node request handler that serves the IAM HTTP API (and mounted OAuth/SAML/SCIM protocols) from inside a Nest
 * application, for `app.use('/api/iam', createIamRequestHandler(iam))` or the module's `mount` option. It works with
 * bodies already consumed by Nest's parsers.
 */
export function createIamRequestHandler(iam: Pick<IamInstance, 'handler'>) {
  return async (req: NodeRequest, res: ServerResponse, next?: (error?: unknown) => void) => {
    try {
      const host = req.headers.host ?? 'localhost';
      const encrypted = (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true;
      const url = new URL(
        req.originalUrl ?? req.url ?? '/',
        `${encrypted ? 'https' : 'http'}://${host}`,
      );
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers))
        if (value !== undefined)
          for (const item of Array.isArray(value) ? value : [value]) headers.append(key, item);
      const body = await bodyOf(req);
      if (body !== undefined) headers.set('content-length', String(body.length));
      const response = await iam.handler(
        new Request(url, {
          method: req.method,
          headers,
          body: body?.length ? new Uint8Array(body) : undefined,
        }),
      );
      res.statusCode = response.status;
      response.headers.forEach((value, key) => {
        if (key !== 'set-cookie') res.setHeader(key, value);
      });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) res.setHeader('set-cookie', cookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      const status = (error as { status?: unknown }).status === 413 ? 413 : 500;
      if (status === 500 && next) {
        next(error);
        return;
      }
      res.statusCode = status;
      res.setHeader('content-type', 'application/json');
      res.setHeader('cache-control', 'no-store');
      res.end(
        JSON.stringify({
          error: {
            code: status === 413 ? 'PAYLOAD_TOO_LARGE' : 'INTERNAL_ERROR',
            message: status === 413 ? 'Request body too large' : 'Internal server error',
          },
        }),
      );
    }
  };
}

/** Nest middleware form of `createIamRequestHandler`, registered by `IamModule.forRoot({ mount: true })`. */
@Injectable()
export class IamHttpMiddleware implements NestMiddleware {
  private readonly handle: ReturnType<typeof createIamRequestHandler>;
  constructor(@Inject(IAM_OPTIONS) options: IamModuleOptions) {
    this.handle = createIamRequestHandler(options.iam);
  }
  use(req: NodeRequest, res: ServerResponse, next: (error?: unknown) => void): Promise<void> {
    return this.handle(req, res, next);
  }
}
