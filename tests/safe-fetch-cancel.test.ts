import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createGuardedFetch } from '@better-iam/auth';

/**
 * Regression: cancelling the body of a size-bounded guarded response used to raise an uncaught ERR_INVALID_STATE
 * ("Controller is already closed") from the stream conversion, which would kill a process without an
 * uncaughtException handler. The SSF transmitter cancels the body after every delivery, so any receiver answering 2xx
 * with a body could crash the server.
 */

const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

async function origin(body: string, status = 200): Promise<string> {
  const server = createServer((_request, response) => {
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(body);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
}

describe('guarded fetch bodies', () => {
  it('lets callers cancel bounded bodies without an uncaught stream error', async () => {
    const uncaught: unknown[] = [];
    const record = (error: unknown) => uncaught.push(error);
    process.on('uncaughtException', record);
    try {
      const url = await origin(JSON.stringify({ error: 'x'.repeat(200) }), 500);
      for (const maxBytes of [undefined, 65_536]) {
        const guarded = createGuardedFetch({
          allowInsecureLocalhost: true,
          anyPort: true,
          maxBytes,
        });
        for (let attempt = 0; attempt < 10; attempt++) {
          const response = await guarded(url, { method: 'POST', body: '{}', redirect: 'error' });
          await response.body?.cancel();
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    } finally {
      process.off('uncaughtException', record);
    }
    expect(uncaught).toEqual([]);
  });

  it('still reads whole bodies within the bound and refuses larger ones', async () => {
    const small = await origin(JSON.stringify({ ok: true }));
    const guarded = createGuardedFetch({
      allowInsecureLocalhost: true,
      anyPort: true,
      maxBytes: 1024,
    });
    expect(await (await guarded(small)).json()).toEqual({ ok: true });
    const large = await origin('y'.repeat(64 * 1024));
    await expect((await guarded(large)).text()).rejects.toThrow();
    // A body exactly at the bound is fine.
    const exact = await origin('z'.repeat(1024));
    expect((await (await guarded(exact)).text()).length).toBe(1024);
  });
});
