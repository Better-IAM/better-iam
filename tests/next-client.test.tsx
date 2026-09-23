// @vitest-environment happy-dom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { describe, expect, it, vi } from 'vitest';
import { IamClientError } from '@better-iam/client';

const { router, navigation } = await vi.hoisted(async () => {
  // Resolve from packages/next: that is where the client entry imports next/navigation from.
  const { createRequire } = await import('node:module');
  const { resolve } = await import('node:path');
  const resolveFromNext = createRequire(resolve('packages/next/package.json')).resolve;
  return {
    router: { refresh: vi.fn(), replace: vi.fn() },
    navigation: resolveFromNext('next/navigation.js'),
  };
});
vi.mock(navigation, () => ({ useRouter: () => router }));

const { IamNextProvider, useSession, useSignOut } = await import('../packages/next/src/client.js');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Session = { identity: { id: string; name: string }; session: { tenantId: string } };
const as = (id: string): Session => ({ identity: { id, name: id }, session: { tenantId: 't' } });

describe('@better-iam/next/client', () => {
  it('refreshes server components when the signed-in identity changes and on sign-out', async () => {
    let user: Session | null = as('alice');
    const client = {
      auth: {
        getSession: async () => {
          if (!user) throw new IamClientError('UNAUTHENTICATED', 'No session', 401);
          return user;
        },
        signOut: async () => {
          user = null;
          return { success: true };
        },
      },
    };
    const controls: {
      setSession?: (session: Session | null) => void;
      signOut?: () => Promise<void>;
      name?: string | null;
    } = {};
    function Probe() {
      const session = useSession<typeof client>();
      controls.setSession = session.setSession;
      controls.signOut = useSignOut({ redirectTo: '/login' });
      controls.name = session.session?.identity.name ?? null;
      return null;
    }
    const container = document.createElement('div');
    const root = createRoot(container);
    await act(async () => {
      root.render(
        <IamNextProvider client={client} initialSession={as('alice')} refreshOnFocus={false}>
          <Probe />
        </IamNextProvider>,
      );
    });
    expect(controls.name).toBe('alice');
    expect(router.refresh).not.toHaveBeenCalled();

    await act(async () => controls.setSession!(as('alice')));
    expect(router.refresh).not.toHaveBeenCalled();
    await act(async () => controls.setSession!(as('bob')));
    expect(router.refresh).toHaveBeenCalledTimes(1);

    await act(async () => controls.signOut!());
    expect(controls.name).toBeNull();
    expect(router.replace).toHaveBeenCalledWith('/login');
    expect(router.refresh.mock.calls.length).toBeGreaterThanOrEqual(2);
    await act(async () => root.unmount());
  });
});
