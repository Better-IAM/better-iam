import {
  IamError,
  ipMatches,
  isIpRange,
  type CredentialInput,
  type IamStore,
} from '@better-iam/core';
import type { NetworkBlock } from '@better-iam/auth';
import type { ServerContext } from '../context.js';
import { byNewest, id } from '../utils.js';
import { integer, text } from '../validation.js';

const MIN_DURATION_MS = 60_000;
const MAX_DURATION_MS = 365 * 24 * 60 * 60_000;

/**
 * Incident response: network blocks. A block refuses every authentication flow and every live session whose
 * recorded client IP it covers, and every API key or assumed-role token presented from it, for one tenant or, when
 * root administrators set it on the root tenant with `platform`, for the whole installation. Blocks are checked
 * before rate limits and credentials, so a blocked address cannot count against anyone, and they need a recorded IP
 * (`http.clientInfo`) to bite. Lapsed blocks are deleted by the retention worker (`purgeDeleted`).
 */
export function createSecurityApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const { auth } = ctx;
  /**
   * Runs a block change and clears the cached block lists again once its transaction has committed: the clear inside
   * the transaction alone can race a concurrent read that caches the pre-change list for a few seconds.
   */
  const blockChange: typeof operation = async (...args) => {
    try {
      return await operation(...args);
    } finally {
      auth.invalidateNetworkBlocks();
    }
  };
  const withStatus = (block: NetworkBlock) => ({
    ...block,
    active: block.expiresAt === undefined || block.expiresAt > ctx.now(),
  });
  async function platformScope(
    tx: IamStore,
    tenantId: string,
    principal: Parameters<typeof ctx.rootPrincipal>[1],
  ) {
    const realm = await ctx.tenant(tx, tenantId);
    if (realm.parentId !== null || !(await ctx.rootPrincipal(tx, principal)))
      throw new IamError(
        'ACCESS_DENIED',
        'Platform-wide blocks are set by root administrators on the root tenant',
        403,
      );
  }
  return {
    /**
     * Blocks a network (IPv4/IPv6 address or CIDR block) for the tenant, or for the whole platform with
     * `platform` (root administrators, on the root tenant). `durationMs` (one minute to a year) makes it lapse by
     * itself; without it the block stays until lifted. A network covering the caller's own address (the one their
     * session was issued from, or the one the request comes from) is refused so nobody locks themselves out.
     * Requires iam:security:manage and recent authentication; audited as `security:network-block`.
     */
    blockNetwork: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        network: string;
        reason: string;
        durationMs?: number;
        platform?: boolean;
      },
    ) =>
      blockChange(
        credential,
        input.tenantId,
        'iam:security:manage',
        'security/networks',
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const network = text(input.network, 'network', 64).trim();
          if (!isIpRange(network))
            throw new IamError(
              'INVALID_INPUT',
              'network must be an IPv4/IPv6 address or CIDR block',
            );
          const reason = text(input.reason, 'reason', 512).trim();
          if (!reason) throw new IamError('INVALID_INPUT', 'reason is required');
          const durationMs =
            input.durationMs === undefined
              ? undefined
              : integer(input.durationMs, 'durationMs', MIN_DURATION_MS, MAX_DURATION_MS);
          const platform = input.platform === true;
          if (platform) await platformScope(tx, input.tenantId, principal);
          // Neither the address this session was issued from nor the one this request comes from may be blocked:
          // the first would end the caller's session, the second would refuse their next sign-in and the
          // reauthentication they need to lift the block.
          const own = [principal.session.client?.ip, auth.currentClient()?.ip];
          if (own.some((ip) => ip !== undefined && ipMatches(ip, network)))
            throw new IamError('INVALID_INPUT', 'That network includes your own address');
          const now = ctx.now();
          const existing = (
            await tx.find<NetworkBlock>('authBlocks', { tenantId: input.tenantId })
          ).find((block) => block.network === network && Boolean(block.platform) === platform);
          const block: NetworkBlock = {
            id: existing?.id ?? id(),
            tenantId: input.tenantId,
            network,
            reason,
            createdAt: now,
            createdBy: principal.identity.id,
          };
          if (durationMs !== undefined) block.expiresAt = now + durationMs;
          if (platform) block.platform = true;
          if (existing) await tx.put('authBlocks', block);
          else await tx.insert('authBlocks', block);
          auth.invalidateNetworkBlocks();
          await ctx.events.audit(
            tx,
            principal,
            'security:network-block',
            input.tenantId,
            block.id,
            'allow',
            false,
            {
              network,
              reason,
              platform,
              ...(block.expiresAt !== undefined ? { expiresAt: block.expiresAt } : {}),
              renewed: Boolean(existing),
            },
          );
          return withStatus(block);
        },
      ),
    /** Lifts a block early. Requires iam:security:manage and recent authentication; audited as `security:network-unblock`. */
    unblockNetwork: (credential: CredentialInput, input: { tenantId: string; blockId: string }) =>
      blockChange(
        credential,
        input.tenantId,
        'iam:security:manage',
        'security/networks',
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const block = await ctx.scoped<NetworkBlock>(
            tx,
            'authBlocks',
            text(input.blockId, 'blockId'),
            input.tenantId,
          );
          if (block.platform) await platformScope(tx, input.tenantId, principal);
          await tx.delete('authBlocks', block.id);
          auth.invalidateNetworkBlocks();
          await ctx.events.audit(
            tx,
            principal,
            'security:network-unblock',
            input.tenantId,
            block.id,
            'allow',
            false,
            { network: block.network, platform: Boolean(block.platform) },
          );
          return { success: true as const };
        },
      ),
    /** The tenant's blocks, newest first, each with `active` (not yet lapsed). Requires iam:security:read. */
    listBlocks: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:security:read',
        'security/networks',
        async ({ tx }) =>
          (await tx.find<NetworkBlock>('authBlocks', { tenantId: input.tenantId }))
            .sort(byNewest)
            .map(withStatus),
      ),
  };
}
