import { IamError, type IamPlugin } from '@better-iam/core';
import type { Catalog } from './catalog.js';

/** Plugins are validated once at construction: unique IDs, registered actions, and well-formed POST endpoints. */
export function validatePlugins(plugins: IamPlugin[], catalog: Catalog): void {
  if (new Set(plugins.map((plugin) => plugin.id)).size !== plugins.length)
    throw new IamError('INVALID_CONFIG', 'Duplicate plugin ID');
  for (const plugin of plugins) {
    plugin.validateConfig?.();
    const paths = new Set<string>();
    for (const endpoint of plugin.endpoints ?? []) {
      if (!catalog.actions.has(endpoint.action))
        throw new IamError('INVALID_CONFIG', 'Plugin endpoint action must be registered');
      const path = endpoint.path.replace(/^\//, '');
      const valid =
        endpoint.method === 'POST' &&
        /^[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(path) &&
        !paths.has(path) &&
        typeof endpoint.validate === 'function' &&
        (endpoint.resource === undefined || typeof endpoint.resource === 'function') &&
        typeof endpoint.handler === 'function';
      if (!valid)
        throw new IamError(
          'INVALID_CONFIG',
          'Plugin endpoints require unique paths, POST, validation, and a handler',
        );
      paths.add(path);
    }
  }
}
