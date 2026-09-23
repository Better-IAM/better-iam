import type { CommandSpec } from '../framework.js';
import { accessCommands } from './access.js';
import { apiCommands } from './api.js';
import { auditCommands } from './audit.js';
import { billingCommands } from './billing.js';
import { operationCommands } from './operations.js';
import { sessionCommands } from './session.js';
import { setupCommands } from './setup.js';
import { shellCommands } from './shell.js';
import { storageCommands } from './storage.js';

/** Every built-in command, in help order. */
export const builtinCommands: readonly CommandSpec<any>[] = [
  ...setupCommands,
  ...operationCommands,
  ...billingCommands,
  ...auditCommands,
  ...storageCommands,
  ...accessCommands,
  ...apiCommands,
  ...sessionCommands,
  ...shellCommands,
];
