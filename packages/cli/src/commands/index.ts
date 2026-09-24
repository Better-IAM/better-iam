import type { CommandSpec } from '../framework.js';
import { accessCommands } from './access.js';
import { apiCommands } from './api.js';
import { auditCommands } from './audit.js';
import { billingCommands } from './billing.js';
import { complianceCommands } from './compliance.js';
import { operationCommands } from './operations.js';
import { sessionCommands } from './session.js';
import { setupCommands } from './setup.js';
import { shellCommands } from './shell.js';
import { sshCommands } from './ssh.js';
import { vcCommands } from './vc.js';
import { storageCommands } from './storage.js';
import { vaultCommands } from './vault.js';

/** Every built-in command, in help order. */
export const builtinCommands: readonly CommandSpec<any>[] = [
  ...setupCommands,
  ...operationCommands,
  ...billingCommands,
  ...auditCommands,
  ...storageCommands,
  ...accessCommands,
  ...sshCommands,
  ...vcCommands,
  ...complianceCommands,
  ...vaultCommands,
  ...apiCommands,
  ...sessionCommands,
  ...shellCommands,
];
