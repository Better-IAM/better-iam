import { open, rm } from 'node:fs/promises';
import { copyStore, exportStore, importStore } from '@better-iam/core';
import { defineCommand } from '../framework.js';
import { usageError } from '../errors.js';

/** Snapshot commands: deployment operations straight on storage, like migrate (no credential). */
export const storageCommands = [
  defineCommand({
    name: 'store-export',
    group: 'Storage',
    summary: 'Write every record of the database as a JSON Lines snapshot',
    description:
      'store-export writes every record of the database as a JSON Lines snapshot (one consistent transaction; the file holds credential hashes and encrypted secrets, so protect it like the database). It never overwrites a file.',
    target: 'config',
    configDefaults: false,
    flags: {
      output: {
        type: 'string',
        value: 'PATH',
        required: true,
        description: 'The snapshot file to create (mode 0600; it must not exist)',
      },
    },
    async run({ iam, flags, path }) {
      const output = path(flags.output!);
      const instance = await iam();
      const file = await open(output, 'wx', 0o600);
      let summary;
      try {
        let buffered = '';
        summary = await exportStore(instance.store, async (line) => {
          buffered += line + '\n';
          if (buffered.length >= 1 << 20) {
            await file.writeFile(buffered, 'utf8');
            buffered = '';
          }
        });
        if (buffered) await file.writeFile(buffered, 'utf8');
        await file.sync();
        await file.close();
      } catch (error) {
        await file.close().catch(() => undefined);
        await rm(output, { force: true });
        throw error;
      }
      return { output, ...summary };
    },
  }),
  defineCommand({
    name: 'store-import',
    group: 'Storage',
    summary: 'Load a snapshot into an empty database',
    description:
      'store-import loads a snapshot into an empty database in one transaction; it migrates the target first and changes nothing on failure. Run migrate afterwards to apply plugin migrations.',
    target: 'config',
    configDefaults: false,
    flags: {
      input: { type: 'string', value: 'PATH', required: true, description: 'The snapshot to load' },
    },
    async run({ iam, flags, path }) {
      // Open the file before touching a database, so a wrong path changes nothing.
      const inputPath = path(flags.input!);
      const input = await open(inputPath, 'r');
      try {
        const instance = await iam();
        // Schema only: initialize() would write records, and the target must stay empty until the import.
        await instance.store.migrate();
        const summary = await importStore(instance.store, input.readLines({ encoding: 'utf8' }));
        return { input: inputPath, ...summary, next: 'Run migrate to apply plugin migrations.' };
      } finally {
        await input.close().catch(() => undefined);
      }
    },
  }),
  defineCommand({
    name: 'store-copy',
    group: 'Storage',
    summary: 'Copy the database into the empty database of another configuration',
    description:
      'store-copy copies the configured database into the empty database of --target-config (for example SQLite to PostgreSQL); it migrates the target first and changes nothing on failure.',
    target: 'config',
    configDefaults: false,
    flags: {
      'target-config': {
        type: 'string',
        value: 'PATH',
        required: true,
        description: 'Configuration of the empty target database',
      },
    },
    examples: [
      'better-iam store-copy --config sqlite.config.mjs --target-config postgres.config.mjs',
    ],
    async run({ iam, open: openConfig, flags, path, configPath }) {
      const targetPath = path(flags['target-config']!);
      if ((await configPath())?.path === targetPath)
        throw usageError('--target-config must name a different configuration');
      const source = await iam();
      const target = await openConfig(targetPath);
      await target.store.migrate();
      const summary = await copyStore(source.store, target.store);
      return { target: targetPath, ...summary, next: 'Run migrate with the target configuration.' };
    },
  }),
];
