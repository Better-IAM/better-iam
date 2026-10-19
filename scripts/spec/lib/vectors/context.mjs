// Building blocks for vector files: { description, source, notes?, cases: [{ name, input, output }] }.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { reseed } from '../determinism.mjs';
import { encode, json, outcome, specDir } from '../util.mjs';

export class VectorFile {
  constructor(name, { description, source, notes }) {
    this.name = name;
    this.description = description;
    this.source = source;
    this.notes = notes;
    this.cases = [];
    this.names = new Set();
  }

  /**
   * Adds one case. `run` receives the decoded input and returns the output (or throws: the output is then
   * `{ $error }`). Randomness is reseeded from the file and case name first, so every case is reproducible alone.
   */
  async add(name, input, run, extra = {}) {
    if (this.names.has(name)) throw new Error(`${this.name}: duplicate case ${name}`);
    this.names.add(name);
    reseed(`${this.name}/${name}`);
    const output = await outcome(() => run(input));
    this.cases.push({ name, input: encode(input), output, ...extra });
    return output;
  }

  /** Adds a case whose output was computed already. */
  push(name, input, output, extra = {}) {
    if (this.names.has(name)) throw new Error(`${this.name}: duplicate case ${name}`);
    this.names.add(name);
    this.cases.push({ name, input: encode(input), output: encode(output), ...extra });
  }

  write(output) {
    if (!this.cases.length) throw new Error(`${this.name}: no cases`);
    output.add(
      `vectors/${this.name}.json`,
      json(
        {
          description: this.description,
          source: this.source,
          ...(this.notes ? { notes: this.notes } : {}),
          cases: this.cases,
        },
        { sorted: false },
      ),
    );
    return this.cases.length;
  }
}

const previousFiles = new Map();
/**
 * A case of the checked-in vector file, for values that cannot be reproduced (ECDSA signatures: the nonce comes from
 * OpenSSL). Callers verify the old value with the TypeScript implementation before reusing it.
 */
export async function previousCase(file, name) {
  if (!previousFiles.has(file)) {
    let parsed;
    try {
      parsed = JSON.parse(await readFile(join(specDir, 'vectors', `${file}.json`), 'utf8'));
    } catch {
      parsed = { cases: [] };
    }
    previousFiles.set(file, new Map(parsed.cases.map((item) => [item.name, item])));
  }
  return previousFiles.get(file).get(name);
}
