import { describe, expect, it } from 'vitest';
import {
  IamError,
  classificationTemplates,
  dominates,
  isValidClassificationLabel,
  joinLabels,
  labelCovers,
  labelRank,
  validateLabel,
  validateScheme,
  type ClassificationLabel,
  type ClassificationSchemeDefinition,
  type ClearanceParty,
} from '@better-iam/core';

const scheme: ClassificationSchemeDefinition = validateScheme({
  levels: [
    { id: 'U', name: 'UNCLASSIFIED', rank: 0 },
    { id: 'C', name: 'CONFIDENTIAL', rank: 1 },
    { id: 'S', name: 'SECRET', rank: 2 },
    { id: 'TS', name: 'TOP SECRET', rank: 3 },
  ],
  compartments: [
    { id: 'si', name: 'Special Intelligence' },
    { id: 'tk', name: 'Talent Keyhole' },
    { id: 'hcs', name: 'Human Control System' },
  ],
  ownerCountries: ['USA'],
  caveats: ['NOFORN', 'RELTO'],
});
const corporate = classificationTemplates.corporate;
const nato = classificationTemplates.nato;

function party(
  rank: number,
  compartments: string[] = [],
  citizenship: string[] = ['USA'],
): ClearanceParty {
  return {
    identityId: 'idn_test',
    rank,
    compartments: new Set(compartments),
    citizenship: new Set(citizenship),
  };
}

function invalidInput(run: () => unknown): IamError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(IamError);
    expect((error as IamError).code).toBe('INVALID_INPUT');
    expect((error as IamError).status).toBe(400);
    return error as IamError;
  }
  throw new Error('expected INVALID_INPUT');
}

const levels = (count: number) =>
  Array.from({ length: count }, (_, index) => ({
    id: `L${index}`,
    name: `Level ${index}`,
    rank: index,
  }));

/** Deterministic PRNG (mulberry32) for the property checks. */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}
const countries = ['USA', 'GBR', 'CAN', 'AUS', 'NZL', 'FRA'];
function randomLabel(next: () => number): ClassificationLabel {
  const pick = <T>(items: readonly T[]) => items.filter(() => next() < 0.4);
  const label: ClassificationLabel = { level: scheme.levels[Math.floor(next() * 4)]!.id };
  const compartments = pick(scheme.compartments.map((compartment) => compartment.id));
  if (compartments.length) label.compartments = compartments;
  if (next() < 0.2) label.noforn = true;
  if (next() < 0.5) label.releasableTo = pick(countries.filter((country) => country !== 'USA'));
  return label;
}
function randomParty(next: () => number): ClearanceParty {
  return party(
    Math.floor(next() * 5) - 1,
    scheme.compartments.map((compartment) => compartment.id).filter(() => next() < 0.6),
    countries.filter(() => next() < 0.3),
  );
}

describe('classification templates', () => {
  it('are valid schemes, unchanged by validation', () => {
    for (const [name, template] of Object.entries(classificationTemplates)) {
      expect(validateScheme(template), name).toEqual(template);
      expect(template.compartments, name).toEqual([]);
    }
  });

  it('carry the documented levels, owners and caveats', () => {
    const shape = (definition: ClassificationSchemeDefinition) =>
      definition.levels.map((level) => `${level.id}:${level.rank}`);
    expect(shape(classificationTemplates.us)).toEqual(['U:0', 'C:1', 'S:2', 'TS:3']);
    expect(classificationTemplates.us.ownerCountries).toEqual(['USA']);
    expect(classificationTemplates.us.caveats).toEqual(['NOFORN', 'RELTO']);
    expect(shape(classificationTemplates.uk)).toEqual(['OFFICIAL:0', 'SECRET:1', 'TOP-SECRET:2']);
    expect(classificationTemplates.uk.levels[2]!.name).toBe('TOP SECRET');
    expect(classificationTemplates.uk.ownerCountries).toEqual(['GBR']);
    expect(shape(nato)).toEqual(['NU:0', 'NR:1', 'NC:2', 'NS:3', 'CTS:4']);
    expect(nato.ownerCountries).toEqual([]);
    expect(nato.caveats).toEqual(['RELTO']);
    expect(shape(corporate)).toEqual(['public:0', 'internal:1', 'confidential:2', 'restricted:3']);
    expect(corporate.caveats).toEqual([]);
  });

  it('are frozen; validateScheme returns a mutable copy', () => {
    expect(Object.isFrozen(classificationTemplates)).toBe(true);
    expect(() => {
      (classificationTemplates.us.levels as unknown[]).push({ id: 'X', name: 'X', rank: 9 });
    }).toThrow(TypeError);
    expect(() => {
      (classificationTemplates.us.levels[0] as { rank: number }).rank = 5;
    }).toThrow(TypeError);
    const copy = validateScheme(classificationTemplates.us);
    copy.compartments.push({ id: 'si', name: 'SI' });
    expect(classificationTemplates.us.compartments).toEqual([]);
    expect(validateScheme(copy).compartments).toEqual([{ id: 'si', name: 'SI' }]);
  });
});

describe('validateScheme', () => {
  it('returns a normalized copy and reads absent lists as empty', () => {
    const input = { levels: levels(2) };
    const result = validateScheme(input);
    expect(result).toEqual({
      levels: levels(2),
      compartments: [],
      ownerCountries: [],
      caveats: [],
    });
    input.levels[0]!.name = 'changed';
    expect(result.levels[0]!.name).toBe('Level 0');
  });

  it('accepts gaps between ranks and 20 levels and 200 compartments', () => {
    expect(
      validateScheme({
        levels: [
          { id: 'a', name: 'A', rank: 0 },
          { id: 'b', name: 'B', rank: 10 },
        ],
      }).levels.map((level) => level.rank),
    ).toEqual([0, 10]);
    const compartments = Array.from({ length: 200 }, (_, index) => ({
      id: `c${index}`,
      name: `C ${index}`,
    }));
    expect(validateScheme({ levels: levels(20), compartments }).compartments).toHaveLength(200);
  });

  it('refuses malformed schemes', () => {
    const base = {
      levels: levels(3),
      compartments: [],
      ownerCountries: ['USA'],
      caveats: ['NOFORN'],
    };
    const refused: unknown[] = [
      null,
      'us',
      [],
      { ...base, extra: true },
      { ...base, levels: levels(1) },
      { ...base, levels: levels(21) },
      { ...base, levels: 'U,S' },
      // ranks: must start at 0 and strictly increase in list order
      { ...base, levels: levels(3).map((level) => ({ ...level, rank: level.rank + 1 })) },
      { ...base, levels: [...levels(3)].reverse() },
      { ...base, levels: [levels(2)[0], { id: 'x', name: 'X', rank: 0 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X', rank: 1.5 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X', rank: '1' }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X', rank: 1000 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X', rank: Number.POSITIVE_INFINITY }] },
      // ids and names
      { ...base, levels: [levels(1)[0], { id: 'l0', name: 'Other', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'level 0', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: '-x', name: 'X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'a b', name: 'X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x'.repeat(65), name: 'X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'constructor', name: 'X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'toString', name: 'X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: '__proto__', name: 'X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: '', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: ' X', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X\nY', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X Y', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X‮Y', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X\ud800', rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X'.repeat(65), rank: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X', rank: 1, extra: 1 }] },
      { ...base, levels: [levels(1)[0], { id: 'x', name: 'X', rank: 1, abbreviation: '' }] },
      {
        ...base,
        levels: [levels(1)[0], { id: 'x', name: 'X', rank: 1, abbreviation: 'X'.repeat(17) }],
      },
      {
        ...base,
        levels: [
          { ...levels(1)[0], abbreviation: 'A' },
          { id: 'x', name: 'X', rank: 1, abbreviation: 'a' },
        ],
      },
      // a hole in the list
      { ...base, levels: [levels(1)[0], , { id: 'x', name: 'X', rank: 2 }] },
      // compartments
      { ...base, compartments: 'si' },
      { ...base, compartments: [{ id: 'si' }] },
      { ...base, compartments: [{ id: 'si', name: 'SI', level: 'S' }] },
      {
        ...base,
        compartments: [
          { id: 'si', name: 'SI' },
          { id: 'SI', name: 'Other' },
        ],
      },
      {
        ...base,
        compartments: [
          { id: 'si', name: 'SI' },
          { id: 'tk', name: 'si' },
        ],
      },
      { ...base, compartments: [{ id: 'si/x', name: 'SI' }] },
      {
        ...base,
        compartments: Array.from({ length: 201 }, (_, index) => ({
          id: `c${index}`,
          name: `C ${index}`,
        })),
      },
      // owner countries and caveats
      { ...base, ownerCountries: ['usa'] },
      { ...base, ownerCountries: ['US'] },
      { ...base, ownerCountries: ['NATO'] },
      { ...base, ownerCountries: ['USA', 'USA'] },
      { ...base, ownerCountries: 'USA' },
      { ...base, caveats: ['FOUO'] },
      { ...base, caveats: ['noforn'] },
      { ...base, caveats: ['RELTO', 'RELTO'] },
      { ...base, caveats: 'NOFORN' },
      { ...base, ownerCountries: [], caveats: ['NOFORN'] },
      { ...base, compartments: null },
    ];
    for (const input of refused) invalidInput(() => validateScheme(input));
  });

  it('does not echo compartment names in errors', () => {
    const error = invalidInput(() =>
      validateScheme({
        levels: levels(2),
        compartments: [
          { id: 'a', name: 'GAMMA CODEWORD' },
          { id: 'b', name: 'gamma codeword' },
        ],
      }),
    );
    expect(error.message).not.toMatch(/gamma/i);
  });
});

describe('validateLabel', () => {
  it('normalizes: sorted, empty compartments and noforn false dropped, empty releasableTo kept', () => {
    expect(validateLabel({ level: 'S', compartments: ['tk', 'si'] }, scheme)).toEqual({
      level: 'S',
      compartments: ['si', 'tk'],
    });
    expect(validateLabel({ level: 'S', compartments: [], noforn: false }, scheme)).toEqual({
      level: 'S',
    });
    expect(validateLabel({ level: 'S', noforn: true }, scheme)).toEqual({
      level: 'S',
      noforn: true,
    });
    expect(validateLabel({ level: 'S', releasableTo: [] }, scheme)).toEqual({
      level: 'S',
      releasableTo: [],
    });
    expect(validateLabel({ level: 'S', releasableTo: ['GBR', 'CAN'] }, scheme)).toEqual({
      level: 'S',
      releasableTo: ['CAN', 'GBR'],
    });
    const input = { level: 'TS', compartments: ['si'] };
    const result = validateLabel(input, scheme);
    input.compartments.push('tk');
    expect(result.compartments).toEqual(['si']);
    expect(isValidClassificationLabel({ level: 'TS' }, scheme)).toBe(true);
  });

  it('refuses labels the scheme does not support (fail closed)', () => {
    const refused: Array<[unknown, ClassificationSchemeDefinition]> = [
      [null, scheme],
      ['TS', scheme],
      [['TS'], scheme],
      [{}, scheme],
      [{ level: 'X' }, scheme],
      [{ level: 'ts' }, scheme],
      [{ level: 3 }, scheme],
      [{ level: 'TS', scheme: 'us' }, scheme],
      [{ level: 'TS', caveats: ['NOFORN'] }, scheme],
      [{ level: 'TS', compartments: ['gamma'] }, scheme],
      [{ level: 'TS', compartments: ['SI'] }, scheme],
      [{ level: 'TS', compartments: ['si', 'si'] }, scheme],
      [{ level: 'TS', compartments: 'si' }, scheme],
      [{ level: 'TS', compartments: null }, scheme],
      [{ level: 'TS', compartments: [1] }, scheme],
      [{ level: 'TS', noforn: 'yes' }, scheme],
      [{ level: 'TS', noforn: null }, scheme],
      [{ level: 'TS', releasableTo: null }, scheme],
      [{ level: 'TS', releasableTo: 'GBR' }, scheme],
      [{ level: 'TS', releasableTo: ['gbr'] }, scheme],
      [{ level: 'TS', releasableTo: ['GB'] }, scheme],
      [{ level: 'TS', releasableTo: ['FVEY'] }, scheme],
      [{ level: 'TS', releasableTo: ['GBR', 'GBR'] }, scheme],
      // caveats the scheme does not use
      [{ level: 'restricted', noforn: true }, corporate],
      [{ level: 'restricted', releasableTo: ['GBR'] }, corporate],
      [{ level: 'restricted', releasableTo: [] }, corporate],
      [{ level: 'NS', noforn: true }, nato],
      // a label of another scheme
      [{ level: 'TS' }, classificationTemplates.uk],
    ];
    for (const [label, definition] of refused) {
      invalidInput(() => validateLabel(label, definition));
      expect(isValidClassificationLabel(label, definition)).toBe(false);
    }
  });

  it('does not echo submitted values in errors', () => {
    const error = invalidInput(() =>
      validateLabel({ level: 'TS', compartments: ['GAMMA-CODEWORD'] }, scheme),
    );
    expect(error.message).not.toMatch(/gamma/i);
  });
});

describe('labelRank', () => {
  it('returns the rank of known levels and undefined otherwise', () => {
    expect(labelRank({ level: 'U' }, scheme)).toBe(0);
    expect(labelRank({ level: 'TS', compartments: ['si'] }, scheme)).toBe(3);
    expect(labelRank({ level: 'ts' }, scheme)).toBeUndefined();
    expect(labelRank({ level: 'OFFICIAL' }, scheme)).toBeUndefined();
    expect(labelRank(null as unknown as ClassificationLabel, scheme)).toBeUndefined();
    expect(labelRank({ level: 2 } as unknown as ClassificationLabel, scheme)).toBeUndefined();
  });
});

describe('joinLabels', () => {
  it('treats absent labels as no label', () => {
    expect(joinLabels(undefined, undefined, scheme)).toBeUndefined();
    expect(joinLabels(null as unknown as undefined, undefined, scheme)).toBeUndefined();
    expect(joinLabels({ level: 'S', compartments: ['tk', 'si'] }, undefined, scheme)).toEqual({
      level: 'S',
      compartments: ['si', 'tk'],
    });
    expect(joinLabels(undefined, { level: 'C', releasableTo: [] }, scheme)).toEqual({
      level: 'C',
      releasableTo: [],
    });
    expect(joinLabels(null as unknown as undefined, { level: 'C' }, scheme)).toEqual({
      level: 'C',
    });
  });

  it('takes the highest level whichever side it is on', () => {
    expect(joinLabels({ level: 'TS' }, { level: 'C' }, scheme)).toEqual({ level: 'TS' });
    expect(joinLabels({ level: 'C' }, { level: 'TS' }, scheme)).toEqual({ level: 'TS' });
    expect(joinLabels({ level: 'U' }, { level: 'U' }, scheme)).toEqual({ level: 'U' });
  });

  it('unions compartments and ORs noforn', () => {
    expect(
      joinLabels(
        { level: 'S', compartments: ['tk'] },
        { level: 'C', compartments: ['si', 'tk'] },
        scheme,
      ),
    ).toEqual({ level: 'S', compartments: ['si', 'tk'] });
    expect(joinLabels({ level: 'S', noforn: true }, { level: 'TS' }, scheme)).toEqual({
      level: 'TS',
      noforn: true,
    });
    expect(joinLabels({ level: 'S', noforn: false }, { level: 'S' }, scheme)).toEqual({
      level: 'S',
    });
  });

  it('intersects releasableTo, where an absent list is unrestricted', () => {
    expect(
      joinLabels(
        { level: 'S', releasableTo: ['GBR', 'CAN', 'AUS'] },
        { level: 'S', releasableTo: ['AUS', 'GBR', 'NZL'] },
        scheme,
      ),
    ).toEqual({ level: 'S', releasableTo: ['AUS', 'GBR'] });
    // absent = unrestricted: the other side's list stands (never widened to unrestricted)
    expect(joinLabels({ level: 'S' }, { level: 'C', releasableTo: ['GBR'] }, scheme)).toEqual({
      level: 'S',
      releasableTo: ['GBR'],
    });
    expect(joinLabels({ level: 'S', releasableTo: ['GBR'] }, { level: 'C' }, scheme)).toEqual({
      level: 'S',
      releasableTo: ['GBR'],
    });
    // disjoint lists leave the owner countries only, never "unrestricted"
    const disjoint = joinLabels(
      { level: 'S', releasableTo: ['GBR'] },
      { level: 'S', releasableTo: ['CAN'] },
      scheme,
    );
    expect(disjoint).toEqual({ level: 'S', releasableTo: [] });
    expect(dominates(party(3, [], ['GBR', 'CAN']), disjoint!, scheme)).toBe('releasability');
    expect(dominates(party(3, [], ['USA']), disjoint!, scheme)).toBeUndefined();
  });

  it('does not alias its inputs', () => {
    const a: ClassificationLabel = { level: 'S', compartments: ['si'], releasableTo: ['GBR'] };
    const joined = joinLabels(a, undefined, scheme)!;
    joined.compartments!.push('tk');
    joined.releasableTo!.push('CAN');
    expect(a).toEqual({ level: 'S', compartments: ['si'], releasableTo: ['GBR'] });
  });

  it('keeps an invalid input so every party is refused (fail closed)', () => {
    const top = party(3, ['si', 'tk', 'hcs'], ['USA', 'GBR']);
    const invalidLabels = [
      { level: 'X' },
      { level: 'S', compartments: ['gamma'] },
      { level: 'S', caveats: ['NOFORN'] },
      'TS',
    ] as unknown as ClassificationLabel[];
    for (const bad of invalidLabels) {
      for (const joined of [
        joinLabels({ level: 'U' }, bad, scheme),
        joinLabels(bad, { level: 'TS' }, scheme),
        joinLabels(bad, undefined, scheme),
        joinLabels(undefined, bad, scheme),
      ]) {
        expect(joined).toBeDefined();
        expect(dominates(top, joined!, scheme)).toBe('invalid-label');
      }
    }
  });

  it('is commutative, idempotent and an upper bound of both (property check)', () => {
    const next = random(20261007);
    for (let round = 0; round < 500; round++) {
      const a = randomLabel(next);
      const b = randomLabel(next);
      const joined = joinLabels(a, b, scheme)!;
      expect(isValidClassificationLabel(joined, scheme)).toBe(true);
      expect(joinLabels(b, a, scheme)).toEqual(joined);
      expect(joinLabels(joined, joined, scheme)).toEqual(joined);
      expect(joinLabels(joined, a, scheme)).toEqual(joined);
      expect(labelCovers(joined, a, scheme)).toBe(true);
      expect(labelCovers(joined, b, scheme)).toBe(true);
      // never lowers: whoever may read the join may read both inputs
      for (let check = 0; check < 5; check++) {
        const reader = randomParty(next);
        if (dominates(reader, joined, scheme) === undefined) {
          expect(dominates(reader, a, scheme)).toBeUndefined();
          expect(dominates(reader, b, scheme)).toBeUndefined();
        }
      }
    }
  });
});

describe('dominates', () => {
  it('level: the party rank must be at least the label rank', () => {
    expect(dominates(party(2), { level: 'S' }, scheme)).toBeUndefined();
    expect(dominates(party(3), { level: 'S' }, scheme)).toBeUndefined();
    expect(dominates(party(1), { level: 'S' }, scheme)).toBe('level');
    // no clearance (-1) reads only unlabeled resources: even the lowest level is refused
    expect(dominates(party(-1), { level: 'U' }, scheme)).toBe('level');
    expect(dominates(party(0), { level: 'U' }, scheme)).toBeUndefined();
    for (const rank of [Number.NaN, Number.POSITIVE_INFINITY, 2.5, '3' as unknown as number])
      expect(dominates(party(rank), { level: 'U' }, scheme)).toBe('level');
    expect(dominates(null as unknown as ClearanceParty, { level: 'U' }, scheme)).toBe('level');
  });

  it('compartment: the party must be read into every compartment of the label', () => {
    const label = { level: 'TS', compartments: ['si', 'tk'] };
    expect(dominates(party(3, ['si', 'tk']), label, scheme)).toBeUndefined();
    expect(dominates(party(3, ['si', 'tk', 'hcs']), label, scheme)).toBeUndefined();
    expect(dominates(party(3, ['si']), label, scheme)).toBe('compartment');
    expect(dominates(party(3, []), label, scheme)).toBe('compartment');
    expect(dominates(party(3, ['SI', 'TK']), label, scheme)).toBe('compartment');
    // level is checked before compartments
    expect(dominates(party(2, []), label, scheme)).toBe('level');
    // party compartments that are not a set count as none
    const malformed = { ...party(3), compartments: undefined } as unknown as ClearanceParty;
    expect(dominates(malformed, label, scheme)).toBe('compartment');
    expect(dominates(malformed, { level: 'TS' }, scheme)).toBeUndefined();
  });

  it('noforn: the party must be a citizen of an owner country', () => {
    const label = { level: 'S', noforn: true };
    expect(dominates(party(2, [], ['USA']), label, scheme)).toBeUndefined();
    expect(dominates(party(2, [], ['GBR', 'USA']), label, scheme)).toBeUndefined();
    expect(dominates(party(2, [], ['GBR']), label, scheme)).toBe('noforn');
    expect(dominates(party(2, [], []), label, scheme)).toBe('noforn');
    expect(dominates(party(2, [], ['usa']), label, scheme)).toBe('noforn');
    const owners = validateScheme({ ...scheme, ownerCountries: ['USA', 'GBR'] });
    expect(dominates(party(2, [], ['GBR']), label, owners)).toBeUndefined();
    const ukEyes = classificationTemplates.uk;
    expect(
      dominates(party(1, [], ['GBR']), { level: 'SECRET', noforn: true }, ukEyes),
    ).toBeUndefined();
    expect(dominates(party(1, [], ['USA']), { level: 'SECRET', noforn: true }, ukEyes)).toBe(
      'noforn',
    );
  });

  it('releasability: citizenship must meet releasableTo or the owner countries', () => {
    const label = { level: 'S', releasableTo: ['GBR', 'CAN'] };
    expect(dominates(party(2, [], ['GBR']), label, scheme)).toBeUndefined();
    expect(dominates(party(2, [], ['CAN']), label, scheme)).toBeUndefined();
    expect(dominates(party(2, [], ['USA']), label, scheme)).toBeUndefined();
    expect(dominates(party(2, [], ['FRA', 'CAN']), label, scheme)).toBeUndefined();
    expect(dominates(party(2, [], ['FRA']), label, scheme)).toBe('releasability');
    expect(dominates(party(2, [], []), label, scheme)).toBe('releasability');
    // empty list: owner countries only
    expect(dominates(party(2, [], ['GBR']), { level: 'S', releasableTo: [] }, scheme)).toBe(
      'releasability',
    );
    expect(
      dominates(party(2, [], ['USA']), { level: 'S', releasableTo: [] }, scheme),
    ).toBeUndefined();
    // no releasableTo: unrestricted
    expect(dominates(party(2, [], ['FRA']), { level: 'S' }, scheme)).toBeUndefined();
    // NATO has no owner countries: only the listed countries
    expect(
      dominates(party(3, [], ['FRA']), { level: 'NS', releasableTo: ['FRA', 'DEU'] }, nato),
    ).toBeUndefined();
    expect(
      dominates(party(3, [], ['USA']), { level: 'NS', releasableTo: ['FRA', 'DEU'] }, nato),
    ).toBe('releasability');
    expect(dominates(party(3, [], ['USA']), { level: 'NS', releasableTo: [] }, nato)).toBe(
      'releasability',
    );
    expect(dominates(party(3, [], ['USA']), { level: 'NS' }, nato)).toBeUndefined();
  });

  it('noforn together with releasableTo still means owner citizens only', () => {
    const label = { level: 'S', noforn: true, releasableTo: ['GBR'] };
    expect(dominates(party(2, [], ['GBR']), label, scheme)).toBe('noforn');
    expect(dominates(party(2, [], ['USA']), label, scheme)).toBeUndefined();
  });

  it('invalid-label: refuses everyone, before any other dimension', () => {
    const top = party(19, ['si', 'tk', 'hcs'], ['USA', 'GBR', 'CAN']);
    const refused: Array<[unknown, ClassificationSchemeDefinition]> = [
      [{ level: 'X' }, scheme],
      [{ level: 'TS', compartments: ['gamma'] }, scheme],
      [{ level: 'TS', compartments: ['si', 'si'] }, scheme],
      [{ level: 'TS', releasableTo: ['gbr'] }, scheme],
      [{ level: 'TS', classification: 'U' }, scheme],
      [{ level: 'restricted', noforn: true }, corporate],
      [{ level: 'restricted', releasableTo: [] }, corporate],
      [{ level: 'TS' }, classificationTemplates.uk],
      ['TS', scheme],
      [null, scheme],
      [undefined, scheme],
    ];
    for (const [label, definition] of refused)
      expect(dominates(top, label as ClassificationLabel, definition)).toBe('invalid-label');
    expect(dominates(party(-1), { level: 'X' } as ClassificationLabel, scheme)).toBe(
      'invalid-label',
    );
  });

  it('corporate scheme: level only', () => {
    expect(dominates(party(2, [], []), { level: 'confidential' }, corporate)).toBeUndefined();
    expect(dominates(party(1, [], []), { level: 'confidential' }, corporate)).toBe('level');
  });
});

describe('labelCovers', () => {
  it('is true only when the new label does not lower any dimension', () => {
    const current: ClassificationLabel = {
      level: 'S',
      compartments: ['si'],
      releasableTo: ['GBR', 'CAN'],
    };
    expect(labelCovers(current, current, scheme)).toBe(true);
    expect(labelCovers({ ...current, level: 'TS' }, current, scheme)).toBe(true);
    expect(labelCovers({ ...current, compartments: ['si', 'tk'] }, current, scheme)).toBe(true);
    expect(labelCovers({ ...current, releasableTo: ['GBR'] }, current, scheme)).toBe(true);
    expect(labelCovers({ ...current, releasableTo: [] }, current, scheme)).toBe(true);
    expect(labelCovers({ ...current, noforn: true }, current, scheme)).toBe(true);
    // owner countries are always releasable, so naming them adds nothing
    expect(labelCovers({ ...current, releasableTo: ['CAN', 'GBR', 'USA'] }, current, scheme)).toBe(
      true,
    );

    expect(labelCovers({ ...current, level: 'C' }, current, scheme)).toBe(false);
    expect(labelCovers({ ...current, compartments: [] }, current, scheme)).toBe(false);
    expect(labelCovers({ ...current, compartments: ['tk'] }, current, scheme)).toBe(false);
    expect(labelCovers({ ...current, releasableTo: ['GBR', 'CAN', 'AUS'] }, current, scheme)).toBe(
      false,
    );
    expect(labelCovers({ level: 'S', compartments: ['si'] }, current, scheme)).toBe(false);
    expect(labelCovers({ level: 'TS' }, { level: 'S', noforn: true }, scheme)).toBe(false);
    expect(
      labelCovers({ level: 'TS', releasableTo: [] }, { level: 'S', noforn: true }, scheme),
    ).toBe(false);
    // invalid on either side: never covered
    expect(labelCovers({ level: 'X' }, current, scheme)).toBe(false);
    expect(labelCovers(current, { level: 'X' }, scheme)).toBe(false);
  });
});
