/**
 * Security classification: the pure lattice behind clearances and mandatory access control. A tenant's scheme orders
 * classification levels by rank and lists its compartments (need-to-know control systems) and the dissemination
 * controls it uses. A label marks one resource. A party (a person or agent taking part in a decision) may read a
 * labeled resource only when its adjudicated clearance dominates the label: the Bell-LaPadula simple security property
 * (no read up). Everything here is pure and browser-safe; the server holds schemes, clearances and labels, and fails
 * closed on anything this module calls invalid.
 */
import { IamError } from './index.js';

/** One level of a scheme. Ranks order levels; the lowest (rank 0) is the public or unclassified level. */
export interface ClassificationLevel {
  /** Opaque, stable identifier (`classificationIdPattern`), unique within the scheme ignoring case. */
  id: string;
  /** Display name, such as `TOP SECRET`. */
  name: string;
  rank: number;
  /** Short marking for banners, such as `TS`. */
  abbreviation?: string;
}
/** A compartment (a control system or special access program). Ids are opaque; names may themselves be sensitive. */
export interface Compartment {
  id: string;
  name: string;
}
export interface ClassificationSchemeDefinition {
  /** 2 to 20 levels in rank order: unique ids, integer ranks strictly increasing from 0. */
  levels: ClassificationLevel[];
  /** 0 to 200 compartments with unique ids. */
  compartments: Compartment[];
  /** ISO 3166-1 alpha-3 codes (upper case) of the countries that own the information; NOFORN means their citizens only. */
  ownerCountries: string[];
  /** The dissemination controls labels of this scheme may carry. */
  caveats: Array<'NOFORN' | 'RELTO'>;
}
/**
 * The classification of one resource. Absent `compartments` means none; absent `releasableTo` means unrestricted
 * releasability, while an empty list means releasable to citizens of the owner countries only.
 */
export interface ClassificationLabel {
  /** A level id of the scheme. */
  level: string;
  /** Compartment ids the reader must be read into, every one of them. */
  compartments?: string[];
  /** Not releasable to foreign nationals: readers must be citizens of an owner country. Needs the NOFORN caveat. */
  noforn?: boolean;
  /** REL TO: alpha-3 codes of the countries whose citizens may read it besides the owners. Needs the RELTO caveat. */
  releasableTo?: string[];
}
/** One person or agent taking part in a decision, as their adjudicated clearance stands at decision time. */
export interface ClearanceParty {
  identityId: string;
  /** The rank of the cleared level; -1 = no clearance (the party can read only unlabeled resources). */
  rank: number;
  /** Compartment ids the party is currently read into. */
  compartments: ReadonlySet<string>;
  /** Alpha-3 codes from the adjudicated clearance record, never from identity attributes. */
  citizenship: ReadonlySet<string>;
}
/** Which dimension a party failed. Only officers see it (`clearances.explain`); decisions say CLEARANCE_REQUIRED. */
export type DominanceFailure =
  | 'level'
  | 'compartment'
  | 'noforn'
  | 'releasability'
  | 'invalid-label';
/** The built-in starting points for a tenant's scheme (`classificationTemplates`). */
export type ClassificationTemplateName = 'us' | 'uk' | 'nato' | 'corporate';

/** Level and compartment ids: an ASCII letter or digit, then letters, digits, `.`, `_`, `:` or `-` (64 at most). */
export const classificationIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const countryPattern = /^[A-Z]{3}$/;

/** The bounds `validateScheme` and `validateLabel` enforce. */
export const classificationLimits = {
  minLevels: 2,
  maxLevels: 20,
  maxRank: 999,
  maxCompartments: 200,
  maxOwnerCountries: 64,
  maxReleasableTo: 300,
  maxLevelNameLength: 64,
  maxCompartmentNameLength: 128,
  maxAbbreviationLength: 16,
} as const;

const caveatNames: ReadonlySet<string> = new Set(['NOFORN', 'RELTO']);
const schemeKeys = ['levels', 'compartments', 'ownerCountries', 'caveats'];
const levelKeys = ['id', 'name', 'rank', 'abbreviation'];
const compartmentKeys = ['id', 'name'];
const labelKeys = ['level', 'compartments', 'noforn', 'releasableTo'];

function invalid(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}
const plainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
const onlyKeys = (value: Record<string, unknown>, allowed: readonly string[]): boolean =>
  Object.keys(value).every((key) => allowed.includes(key)) &&
  Object.getOwnPropertySymbols(value).length === 0;
/** An id that cannot be mistaken for an inherited property when someone keys a plain object by it. */
const identifier = (value: unknown): value is string =>
  typeof value === 'string' && classificationIdPattern.test(value) && !(value in Object.prototype);

/**
 * Display text: trimmed and non-empty, without control, line or paragraph separator, bidirectional override,
 * zero-width-no-break or unpaired surrogate characters (names reach consoles, emails and audit views).
 */
function text(value: unknown, max: number): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > max ||
    value.trim() !== value
  )
    return false;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (
      code < 0x20 ||
      (code >= 0x7f && code <= 0x9f) ||
      code === 0x061c ||
      code === 0x200e ||
      code === 0x200f ||
      (code >= 0x2028 && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069) ||
      code === 0xfeff
    )
      return false;
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

/** True when every string is distinct, ignoring case. */
function distinct(values: readonly string[]): boolean {
  return new Set(values.map((value) => value.toLowerCase())).size === values.length;
}

/**
 * Validates a scheme definition and returns a fresh copy (absent `compartments`, `ownerCountries` and `caveats` read
 * as empty). Throws `IamError` `INVALID_INPUT`. Messages name positions, never compartment names or submitted values.
 */
export function validateScheme(input: unknown): ClassificationSchemeDefinition {
  if (!plainObject(input)) invalid('The classification scheme must be an object');
  if (!onlyKeys(input, schemeKeys)) invalid('Unknown classification scheme field');
  const { levels, compartments = [], ownerCountries = [], caveats = [] } = input;
  if (
    !Array.isArray(levels) ||
    levels.length < classificationLimits.minLevels ||
    levels.length > classificationLimits.maxLevels
  )
    invalid(
      `A classification scheme needs ${classificationLimits.minLevels} to ${classificationLimits.maxLevels} levels`,
    );
  const outLevels: ClassificationLevel[] = [];
  for (let index = 0; index < levels.length; index++) {
    const level: unknown = levels[index];
    if (!plainObject(level)) invalid(`levels[${index}] must be an object`);
    if (!onlyKeys(level, levelKeys)) invalid(`levels[${index}] has an unknown field`);
    if (!identifier(level.id)) invalid(`levels[${index}].id is not a valid identifier`);
    if (!text(level.name, classificationLimits.maxLevelNameLength))
      invalid(
        `levels[${index}].name must be 1 to ${classificationLimits.maxLevelNameLength} printable characters`,
      );
    const { rank } = level;
    if (
      typeof rank !== 'number' ||
      !Number.isSafeInteger(rank) ||
      rank > classificationLimits.maxRank
    )
      invalid(`levels[${index}].rank must be an integer from 0 to ${classificationLimits.maxRank}`);
    const previous = outLevels[index - 1];
    if (previous ? rank <= previous.rank : rank !== 0)
      invalid(
        'Level ranks must start at 0 and strictly increase in the order the levels are listed',
      );
    if (
      level.abbreviation !== undefined &&
      !text(level.abbreviation, classificationLimits.maxAbbreviationLength)
    )
      invalid(
        `levels[${index}].abbreviation must be 1 to ${classificationLimits.maxAbbreviationLength} printable characters`,
      );
    outLevels.push({
      id: level.id,
      name: level.name,
      rank,
      ...(level.abbreviation !== undefined ? { abbreviation: level.abbreviation as string } : {}),
    });
  }
  if (!distinct(outLevels.map((level) => level.id)))
    invalid('Level ids must be unique, ignoring case');
  if (!distinct(outLevels.map((level) => level.name)))
    invalid('Level names must be unique, ignoring case');
  const abbreviations = outLevels.flatMap((level) =>
    level.abbreviation ? [level.abbreviation] : [],
  );
  if (!distinct(abbreviations)) invalid('Level abbreviations must be unique, ignoring case');

  if (!Array.isArray(compartments) || compartments.length > classificationLimits.maxCompartments)
    invalid(
      `A classification scheme has at most ${classificationLimits.maxCompartments} compartments`,
    );
  const outCompartments: Compartment[] = [];
  for (let index = 0; index < compartments.length; index++) {
    const compartment: unknown = compartments[index];
    if (!plainObject(compartment)) invalid(`compartments[${index}] must be an object`);
    if (!onlyKeys(compartment, compartmentKeys))
      invalid(`compartments[${index}] has an unknown field`);
    if (!identifier(compartment.id)) invalid(`compartments[${index}].id is not a valid identifier`);
    if (!text(compartment.name, classificationLimits.maxCompartmentNameLength))
      invalid(
        `compartments[${index}].name must be 1 to ${classificationLimits.maxCompartmentNameLength} printable characters`,
      );
    outCompartments.push({ id: compartment.id, name: compartment.name });
  }
  if (!distinct(outCompartments.map((compartment) => compartment.id)))
    invalid('Compartment ids must be unique, ignoring case');
  if (!distinct(outCompartments.map((compartment) => compartment.name)))
    invalid('Compartment names must be unique, ignoring case');

  if (
    !Array.isArray(ownerCountries) ||
    ownerCountries.length > classificationLimits.maxOwnerCountries
  )
    invalid(`ownerCountries must list at most ${classificationLimits.maxOwnerCountries} countries`);
  const outOwners: string[] = [];
  for (const country of ownerCountries as unknown[]) {
    if (typeof country !== 'string' || !countryPattern.test(country))
      invalid('ownerCountries must be ISO 3166-1 alpha-3 codes in upper case');
    outOwners.push(country);
  }
  if (new Set(outOwners).size !== outOwners.length)
    invalid('ownerCountries must not repeat a country');

  if (!Array.isArray(caveats)) invalid('caveats must be a list');
  const outCaveats: Array<'NOFORN' | 'RELTO'> = [];
  for (const caveat of caveats as unknown[]) {
    if (typeof caveat !== 'string' || !caveatNames.has(caveat))
      invalid('caveats may be NOFORN and RELTO only');
    outCaveats.push(caveat as 'NOFORN' | 'RELTO');
  }
  if (new Set(outCaveats).size !== outCaveats.length) invalid('caveats must not repeat a caveat');
  if (outCaveats.includes('NOFORN') && outOwners.length === 0)
    invalid('The NOFORN caveat needs at least one owner country');

  return {
    levels: outLevels,
    compartments: outCompartments,
    ownerCountries: outOwners,
    caveats: outCaveats,
  };
}

/** The checked, normalized label, or why it is invalid for the scheme (never echoing submitted values). */
function checkLabel(
  label: unknown,
  scheme: ClassificationSchemeDefinition,
): ClassificationLabel | string {
  if (!plainObject(label)) return 'A classification label must be an object';
  if (!onlyKeys(label, labelKeys)) return 'Unknown classification label field';
  const { level, compartments, noforn, releasableTo } = label;
  if (typeof level !== 'string' || !scheme.levels.some((known) => known.id === level))
    return 'The label names a level the scheme does not define';
  let outCompartments: string[] = [];
  if (compartments !== undefined) {
    if (!Array.isArray(compartments) || compartments.length > classificationLimits.maxCompartments)
      return 'Label compartments must be a list of compartment ids';
    const known = new Set(scheme.compartments.map((compartment) => compartment.id));
    const seen = new Set<string>();
    for (const compartment of compartments as unknown[]) {
      if (typeof compartment !== 'string' || !known.has(compartment))
        return 'The label names a compartment the scheme does not define';
      if (seen.has(compartment)) return 'Label compartments must not repeat';
      seen.add(compartment);
    }
    outCompartments = [...seen].sort();
  }
  if (noforn !== undefined && typeof noforn !== 'boolean') return 'Label noforn must be a boolean';
  if (noforn === true && !scheme.caveats.includes('NOFORN'))
    return 'The scheme does not use the NOFORN caveat';
  let outReleasable: string[] | undefined;
  if (releasableTo !== undefined) {
    if (!scheme.caveats.includes('RELTO')) return 'The scheme does not use the RELTO caveat';
    if (!Array.isArray(releasableTo) || releasableTo.length > classificationLimits.maxReleasableTo)
      return `Label releasableTo must list at most ${classificationLimits.maxReleasableTo} countries`;
    const seen = new Set<string>();
    for (const country of releasableTo as unknown[]) {
      if (typeof country !== 'string' || !countryPattern.test(country))
        return 'Label releasableTo must hold ISO 3166-1 alpha-3 codes in upper case';
      if (seen.has(country)) return 'Label releasableTo must not repeat a country';
      seen.add(country);
    }
    outReleasable = [...seen].sort();
  }
  return {
    level,
    ...(outCompartments.length ? { compartments: outCompartments } : {}),
    ...(noforn === true ? { noforn: true } : {}),
    ...(outReleasable ? { releasableTo: outReleasable } : {}),
  };
}

/**
 * Validates a label against a scheme and returns it normalized: compartments and countries sorted, an empty
 * compartment list and `noforn: false` dropped, an empty `releasableTo` kept (it means owner countries only).
 * Throws `IamError` `INVALID_INPUT` for an unknown field, level, compartment or caveat, a caveat the scheme does not
 * use, a malformed country code, or a repeated entry.
 */
export function validateLabel(
  label: unknown,
  scheme: ClassificationSchemeDefinition,
): ClassificationLabel {
  const checked = checkLabel(label, scheme);
  if (typeof checked === 'string') invalid(checked);
  return checked;
}

/** True when `label` is a valid label of the scheme; the non-throwing form of `validateLabel`. */
export function isValidClassificationLabel(
  label: unknown,
  scheme: ClassificationSchemeDefinition,
): label is ClassificationLabel {
  return typeof checkLabel(label, scheme) !== 'string';
}

/** The rank of the label's level in the scheme; undefined when the level is unknown (callers fail closed). */
export function labelRank(
  label: ClassificationLabel,
  scheme: ClassificationSchemeDefinition,
): number | undefined {
  if (!plainObject(label) || typeof label.level !== 'string') return undefined;
  return scheme.levels.find((level) => level.id === label.level)?.rank;
}

/**
 * The least restrictive label at least as restrictive as both: the higher level, the union of compartments, NOFORN
 * when either has it, and the intersection of `releasableTo` lists (an absent list is unrestricted, so the other list
 * stands; disjoint lists leave an empty list, owner countries only). Absent (`undefined` or `null`) inputs are
 * ignored; both absent gives undefined. Never lowers either input. An input that is not a valid label of the scheme
 * makes the result that input unchanged, so it stays invalid and `dominates` refuses every party (fail closed).
 */
export function joinLabels(
  a: ClassificationLabel | undefined,
  b: ClassificationLabel | undefined,
  scheme: ClassificationSchemeDefinition,
): ClassificationLabel | undefined {
  const left = a == null ? undefined : checkLabel(a, scheme);
  if (typeof left === 'string') return a as ClassificationLabel;
  const right = b == null ? undefined : checkLabel(b, scheme);
  if (typeof right === 'string') return b as ClassificationLabel;
  if (!left || !right) return left ?? right;
  const level =
    (labelRank(left, scheme) ?? 0) >= (labelRank(right, scheme) ?? 0) ? left.level : right.level;
  const compartments = [
    ...new Set([...(left.compartments ?? []), ...(right.compartments ?? [])]),
  ].sort();
  let releasableTo: string[] | undefined;
  if (left.releasableTo && right.releasableTo) {
    const other = new Set(right.releasableTo);
    releasableTo = left.releasableTo.filter((country) => other.has(country));
  } else releasableTo = left.releasableTo ?? right.releasableTo;
  return {
    level,
    ...(compartments.length ? { compartments } : {}),
    ...(left.noforn || right.noforn ? { noforn: true } : {}),
    ...(releasableTo ? { releasableTo: [...releasableTo] } : {}),
  };
}

/** A set view of a party's ids; anything that is neither a set nor a list counts as empty (fail closed). */
function held(values: unknown): ReadonlySet<string> {
  if (values instanceof Set) return values as ReadonlySet<string>;
  if (Array.isArray(values)) return new Set(values.filter((value) => typeof value === 'string'));
  return new Set();
}

/** The countries whose citizens may read a valid label, or undefined when releasability is unrestricted. */
function releasableSet(
  label: ClassificationLabel,
  scheme: ClassificationSchemeDefinition,
): Set<string> | undefined {
  if (label.noforn) return new Set(scheme.ownerCountries);
  if (label.releasableTo) return new Set([...label.releasableTo, ...scheme.ownerCountries]);
  return undefined;
}

/**
 * Whether a party may read a resource carrying `label` (no read up). Returns undefined when it may, or the first
 * dimension it fails: `invalid-label` (the label is not valid for the scheme), `level` (rank below the label's, or no
 * usable rank), `compartment` (not read into every compartment), `noforn` (no citizenship of an owner country) or
 * `releasability` (no citizenship among `releasableTo` and the owner countries).
 */
export function dominates(
  party: ClearanceParty,
  label: ClassificationLabel,
  scheme: ClassificationSchemeDefinition,
): DominanceFailure | undefined {
  const checked = checkLabel(label, scheme);
  if (typeof checked === 'string') return 'invalid-label';
  const required = labelRank(checked, scheme);
  if (
    required === undefined ||
    party === null ||
    typeof party !== 'object' ||
    typeof party.rank !== 'number' ||
    !Number.isSafeInteger(party.rank) ||
    party.rank < required
  )
    return 'level';
  const compartments = held(party.compartments);
  if ((checked.compartments ?? []).some((compartment) => !compartments.has(compartment)))
    return 'compartment';
  const citizenship = held(party.citizenship);
  if (checked.noforn && !scheme.ownerCountries.some((country) => citizenship.has(country)))
    return 'noforn';
  if (
    checked.releasableTo &&
    ![...checked.releasableTo, ...scheme.ownerCountries].some((country) => citizenship.has(country))
  )
    return 'releasability';
  return undefined;
}

/**
 * True when replacing `lower` with `upper` never declassifies: both are valid labels of the scheme, `upper` is at
 * least as high, carries every compartment of `lower`, keeps NOFORN when `lower` has it, and is releasable to no
 * country `lower` is not (owner countries always count). Anything else needs a declassification.
 */
export function labelCovers(
  upper: ClassificationLabel,
  lower: ClassificationLabel,
  scheme: ClassificationSchemeDefinition,
): boolean {
  const high = checkLabel(upper, scheme);
  const low = checkLabel(lower, scheme);
  if (typeof high === 'string' || typeof low === 'string') return false;
  if ((labelRank(high, scheme) ?? -1) < (labelRank(low, scheme) ?? Infinity)) return false;
  const compartments = new Set(high.compartments ?? []);
  if ((low.compartments ?? []).some((compartment) => !compartments.has(compartment))) return false;
  if (low.noforn && !high.noforn) return false;
  const highReach = releasableSet(high, scheme);
  const lowReach = releasableSet(low, scheme);
  if (!lowReach) return true;
  return highReach !== undefined && [...highReach].every((country) => lowReach.has(country));
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

/**
 * Starting points for `clearances.defineScheme({ template })`, frozen (copy with `validateScheme` before changing).
 * Compartments are always empty: tenants add their own.
 * - `us`: U, C, S, TS; owner USA; NOFORN and REL TO.
 * - `uk`: OFFICIAL, SECRET, TOP-SECRET; owner GBR; NOFORN (UK EYES ONLY) and REL TO.
 * - `nato`: NU, NR, NC, NS, CTS; NATO is not a country, so no owner countries and REL TO only.
 * - `corporate`: public, internal, confidential, restricted; no dissemination controls.
 */
export const classificationTemplates: Record<
  ClassificationTemplateName,
  ClassificationSchemeDefinition
> = deepFreeze({
  us: {
    levels: [
      { id: 'U', name: 'UNCLASSIFIED', rank: 0, abbreviation: 'U' },
      { id: 'C', name: 'CONFIDENTIAL', rank: 1, abbreviation: 'C' },
      { id: 'S', name: 'SECRET', rank: 2, abbreviation: 'S' },
      { id: 'TS', name: 'TOP SECRET', rank: 3, abbreviation: 'TS' },
    ],
    compartments: [],
    ownerCountries: ['USA'],
    caveats: ['NOFORN', 'RELTO'],
  },
  uk: {
    levels: [
      { id: 'OFFICIAL', name: 'OFFICIAL', rank: 0, abbreviation: 'O' },
      { id: 'SECRET', name: 'SECRET', rank: 1, abbreviation: 'S' },
      { id: 'TOP-SECRET', name: 'TOP SECRET', rank: 2, abbreviation: 'TS' },
    ],
    compartments: [],
    ownerCountries: ['GBR'],
    caveats: ['NOFORN', 'RELTO'],
  },
  nato: {
    levels: [
      { id: 'NU', name: 'NATO UNCLASSIFIED', rank: 0, abbreviation: 'NU' },
      { id: 'NR', name: 'NATO RESTRICTED', rank: 1, abbreviation: 'NR' },
      { id: 'NC', name: 'NATO CONFIDENTIAL', rank: 2, abbreviation: 'NC' },
      { id: 'NS', name: 'NATO SECRET', rank: 3, abbreviation: 'NS' },
      { id: 'CTS', name: 'COSMIC TOP SECRET', rank: 4, abbreviation: 'CTS' },
    ],
    compartments: [],
    ownerCountries: [],
    caveats: ['RELTO'],
  },
  corporate: {
    levels: [
      { id: 'public', name: 'Public', rank: 0 },
      { id: 'internal', name: 'Internal', rank: 1 },
      { id: 'confidential', name: 'Confidential', rank: 2 },
      { id: 'restricted', name: 'Restricted', rank: 3 },
    ],
    compartments: [],
    ownerCountries: [],
    caveats: [],
  },
});
