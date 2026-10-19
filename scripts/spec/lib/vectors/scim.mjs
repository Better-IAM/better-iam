// SCIM 2.0 (RFC 7644) filter vectors: parsing, evaluation against rendered resources, sorting, projection.
import { dist } from '../util.mjs';
import { VectorFile } from './context.mjs';

const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

const alice = {
  schemas: [USER, ENTERPRISE],
  id: 'u1',
  externalId: 'EXT-1',
  userName: 'Alice@Example.com',
  name: { givenName: 'Alice', familyName: 'Smith', formatted: 'Alice Smith' },
  displayName: 'Alice Smith',
  active: true,
  title: 'Engineer',
  emails: [
    { value: 'alice@example.com', type: 'work', primary: true },
    { value: 'alice@home.example', type: 'home' },
  ],
  groups: [{ value: 'g1', display: 'Engineering' }],
  [ENTERPRISE]: { employeeNumber: '1001', department: 'R&D', manager: { value: 'u2' } },
  meta: { resourceType: 'User', created: '2026-01-01T00:00:00.000Z', version: 'W/"3"' },
};
const bob = {
  schemas: [USER],
  id: 'u2',
  userName: 'bob@example.com',
  name: { givenName: 'Bob', familyName: 'Jones' },
  active: false,
  emails: [{ value: 'bob@example.com', type: 'work' }],
  meta: { resourceType: 'User', created: '2025-06-01T00:00:00.000Z', version: 'W/"1"' },
};
const carol = {
  schemas: [USER],
  id: 'u3',
  userName: 'carol@example.com',
  displayName: '',
  active: true,
  emails: [],
  meta: { resourceType: 'User', created: '2026-02-01T00:00:00.000Z', version: 'W/"1"' },
};

export async function scimVectors(output) {
  const filter = await dist('scim', 'filter.js');
  const file = new VectorFile('scim-filter', {
    description:
      'SCIM filters (RFC 7644 section 3.4.2.2) as the SCIM server reads them: parseFilterExpression -> FilterNode (attribute paths lowercased, schema URNs stripped except the enterprise extension, which stays one segment), invalid filters throw IamError invalidFilter (400). `matches` cases evaluate the parsed filter against three rendered users (ids u1, u2, u3) and list the ids that pass. id, externalId and members.value compare case-exactly; everything else ignores case.',
    source:
      'packages/scim/src/filter.ts#parseFilterExpression,evaluateFilter,attributePath,sortResources,projectResource,attributeList',
    notes: { resources: [alice, bob, carol] },
  });
  const users = [alice, bob, carol];
  const filters = [
    'userName eq "alice@example.com"',
    'userName eq "ALICE@EXAMPLE.COM"',
    'id eq "U1"',
    'id eq "u1"',
    'externalId eq "ext-1"',
    'userName ne "bob@example.com"',
    'userName co "example"',
    'userName sw "ali"',
    'userName ew ".com"',
    'title pr',
    'displayName pr',
    'emails pr',
    'name.familyName eq "Smith"',
    'name.givenName sw "B" or name.givenName sw "A"',
    'active eq true',
    'active eq false and userName co "bob"',
    'not (active eq true)',
    'emails[type eq "work" and value co "alice"]',
    'emails[type eq "home"]',
    'emails.value ew "home.example"',
    'emails.type ne "home"',
    'meta.created gt "2025-12-31T00:00:00.000Z"',
    'meta.created le "2026-01-01T00:00:00.000Z"',
    'urn:ietf:params:scim:schemas:core:2.0:User:userName eq "bob@example.com"',
    `${ENTERPRISE}:employeeNumber eq "1001"`,
    `${ENTERPRISE}:manager.value eq "u2"`,
    'groups.value eq "g1"',
    'groups[display eq "engineering"]',
    'title eq null',
    'title ne null',
    '(userName sw "a" or userName sw "b") and active eq true',
    'userName eq "a\\"quoted"',
    'USERNAME EQ "alice@example.com"',
    'userName gt 5',
    // invalid filters
    '',
    '   ',
    'userName',
    'userName eq',
    'userName xx "a"',
    'userName eq "unterminated',
    'userName eq "a" and',
    '(userName eq "a"',
    'userName eq "a")',
    'active eq "yes"',
    'active gt true',
    'userName co 5',
    'userName eq {"a":1}',
    'userName eq [1]',
    'urn:example:custom:attr eq "x"',
    'a.b.c.d eq "x"',
    '1abc eq "x"',
    'userName eq "a" # comment',
    'x'.repeat(2049),
    Array.from({ length: 65 }, (_, i) => `userName eq "${i}"`).join(' or '),
    `${'('.repeat(18)}userName eq "a"${')'.repeat(18)}`,
    `${ENTERPRISE}: eq "x"`,
  ];
  for (const [index, value] of filters.entries()) {
    const label = `${String(index + 1).padStart(2, '0')} ${value.length > 60 ? `${value.slice(0, 57)}...` : value}`;
    await file.add(`parse ${label}`, { filter: value }, (input) =>
      filter.parseFilterExpression(input.filter),
    );
    await file.add(`matches ${label}`, { filter: value }, (input) => {
      const node = filter.parseFilterExpression(input.filter);
      return users.filter((user) => filter.evaluateFilter(node, user)).map((user) => user.id);
    });
  }
  for (const raw of [
    'userName',
    'name.givenName',
    'Emails.Value',
    `${USER}:userName`,
    ENTERPRISE,
    `${ENTERPRISE}:manager.value`,
    'urn:x:y',
    'a b',
    `${USER}:`,
  ])
    await file.add(`attributePath ${raw}`, { raw }, (input) => filter.attributePath(input.raw));
  for (const [sortBy, sortOrder] of [
    ['userName', undefined],
    ['userName', 'descending'],
    ['name.familyName', 'ascending'],
    ['emails', 'ascending'],
    ['displayName', 'descending'],
    ['title', 'ascending'],
    ['userName', 'sideways'],
    [undefined, undefined],
  ])
    await file.add(
      `sort ${sortBy ?? 'none'} ${sortOrder ?? 'default'}`,
      { sortBy, sortOrder },
      (input) =>
        filter.sortResources([...users], input.sortBy, input.sortOrder).map((user) => user.id),
    );
  for (const [name, attributes, excluded] of [
    ['attributes userName', ['userName'], undefined],
    ['attributes sub-attribute', ['name.givenName', 'emails.value'], undefined],
    ['attributes enterprise', [`${ENTERPRISE}:employeeNumber`], undefined],
    ['attributes always id and schemas', ['id', 'schemas'], undefined],
    ['excluded emails', undefined, ['emails']],
    ['excluded sub-attribute', undefined, ['emails.type', 'name.formatted']],
    ['excluded id is ignored', undefined, ['id']],
    ['both lists', ['userName'], ['emails']],
    ['none', undefined, undefined],
  ])
    await file.add(`project ${name}`, { resource: alice, attributes, excluded }, (input) =>
      filter.projectResource(structuredClone(input.resource), input.attributes, input.excluded),
    );
  for (const value of [
    'userName,emails',
    ' userName , name.givenName ,',
    '',
    null,
    ['a', 'b'],
    Array.from({ length: 51 }, () => 'a').join(','),
    [1],
  ])
    await file.add(`attributeList ${JSON.stringify(value)?.slice(0, 40)}`, { value }, (input) =>
      filter.attributeList(input.value),
    );
  return { 'scim-filter': file.write(output) };
}
