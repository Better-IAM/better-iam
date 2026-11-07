// Writes windows.json: insideWindow (packages/server/src/context.ts) over windows, time zones and instants around DST
// changes, for the Go access window differential test (context_test.go).
// Regenerate (after building the TypeScript packages): node go/server/testdata/windows.mjs > go/server/testdata/windows.json
import { insideWindow } from '../../../packages/server/dist/context.js';

const zones = ['UTC', 'America/New_York', 'Europe/Berlin', 'Asia/Kolkata', 'Australia/Lord_Howe', 'Pacific/Chatham',
  'america/los_angeles', 'US/Eastern', '+05:30', '-0800', 'Etc/GMT+5'];
const windows = [
  { from: '09:00', to: '17:00' },
  { from: '22:00', to: '06:00' },
  { from: '00:00', to: '23:59', days: [0, 6] },
  { from: '17:30', to: '02:15', days: [1, 2, 3, 4, 5] },
  { from: '01:30', to: '03:30', days: [0] },
];
const starts = [Date.UTC(2026, 2, 7, 20), Date.UTC(2026, 2, 28, 20), Date.UTC(2026, 9, 31, 20)];
const cases = [];
for (const timeZone of zones)
  for (const window of windows)
    for (const start of starts)
      for (let step = 0; step < 30; step++) {
        const at = start + step * 41 * 60_000;
        cases.push({ window: { ...window, timeZone }, at, inside: insideWindow({ ...window, timeZone }, at) });
      }
process.stdout.write(JSON.stringify({ node: process.version, tz: process.versions.tz, cases }) + '\n');
