// Renders the Better IAM mark (components/logo.tsx) into every favicon and app icon the docs site and the console
// serve. Run it after changing the mark: `node apps/docs/scripts/generate-icons.mjs`. The outputs are committed.
//
//   favicon.ico            16, 32, 48 px ink tiles, for browsers and tools without SVG favicon support
//   icon.svg               the bare mark, ink on light tabs and white on dark ones (prefers-color-scheme)
//   apple-touch-icon.png   180 px, full bleed (iOS rounds the corners itself)
//   icon-192.png, icon-512.png, icon-maskable-512.png   web app manifest icons (app/manifest.ts)
import { mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const app = join(dirname(fileURLToPath(import.meta.url)), '..');
// sharp ships with Next.js for image optimization; resolve it through next instead of adding a dependency.
const sharp = createRequire(createRequire(join(app, 'package.json')).resolve('next/package.json'))(
  'sharp',
);

/** The mark from components/logo.tsx: a shield with a keyhole, on a 24 px grid, spanning y 1.75 to 22.25. */
const mark =
  'M12 1.75 3.75 4.9v6.02c0 5.02 3.44 9.6 8.25 11.33 4.81-1.73 8.25-6.31 8.25-11.33V4.9L12 1.75ZM10.84 11.83a2.35 2.35 0 1 1 2.32 0l.56 3.92h-3.44l.56-3.92Z';
const markHeight = 20.5;
const ink = '#121212';
const paper = '#fafafa';

/** The mark centered on a square ink tile. `fill` is the mark's height as a share of the tile; `radius` rounds the corners. */
function tile(size, { fill, radius = 0 }) {
  const scale = (size * fill) / markHeight;
  const offset = size / 2 - 12 * scale;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
  <rect width="${size}" height="${size}" rx="${size * radius}" fill="${ink}"/>
  <path transform="translate(${offset} ${offset}) scale(${scale})" fill="${paper}" fill-rule="evenodd" d="${mark}"/>
</svg>`;
}

const png = (svg) => sharp(Buffer.from(svg)).png({ compressionLevel: 9 }).toBuffer();

/** An ICO container holding PNG images, which every browser since IE 11 and Windows Vista reads. */
function ico(images) {
  const header = Buffer.alloc(6 + 16 * images.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach(({ size, data }, index) => {
    const entry = 6 + 16 * index;
    header.writeUInt8(size >= 256 ? 0 : size, entry);
    header.writeUInt8(size >= 256 ? 0 : size, entry + 1);
    header.writeUInt8(0, entry + 2);
    header.writeUInt8(0, entry + 3);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(data.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...images.map((image) => image.data)]);
}

// Small sizes get a larger mark so the keyhole survives at 16 px.
const favicon = ico(
  await Promise.all(
    [
      [16, 0.84],
      [32, 0.78],
      [48, 0.74],
    ].map(async ([size, fill]) => ({ size, data: await png(tile(size, { fill, radius: 0.22 })) })),
  ),
);

const adaptiveSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="1.5 1.5 21 21">
  <style>path{fill:${ink}}@media (prefers-color-scheme:dark){path{fill:${paper}}}</style>
  <path fill-rule="evenodd" d="${mark}"/>
</svg>
`;

const files = {
  'favicon.ico': favicon,
  'icon.svg': adaptiveSvg,
  'apple-touch-icon.png': await png(tile(180, { fill: 0.6 })),
  'icon-192.png': await png(tile(192, { fill: 0.62, radius: 0.22 })),
  'icon-512.png': await png(tile(512, { fill: 0.62, radius: 0.22 })),
  // Maskable icons are cropped to a circle as small as 80% of the width; the mark stays well inside it.
  'icon-maskable-512.png': await png(tile(512, { fill: 0.55 })),
};

// The console serves the same browser icons (it has no manifest).
const targets = [
  [join(app, 'public'), Object.keys(files)],
  [join(app, '../console/public'), ['favicon.ico', 'icon.svg', 'apple-touch-icon.png']],
];
for (const [dir, names] of targets) {
  await mkdir(dir, { recursive: true });
  for (const name of names) await writeFile(join(dir, name), files[name]);
  console.log(`${dir}: ${names.join(', ')}`);
}
