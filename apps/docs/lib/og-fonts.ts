/**
 * The site's typefaces for social cards. `next/og` reads TTF, OTF, or WOFF but not the WOFF2 files `next/font`
 * serves, so the cards fetch static TTF instances from Google Fonts, which the build already reaches for
 * `next/font/google`. Loaded once per process; offline, cards fall back to the renderer's built-in font.
 */

type Weight = 400 | 500 | 600;

export interface OgFont {
  name: string;
  data: ArrayBuffer;
  weight: Weight;
  style: 'normal';
}

const faces: [name: string, weight: Weight][] = [
  ['Inter', 400],
  ['Inter', 600],
  ['JetBrains Mono', 500],
];

async function load(name: string, weight: Weight): Promise<ArrayBuffer> {
  const cssUrl = `https://fonts.googleapis.com/css2?family=${name.replaceAll(' ', '+')}:wght@${weight}`;
  const css = await fetch(cssUrl).then((response) => {
    if (!response.ok) throw new Error(`${cssUrl} answered ${response.status}`);
    return response.text();
  });
  const fontUrl = /src: url\((.+?)\) format\('(?:opentype|truetype)'\)/.exec(css)?.[1];
  if (!fontUrl) throw new Error(`no TTF source for ${name} ${weight}`);
  const response = await fetch(fontUrl);
  if (!response.ok) throw new Error(`${fontUrl} answered ${response.status}`);
  return response.arrayBuffer();
}

let fonts: Promise<OgFont[]> | undefined;

export function ogFonts(): Promise<OgFont[]> {
  fonts ??= Promise.all(
    faces.map(async ([name, weight]) => ({
      name,
      weight,
      style: 'normal' as const,
      data: await load(name, weight),
    })),
  ).catch((error: Error) => {
    console.warn(`[og] Social cards use the default font: ${error.message}`);
    return [];
  });
  return fonts;
}
