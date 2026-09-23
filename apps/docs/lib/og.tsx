import { ImageResponse } from 'next/og';
import { socialImageSize } from './metadata';
import { ogFonts } from './og-fonts';
import { creator } from './shared';

/**
 * The 1200×630 social card behind every page's `og:image` and `twitter:image`, drawn in the site's language:
 * monochrome, hairline rails with crosshair marks, hatched gutters, and the shield mark hatched on the right.
 */

const { width: W, height: H } = socialImageSize;
const rail = { left: 64, right: W - 64, top: 104, bottom: H - 104 };
const color = {
  background: '#121212',
  ink: '#fafafa',
  secondary: '#a3a3a3',
  tertiary: '#737373',
  line: '#2e2e2e',
  hatch: '#222222',
  shield: '#3a3a3a',
};

/** components/logo.tsx: a shield with a keyhole on a 24 px grid, 20.5 units tall around (12, 12). */
const mark =
  'M12 1.75 3.75 4.9v6.02c0 5.02 3.44 9.6 8.25 11.33 4.81-1.73 8.25-6.31 8.25-11.33V4.9L12 1.75ZM10.84 11.83a2.35 2.35 0 1 1 2.32 0l.56 3.92h-3.44l.56-3.92Z';

function place(centerX: number, centerY: number, height: number) {
  const scale = height / 20.5;
  return {
    scale,
    transform: `translate(${centerX - 12 * scale} ${centerY - 12 * scale}) scale(${scale})`,
  };
}

/** Rails, crosshairs, hatching, and the watermark, as one SVG under the text. */
function backdrop() {
  const shield = place(rail.right - 184, (rail.top + rail.bottom) / 2, 360);
  const crosses = [rail.left, rail.right]
    .flatMap((x) =>
      [rail.top, rail.bottom].map((y) => `M${x - 9} ${y}H${x + 9}M${x} ${y - 9}V${y + 9}`),
    )
    .join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <defs>
    <pattern id="hatch" width="9" height="9" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
      <line x1="0" y1="0" x2="0" y2="9" stroke="${color.hatch}" stroke-width="2"/>
    </pattern>
    <pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse" x="${rail.left}" y="${rail.top}">
      <path d="M48 0H0V48" fill="none" stroke="#1d1d1d" stroke-width="1"/>
    </pattern>
    <linearGradient id="fade" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0.3" stop-color="#fff" stop-opacity="0"/>
      <stop offset="1" stop-color="#fff" stop-opacity="1"/>
    </linearGradient>
    <mask id="grid-mask">
      <rect x="${rail.left}" y="${rail.top}" width="${rail.right - rail.left}" height="${rail.bottom - rail.top}" fill="url(#fade)"/>
    </mask>
    <clipPath id="shield">
      <path transform="${shield.transform}" d="${mark}" clip-rule="evenodd"/>
    </clipPath>
  </defs>
  <rect width="${W}" height="${H}" fill="${color.background}"/>
  <rect width="${rail.left}" height="${H}" fill="url(#hatch)"/>
  <rect x="${rail.right}" width="${W - rail.right}" height="${H}" fill="url(#hatch)"/>
  <rect x="${rail.left}" y="${rail.top}" width="${rail.right - rail.left}" height="${rail.bottom - rail.top}" fill="url(#grid)" mask="url(#grid-mask)"/>
  <rect x="${rail.left}" y="${rail.top}" width="${rail.right - rail.left}" height="${rail.bottom - rail.top}" fill="url(#hatch)" clip-path="url(#shield)"/>
  <path transform="${shield.transform}" d="${mark}" fill="none" stroke="${color.shield}" stroke-width="${1.5 / shield.scale}"/>
  <path d="M${rail.left} 0V${H}M${rail.right} 0V${H}M0 ${rail.top}H${W}M0 ${rail.bottom}H${W}" stroke="${color.line}" stroke-width="1"/>
  <path d="${crosses}" stroke="${color.tertiary}" stroke-width="1.5"/>
</svg>`;
  return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
}

export interface SocialCard {
  /** Where the page sits, shown top right: `['Guides', 'Authentication']`. */
  trail: string[];
  title: string;
  description?: string;
  /** Short monospace tags in the footer, such as the npm packages a page documents. */
  tags?: string[];
}

function titleSize(title: string) {
  if (title.length <= 22) return 76;
  if (title.length <= 40) return 66;
  return 56;
}

export async function socialCard({ trail, title, description, tags = [] }: SocialCard) {
  const fonts = await ogFonts();
  const size = titleSize(title);
  const initials = creator
    .split(' ')
    .map((part) => part[0])
    .join('');
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          position: 'relative',
          background: color.background,
          color: color.ink,
          fontFamily: 'Inter',
        }}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={backdrop()} width={W} height={H} alt="" style={{ position: 'absolute' }} />

        <div
          style={{
            position: 'absolute',
            left: rail.left,
            top: 0,
            width: rail.right - rail.left,
            height: rail.top,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 40px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <svg width="38" height="38" viewBox="0 0 24 24">
              <path fill={color.ink} fillRule="evenodd" d={mark} />
            </svg>
            <div style={{ display: 'flex', fontSize: 32, fontWeight: 600, letterSpacing: -0.4 }}>
              Better<span style={{ color: color.secondary }}>IAM</span>
            </div>
          </div>
          <div
            style={{
              display: 'flex',
              gap: 14,
              fontFamily: 'JetBrains Mono',
              fontWeight: 500,
              fontSize: 18,
              letterSpacing: 2,
              textTransform: 'uppercase',
              color: color.secondary,
            }}
          >
            {trail.map((part, index) => (
              <span key={part} style={{ display: 'flex', gap: 14 }}>
                {index > 0 ? <span style={{ color: color.tertiary }}>/</span> : null}
                {part}
              </span>
            ))}
          </div>
        </div>

        <div
          style={{
            position: 'absolute',
            left: rail.left,
            top: rail.top,
            width: rail.right - rail.left,
            height: rail.bottom - rail.top,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'flex-end',
            padding: '0 40px 42px',
          }}
        >
          <div
            style={{
              display: 'block',
              maxWidth: 660,
              fontSize: size,
              fontWeight: 600,
              letterSpacing: size * -0.035,
              lineHeight: 1.05,
              lineClamp: 3,
            }}
          >
            {title}
          </div>
          {description ? (
            <div
              style={{
                display: 'block',
                maxWidth: 660,
                marginTop: 22,
                fontSize: 26,
                lineHeight: 1.42,
                color: color.secondary,
                lineClamp: 3,
              }}
            >
              {description}
            </div>
          ) : null}
        </div>

        <div
          style={{
            position: 'absolute',
            left: rail.left,
            top: rail.bottom,
            width: rail.right - rail.left,
            height: H - rail.bottom,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 40px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 22 }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 36,
                height: 36,
                borderRadius: 999,
                background: color.ink,
                color: color.background,
                fontFamily: 'JetBrains Mono',
                fontWeight: 500,
                fontSize: 14,
              }}
            >
              {initials}
            </div>
            <span style={{ color: color.secondary }}>Created by</span>
            <span style={{ fontWeight: 600 }}>{creator}</span>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {tags.slice(0, 3).map((tag) => (
              <div
                key={tag}
                style={{
                  display: 'flex',
                  padding: '6px 16px',
                  border: `1px solid ${color.shield}`,
                  borderRadius: 999,
                  background: color.background,
                  fontFamily: 'JetBrains Mono',
                  fontWeight: 500,
                  fontSize: 17,
                  color: '#d4d4d4',
                }}
              >
                {tag}
              </div>
            ))}
          </div>
        </div>
      </div>
    ),
    { ...socialImageSize, fonts: fonts.length ? fonts : undefined },
  );
}
