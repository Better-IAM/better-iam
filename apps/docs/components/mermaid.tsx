'use client';

import { use, useEffect, useId, useState } from 'react';
import { useTheme } from 'next-themes';

type MermaidModule = (typeof import('mermaid'))['default'];

let mermaidPromise: Promise<MermaidModule> | undefined;
const loadMermaid = () => (mermaidPromise ??= import('mermaid').then((mod) => mod.default));

const cache = new Map<string, Promise<string>>();

function renderChart(id: string, chart: string, theme: 'dark' | 'default'): Promise<string> {
  const key = `${theme}:${chart}`;
  let pending = cache.get(key);
  if (!pending) {
    pending = loadMermaid().then(async (mermaid) => {
      // Mermaid's `base` theme takes every color from these variables: neutral grays to match the monochrome site.
      const dark = theme === 'dark';
      const ink = dark ? '#fafafa' : '#0a0a0a';
      const node = dark ? '#262626' : '#ffffff';
      const edge = dark ? '#404040' : '#d4d4d4';
      const muted = dark ? '#171717' : '#f7f7f7';
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        fontFamily: 'var(--font-inter), ui-sans-serif, system-ui',
        theme: 'base',
        themeVariables: {
          darkMode: dark,
          background: 'transparent',
          primaryColor: node,
          primaryBorderColor: dark ? '#737373' : '#0a0a0a',
          primaryTextColor: ink,
          secondaryColor: muted,
          secondaryBorderColor: edge,
          secondaryTextColor: ink,
          tertiaryColor: muted,
          tertiaryBorderColor: edge,
          tertiaryTextColor: ink,
          lineColor: dark ? '#a3a3a3' : '#737373',
          textColor: ink,
          mainBkg: node,
          nodeBorder: dark ? '#737373' : '#0a0a0a',
          clusterBkg: muted,
          clusterBorder: edge,
          edgeLabelBackground: dark ? '#121212' : '#ffffff',
          actorBkg: node,
          actorBorder: dark ? '#737373' : '#0a0a0a',
          actorTextColor: ink,
          signalColor: ink,
          signalTextColor: ink,
          noteBkgColor: muted,
          noteBorderColor: edge,
          noteTextColor: ink,
          labelBoxBkgColor: node,
          labelBoxBorderColor: edge,
          labelTextColor: ink,
          loopTextColor: ink,
          activationBkgColor: muted,
          activationBorderColor: edge,
        },
      });
      const { svg } = await mermaid.render(id, chart.replaceAll('\\n', '\n'));
      return svg;
    });
    cache.set(key, pending);
  }
  return pending;
}

function Chart({ id, chart, theme }: { id: string; chart: string; theme: 'dark' | 'default' }) {
  const svg = use(renderChart(id, chart, theme));
  return (
    <div
      className="not-prose my-6 flex justify-center overflow-x-auto rounded-2xl border border-border-button-default bg-surface-sunken p-4 [&_svg]:h-auto [&_svg]:max-w-full"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}

/** Renders a Mermaid diagram produced by `remarkMdxMermaid` from ```mermaid code blocks. */
export function Mermaid({ chart }: { chart: string }) {
  const id = useId().replace(/[^a-zA-Z0-9]/g, '');
  const [mounted, setMounted] = useState(false);
  const { resolvedTheme } = useTheme();

  useEffect(() => setMounted(true), []);

  if (!mounted) {
    return (
      <div
        className="not-prose my-6 h-48 animate-pulse rounded-2xl border border-border-button-default bg-surface-sunken"
        aria-hidden
      />
    );
  }
  return (
    <Chart
      id={`mermaid-${id}`}
      chart={chart}
      theme={resolvedTheme === 'dark' ? 'dark' : 'default'}
    />
  );
}
