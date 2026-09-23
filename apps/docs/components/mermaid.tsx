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
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        fontFamily: 'var(--font-geist-sans), ui-sans-serif, system-ui',
        theme,
        themeVariables:
          theme === 'dark'
            ? {
                primaryColor: '#0f2a2a',
                primaryBorderColor: '#3fd6b6',
                lineColor: '#6b7a90',
                primaryTextColor: '#e6edf5',
              }
            : {
                primaryColor: '#e7faf5',
                primaryBorderColor: '#0e8f7a',
                lineColor: '#8b98ab',
                primaryTextColor: '#0f172a',
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
      className="not-prose my-6 flex justify-center overflow-x-auto rounded-xl border bg-fd-card p-4 [&_svg]:h-auto [&_svg]:max-w-full"
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
      <div className="not-prose my-6 h-48 animate-pulse rounded-xl border bg-fd-card" aria-hidden />
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
