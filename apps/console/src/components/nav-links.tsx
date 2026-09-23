'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { currentArea, pageMatches, type NavArea } from '@/lib/navigation';

/** The top bar's section tabs; the section holding the current page is marked. */
export function AreaTabs({ areas }: { areas: NavArea[] }) {
  const pathname = usePathname();
  const active = currentArea(areas, pathname)?.area.key;
  return (
    <nav className="area-tabs" aria-label="Sections">
      {areas.map((area) => (
        <Link
          key={area.key}
          href={area.href}
          className={area.key === active ? 'active' : undefined}
          aria-current={area.key === active ? 'true' : undefined}
        >
          {area.label}
        </Link>
      ))}
    </nav>
  );
}

/**
 * The sidebar of the current section: its landing page and every page in it, nothing else. Pages outside any section
 * (your account) and single-page sections have none.
 */
export function AreaNav({ areas }: { areas: NavArea[] }) {
  const pathname = usePathname();
  const found = currentArea(areas, pathname);
  if (!found || (!found.area.landing && found.area.pages.length < 2)) return null;
  const { area } = found;
  const onLanding = area.landing && pathname === area.href;
  return (
    <aside className="area-nav">
      <div className="area-nav-head">
        {area.landing ? (
          <Link href={area.href} className="area-nav-title">
            {area.label}
          </Link>
        ) : (
          <span className="area-nav-title">{area.label}</span>
        )}
        <p>{area.description}</p>
      </div>
      <nav aria-label={`${area.label} pages`}>
        {area.landing && (
          <Link
            href={area.href}
            className={onLanding ? 'active' : undefined}
            aria-current={onLanding ? 'page' : undefined}
          >
            Overview
          </Link>
        )}
        {area.pages.map((page) => {
          const current = found.page?.href === page.href;
          return (
            <Link
              key={page.href}
              href={page.href}
              className={current ? 'active' : undefined}
              aria-current={current ? 'page' : undefined}
              title={page.description}
            >
              {page.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}

/** "Jump to…": finds any page of any section by name or description. `/` or Ctrl+K focuses it. */
export function JumpTo({ areas }: { areas: NavArea[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(0);
  const term = query.trim().toLowerCase();
  const results = useMemo(
    () =>
      term
        ? areas
            .flatMap((area) => area.pages.map((page) => ({ ...page, area: area.label })))
            .filter((page) =>
              `${page.label} ${page.description} ${page.area}`.toLowerCase().includes(term),
            )
            .sort(
              (a, b) =>
                Number(!a.label.toLowerCase().startsWith(term)) -
                Number(!b.label.toLowerCase().startsWith(term)),
            )
            .slice(0, 8)
        : [],
    [areas, term],
  );
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable;
      if (
        (event.key === '/' && !typing) ||
        (event.key === 'k' && (event.ctrlKey || event.metaKey))
      ) {
        event.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  // Leaving the page clears the search.
  useEffect(() => setQuery(''), [pathname]);
  const go = (href: string) => {
    setQuery('');
    input.current?.blur();
    router.push(href);
  };
  return (
    <div className="jump">
      <input
        ref={input}
        type="search"
        className="jump-input"
        placeholder="Jump to a page…"
        aria-label="Jump to a page"
        aria-expanded={results.length > 0}
        aria-controls="jump-results"
        role="combobox"
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
          setSelected(0);
        }}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown') {
            event.preventDefault();
            setSelected((index) => Math.min(index + 1, results.length - 1));
          } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            setSelected((index) => Math.max(index - 1, 0));
          } else if (event.key === 'Enter' && results[selected]) {
            event.preventDefault();
            go(results[selected].href);
          } else if (event.key === 'Escape') {
            setQuery('');
            input.current?.blur();
          }
        }}
      />
      <kbd className="jump-key" aria-hidden="true">
        /
      </kbd>
      {term && (
        <div className="jump-results" id="jump-results" role="listbox">
          {results.length ? (
            results.map((page, index) => (
              <Link
                key={page.href}
                href={page.href}
                role="option"
                aria-selected={index === selected}
                className={index === selected ? 'selected' : undefined}
                onMouseEnter={() => setSelected(index)}
                onClick={() => setQuery('')}
              >
                <span className="jump-label">
                  {page.label}
                  {pageMatches(pathname, page) && <span className="jump-here">you are here</span>}
                </span>
                <span className="jump-area">{page.area}</span>
                <span className="jump-description">{page.description}</span>
              </Link>
            ))
          ) : (
            <span className="jump-empty">No page matches “{query.trim()}”.</span>
          )}
        </div>
      )}
    </div>
  );
}

/** The account menu in the top bar: closes on navigation and on a click elsewhere. */
export function AccountMenu({ label, children }: { label: ReactNode; children: ReactNode }) {
  const pathname = usePathname();
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (menu.current) menu.current.open = false;
  }, [pathname]);
  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      if (menu.current?.open && !menu.current.contains(event.target as Node))
        menu.current.open = false;
    };
    document.addEventListener('click', onClick);
    return () => document.removeEventListener('click', onClick);
  }, []);
  return (
    <details className="account-menu" ref={menu}>
      <summary>{label}</summary>
      <div className="account-panel">{children}</div>
    </details>
  );
}
