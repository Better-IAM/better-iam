import Link from 'next/link';
import type { ReactNode } from 'react';
import type { NavArea } from '@/lib/navigation';
import { AccountMenu, AreaNav, AreaTabs, JumpTo } from './nav-links';

/**
 * The console frame: a top bar with the brand, page search, extra links and the account menu over a row of section
 * tabs; below it, the current section's own sidebar (none outside a section) beside the page.
 */
export function Shell({
  brand,
  subtitle,
  homeHref,
  areas,
  account,
  accountMenu,
  links,
  children,
}: {
  brand: string;
  subtitle?: string;
  homeHref: string;
  areas: NavArea[];
  /** Who is signed in, shown on the account button. */
  account: { name: string; detail?: string };
  /** The account menu's contents (profile links, sign-out). */
  accountMenu: ReactNode;
  /** Extra links at the right of the top bar. */
  links?: ReactNode;
  children: ReactNode;
}) {
  const initials =
    account.name
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]!.toUpperCase())
      .join('') || '?';
  return (
    <div className="app">
      <header className="appbar">
        <div className="appbar-row">
          <Link href={homeHref} className="appbar-brand">
            <strong>{brand}</strong>
            {subtitle && <span>{subtitle}</span>}
          </Link>
          <JumpTo areas={areas} />
          <div className="appbar-end">
            {links}
            <AccountMenu
              label={
                <>
                  <span className="avatar" aria-hidden="true">
                    {initials}
                  </span>
                  <span className="account-name">{account.name}</span>
                </>
              }
            >
              <div className="account-who">
                <strong>{account.name}</strong>
                {account.detail && <span>{account.detail}</span>}
              </div>
              {accountMenu}
            </AccountMenu>
          </div>
        </div>
        <AreaTabs areas={areas} />
      </header>
      <div className="workspace">
        <AreaNav areas={areas} />
        <main className="main">{children}</main>
      </div>
    </div>
  );
}
