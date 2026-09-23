import { SiteFooter } from '@/components/site/site-footer';
import { SiteHeader } from '@/components/site/site-header';
import { SmoothScroll } from '@/components/site/smooth-scroll';

/** Marketing pages (home, playground): the shared header and footer inside the rails, with Lenis smooth scrolling. */
export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <SmoothScroll>
      <div className="site flex min-h-screen flex-1 flex-col">
        <SiteHeader />
        <div className="flex flex-1 flex-col">{children}</div>
        <SiteFooter />
      </div>
    </SmoothScroll>
  );
}
