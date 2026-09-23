import type { SVGProps } from 'react';

/** Better IAM mark: a shield whose inner cut forms a keyhole, drawn on a 24px grid. */
export function LogoMark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" {...props}>
      <path
        d="M12 1.75 3.75 4.9v6.02c0 5.02 3.44 9.6 8.25 11.33 4.81-1.73 8.25-6.31 8.25-11.33V4.9L12 1.75Z"
        fill="currentColor"
        opacity={0.16}
      />
      <path
        d="M12 1.75 3.75 4.9v6.02c0 5.02 3.44 9.6 8.25 11.33 4.81-1.73 8.25-6.31 8.25-11.33V4.9L12 1.75Z"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinejoin="round"
      />
      <circle cx={12} cy={9.75} r={2.35} fill="currentColor" />
      <path d="M10.9 11.4h2.2l.62 4.35h-3.44l.62-4.35Z" fill="currentColor" />
    </svg>
  );
}

export function Logo() {
  return (
    <span className="inline-flex items-center gap-2 font-semibold tracking-tight">
      <LogoMark className="size-5 text-fd-primary" />
      <span>
        Better<span className="text-fd-primary">IAM</span>
      </span>
    </span>
  );
}
