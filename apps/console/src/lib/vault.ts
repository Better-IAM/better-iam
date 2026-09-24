/** The console path of a vault secret: each name segment encoded on its own, so `/` stays a separator. */
export function secretHref(base: string, name: string): string {
  return `${base}/vault/${name.split('/').map(encodeURIComponent).join('/')}`;
}
