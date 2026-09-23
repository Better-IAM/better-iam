// Tells Bing (and the other IndexNow search engines: Yandex, Seznam, Naver) which pages changed, so they recrawl
// them within minutes instead of waiting for the sitemap. Google does not use IndexNow; it reads the sitemap.
//
//   node apps/docs/scripts/indexnow.mjs --changed <from-sha> <to-sha>   pages whose sources changed between commits
//   node apps/docs/scripts/indexnow.mjs --all                          every URL in the live sitemap
//   node apps/docs/scripts/indexnow.mjs /docs/guides/quickstart ...    specific paths
//
// Options: --site <origin> (default DOCS_SITE_URL or https://better-iam.com), --dry-run.
// The key is the file `public/<32 hex characters>.txt`, served at the site root, which proves the site is ours.
// .github/workflows/indexnow.yml runs `--changed` after every successful Railway deploy.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const app = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args.splice(index, 2)[1];
};
const site = (option('--site') ?? process.env.DOCS_SITE_URL ?? 'https://better-iam.com').replace(
  /\/$/,
  '',
);
const dryRun = args.includes('--dry-run');

const keyFile = readdirSync(join(app, 'public')).find((name) => /^[0-9a-f]{32}\.txt$/.test(name));
if (!keyFile) throw new Error('No IndexNow key file (public/<32 hex characters>.txt).');
const key = readFileSync(join(app, 'public', keyFile), 'utf8').trim();

/** The docs URL a content file is published at: `guides/index.mdx` is `/docs/guides`. */
function contentUrl(file) {
  const slug = file
    .replace(/^apps\/docs\/content\/docs\//, '')
    .replace(/\.mdx?$/, '')
    .replace(/(^|\/)index$/, '');
  return slug ? `/docs/${slug}` : '/docs/guides';
}

function changedPaths(from, to) {
  const files = execFileSync('git', ['diff', '--name-only', `${from}..${to}`, '--', 'apps/docs'], {
    encoding: 'utf8',
  })
    .split('\n')
    .filter(Boolean);
  const paths = new Set();
  for (const file of files) {
    if (/^apps\/docs\/content\/docs\/.+\.mdx?$/.test(file)) paths.add(contentUrl(file));
    else if (/^apps\/docs\/(app\/\(home\)\/page\.tsx|components\/home\/)/.test(file))
      paths.add('/');
    else if (/^apps\/docs\/(app\/\(home\)\/playground\/|components\/playground\/)/.test(file))
      paths.add('/playground');
  }
  return [...paths];
}

async function sitemapUrls() {
  const response = await fetch(`${site}/sitemap.xml`);
  if (!response.ok) throw new Error(`${site}/sitemap.xml answered ${response.status}`);
  return [...(await response.text()).matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
}

let urls;
if (args.includes('--all')) urls = await sitemapUrls();
else if (args.includes('--changed')) {
  const [from, to = 'HEAD'] = args.slice(args.indexOf('--changed') + 1);
  urls = from ? changedPaths(from, to) : await sitemapUrls();
} else urls = args.filter((arg) => !arg.startsWith('--'));
urls = urls.map((url) => new URL(url, site).toString());

if (!urls.length) {
  console.log('IndexNow: no changed pages to submit.');
  process.exit(0);
}
console.log(`IndexNow: ${urls.length} URL(s) for ${site}${dryRun ? ' (dry run)' : ''}`);
for (const url of urls.slice(0, 20)) console.log(`  ${url}`);
if (urls.length > 20) console.log(`  … and ${urls.length - 20} more`);
if (dryRun) process.exit(0);

// One request takes up to 10,000 URLs; 200 and 202 both mean accepted.
const response = await fetch('https://api.indexnow.org/indexnow', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json; charset=utf-8' },
  body: JSON.stringify({
    host: new URL(site).host,
    key,
    keyLocation: `${site}/${keyFile}`,
    urlList: urls.slice(0, 10_000),
  }),
});
console.log(`IndexNow answered ${response.status} ${response.statusText}`);
if (!response.ok) {
  console.error(await response.text());
  process.exit(1);
}
