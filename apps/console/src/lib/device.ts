/** Client details as Better IAM records them on sessions, devices, and authentication events. */
export interface ClientInfo {
  ip?: string;
  userAgent?: string;
  label?: string;
}

const BROWSERS: [pattern: RegExp, name: string][] = [
  [/\bEdg(?:e|A|iOS)?\/(\d+)/, 'Edge'],
  [/\bOPR\/(\d+)/, 'Opera'],
  [/\bSamsungBrowser\/(\d+)/, 'Samsung Internet'],
  [/\bFirefox\/(\d+)/, 'Firefox'],
  [/\bFxiOS\/(\d+)/, 'Firefox'],
  [/\bCriOS\/(\d+)/, 'Chrome'],
  [/\bChrome\/(\d+)/, 'Chrome'],
  [/\bVersion\/(\d+)[^)]*\bSafari\//, 'Safari'],
  [/\bcurl\/(\d+)/, 'curl'],
  [/\bPostmanRuntime\/(\d+)/, 'Postman'],
  [/\bnode(?:-fetch)?\/?(\d+)?/i, 'Node.js'],
];
const SYSTEMS: [pattern: RegExp, name: string][] = [
  [/\bWindows NT/, 'Windows'],
  [/\biPhone\b/, 'iPhone'],
  [/\biPad\b/, 'iPad'],
  [/\bMacintosh\b/, 'macOS'],
  [/\bAndroid\b/, 'Android'],
  [/\bCrOS\b/, 'ChromeOS'],
  [/\bLinux\b|\bX11\b/, 'Linux'],
];

/**
 * A short human name for a user agent ("Chrome 128 on Windows", "Safari on iPhone", "curl 8"), or the first
 * characters of the raw string when nothing is recognized. Purely cosmetic: nothing about the client is trusted.
 */
export function describeUserAgent(userAgent: string | undefined): string | undefined {
  if (!userAgent) return undefined;
  const browser = BROWSERS.map(([pattern, name]) => {
    const match = pattern.exec(userAgent);
    return match ? `${name}${match[1] ? ` ${match[1]}` : ''}` : undefined;
  }).find(Boolean);
  const system = SYSTEMS.find(([pattern]) => pattern.test(userAgent))?.[1];
  if (!browser && !system) return userAgent.slice(0, 40);
  if (browser && system) return `${browser} on ${system}`;
  return browser ?? system;
}

/** The device column of a session or device list: the application's label, else the described user agent. */
export function describeClient(client: ClientInfo | undefined): string | undefined {
  if (!client) return undefined;
  return client.label ?? describeUserAgent(client.userAgent) ?? client.ip;
}

/** "Chrome 128 on Windows · 203.0.113.7": the device and, when known, the address. */
export function clientLine(client: ClientInfo | undefined): string {
  if (!client) return '';
  const device = client.label ?? describeUserAgent(client.userAgent);
  return [device, device === client.ip ? undefined : client.ip].filter(Boolean).join(' · ');
}
