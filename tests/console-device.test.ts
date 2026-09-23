import { describe, expect, it } from 'vitest';
import { clientLine, describeClient, describeUserAgent } from '../apps/console/src/lib/device.js';

describe('console device names', () => {
  it('turns common user agents into short names and leaves unknown ones recognizable', () => {
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
      ),
    ).toBe('Chrome 128 on Windows');
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
      ),
    ).toBe('Edge 128 on Windows');
    expect(
      describeUserAgent(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
      ),
    ).toBe('Safari 17 on iPhone');
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0',
      ),
    ).toBe('Firefox 128 on macOS');
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/127.0.0.0 Mobile',
      ),
    ).toBe('Chrome 127 on Android');
    expect(describeUserAgent('curl/8.7.1')).toBe('curl 8');
    expect(describeUserAgent('Mozilla/5.0 (Macintosh)')).toBe('macOS');
    expect(describeUserAgent('SomeBot/1.0 (+https://example.test/bot)')).toBe(
      'SomeBot/1.0 (+https://example.test/bot)',
    );
    expect(describeUserAgent('x'.repeat(100))).toHaveLength(40);
    expect(describeUserAgent(undefined)).toBeUndefined();
  });

  it('prefers the application label and appends the address once', () => {
    expect(describeClient({ label: 'Work laptop', userAgent: 'curl/8.7.1' })).toBe('Work laptop');
    expect(describeClient({ userAgent: 'curl/8.7.1', ip: '203.0.113.7' })).toBe('curl 8');
    expect(describeClient({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(describeClient(undefined)).toBeUndefined();
    expect(clientLine({ userAgent: 'curl/8.7.1', ip: '203.0.113.7' })).toBe('curl 8 · 203.0.113.7');
    expect(clientLine({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(clientLine({ label: 'Phone' })).toBe('Phone');
    expect(clientLine(undefined)).toBe('');
  });
});
