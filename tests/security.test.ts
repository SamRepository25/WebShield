import { describe, it, expect, vi, beforeEach } from 'vitest';
import { isBlockedAddress } from '@/lib/security';

describe('isBlockedAddress', () => {
  it('blocks loopback addresses', () => {
    expect(isBlockedAddress('127.0.0.1')).toBe(true);
    expect(isBlockedAddress('::1')).toBe(true);
  });

  it('blocks private IPv4 ranges', () => {
    expect(isBlockedAddress('10.0.0.5')).toBe(true);
    expect(isBlockedAddress('172.16.0.1')).toBe(true);
    expect(isBlockedAddress('172.31.255.255')).toBe(true);
    expect(isBlockedAddress('192.168.1.1')).toBe(true);
  });

  it('blocks link-local addresses, including the cloud metadata IP', () => {
    expect(isBlockedAddress('169.254.169.254')).toBe(true);
    expect(isBlockedAddress('169.254.0.1')).toBe(true);
  });

  it('blocks the unspecified / "any" address', () => {
    expect(isBlockedAddress('0.0.0.0')).toBe(true);
  });

  it('blocks carrier-grade NAT and documentation ranges', () => {
    expect(isBlockedAddress('100.64.0.1')).toBe(true); // CGNAT
    expect(isBlockedAddress('192.0.2.1')).toBe(true); // TEST-NET-1
    expect(isBlockedAddress('198.51.100.1')).toBe(true); // TEST-NET-2
    expect(isBlockedAddress('203.0.113.1')).toBe(true); // TEST-NET-3
  });

  it('blocks multicast / reserved IPv4', () => {
    expect(isBlockedAddress('224.0.0.1')).toBe(true);
    expect(isBlockedAddress('240.0.0.1')).toBe(true);
  });

  it('blocks private and reserved IPv6 ranges', () => {
    expect(isBlockedAddress('fc00::1')).toBe(true); // unique local
    expect(isBlockedAddress('fe80::1')).toBe(true); // link-local
    expect(isBlockedAddress('ff02::1')).toBe(true); // multicast
    expect(isBlockedAddress('::')).toBe(true); // unspecified
  });

  it('blocks IPv4-mapped IPv6 addresses that wrap a private IPv4', () => {
    expect(isBlockedAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedAddress('::ffff:169.254.169.254')).toBe(true);
    expect(isBlockedAddress('::ffff:10.0.0.1')).toBe(true);
  });

  it('allows ordinary public IPv4 and IPv6 addresses', () => {
    expect(isBlockedAddress('8.8.8.8')).toBe(false);
    expect(isBlockedAddress('1.1.1.1')).toBe(false);
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false); // Cloudflare DNS
  });

  it('treats malformed input as blocked rather than throwing', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
    expect(isBlockedAddress('')).toBe(true);
  });
});

// dns.lookup is mocked so these tests never make a real network call —
// they only verify assertPublicUrl's own validation logic.
vi.mock('node:dns/promises', () => ({
  default: {
    lookup: vi.fn(),
  },
}));

describe('assertPublicUrl', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('rejects literal localhost / internal hostnames without a DNS lookup', async () => {
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://localhost/')).rejects.toThrow(/private or internal/i);
    await expect(assertPublicUrl('http://foo.localhost/')).rejects.toThrow(/private or internal/i);
    await expect(assertPublicUrl('http://box.internal/')).rejects.toThrow(/private or internal/i);
    await expect(assertPublicUrl('http://metadata.google.internal/')).rejects.toThrow(/private or internal/i);
  });

  it('rejects literal private/loopback/metadata IPs directly in the URL', async () => {
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://127.0.0.1/')).rejects.toThrow(/private or reserved/i);
    await expect(assertPublicUrl('http://169.254.169.254/')).rejects.toThrow(/private or reserved/i);
    await expect(assertPublicUrl('http://[::1]/')).rejects.toThrow(/private or reserved/i);
  });

  it('rejects non-HTTP protocols', async () => {
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('file:///etc/passwd')).rejects.toThrow(/http and https/i);
    await expect(assertPublicUrl('ftp://example.com/')).rejects.toThrow(/http and https/i);
  });

  it('rejects URLs with embedded credentials', async () => {
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://user:pass@example.com/')).rejects.toThrow(/embedded credentials/i);
  });

  it('rejects non-standard ports', async () => {
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://example.com:8080/')).rejects.toThrow(/standard http and https ports/i);
  });

  it('rejects a hostname that resolves only to a private address (DNS rebinding target)', async () => {
    const dns = (await import('node:dns/promises')).default;
    (dns.lookup as ReturnType<typeof vi.fn>).mockResolvedValue([
      { address: '10.0.0.5', family: 4 },
    ]);
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://internal-service.example.com/')).rejects.toThrow(
      /private or reserved network address/i
    );
  });

  it('rejects a hostname with mixed public and private records (any private record blocks it)', async () => {
    const dns = (await import('node:dns/promises')).default;
    (dns.lookup as ReturnType<typeof vi.fn>).mockResolvedValue([
      { address: '8.8.8.8', family: 4 },
      { address: '169.254.169.254', family: 4 },
    ]);
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://mixed.example.com/')).rejects.toThrow(
      /private or reserved network address/i
    );
  });

  it('allows a hostname that resolves only to public addresses', async () => {
    const dns = (await import('node:dns/promises')).default;
    (dns.lookup as ReturnType<typeof vi.fn>).mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
    ]);
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('example.com')).resolves.toBe('https://example.com/');
  });

  it('rejects a hostname that fails to resolve', async () => {
    const dns = (await import('node:dns/promises')).default;
    (dns.lookup as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('ENOTFOUND'));
    const { assertPublicUrl } = await import('@/lib/security');
    await expect(assertPublicUrl('http://does-not-exist.example/')).rejects.toThrow(/could not resolve/i);
  });
});
