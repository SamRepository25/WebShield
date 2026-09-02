import dns from 'node:dns/promises';
import net from 'node:net';
import { Agent } from 'undici';

function normalizeIp(ip: string): string {
  return ip.replace(/^\[|\]$/g, '').toLowerCase();
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const value = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  const ranges = [
    [0x00000000, 0x00ffffff],
    [0x0a000000, 0x0affffff],
    [0x64400000, 0x647fffff],
    [0x7f000000, 0x7fffffff],
    [0xa9fe0000, 0xa9feffff],
    [0xac100000, 0xac1fffff],
    [0xc0a80000, 0xc0a8ffff],
    [0xc0000000, 0xc00000ff],
    [0xc0000200, 0xc00002ff],
    [0xc0006400, 0xc00064ff],
    [0xc6120000, 0xc613ffff],
    [0xc6336400, 0xc63364ff],
    [0xcb007100, 0xcb0071ff],
    [0xe0000000, 0xffffffff],
  ];
  return ranges.some(([start, end]) => value >= start && value <= end);
}

function ipv6ToBigInt(ip: string): bigint | null {
  let value = ip;
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const ipv4 = value.slice(lastColon + 1);
    const parts = ipv4.split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    const high = ((parts[0] << 8) | parts[1]).toString(16);
    const low = ((parts[2] << 8) | parts[3]).toString(16);
    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
  return groups.reduce((result, group) => (result << 16n) | BigInt(parseInt(group, 16)), 0n);
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = normalizeIp(ip);
  const value = ipv6ToBigInt(normalized);
  if (value === null) return true;
  const mask = (bits: number) => ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
  const prefix = (bits: number) => value & mask(bits);
  const mapped = value >> 32n;
  if (mapped === 0xffffn) return isPrivateIpv4(`${Number((value >> 24n) & 255n)}.${Number((value >> 16n) & 255n)}.${Number((value >> 8n) & 255n)}.${Number(value & 255n)}`);
  return (
    value === 0n ||
    value === 1n ||
    prefix(7) === 0xfc000000000000000000000000000000n ||
    prefix(10) === 0xfe800000000000000000000000000000n ||
    prefix(32) === 0x20010db8000000000000000000000000n ||
    prefix(8) === 0xff000000000000000000000000000000n
  );
}

export function isBlockedAddress(address: string): boolean {
  const normalized = normalizeIp(address);
  const family = net.isIP(normalized);
  if (family === 4) return isPrivateIpv4(normalized);
  if (family === 6) return isPrivateIpv6(normalized);
  return true;
}

export async function assertPublicUrl(raw: string): Promise<string> {
  let url = raw.trim();
  if (!url) throw new Error('URL is required.');
  // Only default a bare hostname (no scheme at all, e.g. "example.com")
  // to https://. A string with some other explicit "scheme://" (file://,
  // ftp://, gopher://, ws://, ...) must be parsed as-is so the http/https
  // check below can reject it by protocol — blindly prefixing it here
  // would instead treat the scheme text as part of a bogus hostname and
  // send it to a DNS lookup instead of cleanly refusing it.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = `https://${url}`;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Please provide a valid website URL.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
  if (parsed.username || parsed.password) throw new Error('URLs with embedded credentials are not allowed.');
  if (parsed.port && !['80', '443'].includes(parsed.port)) throw new Error('Only standard HTTP and HTTPS ports are allowed.');

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname === 'metadata.google.internal') {
    throw new Error('Private or internal network targets are not allowed.');
  }

  if (net.isIP(hostname)) {
    if (isBlockedAddress(hostname)) throw new Error('Private or reserved IP addresses are not allowed.');
    return parsed.toString();
  }

  let records: Array<{ address: string; family: number }>;
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error('Could not resolve the target hostname.');
  }

  if (!records.length || records.some((record) => isBlockedAddress(record.address))) {
    throw new Error('The target resolves to a private or reserved network address.');
  }

  return parsed.toString();
}

// assertPublicUrl() validates DNS results at check time, but Node's global
// fetch() performs its own, separate DNS resolution when it actually opens
// the connection. That gap between "checked" and "connected" is exactly
// what DNS-rebinding attacks exploit: the name resolves to a public IP
// during the check and to a private/internal IP a moment later during the
// real connect. `secureDispatcher` closes that gap by re-validating every
// address at the moment a socket is opened, for every request made through
// it — regardless of how the process was started (it does not depend on
// any `-r`/`--require` flag being set by the deploy platform).
function lookupPublicOnly(
  hostname: string,
  options: { family?: number },
  callback: (err: Error | null, addresses: Array<{ address: string; family: number }>) => void
): void {
  dns
    .lookup(hostname, { all: true, verbatim: true })
    .then((records) => {
      let usable = records.filter((record) => !isBlockedAddress(record.address));
      if (options.family) usable = usable.filter((r) => r.family === options.family);
      if (!usable.length) {
        callback(new Error('The target resolves to a private or reserved network address.'), []);
        return;
      }
      callback(null, usable);
    })
    .catch(() => callback(new Error('Could not resolve the target hostname.'), []));
}

export const secureDispatcher = new Agent({
  connect: {
    lookup: lookupPublicOnly,
  },
});

// Wrapper around fetch() that always routes through secureDispatcher, so
// every outbound scan request is protected against DNS rebinding at the
// socket layer, on top of the upfront assertPublicUrl() check.
export function safeFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, dispatcher: secureDispatcher } as RequestInit);
}
