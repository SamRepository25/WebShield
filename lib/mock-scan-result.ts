import type { ScanResult } from './types';

export const mockScanResult: ScanResult = {
  url: 'https://example.com',
  scannedAt: '2026-07-09T14:32:00Z',
  score: 72,
  grade: 'B',
  https: {
    enabled: true,
    valid: true,
    expiresAt: '2026-12-15',
    issuer: "Let's Encrypt R3",
    protocol: 'TLS 1.3',
    daysRemaining: 159,
  },
  headers: [
    {
      name: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains; preload',
      status: 'present',
      description:
        'Enforces HTTPS connections and protects against protocol downgrade attacks.',
      severity: 'high',
    },
    {
      name: 'Content-Security-Policy',
      value: "default-src https:; script-src https: 'unsafe-inline'",
      status: 'weak',
      description:
        'Restricts resource loading to prevent XSS and data injection attacks. Current policy allows unsafe inline scripts.',
      severity: 'high',
    },
    {
      name: 'X-Content-Type-Options',
      value: 'nosniff',
      status: 'present',
      description:
        'Prevents browsers from MIME-type sniffing and interpreting files as a different type than declared.',
      severity: 'medium',
    },
    {
      name: 'X-Frame-Options',
      value: 'SAMEORIGIN',
      status: 'present',
      description:
        'Prevents clickjacking by restricting the page from being embedded in iframes.',
      severity: 'medium',
    },
    {
      name: 'Referrer-Policy',
      value: 'strict-origin-when-cross-origin',
      status: 'present',
      description:
        'Controls how much referrer information is included with requests made from the page.',
      severity: 'low',
    },
    {
      name: 'Permissions-Policy',
      value: 'Not set',
      status: 'missing',
      description:
        'Controls which browser features and APIs (camera, microphone, geolocation) the page can access.',
      severity: 'medium',
    },
  ],
  rawHeaders: [
    { name: 'Server', value: 'nginx/1.25.3' },
    { name: 'Date', value: 'Thu, 09 Jul 2026 14:32:00 GMT' },
    { name: 'Content-Type', value: 'text/html; charset=UTF-8' },
    { name: 'Content-Length', value: '1256' },
    { name: 'Connection', value: 'keep-alive' },
    { name: 'Cache-Control', value: 'public, max-age=3600' },
    { name: 'ETag', value: '"4e9-601c3d2a8b400"' },
    { name: 'Last-Modified', value: 'Wed, 08 Jul 2026 10:15:00 GMT' },
    { name: 'Vary', value: 'Accept-Encoding' },
    { name: 'Content-Encoding', value: 'gzip' },
    { name: 'X-Powered-By', value: 'Express' },
    { name: 'Set-Cookie', value: 'session=abc123; HttpOnly; Secure; SameSite=Strict' },
    { name: 'X-Cache', value: 'HIT' },
    { name: 'X-Served-By', value: 'cache-ewr18123' },
  ],
  recommendations: [
    {
      id: 'rec-1',
      title: 'Strengthen Content-Security-Policy',
      description:
        "The current CSP allows unsafe inline scripts, which weakens XSS protection. Remove 'unsafe-inline' from script-src and use nonces or hashes for inline scripts.",
      severity: 'high',
      impact: 'Reduces risk of Cross-Site Scripting (XSS) attacks significantly.',
    },
    {
      id: 'rec-2',
      title: 'Add Permissions-Policy header',
      description:
        'The Permissions-Policy header is missing. Add it to explicitly restrict access to browser features like camera, microphone, and geolocation.',
      severity: 'medium',
      impact: 'Limits attack surface by restricting powerful browser APIs.',
    },
  ],
  vulnerabilities: {
    count: 2,
    critical: 0,
    high: 0,
    medium: 1,
    low: 0,
  },
};
