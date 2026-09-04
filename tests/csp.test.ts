import { describe, it, expect } from 'vitest';
import { buildCsp } from '@/middleware';

describe('Content-Security-Policy', () => {
  it('does not allow unsafe-inline or unsafe-eval script execution', () => {
    const csp = buildCsp('test-nonce-123');
    const scriptSrc = csp.split(';').find((d) => d.trim().startsWith('script-src'));
    expect(scriptSrc).toBeDefined();
    expect(scriptSrc).not.toMatch(/unsafe-inline/);
    expect(scriptSrc).not.toMatch(/unsafe-eval/);
  });

  it('includes the per-request nonce in script-src', () => {
    const csp = buildCsp('abc123');
    expect(csp).toContain("'nonce-abc123'");
  });

  it('blocks framing and disallows plugin content', () => {
    const csp = buildCsp('n');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
  });

  it('produces a different nonce each time it is called with different input', () => {
    const a = buildCsp('nonce-a');
    const b = buildCsp('nonce-b');
    expect(a).not.toBe(b);
  });
});
