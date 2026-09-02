import { describe, it, expect, vi, beforeEach } from 'vitest';

// runScan calls into lib/security for every hop. Mocking it here lets us
// test the redirect-revalidation *behavior* in runScan without making real
// network requests or depending on DNS/TLS.
vi.mock('@/lib/security', () => ({
  assertPublicUrl: vi.fn(async (url: string) => {
    if (/internal-service|169\.254\.169\.254|127\.0\.0\.1/.test(url)) {
      throw new Error('The target resolves to a private or reserved network address.');
    }
    return url;
  }),
  safeFetch: vi.fn(),
}));

import { assertPublicUrl, safeFetch } from '@/lib/security';
import { runScan, ScanError } from '@/lib/scanner';

function headerResponse(status: number, headers: Record<string, string>): Response {
  return new Response(null, { status, headers });
}

describe('runScan SSRF redirect handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects a redirect chain that points at a private/internal address', async () => {
    (safeFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      headerResponse(302, { location: 'http://internal-service.example/admin' })
    );

    await expect(runScan('http://public-site.example/')).rejects.toMatchObject({
      status: 400,
    } satisfies Partial<ScanError>);

    // Only the first hop should ever be fetched — the malicious redirect
    // target must be rejected before a request is made to it.
    expect(safeFetch).toHaveBeenCalledTimes(1);
  });

  it('rejects a redirect straight to a cloud metadata address', async () => {
    (safeFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      headerResponse(302, { location: 'http://169.254.169.254/latest/meta-data/' })
    );

    await expect(runScan('http://public-site.example/')).rejects.toMatchObject({ status: 400 });
  });

  it('re-validates every hop, not just the first redirect', async () => {
    (safeFetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(headerResponse(301, { location: 'http://hop-two.example/' }))
      .mockResolvedValueOnce(headerResponse(302, { location: 'http://127.0.0.1/' }));

    await expect(runScan('http://public-site.example/')).rejects.toMatchObject({ status: 400 });
    expect(safeFetch).toHaveBeenCalledTimes(2);
    // assertPublicUrl must be called for the initial URL AND each hop.
    expect(assertPublicUrl).toHaveBeenCalledWith(expect.stringContaining('public-site.example'));
    expect(assertPublicUrl).toHaveBeenCalledWith(expect.stringContaining('hop-two.example'));
    expect(assertPublicUrl).toHaveBeenCalledWith(expect.stringContaining('127.0.0.1'));
  });

  it('follows a benign redirect chain and completes the scan', async () => {
    (safeFetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(headerResponse(301, { location: 'http://www.public-site.example/' }))
      .mockResolvedValueOnce(headerResponse(200, { 'content-type': 'text/html' }));

    const result = await runScan('http://public-site.example/');
    expect(result.finalUrl).toBe('http://www.public-site.example/');
    expect(safeFetch).toHaveBeenCalledTimes(2);
  });
});
