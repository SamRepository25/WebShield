import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/security', () => ({
  assertPublicUrl: vi.fn(async (url: string) => {
    if (/localhost|127\.0\.0\.1|169\.254\.169\.254|\.internal/.test(url)) {
      throw new Error('Private or internal network targets are not allowed.');
    }
    if (!/^https?:\/\//i.test(url)) return `https://${url}/`;
    return url;
  }),
}));

vi.mock('@/lib/scanner', () => ({
  runScan: vi.fn(),
  ScanError: class ScanError extends Error {},
  gradeFromScore: vi.fn(),
}));

vi.mock('@/lib/telegram', () => ({
  sendWebsiteDownAlert: vi.fn(),
  sendWebsiteRecoveredAlert: vi.fn(),
  sendScoreDropAlert: vi.fn(),
  sendSSLAlert: vi.fn(),
  sendHeaderAlert: vi.fn(),
}));

vi.mock('@/lib/monitoring-store', () => ({
  getSites: vi.fn(),
  getSite: vi.fn(async () => ({ id: 'site_1', url: 'https://existing.example/', frequency: 'daily' })),
  insertSite: vi.fn(async (fields) => ({ id: 'site_new', ...fields })),
  updateSiteFields: vi.fn(async (id, fields) => ({ id, url: 'https://existing.example/', ...fields })),
  deleteSite: vi.fn(),
  insertScan: vi.fn(),
  getScansForSite: vi.fn(async () => []),
  getAllScans: vi.fn(),
  getScanCount: vi.fn(),
  getRecentScans: vi.fn(async () => []),
  getDueSites: vi.fn(),
}));

import { assertPublicUrl } from '@/lib/security';
import { createSite, updateSite } from '@/lib/monitoring-service';

describe('monitored-site URL validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects creating a monitored site that targets a private/internal address', async () => {
    await expect(
      createSite({ name: 'Internal admin panel', url: 'http://169.254.169.254/' })
    ).rejects.toThrow(/private or internal/i);
    await expect(
      createSite({ name: 'Local service', url: 'http://localhost:8080/' })
    ).rejects.toThrow(/private or internal/i);
  });

  it('validates the URL through the shared SSRF check when creating a site', async () => {
    await createSite({ name: 'Public site', url: 'public-site.example' });
    expect(assertPublicUrl).toHaveBeenCalledWith('public-site.example');
  });

  it('rejects updating a monitored site to point at a private/internal address', async () => {
    await expect(updateSite('site_1', { url: 'http://internal-app.internal/' })).rejects.toThrow(
      /private or internal/i
    );
  });

  it('allows updating non-URL fields without re-triggering URL validation errors', async () => {
    await expect(updateSite('site_1', { name: 'Renamed site' })).resolves.toBeTruthy();
    expect(assertPublicUrl).not.toHaveBeenCalled();
  });
});
