import { runScan, ScanError, gradeFromScore } from '@/lib/scanner';
import type { ScanResult } from '@/lib/types';
import type {
  MonitoredSite,
  MonitoredSiteInput,
  ScanRecord,
  ScanFrequency,
  ScanTrigger,
  DashboardStats,
  ScanDiff,
} from '@/lib/monitoring-types';
import { FREQUENCY_MS } from '@/lib/monitoring-types';
import {
  getSites,
  getSite,
  insertSite,
  updateSiteFields,
  deleteSite as deleteSiteStore,
  insertScan,
  getScansForSite,
  getAllScans,
  getScanCount,
  getRecentScans,
  getDueSites as getDueSitesStore,
} from '@/lib/monitoring-store';

function normalizeUrl(raw: string): string {
  let url = raw.trim();
  if (!url) throw new Error('URL is required.');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Please provide a valid website URL.');
  }
  if (!parsed.hostname || !parsed.hostname.includes('.'))
    throw new Error('Please provide a valid website URL.');
  return url;
}

function computeNextScanAt(frequency: ScanFrequency, from: Date = new Date()): string {
  return new Date(from.getTime() + FREQUENCY_MS[frequency]).toISOString();
}

export async function listSites(): Promise<MonitoredSite[]> {
  return getSites();
}

export async function createSite(input: MonitoredSiteInput): Promise<MonitoredSite> {
  const name = input.name?.trim();
  if (!name) throw new Error('Site name is required.');
  const url = normalizeUrl(input.url);
  const frequency = input.frequency ?? 'daily';
  const monitoringEnabled = input.monitoring_enabled ?? true;

  return insertSite({
    name,
    url,
    frequency,
    monitoring_enabled: monitoringEnabled,
    next_scan_at: monitoringEnabled ? computeNextScanAt(frequency) : null,
  });
}

export async function updateSite(
  id: string,
  input: Partial<MonitoredSiteInput>
): Promise<MonitoredSite> {
  const existing = await getSite(id);
  if (!existing) throw new Error('Site not found.');

  const fields: Partial<MonitoredSite> = {};
  if (input.name !== undefined) {
    const name = input.name.trim();
    if (!name) throw new Error('Site name cannot be empty.');
    fields.name = name;
  }
  if (input.url !== undefined) fields.url = normalizeUrl(input.url);
  if (input.frequency !== undefined) {
    fields.frequency = input.frequency;
    if (existing.monitoring_enabled) {
      fields.next_scan_at = computeNextScanAt(input.frequency);
    }
  }
  if (input.monitoring_enabled !== undefined) {
    fields.monitoring_enabled = input.monitoring_enabled;
    if (input.monitoring_enabled) {
      const freq = input.frequency ?? existing.frequency;
      fields.next_scan_at = computeNextScanAt(freq);
    } else {
      fields.next_scan_at = null;
    }
  }

  const updated = await updateSiteFields(id, fields);
  if (!updated) throw new Error('Site not found.');
  return updated;
}

export async function deleteSite(id: string): Promise<void> {
  await deleteSiteStore(id);
}

function summarizeResult(result: ScanResult) {
  const present = result.headers.filter((h) => h.status === 'present').length;
  const weak = result.headers.filter((h) => h.status === 'weak').length;
  const missing = result.headers.filter((h) => h.status === 'missing').length;
  return {
    score: result.score,
    grade: result.grade,
    https_enabled: result.https.enabled,
    https_valid: result.https.valid,
    https_redirect: result.https.redirectFromHttp,
    headers_present: present,
    headers_weak: weak,
    headers_missing: missing,
    vulnerability_count: result.vulnerabilities.count,
    critical_count: result.vulnerabilities.critical,
    high_count: result.vulnerabilities.high,
    medium_count: result.vulnerabilities.medium,
    low_count: result.vulnerabilities.low,
    info_count: result.vulnerabilities.info,
    result_json: result,
  };
}

export async function executeScan(
  siteId: string,
  trigger: ScanTrigger = 'manual'
): Promise<{ scan: ScanRecord; result: ScanResult; diff: ScanDiff | null }> {
  const site = await getSite(siteId);
  if (!site) throw new Error('Site not found.');

  const previousScans = await getScansForSite(siteId, 1);
  const prevScan = previousScans[0];

  const result = await runScan(site.url);
  const summary = summarizeResult(result);

  const scan = await insertScan({
    site_id: siteId,
    url: site.url,
    ...summary,
    trigger,
  });

  const nextScanAt = trigger === 'scheduled' ? computeNextScanAt(site.frequency) : null;
  await updateSiteFields(siteId, {
    last_scan_at: scan.scanned_at,
    last_score: result.score,
    last_grade: result.grade,
    next_scan_at: nextScanAt,
  });

  const diff = prevScan ? computeDiff(prevScan.result_json, result) : null;

  return { scan, result, diff };
}

export function computeDiff(prev: ScanResult, curr: ScanResult): ScanDiff {
  const prevHeaderNames = new Set(prev.headers.map((h) => h.name));
  const currHeaderNames = new Set(curr.headers.map((h) => h.name));
  const missingHeaders = Array.from(prevHeaderNames).filter(
    (n) => currHeaderNames.has(n) && curr.headers.find((h) => h.name === n)?.status === 'missing' && prev.headers.find((h) => h.name === n)?.status !== 'missing'
  );
  const addedHeaders = Array.from(currHeaderNames).filter(
    (n) => prevHeaderNames.has(n) && prev.headers.find((h) => h.name === n)?.status === 'missing' && curr.headers.find((h) => h.name === n)?.status !== 'missing'
  );

  return {
    scoreDelta: curr.score - prev.score,
    gradeChanged: curr.grade !== prev.grade,
    httpsChanged: curr.https.enabled !== prev.https.enabled || curr.https.valid !== prev.https.valid,
    missingHeaders,
    addedHeaders,
    newVulnerabilities: Math.max(0, curr.vulnerabilities.count - prev.vulnerabilities.count),
  };
}

export async function listScans(opts?: {
  siteId?: string;
  limit?: number;
  offset?: number;
}): Promise<ScanRecord[]> {
  if (opts?.siteId) {
    return getScansForSite(opts.siteId, opts.limit);
  }
  return getAllScans(opts?.limit, opts?.offset);
}

export async function getDashboardStats(): Promise<DashboardStats> {
  const sites = await getSites();
  const totalScans = await getScanCount();
  const recent = await getRecentScans(30);

  const totalSites = sites.length;
  const activeSites = sites.filter((s) => s.monitoring_enabled).length;

  const sortedByScan = sites.slice().sort(
    (a, b) => new Date(b.last_scan_at ?? 0).getTime() - new Date(a.last_scan_at ?? 0).getTime()
  );
  const latest = sortedByScan[0];
  const latestScore = latest?.last_score ?? null;
  const latestGrade = latest?.last_grade ?? null;
  const lastScanAt = latest?.last_scan_at ?? null;

  let previousScore: number | null = null;
  if (latest) {
    const prevScans = await getScansForSite(latest.id, 2);
    if (prevScans.length >= 2) previousScore = prevScans[1].score;
  }

  let scoreTrend: DashboardStats['scoreTrend'] = 'unknown';
  if (latestScore !== null && previousScore !== null) {
    if (latestScore > previousScore) scoreTrend = 'up';
    else if (latestScore < previousScore) scoreTrend = 'down';
    else scoreTrend = 'stable';
  }

  const scores = sites.map((s) => s.last_score).filter((s): s is number => s !== null);
  const averageScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;

  const httpsEnabled = latestScore !== null ? true : null;

  return {
    totalSites,
    activeSites,
    totalScans,
    lastScanAt,
    latestScore,
    latestGrade,
    previousScore,
    scoreTrend,
    httpsEnabled,
    averageScore,
    scoreHistory: recent.map((s) => ({
      scanned_at: s.scanned_at,
      score: s.score,
      grade: s.grade,
      url: s.url,
    })),
  };
}

export async function getDueSites(): Promise<MonitoredSite[]> {
  return getDueSitesStore();
}

export { gradeFromScore };
