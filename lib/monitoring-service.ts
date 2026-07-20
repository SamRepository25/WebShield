import { supabase } from '@/lib/supabase';
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
  const { data, error } = await supabase
    .from('monitored_sites')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) throw new Error(`Failed to load sites: ${error.message}`);
  return (data ?? []) as MonitoredSite[];
}

export async function createSite(input: MonitoredSiteInput): Promise<MonitoredSite> {
  const name = input.name?.trim();
  if (!name) throw new Error('Site name is required.');
  const url = normalizeUrl(input.url);
  const frequency = input.frequency ?? 'daily';
  const monitoringEnabled = input.monitoring_enabled ?? true;

  const insert = {
    name,
    url,
    frequency,
    monitoring_enabled: monitoringEnabled,
    next_scan_at: monitoringEnabled ? computeNextScanAt(frequency) : null,
  };

  const { data, error } = await supabase
    .from('monitored_sites')
    .insert(insert)
    .select()
    .single();
  if (error) throw new Error(`Failed to create site: ${error.message}`);
  return data as MonitoredSite;
}

export async function updateSite(
  id: string,
  input: Partial<MonitoredSiteInput>
): Promise<MonitoredSite> {
  const update: Record<string, unknown> = {};
  if (input.name !== undefined) {
    const name = input.name.trim();
    if (!name) throw new Error('Site name cannot be empty.');
    update.name = name;
  }
  if (input.url !== undefined) update.url = normalizeUrl(input.url);
  if (input.frequency !== undefined) {
    update.frequency = input.frequency;
    const { data: current } = await supabase
      .from('monitored_sites')
      .select('monitoring_enabled')
      .eq('id', id)
      .maybeSingle();
    if (current?.monitoring_enabled) {
      update.next_scan_at = computeNextScanAt(input.frequency);
    }
  }
  if (input.monitoring_enabled !== undefined) {
    update.monitoring_enabled = input.monitoring_enabled;
    if (input.monitoring_enabled) {
      const { data: cur } = await supabase
        .from('monitored_sites')
        .select('frequency')
        .eq('id', id)
        .maybeSingle();
      const freq = (cur?.frequency as ScanFrequency) ?? 'daily';
      update.next_scan_at = computeNextScanAt(freq);
    } else {
      update.next_scan_at = null;
    }
  }

  const { data, error } = await supabase
    .from('monitored_sites')
    .update(update)
    .eq('id', id)
    .select()
    .single();
  if (error) throw new Error(`Failed to update site: ${error.message}`);
  return data as MonitoredSite;
}

export async function deleteSite(id: string): Promise<void> {
  const { error } = await supabase.from('monitored_sites').delete().eq('id', id);
  if (error) throw new Error(`Failed to delete site: ${error.message}`);
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
  const { data: site, error: siteErr } = await supabase
    .from('monitored_sites')
    .select('*')
    .eq('id', siteId)
    .maybeSingle();
  if (siteErr) throw new Error(`Failed to load site: ${siteErr.message}`);
  if (!site) throw new Error('Site not found.');

  const result = await runScan(site.url);
  const summary = summarizeResult(result);

  const { data: prevScan, error: prevErr } = await supabase
    .from('scans')
    .select('result_json')
    .eq('site_id', siteId)
    .order('scanned_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (prevErr) throw new Error(`Failed to load previous scan: ${prevErr.message}`);

  const { data: scanRow, error: insertErr } = await supabase
    .from('scans')
    .insert({
      site_id: siteId,
      url: site.url,
      ...summary,
      trigger,
    })
    .select()
    .single();
  if (insertErr) throw new Error(`Failed to store scan: ${insertErr.message}`);

  const nextScanAt = trigger === 'scheduled' ? computeNextScanAt(site.frequency) : null;
  const { error: updateErr } = await supabase
    .from('monitored_sites')
    .update({
      last_scan_at: new Date().toISOString(),
      last_score: result.score,
      last_grade: result.grade,
      next_scan_at: nextScanAt,
    })
    .eq('id', siteId);
  if (updateErr) throw new Error(`Failed to update site: ${updateErr.message}`);

  const diff = prevScan?.result_json
    ? computeDiff(prevScan.result_json as ScanResult, result)
    : null;

  return { scan: scanRow as ScanRecord, result, diff };
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
  let query = supabase.from('scans').select('*');
  if (opts?.siteId) query = query.eq('site_id', opts.siteId);
  query = query.order('scanned_at', { ascending: false });
  if (opts?.limit) query = query.limit(opts.limit);
  if (opts?.offset) query = query.range(opts.offset, opts.offset + (opts.limit ?? 50) - 1);
  const { data, error } = await query;
  if (error) throw new Error(`Failed to load scans: ${error.message}`);
  return (data ?? []) as ScanRecord[];
}

export async function getDashboardStats(): Promise<DashboardStats> {
  const [sitesRes, scansRes, recentRes] = await Promise.all([
    supabase.from('monitored_sites').select('id, monitoring_enabled, last_score, last_grade, last_scan_at'),
    supabase.from('scans').select('id', { count: 'exact', head: true }),
    supabase
      .from('scans')
      .select('scanned_at, score, grade, url')
      .order('scanned_at', { ascending: false })
      .limit(30),
  ]);

  if (sitesRes.error) throw new Error(`Failed to load sites: ${sitesRes.error.message}`);
  if (scansRes.error) throw new Error(`Failed to load scan count: ${scansRes.error.message}`);
  if (recentRes.error) throw new Error(`Failed to load recent scans: ${recentRes.error.message}`);

  const sites = sitesRes.data ?? [];
  const totalSites = sites.length;
  const activeSites = sites.filter((s) => s.monitoring_enabled).length;
  const totalScans = scansRes.count ?? 0;

  const sortedByScan = [...sites].sort(
    (a, b) => new Date(b.last_scan_at ?? 0).getTime() - new Date(a.last_scan_at ?? 0).getTime()
  );
  const latest = sortedByScan[0];
  const latestScore = latest?.last_score ?? null;
  const latestGrade = latest?.last_grade ?? null;
  const lastScanAt = latest?.last_scan_at ?? null;

  let previousScore: number | null = null;
  if (latest) {
    const { data: prevScan } = await supabase
      .from('scans')
      .select('score')
      .eq('site_id', latest.id)
      .order('scanned_at', { ascending: false })
      .range(1, 1)
      .maybeSingle();
    previousScore = prevScan?.score ?? null;
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
    scoreHistory: (recentRes.data ?? []).map((s) => ({
      scanned_at: s.scanned_at,
      score: s.score,
      grade: s.grade,
      url: s.url,
    })),
  };
}

export async function getDueSites(): Promise<MonitoredSite[]> {
  const nowIso = new Date().toISOString();
  const { data, error } = await supabase
    .from('monitored_sites')
    .select('*')
    .eq('monitoring_enabled', true)
    .or(`next_scan_at.is.null,next_scan_at.lte.${nowIso}`)
    .order('next_scan_at', { ascending: true, nullsFirst: true });
  if (error) throw new Error(`Failed to load due sites: ${error.message}`);
  return (data ?? []) as MonitoredSite[];
}

export { gradeFromScore };
