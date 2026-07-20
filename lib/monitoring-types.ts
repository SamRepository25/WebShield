import type { ScanResult } from '@/lib/types';

export type ScanFrequency = '6h' | '12h' | 'daily' | 'weekly';

export type ScanTrigger = 'manual' | 'scheduled';

export interface MonitoredSite {
  id: string;
  name: string;
  url: string;
  frequency: ScanFrequency;
  monitoring_enabled: boolean;
  last_scan_at: string | null;
  next_scan_at: string | null;
  last_score: number | null;
  last_grade: string | null;
  created_at: string;
  updated_at: string;
}

export interface MonitoredSiteInput {
  name: string;
  url: string;
  frequency?: ScanFrequency;
  monitoring_enabled?: boolean;
}

export interface ScanRecord {
  id: string;
  site_id: string | null;
  url: string;
  score: number;
  grade: string;
  https_enabled: boolean;
  https_valid: boolean;
  https_redirect: boolean;
  headers_present: number;
  headers_weak: number;
  headers_missing: number;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  result_json: ScanResult;
  trigger: ScanTrigger;
  scanned_at: string;
}

export interface DashboardStats {
  totalSites: number;
  activeSites: number;
  totalScans: number;
  lastScanAt: string | null;
  latestScore: number | null;
  latestGrade: string | null;
  previousScore: number | null;
  scoreTrend: 'up' | 'down' | 'stable' | 'unknown';
  httpsEnabled: boolean | null;
  averageScore: number | null;
  scoreHistory: Array<{ scanned_at: string; score: number; grade: string; url: string }>;
}

export interface ScanDiff {
  scoreDelta: number;
  gradeChanged: boolean;
  httpsChanged: boolean;
  missingHeaders: string[];
  addedHeaders: string[];
  newVulnerabilities: number;
}

export const FREQUENCY_LABELS: Record<ScanFrequency, string> = {
  '6h': 'Every 6 Hours',
  '12h': 'Every 12 Hours',
  daily: 'Daily',
  weekly: 'Weekly',
};

export const FREQUENCY_MS: Record<ScanFrequency, number> = {
  '6h': 6 * 60 * 60 * 1000,
  '12h': 12 * 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
};
