export type HeaderStatus = 'present' | 'missing' | 'weak';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityHeader {
  name: string;
  value: string;
  status: HeaderStatus;
  description: string;
  whyItMatters: string;
  exampleValue: string;
  severity: Severity;
  isWeak: boolean;
  weaknessReason?: string;
}

export interface RawHeader {
  name: string;
  value: string;
}

export interface HttpsInfo {
  enabled: boolean;
  redirectFromHttp: boolean;
  valid: boolean;
  expiresAt: string;
  issuer: string;
  protocol: string;
  daysRemaining: number;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  whyItMatters: string;
  impact: string;
  exampleImplementation: string;
  severity: Severity;
}

export interface Vulnerabilities {
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  url: string;
  scannedAt: string;
  scanDurationMs: number;
  score: number;
  grade: string;
  https: HttpsInfo;
  headers: SecurityHeader[];
  rawHeaders: RawHeader[];
  recommendations: Recommendation[];
  vulnerabilities: Vulnerabilities;
}

export interface ScanRequest {
  url: string;
}

export interface ApiError {
  detail: string;
}
