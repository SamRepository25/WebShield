export type HeaderStatus = 'present' | 'missing' | 'weak' | 'report-only';

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
  pointsAwarded: number;
  maxPoints: number;
  category: 'transport' | 'content' | 'browser' | 'cookies' | 'infrastructure';
}

export interface RawHeader {
  name: string;
  value: string;
}

export interface CookieInfo {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  weaknesses: string[];
}

export interface RedirectStep {
  url: string;
  status: number;
  https: boolean;
}

export interface HttpsInfo {
  enabled: boolean;
  redirectFromHttp: boolean;
  valid: boolean;
  expiresAt: string;
  issuer: string;
  protocol: string;
  daysRemaining: number;
  hstsPreloadReady: boolean;
}

export interface ServerInfo {
  server: string;
  poweredBy: string;
  xPoweredBy: string;
  compression: string;
  finalStatusCode: number;
  redirectCount: number;
  redirectChain: RedirectStep[];
  mixedContent: boolean;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  whyItMatters: string;
  impact: string;
  exampleImplementation: string;
  severity: Severity;
  references?: string[];
}

export interface Vulnerabilities {
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScoreBreakdown {
  transport: number;
  content: number;
  browser: number;
  cookies: number;
  infrastructure: number;
  total: number;
  maxTotal: number;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  scannedAt: string;
  scanDurationMs: number;
  score: number;
  grade: string;
  scoreBreakdown: ScoreBreakdown;
  https: HttpsInfo;
  server: ServerInfo;
  cookies: CookieInfo[];
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
