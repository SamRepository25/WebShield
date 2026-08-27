export type HeaderStatus = 'present' | 'missing' | 'weak' | 'report-only';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// How important a header realistically is. 'essential' headers materially
// reduce real-world attack surface for most sites. 'recommended' headers
// add meaningful hardening but aren't universally required. 'optional'
// headers (advanced browser-isolation headers like COEP/COOP/CORP, legacy
// headers, monitoring-only headers) are context-dependent hardening and
// should never by themselves drag a site down to a poor grade.
export type HeaderTier = 'essential' | 'recommended' | 'optional';

export interface SecurityHeader {
  name: string;
  value: string;
  status: HeaderStatus;
  description: string;
  whyItMatters: string;
  exampleValue: string;
  severity: Severity;
  tier: HeaderTier;
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
  // Heuristic: does the cookie's name look like it carries session/auth
  // state? Drives whether a missing HttpOnly flag is treated as a real
  // weakness or just an informational note.
  looksSensitive: boolean;
  // Real, actionable security weaknesses (drive score and recommendations).
  weaknesses: string[];
  // Context notes that are not, by themselves, security weaknesses (e.g. a
  // cookie intentionally readable by JavaScript).
  informational: string[];
}

export type RedirectType =
  | 'initial'
  | 'protocol-upgrade'
  | 'domain-change'
  | 'www-change'
  | 'path-change'
  | 'other';

export interface RedirectStep {
  url: string;
  status: number;
  https: boolean;
  redirectType: RedirectType;
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
  tier: HeaderTier;
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
