import tls from 'node:tls';
import type {
  ScanResult,
  SecurityHeader,
  HttpsInfo,
  ServerInfo,
  CookieInfo,
  RedirectStep,
  RedirectType,
  Recommendation,
  Vulnerabilities,
  Severity,
  ScoreBreakdown,
  HeaderStatus,
  HeaderTier,
} from '@/lib/types';

export const REQUEST_TIMEOUT = 12000;
export const USER_AGENT = 'WebShieldScanner/1.0 (+https://webshield.app)';
export const MAX_REDIRECTS = 10;

const PRIVATE_IPV4_RANGES = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^172\.(?:1[6-9]|2\d|3[01])\./,
];

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host === 'metadata.google.internal' ||
    host === 'metadata' ||
    host === '169.254.169.254'
  ) return true;
  if (host === '::1' || host === '0:0:0:0:0:0:0:1' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) return true;
  return PRIVATE_IPV4_RANGES.some((range) => range.test(host));
}

function assertSafeUrl(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ScanError('Please provide a valid website URL.', 400);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new ScanError('Only HTTP and HTTPS URLs can be scanned.', 400);
  }
  if (!parsed.hostname || isBlockedHostname(parsed.hostname)) {
    throw new ScanError('Private, local, and metadata network addresses cannot be scanned.', 400);
  }
  return parsed;
}

export function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) throw new ScanError('URL is required.', 400);
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return assertSafeUrl(withProtocol).href;
}

type Category = 'transport' | 'content' | 'browser' | 'cookies' | 'infrastructure';

interface HeaderSpec {
  key: string;
  prettyName: string;
  category: Category;
  maxPoints: number;
  severity: Severity;
  tier: HeaderTier;
  description: string;
  whyItMatters: string;
  exampleValue: string;
  isOptional?: boolean;
  isLegacy?: boolean;
  checkWeakness?: (value: string) => { isWeak: boolean; reason?: string; penalty: number };
}

export const HEADER_SPECS: HeaderSpec[] = [
  { key: 'strict-transport-security', prettyName: 'Strict-Transport-Security', category: 'transport', maxPoints: 20, severity: 'high', tier: 'essential', description: 'Forces browsers to use HTTPS for future requests.', whyItMatters: 'Reduces protocol downgrade and SSL stripping attacks.', exampleValue: 'max-age=63072000; includeSubDomains; preload', checkWeakness: (value) => { if (!value) return { isWeak: false, penalty: 0 }; const lower = value.toLowerCase(); const reasons: string[] = []; const match = lower.match(/max-age=(\d+)/); if (!match) reasons.push('is missing max-age'); else if (parseInt(match[1], 10) < 1036800) reasons.push('has a short max-age'); if (!lower.includes('includesubdomains')) reasons.push('does not include includeSubDomains'); return reasons.length ? { isWeak: true, reason: `HSTS ${reasons.join('; ')}.`, penalty: Math.min(reasons.length * 3, 8) } : { isWeak: false, penalty: 0 }; } },
  { key: 'content-security-policy', prettyName: 'Content-Security-Policy', category: 'content', maxPoints: 25, severity: 'high', tier: 'essential', description: 'Controls which sources the browser may load.', whyItMatters: 'Mitigates many XSS and content injection attacks.', exampleValue: "default-src 'self'; object-src 'none'; frame-ancestors 'none'", checkWeakness: (value) => { if (!value) return { isWeak: false, penalty: 0 }; const lower = value.toLowerCase(); const reasons: string[] = []; let penalty = 0; if (lower.includes("'unsafe-inline'")) { reasons.push("contains 'unsafe-inline'"); penalty += 5; } if (lower.includes("'unsafe-eval'")) { reasons.push("contains 'unsafe-eval'"); penalty += 5; } if (lower.includes('default-src *') || lower.includes(' *;')) { reasons.push('uses a wildcard source'); penalty += 5; } if (!lower.includes('default-src') && !lower.includes('script-src')) { reasons.push('is missing default-src or script-src'); penalty += 10; } return reasons.length ? { isWeak: true, reason: `CSP ${reasons.join('; ')}.`, penalty: Math.min(penalty, 18) } : { isWeak: false, penalty: 0 }; } },
  { key: 'content-security-policy-report-only', prettyName: 'Content-Security-Policy-Report-Only', category: 'content', maxPoints: 0, severity: 'info', tier: 'optional', description: 'Monitors CSP violations without enforcing them.', whyItMatters: 'Useful for testing CSP before enforcement.', exampleValue: "default-src 'self'; report-uri /csp-report", isOptional: true },
  { key: 'x-frame-options', prettyName: 'X-Frame-Options', category: 'browser', maxPoints: 5, severity: 'medium', tier: 'essential', description: 'Restricts framing to help prevent clickjacking.', whyItMatters: 'Stops malicious sites from embedding sensitive UI.', exampleValue: 'DENY', isLegacy: true, checkWeakness: (value) => { if (!value) return { isWeak: false, penalty: 0 }; const lower = value.toLowerCase().trim(); return lower === 'deny' || lower === 'sameorigin' ? { isWeak: false, penalty: 0 } : { isWeak: true, reason: 'X-Frame-Options should be DENY or SAMEORIGIN.', penalty: 2 }; } },
  { key: 'x-content-type-options', prettyName: 'X-Content-Type-Options', category: 'browser', maxPoints: 5, severity: 'medium', tier: 'essential', description: 'Disables MIME type sniffing.', whyItMatters: 'Reduces content type confusion attacks.', exampleValue: 'nosniff', checkWeakness: (value) => !value || value.toLowerCase().trim() === 'nosniff' ? { isWeak: false, penalty: 0 } : { isWeak: true, reason: 'X-Content-Type-Options should be nosniff.', penalty: 2 } },
  { key: 'referrer-policy', prettyName: 'Referrer-Policy', category: 'browser', maxPoints: 5, severity: 'low', tier: 'recommended', description: 'Controls referrer information sent with requests.', whyItMatters: 'Limits URL and query leakage to third parties.', exampleValue: 'strict-origin-when-cross-origin', checkWeakness: (value) => { const lower = value.toLowerCase().trim(); return lower === 'unsafe-url' || lower === 'no-referrer-when-downgrade' ? { isWeak: true, reason: 'Referrer policy can leak full URLs.', penalty: 2 } : { isWeak: false, penalty: 0 }; } },
  { key: 'permissions-policy', prettyName: 'Permissions-Policy', category: 'browser', maxPoints: 10, severity: 'medium', tier: 'recommended', description: 'Restricts powerful browser features.', whyItMatters: 'Reduces browser API attack surface.', exampleValue: 'geolocation=(), camera=(), microphone=()' },
  { key: 'cross-origin-embedder-policy', prettyName: 'Cross-Origin-Embedder-Policy', category: 'browser', maxPoints: 0, severity: 'info', tier: 'optional', description: 'Controls cross-origin embedding isolation.', whyItMatters: 'Enables stronger isolation for some applications.', exampleValue: 'require-corp', isOptional: true },
  { key: 'cross-origin-opener-policy', prettyName: 'Cross-Origin-Opener-Policy', category: 'browser', maxPoints: 0, severity: 'info', tier: 'optional', description: 'Isolates browsing contexts from cross-origin windows.', whyItMatters: 'Adds cross-origin isolation.', exampleValue: 'same-origin', isOptional: true },
  { key: 'cross-origin-resource-policy', prettyName: 'Cross-Origin-Resource-Policy', category: 'browser', maxPoints: 0, severity: 'info', tier: 'optional', description: 'Restricts cross-origin resource loading.', whyItMatters: 'Reduces cross-origin information exposure.', exampleValue: 'same-origin', isOptional: true },
];

const SENSITIVE_COOKIE_PATTERN = /(session|sess|auth|token|jwt|login|credential|csrf|xsrf|^sid$|_sid$|account|user_id|uid)/i;

function parseSetCookie(header: string): CookieInfo | null {
  if (!header) return null;
  const parts = header.split(';').map((part) => part.trim());
  const name = (parts[0] || '').split('=')[0] || '';
  const lower = header.toLowerCase();
  const secure = /(?:^|;)\s*secure(?:;|$)/i.test(header);
  const httpOnly = /(?:^|;)\s*httponly(?:;|$)/i.test(header);
  const sameSiteMatch = lower.match(/samesite=(lax|strict|none)/);
  const sameSite = sameSiteMatch ? sameSiteMatch[1][0].toUpperCase() + sameSiteMatch[1].slice(1) : 'None';
  const looksSensitive = SENSITIVE_COOKIE_PATTERN.test(name);
  const weaknesses: string[] = [];
  const informational: string[] = [];
  if (!secure) weaknesses.push('Missing Secure flag');
  if (!httpOnly) {
    if (looksSensitive) weaknesses.push('Missing HttpOnly flag on a session/auth-like cookie');
    else informational.push('No HttpOnly flag; this may be intentional for a non-sensitive cookie');
  }
  if (!sameSiteMatch) informational.push('No explicit SameSite attribute');
  else if (sameSite === 'None' && !secure) weaknesses.push('SameSite=None requires Secure');
  return { name, secure, httpOnly, sameSite, looksSensitive, weaknesses, informational };
}

function extractCookies(headers: Headers): CookieInfo[] {
  const getSetCookie = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  const values = typeof getSetCookie === 'function' ? getSetCookie.call(headers) : [];
  if (values.length) return values.map(parseSetCookie).filter((cookie): cookie is CookieInfo => Boolean(cookie));
  const value = headers.get('set-cookie');
  return value ? [parseSetCookie(value)].filter((cookie): cookie is CookieInfo => Boolean(cookie)) : [];
}

function classifyRedirect(fromUrl: string, toUrl: string): RedirectType {
  try {
    const from = new URL(fromUrl);
    const to = new URL(toUrl);
    if (from.protocol === 'http:' && to.protocol === 'https:') return 'protocol-upgrade';
    const stripWww = (host: string) => host.replace(/^www\./i, '');
    if (stripWww(from.hostname) !== stripWww(to.hostname)) return 'domain-change';
    if (from.hostname !== to.hostname) return 'www-change';
    if (from.pathname !== to.pathname || from.search !== to.search) return 'path-change';
  } catch {}
  return 'other';
}

async function checkHttpToHttpsUpgrade(hostname: string): Promise<boolean> {
  let currentUrl = `http://${hostname}`;
  for (let hops = 0; hops <= MAX_REDIRECTS; hops++) {
    if (currentUrl.startsWith('https://')) return true;
    try {
      const response = await fetch(currentUrl, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'User-Agent': USER_AGENT } });
      if (response.status < 300 || response.status >= 400) return false;
      const location = response.headers.get('location');
      if (!location) return false;
      const nextUrl = new URL(location, currentUrl).href;
      assertSafeUrl(nextUrl);
      currentUrl = nextUrl;
    } catch {
      return false;
    }
  }
  return false;
}

function inspectTls(hostname: string): Promise<{ valid: boolean; expiresAt: string; issuer: string; protocol: string; daysRemaining: number }> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: { valid: boolean; expiresAt: string; issuer: string; protocol: string; daysRemaining: number }) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false });
    socket.setTimeout(8000);
    socket.once('secureConnect', () => {
      try {
        const certificate = socket.getPeerCertificate();
        const expiresAt = certificate.valid_to || '';
        const validTo = expiresAt ? new Date(expiresAt) : null;
        const daysRemaining = validTo && !Number.isNaN(validTo.getTime()) ? Math.ceil((validTo.getTime() - Date.now()) / 86400000) : 0;
        const issuer = certificate.issuer && typeof certificate.issuer === 'object'
          ? Object.entries(certificate.issuer).map(([key, value]) => `${key}=${value}`).join(', ')
          : '';
        finish({ valid: socket.authorized, expiresAt, issuer, protocol: socket.getProtocol() || '', daysRemaining });
      } catch {
        finish({ valid: false, expiresAt: '', issuer: '', protocol: '', daysRemaining: 0 });
      } finally { socket.end(); }
    });
    socket.once('timeout', () => { socket.destroy(); finish({ valid: false, expiresAt: '', issuer: '', protocol: '', daysRemaining: 0 }); });
    socket.once('error', () => finish({ valid: false, expiresAt: '', issuer: '', protocol: '', daysRemaining: 0 }));
  });
}

async function getHttpsInfo(hostname: string, httpsOk: boolean, hstsValue: string): Promise<HttpsInfo> {
  if (!httpsOk) return { enabled: false, redirectFromHttp: false, valid: false, expiresAt: '', issuer: '', protocol: '', daysRemaining: 0, hstsPreloadReady: false };
  const redirectFromHttp = await checkHttpToHttpsUpgrade(hostname);
  const lower = hstsValue.toLowerCase();
  const maxAge = lower.match(/max-age=(\d+)/);
  const tlsInfo = await inspectTls(hostname);
  return {
    enabled: true,
    redirectFromHttp,
    valid: tlsInfo.valid,
    expiresAt: tlsInfo.expiresAt,
    issuer: tlsInfo.issuer,
    protocol: tlsInfo.protocol,
    daysRemaining: tlsInfo.daysRemaining,
    hstsPreloadReady: lower.includes('preload') && lower.includes('includesubdomains') && Boolean(maxAge?.[1] && parseInt(maxAge[1], 10) >= 31536000),
  };
}

function analyzeHeaders(headers: Headers, httpsEnabled: boolean): { headerInfos: SecurityHeader[]; scoreByCategory: Record<Category, number>; vulnerabilities: Vulnerabilities } {
  const values = new Map<string, string>();
  headers.forEach((value, key) => values.set(key.toLowerCase(), value));
  const scoreByCategory: Record<Category, number> = { transport: 0, content: 0, browser: 0, cookies: 0, infrastructure: 0 };
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const csp = (values.get('content-security-policy') || '').toLowerCase();
  const headerInfos = HEADER_SPECS.map((spec) => {
    const value = values.get(spec.key) || '';
    const present = Boolean(value);
    const weakness = spec.checkWeakness?.(value) || { isWeak: false, penalty: 0 };
    let status: HeaderStatus = present ? (weakness.isWeak ? 'weak' : 'present') : 'missing';
    let severity = spec.severity;
    let pointsAwarded = present ? spec.maxPoints : 0;
    let weaknessReason = weakness.reason;
    if (spec.key === 'content-security-policy' && !present && values.has('content-security-policy-report-only')) { status = 'report-only'; severity = 'info'; weaknessReason = 'CSP is report-only and not enforced.'; }
    if (spec.key === 'strict-transport-security' && !httpsEnabled) { severity = 'info'; weaknessReason = 'HTTPS is not enabled, so HSTS is not applicable yet.'; }
    if (spec.key === 'x-frame-options' && !present && csp.includes('frame-ancestors')) { severity = 'info'; pointsAwarded = spec.maxPoints; weaknessReason = 'CSP frame-ancestors already provides clickjacking protection.'; }
    if (present && weakness.isWeak) pointsAwarded = Math.max(spec.maxPoints - weakness.penalty, spec.maxPoints * 0.4);
    if (status === 'missing' || status === 'weak' || status === 'report-only') {
      if (severity === 'critical') counts.critical++;
      else if (severity === 'high') counts.high++;
      else if (severity === 'medium') counts.medium++;
      else if (severity === 'low') counts.low++;
      else counts.info++;
    }
    scoreByCategory[spec.category] += pointsAwarded;
    return { name: spec.prettyName, value: value || 'Not set', status, description: spec.description, whyItMatters: spec.whyItMatters, exampleValue: spec.exampleValue, severity, tier: spec.tier, isWeak: weakness.isWeak, weaknessReason, pointsAwarded, maxPoints: spec.maxPoints, category: spec.category };
  });
  return { headerInfos, scoreByCategory, vulnerabilities: { count: counts.critical + counts.high + counts.medium + counts.low + counts.info, ...counts } };
}

function analyzeCookies(cookies: CookieInfo[]) {
  if (!cookies.length) return { score: 0, maxScore: 0 };
  const sensitive = cookies.filter((cookie) => cookie.looksSensitive);
  const relevant = sensitive.length ? sensitive : cookies;
  const secure = cookies.filter((cookie) => cookie.secure).length / cookies.length;
  const httpOnly = relevant.filter((cookie) => cookie.httpOnly).length / relevant.length;
  const sameSite = cookies.filter((cookie) => cookie.sameSite !== 'None' || cookie.secure).length / cookies.length;
  return { score: Math.round((secure * 5 + httpOnly * 3 + sameSite * 2) * 10) / 10, maxScore: 10 };
}

function getServerInfo(headers: Headers, httpStatus: number, redirectChain: RedirectStep[]): ServerInfo {
  return { server: headers.get('server') || '', poweredBy: headers.get('powered-by') || '', xPoweredBy: headers.get('x-powered-by') || '', compression: headers.get('content-encoding') || 'none', finalStatusCode: httpStatus, redirectCount: Math.max(0, redirectChain.length - 1), redirectChain, mixedContent: false };
}

function computeScore(scoreByCategory: Record<Category, number>, httpsInfo: HttpsInfo, cookieScore: number, serverInfo: ServerInfo): { total: number; breakdown: ScoreBreakdown } {
  const transport = scoreByCategory.transport + (httpsInfo.enabled ? 10 : 0) + (httpsInfo.redirectFromHttp ? 5 : 0) + (httpsInfo.hstsPreloadReady ? 5 : 0);
  const infrastructure = (serverInfo.finalStatusCode > 0 && serverInfo.finalStatusCode < 400 ? 3 : 0) + (serverInfo.compression !== 'none' ? 2 : 0) + (!serverInfo.server ? 2 : 0) + (!serverInfo.xPoweredBy && !serverInfo.poweredBy ? 3 : 0);
  const content = scoreByCategory.content;
  const browser = scoreByCategory.browser;
  const cookies = cookieScore;
  const total = Math.min(100, transport + content + browser + cookies + infrastructure);
  return { total, breakdown: { transport, content, browser, cookies, infrastructure, total, maxTotal: 100 } };
}

export function gradeFromScore(score: number): string { if (score >= 90) return 'A'; if (score >= 80) return 'B'; if (score >= 70) return 'C'; if (score >= 60) return 'D'; if (score >= 50) return 'E'; return 'F'; }

function buildRecommendations(headers: SecurityHeader[], httpsInfo: HttpsInfo, cookies: CookieInfo[], serverInfo: ServerInfo): Recommendation[] {
  const recommendations: Recommendation[] = [];
  let id = 1;
  for (const header of headers.filter((item) => item.status === 'missing' || item.status === 'weak' || item.status === 'report-only')) {
    if (header.severity === 'info' && (header.name === 'Strict-Transport-Security' || header.name === 'X-Frame-Options')) continue;
    recommendations.push({ id: `rec-${id++}`, title: `${header.tier === 'optional' ? 'Optional hardening: ' : header.tier === 'recommended' ? 'Recommended: ' : ''}Configure ${header.name}`, description: header.weaknessReason || `${header.name} is ${header.status}.`, whyItMatters: header.whyItMatters, impact: header.description, exampleImplementation: `${header.name}: ${header.exampleValue}`, severity: header.severity, tier: header.tier });
  }
  const weakCookies = cookies.filter((cookie) => cookie.weaknesses.length);
  if (weakCookies.length) recommendations.push({ id: `rec-${id++}`, title: 'Secure sensitive cookies', description: weakCookies.flatMap((cookie) => cookie.weaknesses).join('; '), whyItMatters: 'Cookie weaknesses can contribute to session theft or insecure transport.', impact: 'Reduces cookie theft and session abuse risk.', exampleImplementation: 'Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax', severity: 'medium', tier: 'essential' });
  if (serverInfo.server || serverInfo.xPoweredBy || serverInfo.poweredBy) recommendations.push({ id: `rec-${id++}`, title: 'Reduce server fingerprinting', description: 'Server technology details are exposed in response headers.', whyItMatters: 'Fingerprinting can help attackers target known weaknesses.', impact: 'Reduces unnecessary information disclosure.', exampleImplementation: 'Remove unnecessary Server and X-Powered-By headers.', severity: 'low', tier: 'recommended' });
  if (!httpsInfo.enabled) recommendations.push({ id: `rec-${id++}`, title: 'Enable HTTPS', description: 'The site did not finish on HTTPS.', whyItMatters: 'HTTPS protects data in transit.', impact: 'Protects visitors from passive interception and tampering.', exampleImplementation: 'Deploy a valid TLS certificate and redirect HTTP to HTTPS.', severity: 'critical', tier: 'essential' });
  else if (!httpsInfo.redirectFromHttp) recommendations.push({ id: `rec-${id++}`, title: 'Redirect HTTP to HTTPS', description: 'HTTPS is available but HTTP upgrade was not detected.', whyItMatters: 'Users can otherwise remain on an unencrypted connection.', impact: 'Ensures visitors end up on HTTPS.', exampleImplementation: 'Return a permanent redirect from HTTP to HTTPS.', severity: 'medium', tier: 'essential' });
  return recommendations;
}

export class ScanError extends Error {
  constructor(message: string, public status: number) { super(message); this.name = 'ScanError'; }
}

function mapFetchError(message: string, hostname: string): ScanError {
  if (/timeout|abort/i.test(message)) return new ScanError(`Request to ${hostname} timed out.`, 504);
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) return new ScanError(`Could not resolve ${hostname}.`, 502);
  if (/certificate|cert|tls|ssl/i.test(message)) return new ScanError(`TLS verification failed for ${hostname}.`, 422);
  return new ScanError(`Could not reach ${hostname}. Please check the URL and try again.`, 502);
}

export async function runScan(rawUrl: string): Promise<ScanResult> {
  const startTime = Date.now();
  const initial = assertSafeUrl(normalizeUrl(rawUrl));
  const url = initial.href;
  const hostname = initial.hostname;
  const mergedHeaders = new Headers();
  const redirectChain: RedirectStep[] = [];
  let currentUrl = url;
  let finalResponse: Response | null = null;
  try {
    for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
      const current = assertSafeUrl(currentUrl);
      const response = await fetch(current.href, { method: 'GET', headers: { 'User-Agent': USER_AGENT }, redirect: 'manual', signal: AbortSignal.timeout(REQUEST_TIMEOUT) });
      response.headers.forEach((value, key) => { if (!mergedHeaders.has(key)) mergedHeaders.set(key, value); });
      const previous = redirectChain.at(-1)?.url;
      redirectChain.push({ url: current.href, status: response.status, https: current.protocol === 'https:', redirectType: previous ? classifyRedirect(previous, current.href) : 'initial' });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) { finalResponse = response; break; }
        currentUrl = new URL(location, current.href).href;
        if (redirectCount === MAX_REDIRECTS) throw new ScanError(`Too many redirects for ${hostname}.`, 502);
        continue;
      }
      finalResponse = response;
      break;
    }
  } catch (error) {
    if (error instanceof ScanError) throw error;
    throw mapFetchError(error instanceof Error ? error.message : '', hostname);
  }
  if (!finalResponse) throw new ScanError(`Could not fetch ${hostname}.`, 502);
  if (finalResponse.status >= 400) throw new ScanError(`The site ${hostname} returned an HTTP ${finalResponse.status} error.`, 502);
  const httpsOk = currentUrl.startsWith('https://');
  const https = await getHttpsInfo(new URL(currentUrl).hostname, httpsOk, mergedHeaders.get('strict-transport-security') || '');
  const { headerInfos, scoreByCategory, vulnerabilities } = analyzeHeaders(mergedHeaders, httpsOk);
  const cookies = extractCookies(mergedHeaders);
  const cookieAnalysis = analyzeCookies(cookies);
  const server = getServerInfo(mergedHeaders, finalResponse.status, redirectChain);
  const { total, breakdown } = computeScore(scoreByCategory, https, cookieAnalysis.score, server);
  const score = Math.round(total);
  return { url, finalUrl: currentUrl, scannedAt: new Date().toISOString(), scanDurationMs: Date.now() - startTime, score, grade: gradeFromScore(score), scoreBreakdown: breakdown, https, server, cookies, headers: headerInfos, rawHeaders: Array.from(mergedHeaders.entries()).map(([name, value]) => ({ name, value })), recommendations: buildRecommendations(headerInfos, https, cookies, server), vulnerabilities };
}
