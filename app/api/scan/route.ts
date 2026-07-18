import { NextRequest, NextResponse } from 'next/server';
import type {
  ScanResult,
  SecurityHeader,
  HttpsInfo,
  ServerInfo,
  CookieInfo,
  RedirectStep,
  Recommendation,
  Vulnerabilities,
  Severity,
  ScoreBreakdown,
  HeaderStatus,
} from '@/lib/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 25;

const REQUEST_TIMEOUT = 12000;
const USER_AGENT = 'WebShieldScanner/1.0 (+https://webshield.app)';
const MAX_REDIRECTS = 10;

type Category = 'transport' | 'content' | 'browser' | 'cookies' | 'infrastructure';

interface HeaderSpec {
  key: string;
  prettyName: string;
  category: Category;
  maxPoints: number;
  severity: Severity;
  description: string;
  whyItMatters: string;
  exampleValue: string;
  isOptional?: boolean;
  isLegacy?: boolean;
  checkWeakness?: (value: string) => { isWeak: boolean; reason?: string; penalty: number };
}

const HEADER_SPECS: HeaderSpec[] = [
  {
    key: 'strict-transport-security',
    prettyName: 'Strict-Transport-Security',
    category: 'transport',
    maxPoints: 20,
    severity: 'high',
    description:
      'Tells browsers to only connect via HTTPS for the specified duration, preventing protocol downgrade and SSL stripping attacks.',
    whyItMatters:
      'Without HSTS, a man-in-the-middle attacker can force a downgrade to HTTP and intercept or tamper with traffic.',
    exampleValue: 'max-age=63072000; includeSubDomains; preload',
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase();
      const reasons: string[] = [];
      const maxAgeMatch = lower.match(/max-age=(\d+)/);
      if (!maxAgeMatch) reasons.push('is missing a max-age directive');
      else if (parseInt(maxAgeMatch[1], 10) < 1036800)
        reasons.push(`max-age of ${maxAgeMatch[1]} is below the recommended 12 weeks (1036800)`);
      if (!lower.includes('includesubdomains'))
        reasons.push('does not include includeSubDomains');
      if (reasons.length === 0) return { isWeak: false, penalty: 0 };
      return { isWeak: true, reason: `HSTS ${reasons.join('; ')}.`, penalty: Math.min(reasons.length * 3, 8) };
    },
  },
  {
    key: 'content-security-policy',
    prettyName: 'Content-Security-Policy',
    category: 'content',
    maxPoints: 25,
    severity: 'high',
    description:
      'Controls which sources the browser may load resources from, mitigating Cross-Site Scripting (XSS) and data injection.',
    whyItMatters:
      'CSP is the most effective defense against XSS. Without it, any injected script can execute and steal data or credentials.',
    exampleValue:
      "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase();
      const reasons: string[] = [];
      if (lower.includes("'unsafe-inline'"))
        reasons.push("contains 'unsafe-inline' which allows inline scripts and styles");
      if (lower.includes("'unsafe-eval'"))
        reasons.push("contains 'unsafe-eval' which allows eval() and similar functions");
      if (lower.includes('* ')) reasons.push('uses a wildcard source which permits loading from any origin');
      if (lower.includes('http:')) reasons.push('references insecure http: sources');
      if (lower.includes('*://')) reasons.push('uses a protocol wildcard which permits insecure origins');
      if (!lower.includes('default-src') && !lower.includes('script-src'))
        reasons.push('lacks a default-src or script-src directive');
      if (reasons.length === 0) return { isWeak: false, penalty: 0 };
      return { isWeak: true, reason: `CSP ${reasons.join('; ')}.`, penalty: Math.min(reasons.length * 4, 15) };
    },
  },
  {
    key: 'content-security-policy-report-only',
    prettyName: 'Content-Security-Policy-Report-Only',
    category: 'content',
    maxPoints: 10,
    severity: 'info',
    description:
      'A report-only CSP that monitors violations without enforcing restrictions. Used for testing before full enforcement.',
    whyItMatters:
      'Report-Only CSP lets you deploy CSP safely by collecting violation reports first, then switching to enforcement once confident.',
    exampleValue:
      "default-src 'self'; report-uri /csp-reports",
    isOptional: true,
  },
  {
    key: 'x-frame-options',
    prettyName: 'X-Frame-Options',
    category: 'browser',
    maxPoints: 5,
    severity: 'medium',
    description:
      'Prevents the page from being embedded in iframes by unauthorized sites, stopping clickjacking attacks. Legacy header superseded by CSP frame-ancestors.',
    whyItMatters:
      'Without frame protection, attackers can overlay invisible UI on your page to trick users into clicking hidden actions.',
    exampleValue: 'DENY',
    isLegacy: true,
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      if (lower === 'deny' || lower === 'sameorigin') return { isWeak: false, penalty: 0 };
      if (lower.startsWith('allow-from'))
        return { isWeak: true, reason: 'uses ALLOW-FROM which is deprecated and ignored by modern browsers', penalty: 2 };
      return { isWeak: true, reason: 'has an unrecognized value', penalty: 2 };
    },
  },
  {
    key: 'x-content-type-options',
    prettyName: 'X-Content-Type-Options',
    category: 'browser',
    maxPoints: 5,
    severity: 'medium',
    description:
      'Disables MIME-type sniffing so the browser trusts the declared Content-Type and never interprets files as a different type.',
    whyItMatters:
      'Without nosniff, an uploaded text file could be executed as a script, enabling XSS through content-type confusion.',
    exampleValue: 'nosniff',
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      if (value.toLowerCase().trim() !== 'nosniff')
        return { isWeak: true, reason: 'should be set to nosniff', penalty: 2 };
      return { isWeak: false, penalty: 0 };
    },
  },
  {
    key: 'referrer-policy',
    prettyName: 'Referrer-Policy',
    category: 'browser',
    maxPoints: 5,
    severity: 'low',
    description:
      'Controls how much Referer header information is sent with outbound requests, protecting user privacy.',
    whyItMatters:
      'Without a restrictive policy, full URLs (including query parameters) can leak to third parties via the Referer header.',
    exampleValue: 'strict-origin-when-cross-origin',
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      const safe = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      if (safe.includes(lower)) return { isWeak: false, penalty: 0 };
      if (lower === 'unsafe-url' || lower === 'no-referrer-when-downgrade')
        return { isWeak: true, reason: 'allows referrer leakage to third parties', penalty: 2 };
      return { isWeak: false, penalty: 0 };
    },
  },
  {
    key: 'permissions-policy',
    prettyName: 'Permissions-Policy',
    category: 'browser',
    maxPoints: 10,
    severity: 'medium',
    description:
      'Restricts access to powerful browser features such as camera, microphone, geolocation, and payment APIs.',
    whyItMatters:
      'Without this policy, embedded content or compromised scripts could access sensitive device capabilities.',
    exampleValue: 'camera=(), microphone=(), geolocation=()',
  },
  {
    key: 'cross-origin-embedder-policy',
    prettyName: 'Cross-Origin-Embedder-Policy',
    category: 'browser',
    maxPoints: 5,
    severity: 'low',
    description:
      'Requires cross-origin resources to opt-in via CORS, enabling a secure context for powerful APIs like SharedArrayBuffer.',
    whyItMatters:
      'COEP prevents cross-origin resources from being loaded without explicit permission, mitigating Spectre-class attacks.',
    exampleValue: 'require-corp',
    isOptional: true,
  },
  {
    key: 'cross-origin-opener-policy',
    prettyName: 'Cross-Origin-Opener-Policy',
    category: 'browser',
    maxPoints: 5,
    severity: 'low',
    description:
      'Isolates the browsing context from cross-origin documents, preventing them from accessing your window object.',
    whyItMatters:
      'COOP prevents cross-origin documents from interacting with your page, defending against cross-origin attacks.',
    exampleValue: "same-origin",
    isOptional: true,
  },
  {
    key: 'cross-origin-resource-policy',
    prettyName: 'Cross-Origin-Resource-Policy',
    category: 'browser',
    maxPoints: 3,
    severity: 'low',
    description:
      'Restricts who can embed a resource, providing a defense-in-depth against cross-origin information leakage.',
    whyItMatters:
      'CORP prevents your resources from being loaded by arbitrary sites, reducing the risk of cross-origin attacks.',
    exampleValue: 'same-origin',
    isOptional: true,
  },
  {
    key: 'origin-agent-cluster',
    prettyName: 'Origin-Agent-Cluster',
    category: 'browser',
    maxPoints: 2,
    severity: 'info',
    description:
      'Requests the browser to segregate the origin into its own agent cluster, improving isolation.',
    whyItMatters:
      'Improves performance isolation and security by separating origins into distinct agent clusters.',
    exampleValue: '?1',
    isOptional: true,
  },
  {
    key: 'x-xss-protection',
    prettyName: 'X-XSS-Protection',
    category: 'browser',
    maxPoints: 0,
    severity: 'info',
    description:
      'Legacy Internet Explorer XSS filter header. Deprecated and removed from modern browsers. CSP is the modern replacement.',
    whyItMatters:
      'This header is deprecated. Modern browsers ignore it. Use Content-Security-Policy instead for XSS protection.',
    exampleValue: '1; mode=block',
    isLegacy: true,
    isOptional: true,
  },
  {
    key: 'clear-site-data',
    prettyName: 'Clear-Site-Data',
    category: 'browser',
    maxPoints: 2,
    severity: 'info',
    description:
      'Instructs the browser to clear site data (cookies, storage, cache) — useful for logout flows.',
    whyItMatters:
      'Clear-Site-Data ensures sensitive data is purged on logout, reducing the risk of session残留 attacks.',
    exampleValue: '"cache", "cookies", "storage"',
    isOptional: true,
  },
];

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

function parseSetCookie(header: string): CookieInfo | null {
  if (!header) return null;
  const parts = header.split(';').map((p) => p.trim());
  const namePart = parts[0] || '';
  const name = namePart.split('=')[0] || '';
  const lower = header.toLowerCase();
  const secure = lower.includes('secure');
  const httpOnly = lower.includes('httponly');
  let sameSite = 'None';
  const ssMatch = lower.match(/samesite=(lax|strict|none)/);
  if (ssMatch) sameSite = ssMatch[1].charAt(0).toUpperCase() + ssMatch[1].slice(1);
  const weaknesses: string[] = [];
  if (!secure) weaknesses.push('Missing Secure flag');
  if (!httpOnly) weaknesses.push('Missing HttpOnly flag');
  if (!ssMatch) weaknesses.push('Missing SameSite attribute');
  else if (sameSite === 'None') weaknesses.push('SameSite=None weakens CSRF protection');
  return { name, secure, httpOnly, sameSite, weaknesses };
}

function extractCookies(headers: Headers): CookieInfo[] {
  const cookies: CookieInfo[] = [];
  headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') {
      const parsed = parseSetCookie(value);
      if (parsed) cookies.push(parsed);
    }
  });
  return cookies;
}

async function checkHttpRedirect(hostname: string): Promise<boolean> {
  try {
    const res = await fetch(`http://${hostname}`, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': USER_AGENT },
    });
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      return Boolean(location && location.startsWith('https'));
    }
    return false;
  } catch {
    return false;
  }
}

async function getHttpsInfo(
  hostname: string,
  httpsOk: boolean,
  hstsValue: string
): Promise<HttpsInfo> {
  if (!httpsOk) {
    return {
      enabled: false,
      redirectFromHttp: false,
      valid: false,
      expiresAt: '',
      issuer: '',
      protocol: '',
      daysRemaining: 0,
      hstsPreloadReady: false,
    };
  }
  const redirectFromHttp = await checkHttpRedirect(hostname);
  const hstsLower = (hstsValue || '').toLowerCase();
  const hstsPreloadReady =
    hstsLower.includes('preload') &&
    hstsLower.includes('includesubdomains') &&
    Boolean(hstsLower.match(/max-age=(\d+)/)?.[1] && parseInt(hstsLower.match(/max-age=(\d+)/)![1], 10) >= 31536000);
  return {
    enabled: true,
    redirectFromHttp,
    valid: true,
    expiresAt: '',
    issuer: 'Verified via TLS connection',
    protocol: 'TLS',
    daysRemaining: 0,
    hstsPreloadReady,
  };
}

function getServerInfo(
  headers: Headers,
  finalStatus: number,
  redirectChain: RedirectStep[],
  finalUrl: string
): ServerInfo {
  const server = headers.get('server') || '';
  const xPoweredBy = headers.get('x-powered-by') || '';
  const poweredBy = headers.get('powered-by') || '';
  const encoding = headers.get('content-encoding') || '';
  const compression = encoding || 'none';
  const finalUrlHttp = finalUrl.startsWith('https://');
  const mixedContent = false;
  return {
    server,
    poweredBy,
    xPoweredBy,
    compression,
    finalStatusCode: finalStatus,
    redirectCount: redirectChain.length - 1,
    redirectChain,
    mixedContent,
  };
}

function analyzeHeaders(
  headers: Headers,
  cspEnforced: boolean
): {
  headerInfos: SecurityHeader[];
  scoreByCategory: Record<Category, number>;
  vulnerabilities: Vulnerabilities;
} {
  const lower = new Map<string, string>();
  headers.forEach((value, key) => lower.set(key.toLowerCase(), value));

  const headerInfos: SecurityHeader[] = [];
  const scoreByCategory: Record<Category, number> = {
    transport: 0,
    content: 0,
    browser: 0,
    cookies: 0,
    infrastructure: 0,
  };
  const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const spec of HEADER_SPECS) {
    const value = lower.get(spec.key) ?? '';
    const present = Boolean(value);
    const weakness = spec.checkWeakness ? spec.checkWeakness(value) : { isWeak: false, penalty: 0 };

    let status: HeaderStatus;
    let earned = 0;

    if (spec.key === 'content-security-policy' && !present && lower.has('content-security-policy-report-only')) {
      status = 'report-only';
      earned = 0;
      vulnCounts.info++;
    } else if (spec.key === 'content-security-policy-report-only' && present) {
      status = 'report-only';
      earned = spec.maxPoints;
    } else if (!present) {
      status = 'missing';
      earned = 0;
      if (!spec.isOptional) {
        const sev = spec.severity;
        if (sev === 'critical') vulnCounts.critical++;
        else if (sev === 'high') vulnCounts.high++;
        else if (sev === 'medium') vulnCounts.medium++;
        else if (sev === 'low') vulnCounts.low++;
      } else {
        vulnCounts.info++;
      }
    } else if (weakness.isWeak) {
      status = 'weak';
      earned = Math.max(spec.maxPoints - weakness.penalty, spec.maxPoints * 0.4);
      if (spec.severity === 'high' || spec.severity === 'critical') vulnCounts.medium++;
      else vulnCounts.low++;
    } else {
      status = 'present';
      earned = spec.maxPoints;
    }

    if (spec.isLegacy && spec.maxPoints === 0) {
      earned = 0;
    }

    scoreByCategory[spec.category] += earned;

    headerInfos.push({
      name: spec.prettyName,
      value: value || 'Not set',
      status,
      description: spec.description,
      whyItMatters: spec.whyItMatters,
      exampleValue: spec.exampleValue,
      severity: spec.severity,
      isWeak: weakness.isWeak,
      weaknessReason: weakness.reason,
      pointsAwarded: Math.round(earned * 10) / 10,
      maxPoints: spec.maxPoints,
      category: spec.category,
    });
  }

  const vulnerabilities: Vulnerabilities = {
    count: vulnCounts.critical + vulnCounts.high + vulnCounts.medium + vulnCounts.low + vulnCounts.info,
    ...vulnCounts,
  };

  return { headerInfos, scoreByCategory, vulnerabilities };
}

function analyzeCookies(cookies: CookieInfo[]): {
  score: number;
  maxScore: number;
  issues: string[];
} {
  if (cookies.length === 0) {
    return { score: 0, maxScore: 0, issues: [] };
  }
  let earned = 0;
  const max = 10;
  const issues: string[] = [];
  const secureCount = cookies.filter((c) => c.secure).length;
  const httpOnlyCount = cookies.filter((c) => c.httpOnly).length;
  const sameSiteCount = cookies.filter((c) => c.sameSite !== 'None').length;
  earned += (secureCount / cookies.length) * 4;
  earned += (httpOnlyCount / cookies.length) * 3;
  earned += (sameSiteCount / cookies.length) * 3;
  if (secureCount < cookies.length) issues.push('Some cookies missing Secure flag');
  if (httpOnlyCount < cookies.length) issues.push('Some cookies missing HttpOnly flag');
  if (sameSiteCount < cookies.length) issues.push('Some cookies missing or weak SameSite');
  return { score: Math.round(earned * 10) / 10, maxScore: max, issues };
}

function computeScore(
  scoreByCategory: Record<Category, number>,
  httpsInfo: HttpsInfo,
  cookieScore: number,
  cookieMax: number,
  serverInfo: ServerInfo
): { total: number; breakdown: ScoreBreakdown } {
  const transportBase = scoreByCategory.transport;
  const transportHttps = httpsInfo.enabled ? 10 : 0;
  const transportRedirect = httpsInfo.redirectFromHttp ? 5 : 0;
  const transportPreload = httpsInfo.hstsPreloadReady ? 5 : 0;
  const transport = transportBase + transportHttps + transportRedirect + transportPreload;

  const content = scoreByCategory.content;
  const browser = scoreByCategory.browser;
  const cookies = cookieScore;

  let infrastructure = 0;
  if (!serverInfo.server && !serverInfo.xPoweredBy && !serverInfo.poweredBy) infrastructure += 5;
  else {
    if (!serverInfo.server) infrastructure += 2;
    if (!serverInfo.xPoweredBy && !serverInfo.poweredBy) infrastructure += 3;
  }
  if (serverInfo.compression && serverInfo.compression !== 'none') infrastructure += 2;
  if (serverInfo.finalStatusCode > 0 && serverInfo.finalStatusCode < 400) infrastructure += 3;

  const maxTransport = 20 + 10 + 5 + 5;
  const maxContent = 25 + 10;
  const maxBrowser = 5 + 5 + 5 + 10 + 5 + 5 + 3 + 2 + 2;
  const maxCookies = cookieMax;
  const maxInfra = 10;

  const total = Math.min(
    transport + content + browser + cookies + infrastructure,
    maxTransport + maxContent + maxBrowser + maxCookies + maxInfra
  );

  const breakdown: ScoreBreakdown = {
    transport: Math.round(transport * 10) / 10,
    content: Math.round(content * 10) / 10,
    browser: Math.round(browser * 10) / 10,
    cookies: Math.round(cookies * 10) / 10,
    infrastructure: Math.round(infrastructure * 10) / 10,
    total: Math.round(total * 10) / 10,
    maxTotal: maxTransport + maxContent + maxBrowser + maxCookies + maxInfra,
  };

  return { total: breakdown.total, breakdown };
}

function gradeFromScore(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

function buildRecommendations(
  headerInfos: SecurityHeader[],
  httpsInfo: HttpsInfo,
  cookies: CookieInfo[],
  serverInfo: ServerInfo
): Recommendation[] {
  const recs: Recommendation[] = [];
  let id = 0;
  const nextId = () => `rec-${++id}`;

  const recTemplates: Record<string, Omit<Recommendation, 'id' | 'severity'>> = {
    'strict-transport-security': {
      title: 'Add Strict-Transport-Security (HSTS) header',
      description:
        'HSTS is missing. Add it to force browsers to always use HTTPS for your domain and prevent protocol downgrade attacks.',
      whyItMatters:
        'Without HSTS, users who type http:// or are redirected by an attacker can be downgraded to insecure HTTP, exposing them to man-in-the-middle attacks.',
      impact: 'Protects against SSL stripping and protocol downgrade attacks.',
      exampleImplementation:
        'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
    },
    'content-security-policy': {
      title: 'Add Content-Security-Policy header',
      description:
        "CSP is missing. Without it, your site has no defense against injected scripts running in your users' browsers.",
      whyItMatters:
        'CSP is the primary mitigation for Cross-Site Scripting (XSS). It restricts which scripts can execute and where resources can be loaded from.',
      impact: 'Significantly reduces risk of XSS and data exfiltration attacks.',
      exampleImplementation:
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
    },
    'x-frame-options': {
      title: 'Add X-Frame-Options or CSP frame-ancestors',
      description:
        'Frame protection is missing. Add CSP frame-ancestors (modern) or X-Frame-Options (legacy) to prevent clickjacking.',
      whyItMatters:
        'Without frame protection, attackers can overlay your page in a transparent iframe and trick users into clicking hidden actions (clickjacking).',
      impact: 'Prevents clickjacking attacks that exploit user trust.',
      exampleImplementation: "Content-Security-Policy: frame-ancestors 'none'",
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
    },
    'x-content-type-options': {
      title: 'Add X-Content-Type-Options header',
      description:
        "X-Content-Type-Options is missing. Set it to 'nosniff' to stop browsers from sniffing MIME types.",
      whyItMatters:
        'Without nosniff, the browser may interpret a file as a different type than declared, allowing an uploaded text file to execute as a script.',
      impact: 'Reduces risk of content-type confusion and XSS via file uploads.',
      exampleImplementation: 'X-Content-Type-Options: nosniff',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
    },
    'referrer-policy': {
      title: 'Add Referrer-Policy header',
      description:
        'Referrer-Policy is missing. Add it to control how much referrer information is shared with external sites.',
      whyItMatters:
        'Without a restrictive policy, full URLs (including sensitive query parameters) can leak to third-party sites via the Referer header.',
      impact: 'Protects user privacy by limiting referrer data leakage.',
      exampleImplementation: 'Referrer-Policy: strict-origin-when-cross-origin',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
    },
    'permissions-policy': {
      title: 'Add Permissions-Policy header',
      description:
        'Permissions-Policy is missing. Add it to restrict access to powerful browser features like camera, microphone, and geolocation.',
      whyItMatters:
        'Without this policy, compromised scripts or embedded content could access sensitive device capabilities without user consent.',
      impact: 'Limits attack surface by restricting powerful browser APIs.',
      exampleImplementation: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
    },
  };

  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  for (const header of headerInfos) {
    if (header.status === 'present') continue;
    if (header.status === 'report-only' && header.name === 'Content-Security-Policy-Report-Only') continue;

    const template = recTemplates[header.name.toLowerCase()];
    if (!template) continue;

    let description = template.description;
    if (header.status === 'weak' && header.weaknessReason) {
      description = `${header.name} ${header.weaknessReason} Strengthen it to improve your security posture.`;
    }
    if (header.status === 'report-only') {
      description = `${header.name} detected in report-only mode. This monitors violations without enforcement. Consider switching to enforcement once confident.`;
    }

    recs.push({
      id: nextId(),
      title:
        header.status === 'weak'
          ? `Strengthen ${header.name} header`
          : header.status === 'report-only'
          ? `Enforce ${header.name}`
          : template.title,
      description,
      whyItMatters: template.whyItMatters,
      impact: template.impact,
      exampleImplementation: template.exampleImplementation,
      severity: header.severity,
      references: template.references,
    });
  }

  if (!httpsInfo.enabled) {
    recs.push({
      id: nextId(),
      title: 'Enable HTTPS',
      description:
        'Your site does not serve over HTTPS. Obtain an SSL/TLS certificate and serve all traffic exclusively over HTTPS.',
      whyItMatters:
        'HTTPS is the foundation of web security. Without it, all traffic is sent in plaintext and can be intercepted or tampered with.',
      impact: 'Encrypts all traffic and enables secure browser features.',
      exampleImplementation:
        "Obtain a free certificate from Let's Encrypt and configure your server to redirect HTTP to HTTPS.",
      severity: 'critical',
    });
  } else if (!httpsInfo.redirectFromHttp) {
    recs.push({
      id: nextId(),
      title: 'Redirect HTTP to HTTPS',
      description:
        'Your site does not redirect HTTP traffic to HTTPS. Add a permanent redirect so all visitors use the secure connection.',
      whyItMatters:
        'Without a redirect, users who type http:// or follow an old link will connect insecurely, even though HTTPS is available.',
      impact: 'Ensures all visitors use the encrypted connection.',
      exampleImplementation: 'Add a 301 redirect from http:// to https:// in your web server or CDN configuration.',
      severity: 'high',
    });
  }

  const insecureCookies = cookies.filter((c) => c.weaknesses.length > 0);
  if (insecureCookies.length > 0) {
    recs.push({
      id: nextId(),
      title: 'Secure cookies with Secure, HttpOnly, and SameSite flags',
      description: `${insecureCookies.length} cookie(s) have security weaknesses: ${insecureCookies
        .flatMap((c) => c.weaknesses)
        .filter((v, i, a) => a.indexOf(v) === i)
        .join('; ')}.`,
      whyItMatters:
        'Insecure cookies can be stolen over HTTP, accessed via JavaScript (enabling XSS-based theft), or used in CSRF attacks.',
      impact: 'Protects session tokens and user data from theft and CSRF.',
      exampleImplementation: 'Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax; Path=/',
      severity: 'high',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
    });
  }

  if (serverInfo.server || serverInfo.xPoweredBy || serverInfo.poweredBy) {
    recs.push({
      id: nextId(),
      title: 'Hide server version information',
      description:
        'Your server reveals software version information via Server, X-Powered-By, or Powered-By headers. This helps attackers target known vulnerabilities.',
      whyItMatters:
        'Version information allows attackers to quickly identify which CVEs apply to your stack, lowering the bar for exploitation.',
      impact: 'Reduces information leakage and makes targeted attacks harder.',
      exampleImplementation:
        'Remove or obscure the Server and X-Powered-By headers in your web server configuration.',
      severity: 'low',
    });
  }

  recs.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return recs;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now();

  let body: { url?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: 'Invalid JSON body.' }, { status: 400 });
  }

  const rawUrl = body?.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return NextResponse.json({ detail: 'URL is required.' }, { status: 400 });
  }

  let url: string;
  try {
    url = normalizeUrl(rawUrl);
  } catch (err) {
    return NextResponse.json({ detail: (err as Error).message }, { status: 400 });
  }

  const parsed = new URL(url);
  const hostname = parsed.hostname;

  const mergedHeaders = new Headers();
  const redirectChain: RedirectStep[] = [];
  let finalResponse: Response | null = null;
  let currentUrl = url;
  let redirectCount = 0;

  try {
    while (redirectCount <= MAX_REDIRECTS) {
      const res = await fetch(currentUrl, {
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT },
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });

      res.headers.forEach((value, key) => {
        if (!mergedHeaders.has(key)) mergedHeaders.set(key, value);
      });

      redirectChain.push({
        url: currentUrl,
        status: res.status,
        https: currentUrl.startsWith('https://'),
      });

      const status = res.status;
      if (status >= 300 && status < 400) {
        const location = res.headers.get('location');
        if (!location) {
          finalResponse = res;
          break;
        }
        currentUrl = new URL(location, currentUrl).href;
        redirectCount++;
        continue;
      }

      finalResponse = res;
      break;
    }
  } catch (err) {
    const message = (err as Error).message ?? '';
    if (/ssl|certificate|cert|tls/i.test(message)) {
      return NextResponse.json(
        { detail: `SSL/TLS verification failed for ${hostname}. The certificate may be invalid, expired, or self-signed.` },
        { status: 422 }
      );
    }
    if (/timeout|abort/i.test(message)) {
      return NextResponse.json(
        { detail: `Request to ${hostname} timed out. The site may be slow or unresponsive.` },
        { status: 504 }
      );
    }
    if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) {
      return NextResponse.json(
        { detail: `Could not resolve ${hostname}. The domain may not exist or DNS lookup failed.` },
        { status: 502 }
      );
    }
    if (/ECONNREFUSED|ECONNRESET|fetch failed/i.test(message)) {
      return NextResponse.json(
        { detail: `Could not connect to ${hostname}. The site may be offline or refusing connections.` },
        { status: 502 }
      );
    }
    return NextResponse.json(
      { detail: `Could not reach ${hostname}. Please check the URL and try again.` },
      { status: 502 }
    );
  }

  if (redirectCount > MAX_REDIRECTS) {
    return NextResponse.json(
      { detail: `Too many redirects for ${hostname}. The site may have a redirect loop.` },
      { status: 502 }
    );
  }

  if (!finalResponse) {
    return NextResponse.json(
      { detail: `Could not fetch ${hostname}. Please check the URL and try again.` },
      { status: 502 }
    );
  }

  const httpStatus = finalResponse.status;
  if (httpStatus >= 400) {
    return NextResponse.json(
      { detail: `The site ${hostname} returned an HTTP ${httpStatus} error.` },
      { status: 502 }
    );
  }

  const httpsOk = httpStatus > 0 && httpStatus < 500 && currentUrl.startsWith('https://');
  const hstsValue = mergedHeaders.get('strict-transport-security') ?? '';
  const httpsInfo = await getHttpsInfo(hostname, httpsOk, hstsValue);
  const cspEnforced = Boolean(mergedHeaders.get('content-security-policy'));
  const { headerInfos, scoreByCategory, vulnerabilities } = analyzeHeaders(mergedHeaders, cspEnforced);
  const cookies = extractCookies(mergedHeaders);
  const cookieAnalysis = analyzeCookies(cookies);
  const serverInfo = getServerInfo(mergedHeaders, httpStatus, redirectChain, currentUrl);
  const { total, breakdown } = computeScore(
    scoreByCategory,
    httpsInfo,
    cookieAnalysis.score,
    cookieAnalysis.maxScore,
    serverInfo
  );
  const score = Math.round(total);
  const recommendations = buildRecommendations(headerInfos, httpsInfo, cookies, serverInfo);

  const rawHeaders = Array.from(mergedHeaders.entries()).map(([name, value]) => ({
    name,
    value,
  }));

  const scanDurationMs = Date.now() - startTime;

  const result: ScanResult = {
    url,
    finalUrl: currentUrl,
    scannedAt: new Date().toISOString(),
    scanDurationMs,
    score,
    grade: gradeFromScore(score),
    scoreBreakdown: breakdown,
    https: httpsInfo,
    server: serverInfo,
    cookies,
    headers: headerInfos,
    rawHeaders,
    recommendations,
    vulnerabilities,
  };

  return NextResponse.json(result);
}
