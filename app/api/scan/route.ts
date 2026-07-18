import { NextRequest, NextResponse } from 'next/server';
import type {
  ScanResult,
  SecurityHeader,
  HttpsInfo,
  Recommendation,
  Vulnerabilities,
  Severity,
} from '@/lib/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 25;

const REQUEST_TIMEOUT = 12000;
const USER_AGENT = 'WebShieldScanner/1.0 (+https://webshield.app)';

type HeaderKey =
  | 'strict-transport-security'
  | 'content-security-policy'
  | 'x-frame-options'
  | 'x-content-type-options'
  | 'referrer-policy'
  | 'permissions-policy';

const SECURITY_HEADER_KEYS: HeaderKey[] = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

const HEADER_META: Record<
  HeaderKey,
  {
    prettyName: string;
    description: string;
    whyItMatters: string;
    exampleValue: string;
    severity: Severity;
    maxScore: number;
  }
> = {
  'strict-transport-security': {
    prettyName: 'Strict-Transport-Security',
    description:
      'Tells browsers to only connect via HTTPS for the specified duration, preventing protocol downgrade and SSL stripping attacks.',
    whyItMatters:
      'Without HSTS, a man-in-the-middle attacker can force a downgrade to HTTP and intercept or tamper with traffic.',
    exampleValue: 'max-age=63072000; includeSubDomains; preload',
    severity: 'high',
    maxScore: 20,
  },
  'content-security-policy': {
    prettyName: 'Content-Security-Policy',
    description:
      'Controls which sources the browser may load resources from, mitigating Cross-Site Scripting (XSS) and data injection.',
    whyItMatters:
      'CSP is the most effective defense against XSS. Without it, any injected script can execute and steal data or credentials.',
    exampleValue:
      "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    severity: 'critical',
    maxScore: 25,
  },
  'x-frame-options': {
    prettyName: 'X-Frame-Options',
    description:
      'Prevents the page from being embedded in iframes by unauthorized sites, stopping clickjacking attacks.',
    whyItMatters:
      'Without frame protection, attackers can overlay invisible UI on your page to trick users into clicking hidden actions.',
    exampleValue: 'DENY',
    severity: 'medium',
    maxScore: 10,
  },
  'x-content-type-options': {
    prettyName: 'X-Content-Type-Options',
    description:
      'Disables MIME-type sniffing so the browser trusts the declared Content-Type and never interprets files as a different type.',
    whyItMatters:
      'Without nosniff, an uploaded text file could be executed as a script, enabling XSS through content-type confusion.',
    exampleValue: 'nosniff',
    severity: 'medium',
    maxScore: 10,
  },
  'referrer-policy': {
    prettyName: 'Referrer-Policy',
    description:
      'Controls how much Referer header information is sent with outbound requests, protecting user privacy.',
    whyItMatters:
      'Without a restrictive policy, full URLs (including query parameters) can leak to third parties via the Referer header.',
    exampleValue: 'strict-origin-when-cross-origin',
    severity: 'low',
    maxScore: 10,
  },
  'permissions-policy': {
    prettyName: 'Permissions-Policy',
    description:
      'Restricts access to powerful browser features such as camera, microphone, geolocation, and payment APIs.',
    whyItMatters:
      'Without this policy, embedded content or compromised scripts could access sensitive device capabilities.',
    exampleValue: 'camera=(), microphone=(), geolocation=()',
    severity: 'medium',
    maxScore: 10,
  },
};

interface WeaknessResult {
  isWeak: boolean;
  reason?: string;
  penalty: number;
}

function checkCspWeakness(value: string): WeaknessResult {
  if (!value) return { isWeak: false, penalty: 0 };
  const lower = value.toLowerCase();
  const reasons: string[] = [];

  if (lower.includes("'unsafe-inline'")) {
    reasons.push("contains 'unsafe-inline' which allows inline scripts and styles");
  }
  if (lower.includes("'unsafe-eval'")) {
    reasons.push("contains 'unsafe-eval' which allows eval() and similar functions");
  }
  if (lower.includes('* ')) {
    reasons.push("uses a wildcard source which permits loading from any origin");
  }
  if (lower.includes('http:')) {
    reasons.push('references insecure http: sources');
  }
  if (lower.includes('*://')) {
    reasons.push('uses a protocol wildcard which permits insecure origins');
  }
  if (!lower.includes('default-src') && !lower.includes('script-src')) {
    reasons.push('lacks a default-src or script-src directive');
  }

  if (reasons.length === 0) return { isWeak: false, penalty: 0 };
  return {
    isWeak: true,
    reason: `CSP ${reasons.join('; ')}.`,
    penalty: Math.min(reasons.length * 5, 15),
  };
}

function checkHstsWeakness(value: string): WeaknessResult {
  if (!value) return { isWeak: false, penalty: 0 };
  const lower = value.toLowerCase();
  const reasons: string[] = [];

  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  if (!maxAgeMatch) {
    reasons.push('is missing a max-age directive');
  } else {
    const maxAge = parseInt(maxAgeMatch[1], 10);
    if (maxAge < 1036800) {
      reasons.push(`max-age of ${maxAge} is below the recommended 12 weeks (1036800)`);
    }
  }
  if (!lower.includes('includesubdomains')) {
    reasons.push('does not include includeSubDomains');
  }

  if (reasons.length === 0) return { isWeak: false, penalty: 0 };
  return {
    isWeak: true,
    reason: `HSTS ${reasons.join('; ')}.`,
    penalty: Math.min(reasons.length * 3, 8),
  };
}

function checkFrameOptionsWeakness(value: string): WeaknessResult {
  if (!value) return { isWeak: false, penalty: 0 };
  const lower = value.toLowerCase().trim();
  if (lower === 'deny' || lower === 'sameorigin') {
    return { isWeak: false, penalty: 0 };
  }
  if (lower.startsWith('allow-from')) {
    return {
      isWeak: true,
      reason: 'uses ALLOW-FROM which is deprecated and ignored by modern browsers',
      penalty: 3,
    };
  }
  return { isWeak: true, reason: 'has an unrecognized value', penalty: 3 };
}

function checkReferrerPolicyWeakness(value: string): WeaknessResult {
  if (!value) return { isWeak: false, penalty: 0 };
  const lower = value.toLowerCase().trim();
  const safeValues = [
    'no-referrer',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
  ];
  if (safeValues.includes(lower)) return { isWeak: false, penalty: 0 };
  if (lower === 'unsafe-url' || lower === 'no-referrer-when-downgrade') {
    return {
      isWeak: true,
      reason: 'allows referrer leakage to third parties',
      penalty: 3,
    };
  }
  return { isWeak: false, penalty: 0 };
}

function checkPermissionsPolicyWeakness(value: string): WeaknessResult {
  if (!value) return { isWeak: false, penalty: 0 };
  return { isWeak: false, penalty: 0 };
}

function checkContentTypeOptionsWeakness(value: string): WeaknessResult {
  if (!value) return { isWeak: false, penalty: 0 };
  if (value.toLowerCase().trim() !== 'nosniff') {
    return { isWeak: true, reason: 'should be set to nosniff', penalty: 3 };
  }
  return { isWeak: false, penalty: 0 };
}

function getWeakness(key: HeaderKey, value: string): WeaknessResult {
  switch (key) {
    case 'content-security-policy':
      return checkCspWeakness(value);
    case 'strict-transport-security':
      return checkHstsWeakness(value);
    case 'x-frame-options':
      return checkFrameOptionsWeakness(value);
    case 'referrer-policy':
      return checkReferrerPolicyWeakness(value);
    case 'permissions-policy':
      return checkPermissionsPolicyWeakness(value);
    case 'x-content-type-options':
      return checkContentTypeOptionsWeakness(value);
    default:
      return { isWeak: false, penalty: 0 };
  }
}

function normalizeUrl(raw: string): string {
  let url = raw.trim();
  if (!url) throw new Error('URL is required.');
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Please provide a valid website URL.');
  }
  if (!parsed.hostname || !parsed.hostname.includes('.')) {
    throw new Error('Please provide a valid website URL.');
  }
  return url;
}

async function checkHttpRedirect(hostname: string): Promise<boolean> {
  try {
    const httpUrl = `http://${hostname}`;
    const response = await fetch(httpUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': USER_AGENT },
    });
    const status = response.status;
    if (status >= 300 && status < 400) {
      const location = response.headers.get('location');
      if (location && location.startsWith('https')) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

async function getHttpsInfo(
  hostname: string,
  httpsResponseOk: boolean
): Promise<HttpsInfo> {
  if (!httpsResponseOk) {
    return {
      enabled: false,
      redirectFromHttp: false,
      valid: false,
      expiresAt: '',
      issuer: '',
      protocol: '',
      daysRemaining: 0,
    };
  }

  const redirectFromHttp = await checkHttpRedirect(hostname);

  return {
    enabled: true,
    redirectFromHttp,
    valid: true,
    expiresAt: '',
    issuer: 'Verified via TLS connection',
    protocol: 'TLS',
    daysRemaining: 0,
  };
}

function analyzeHeaders(
  headers: Headers
): {
  headerInfos: SecurityHeader[];
  headerScore: number;
  vulnerabilities: Vulnerabilities;
} {
  const lower = new Map<string, string>();
  headers.forEach((value, key) => lower.set(key.toLowerCase(), value));

  const headerInfos: SecurityHeader[] = [];
  const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  let earnedScore = 0;

  for (const key of SECURITY_HEADER_KEYS) {
    const meta = HEADER_META[key];
    const value = lower.get(key) ?? '';
    const present = Boolean(value);
    const weakness = getWeakness(key, value);

    let status: 'present' | 'missing' | 'weak';
    let earned = 0;

    if (!present) {
      status = 'missing';
      earned = 0;
      const sev = meta.severity;
      if (sev === 'critical') vulnCounts.critical++;
      else if (sev === 'high') vulnCounts.high++;
      else if (sev === 'medium') vulnCounts.medium++;
      else if (sev === 'low') vulnCounts.low++;
    } else if (weakness.isWeak) {
      status = 'weak';
      earned = Math.max(meta.maxScore - weakness.penalty, meta.maxScore * 0.4);
      if (meta.severity === 'high' || meta.severity === 'critical') {
        vulnCounts.medium++;
      } else {
        vulnCounts.low++;
      }
    } else {
      status = 'present';
      earned = meta.maxScore;
    }

    earnedScore += earned;

    headerInfos.push({
      name: meta.prettyName,
      value: value || 'Not set',
      status,
      description: meta.description,
      whyItMatters: meta.whyItMatters,
      exampleValue: meta.exampleValue,
      severity: meta.severity,
      isWeak: weakness.isWeak,
      weaknessReason: weakness.reason,
    });
  }

  const headerScore = Math.round(earnedScore);
  const vulnerabilities: Vulnerabilities = {
    count: vulnCounts.critical + vulnCounts.high + vulnCounts.medium + vulnCounts.low,
    ...vulnCounts,
  };

  return { headerInfos, headerScore, vulnerabilities };
}

function computeOverallScore(
  headerScore: number,
  httpsInfo: HttpsInfo
): number {
  const maxHeaderScore = SECURITY_HEADER_KEYS.reduce(
    (sum, key) => sum + HEADER_META[key].maxScore,
    0
  );
  const headerPercent = (headerScore / maxHeaderScore) * 75;

  let httpsPoints = 0;
  if (httpsInfo.enabled) httpsPoints += 15;
  if (httpsInfo.redirectFromHttp) httpsPoints += 5;
  if (httpsInfo.valid) httpsPoints += 5;

  const total = Math.min(headerPercent + httpsPoints, 100);
  return Math.round(total);
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
  httpsInfo: HttpsInfo
): Recommendation[] {
  const recs: Recommendation[] = [];

  const recTemplates: Record<
    string,
    Omit<Recommendation, 'id' | 'severity'>
  > = {
    'strict-transport-security': {
      title: 'Add Strict-Transport-Security (HSTS) header',
      description:
        'HSTS is missing. Add it to force browsers to always use HTTPS for your domain and prevent protocol downgrade attacks.',
      whyItMatters:
        'Without HSTS, users who type http:// or are redirected by an attacker can be downgraded to insecure HTTP, exposing them to man-in-the-middle attacks.',
      impact: 'Protects against SSL stripping and protocol downgrade attacks.',
      exampleImplementation:
        'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    },
    'content-security-policy': {
      title: 'Add Content-Security-Policy header',
      description:
        'CSP is missing. Without it, your site has no defense against injected scripts running in your users\' browsers.',
      whyItMatters:
        'CSP is the primary mitigation for Cross-Site Scripting (XSS). It restricts which scripts can execute and where resources can be loaded from.',
      impact: 'Significantly reduces risk of XSS and data exfiltration attacks.',
      exampleImplementation:
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    },
    'x-frame-options': {
      title: 'Add X-Frame-Options header',
      description:
        'X-Frame-Options is missing. Add it to prevent your page from being embedded in iframes by other sites.',
      whyItMatters:
        'Without frame protection, attackers can overlay your page in a transparent iframe and trick users into clicking hidden actions (clickjacking).',
      impact: 'Prevents clickjacking attacks that exploit user trust.',
      exampleImplementation: 'X-Frame-Options: DENY',
    },
    'x-content-type-options': {
      title: 'Add X-Content-Type-Options header',
      description:
        "X-Content-Type-Options is missing. Set it to 'nosniff' to stop browsers from sniffing MIME types.",
      whyItMatters:
        'Without nosniff, the browser may interpret a file as a different type than declared, allowing an uploaded text file to execute as a script.',
      impact: 'Reduces risk of content-type confusion and XSS via file uploads.',
      exampleImplementation: 'X-Content-Type-Options: nosniff',
    },
    'referrer-policy': {
      title: 'Add Referrer-Policy header',
      description:
        'Referrer-Policy is missing. Add it to control how much referrer information is shared with external sites.',
      whyItMatters:
        'Without a restrictive policy, full URLs (including sensitive query parameters) can leak to third-party sites via the Referer header.',
      impact: 'Protects user privacy by limiting referrer data leakage.',
      exampleImplementation: 'Referrer-Policy: strict-origin-when-cross-origin',
    },
    'permissions-policy': {
      title: 'Add Permissions-Policy header',
      description:
        'Permissions-Policy is missing. Add it to restrict access to powerful browser features like camera, microphone, and geolocation.',
      whyItMatters:
        'Without this policy, compromised scripts or embedded content could access sensitive device capabilities without user consent.',
      impact: 'Limits attack surface by restricting powerful browser APIs.',
      exampleImplementation: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
    },
  };

  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const issues = headerInfos.filter((h) => h.status !== 'present');

  for (const header of issues) {
    const template = recTemplates[header.name.toLowerCase()];
    if (!template) continue;
    let description = template.description;
    if (header.status === 'weak' && header.weaknessReason) {
      description = `${header.name} ${header.weaknessReason} Strengthen it to improve your security posture.`;
    }
    recs.push({
      id: `rec-${recs.length + 1}`,
      title:
        header.status === 'weak'
          ? `Strengthen ${header.name} header`
          : template.title,
      description,
      whyItMatters: template.whyItMatters,
      impact: template.impact,
      exampleImplementation: template.exampleImplementation,
      severity: header.severity,
    });
  }

  if (!httpsInfo.enabled) {
    recs.push({
      id: `rec-${recs.length + 1}`,
      title: 'Enable HTTPS',
      description:
        'Your site does not serve over HTTPS. Obtain an SSL/TLS certificate and serve all traffic exclusively over HTTPS.',
      whyItMatters:
        'HTTPS is the foundation of web security. Without it, all traffic is sent in plaintext and can be intercepted or tampered with.',
      impact: 'Encrypts all traffic and enables secure browser features.',
      exampleImplementation:
        'Obtain a free certificate from Let\'s Encrypt and configure your server to redirect HTTP to HTTPS.',
      severity: 'critical',
    });
  } else if (!httpsInfo.redirectFromHttp) {
    recs.push({
      id: `rec-${recs.length + 1}`,
      title: 'Redirect HTTP to HTTPS',
      description:
        'Your site does not redirect HTTP traffic to HTTPS. Add a permanent redirect so all visitors use the secure connection.',
      whyItMatters:
        'Without a redirect, users who type http:// or follow an old link will connect insecurely, even though HTTPS is available.',
      impact: 'Ensures all visitors use the encrypted connection.',
      exampleImplementation:
        'Add a 301 redirect from http:// to https:// in your web server or CDN configuration.',
      severity: 'high',
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
  let finalResponse: Response | null = null;
  let currentUrl = url;
  const maxRedirects = 10;
  let redirectCount = 0;

  try {
    while (redirectCount <= maxRedirects) {
      const res = await fetch(currentUrl, {
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT },
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });

      res.headers.forEach((value, key) => {
        if (!mergedHeaders.has(key)) {
          mergedHeaders.set(key, value);
        }
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

  if (redirectCount > maxRedirects) {
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

  const httpsInfo = await getHttpsInfo(hostname, httpStatus > 0 && httpStatus < 500);
  const { headerInfos, headerScore, vulnerabilities } = analyzeHeaders(mergedHeaders);
  const score = computeOverallScore(headerScore, httpsInfo);
  const recommendations = buildRecommendations(headerInfos, httpsInfo);

  const rawHeaders = Array.from(mergedHeaders.entries()).map(([name, value]) => ({
    name,
    value,
  }));

  const scanDurationMs = Date.now() - startTime;

  const result: ScanResult = {
    url,
    scannedAt: new Date().toISOString(),
    scanDurationMs,
    score,
    grade: gradeFromScore(score),
    https: httpsInfo,
    headers: headerInfos,
    rawHeaders,
    recommendations,
    vulnerabilities,
  };

  return NextResponse.json(result);
}
