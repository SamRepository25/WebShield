import { NextRequest, NextResponse } from 'next/server';
import type {
  ScanResult,
  SecurityHeader,
  HttpsInfo,
  Recommendation,
  Vulnerabilities,
} from '@/lib/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const REQUEST_TIMEOUT = 12000;
const USER_AGENT = 'WebShieldScanner/1.0 (+https://webshield.app)';

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;

const HEADER_WEIGHTS: Record<string, number> = {
  'strict-transport-security': 2.0,
  'content-security-policy': 2.5,
  'x-frame-options': 1.5,
  'x-content-type-options': 1.0,
  'referrer-policy': 1.0,
  'permissions-policy': 1.0,
};

const HEADER_DESCRIPTIONS: Record<string, string> = {
  'strict-transport-security':
    'Enforces HTTPS connections and protects against protocol downgrade attacks.',
  'content-security-policy':
    'Restricts resource loading to prevent XSS and data injection attacks.',
  'x-frame-options':
    'Prevents clickjacking by restricting the page from being embedded in iframes.',
  'x-content-type-options':
    'Prevents browsers from MIME-type sniffing and interpreting files as a different type.',
  'referrer-policy':
    'Controls how much referrer information is included with requests.',
  'permissions-policy':
    'Controls which browser features and APIs the page can access.',
};

const HEADER_SEVERITIES: Record<string, 'high' | 'medium' | 'low'> = {
  'strict-transport-security': 'high',
  'content-security-policy': 'high',
  'x-frame-options': 'medium',
  'x-content-type-options': 'medium',
  'referrer-policy': 'low',
  'permissions-policy': 'medium',
};

const PRETTY_NAMES: Record<string, string> = {
  'strict-transport-security': 'Strict-Transport-Security',
  'content-security-policy': 'Content-Security-Policy',
  'x-frame-options': 'X-Frame-Options',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
};

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

async function getHttpsInfo(hostname: string): Promise<HttpsInfo> {
  const fallback: HttpsInfo = {
    enabled: false,
    valid: false,
    expiresAt: '',
    issuer: '',
    protocol: '',
    daysRemaining: 0,
  };

  try {
    const response = await fetch(`https://${hostname}`, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    const valid = response.status > 0;
    if (!valid) return fallback;
  } catch {
    return fallback;
  }

  return {
    enabled: true,
    valid: true,
    expiresAt: '',
    issuer: 'Verified via TLS',
    protocol: 'TLS',
    daysRemaining: 0,
  };
}

function analyzeHeaders(
  headers: Headers
): { headerInfos: SecurityHeader[]; score: number; vulnerabilities: Vulnerabilities } {
  const lower = new Map<string, string>();
  headers.forEach((value, key) => lower.set(key.toLowerCase(), value));

  const headerInfos: SecurityHeader[] = [];
 const totalWeight = 100;
let earnedWeight = 40;
  const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const headerName of SECURITY_HEADERS) {
    const value = lower.get(headerName) ?? '';
    const present = Boolean(value);

    if (present) {
  switch (headerName) {
    case "strict-transport-security":
      earnedWeight += 20;
      break;
    case "content-security-policy":
      earnedWeight += 15;
      break;
    case "x-frame-options":
      earnedWeight += 8;
      break;
    case "x-content-type-options":
      earnedWeight += 6;
      break;
    case "referrer-policy":
      earnedWeight += 6;
      break;
    case "permissions-policy":
      earnedWeight += 5;
      break;
  }
}
    headerInfos.push({
      name: PRETTY_NAMES[headerName] ?? headerName,
      value: value || 'Not set',
      status: present ? 'present' : 'missing',
      description: HEADER_DESCRIPTIONS[headerName],
      severity: HEADER_SEVERITIES[headerName],
    });
  }

  if (present) {
  switch (headerName) {
    case "strict-transport-security":
      earnedWeight += 20;
      break;
    case "content-security-policy":
      earnedWeight += 15;
      break;
    case "x-frame-options":
      earnedWeight += 8;
      break;
    case "x-content-type-options":
      earnedWeight += 6;
      break;
    case "referrer-policy":
      earnedWeight += 6;
      break;
    case "permissions-policy":
      earnedWeight += 5;
      break;
  }
}
  const vulnerabilities: Vulnerabilities = {
    count: vulnCounts.critical + vulnCounts.high + vulnCounts.medium + vulnCounts.low,
    ...vulnCounts,
  };

  return { headerInfos, score, vulnerabilities };
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
  const missing = headerInfos.filter((h) => h.status === 'missing');

  const recMap: Record<string, { title: string; description: string; impact: string }> = {
    'strict-transport-security': {
      title: 'Add Strict-Transport-Security (HSTS) header',
      description:
        'HSTS is missing. Add it to force browsers to always use HTTPS and prevent protocol downgrade attacks.',
      impact: 'Protects against man-in-the-middle and SSL stripping attacks.',
    },
    'content-security-policy': {
      title: 'Add Content-Security-Policy header',
      description:
        'CSP is missing. Without it, your site is more vulnerable to XSS and data injection attacks.',
      impact: 'Significantly reduces risk of Cross-Site Scripting (XSS) attacks.',
    },
    'x-frame-options': {
      title: 'Add X-Frame-Options header',
      description:
        'X-Frame-Options is missing. Add it to prevent clickjacking by stopping your page from being embedded in iframes.',
      impact: 'Prevents clickjacking attacks on your users.',
    },
    'x-content-type-options': {
      title: 'Add X-Content-Type-Options header',
      description:
        "X-Content-Type-Options is missing. Set it to 'nosniff' to prevent browsers from MIME-type sniffing.",
      impact: 'Reduces risk of content type confusion attacks.',
    },
    'referrer-policy': {
      title: 'Add Referrer-Policy header',
      description:
        'Referrer-Policy is missing. Add it to control how much referrer information is shared with external sites.',
      impact: 'Protects user privacy by limiting referrer data leakage.',
    },
    'permissions-policy': {
      title: 'Add Permissions-Policy header',
      description:
        'Permissions-Policy is missing. Add it to restrict access to browser features like camera, microphone, and geolocation.',
      impact: 'Limits attack surface by restricting powerful browser APIs.',
    },
  };

  missing.forEach((header, idx) => {
    const template = recMap[header.name.toLowerCase()];
    if (!template) return;
    recs.push({
      id: `rec-${idx + 1}`,
      title: template.title,
      description: template.description,
      severity: header.severity,
      impact: template.impact,
    });
  });

  if (!httpsInfo.enabled) {
    recs.push({
      id: `rec-${recs.length + 1}`,
      title: 'Enable HTTPS',
      description:
        'Your site does not serve over HTTPS. Obtain an SSL certificate and redirect all HTTP traffic to HTTPS.',
      severity: 'critical',
      impact: 'HTTPS is foundational for web security and user trust.',
    });
  }

  return recs;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
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

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': USER_AGENT },
      redirect: 'follow',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
  } catch (err) {
    const message = (err as Error).message ?? '';
    if (message.includes('SSL') || message.includes('certificate') || message.includes('CERT')) {
      return NextResponse.json(
        { detail: `SSL verification failed for ${hostname}.` },
        { status: 422 }
      );
    }
    if (message.includes('timeout') || message.includes('abort')) {
      return NextResponse.json(
        { detail: `Request to ${hostname} timed out.` },
        { status: 504 }
      );
    }
    return NextResponse.json(
      { detail: `Could not connect to ${hostname}. The site may be offline or unreachable.` },
      { status: 502 }
    );
  }

  const headersDict = response.headers;
  const httpsInfo = await getHttpsInfo(hostname);
  const { headerInfos, score, vulnerabilities } = analyzeHeaders(headersDict);
  const recommendations = buildRecommendations(headerInfos, httpsInfo);

  const rawHeaders = Array.from(headersDict.entries()).map(([name, value]) => ({
    name,
    value,
  }));

  const result: ScanResult = {
    url,
    scannedAt: new Date().toISOString(),
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
