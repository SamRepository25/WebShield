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

type Category = 'transport' | 'content' | 'browser' | 'cookies' | 'infrastructure';

interface HeaderSpec {
  key: string;
  prettyName: string;
  category: Category;
  maxPoints: number;
  severity: Severity;
  // essential = materially reduces real-world attack surface for most sites.
  // recommended = meaningful hardening, but not universally required.
  // optional = advanced/context-dependent hardening (browser isolation
  // headers, legacy headers, monitoring-only headers). Missing an optional
  // header is never treated as a vulnerability and never drags a site down
  // to a poor grade by itself.
  tier: HeaderTier;
  description: string;
  whyItMatters: string;
  exampleValue: string;
  isOptional?: boolean;
  isLegacy?: boolean;
  checkWeakness?: (value: string) => { isWeak: boolean; reason?: string; penalty: number };
}

export const HEADER_SPECS: HeaderSpec[] = [
  {
    key: 'strict-transport-security',
    prettyName: 'Strict-Transport-Security',
    category: 'transport',
    maxPoints: 20,
    severity: 'high',
    tier: 'essential',
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
    tier: 'essential',
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
      let penalty = 0;
      if (lower.includes("'unsafe-inline'")) {
        reasons.push("contains 'unsafe-inline' which allows inline scripts and styles");
        penalty += 5;
      }
      if (lower.includes("'unsafe-eval'")) {
        reasons.push("contains 'unsafe-eval' which allows eval() and similar functions");
        penalty += 5;
      }
      if (lower.includes('* ')) {
        reasons.push('uses a wildcard source which permits loading from any origin');
        penalty += 5;
      }
      if (lower.includes('http:')) {
        reasons.push('references insecure http: sources');
        penalty += 4;
      }
      if (lower.includes('*://')) {
        reasons.push('uses a protocol wildcard which permits insecure origins');
        penalty += 4;
      }
      if (!lower.includes('default-src') && !lower.includes('script-src')) {
        reasons.push('is missing a default-src or script-src directive');
        penalty += 10;
      }
      if (reasons.length === 0) return { isWeak: false, penalty: 0 };
      return { isWeak: true, reason: `CSP ${reasons.join('; ')}.`, penalty: Math.min(penalty, 18) };
    },
  },
  {
    key: 'content-security-policy-report-only',
    prettyName: 'Content-Security-Policy-Report-Only',
    category: 'content',
    maxPoints: 10,
    severity: 'info',
    tier: 'optional',
    description:
      'A monitoring-only variant of CSP that reports violations without enforcing them. Useful for rolling out CSP safely.',
    whyItMatters:
      'Report-Only mode lets you measure CSP impact before enforcement, reducing the risk of breaking legitimate functionality.',
    exampleValue: "default-src 'self'; report-uri /csp-report",
    isOptional: true,
  },
  {
    key: 'x-frame-options',
    prettyName: 'X-Frame-Options',
    category: 'browser',
    maxPoints: 5,
    severity: 'medium',
    tier: 'essential',
    description:
      'Prevents clickjacking by restricting whether the page can be embedded in frames. Largely superseded by CSP frame-ancestors.',
    whyItMatters:
      'Without frame protection, attackers can overlay your page with malicious UI to trick users into clicking hidden actions.',
    exampleValue: 'DENY',
    isLegacy: true,
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      if (lower === 'deny' || lower === 'sameorigin') return { isWeak: false, penalty: 0 };
      if (lower.startsWith('allow-from'))
        return { isWeak: true, reason: 'X-Frame-Options ALLOW-FROM is deprecated and ignored by modern browsers.', penalty: 2 };
      return { isWeak: true, reason: 'X-Frame-Options has an unrecognized value.', penalty: 2 };
    },
  },
  {
    key: 'x-content-type-options',
    prettyName: 'X-Content-Type-Options',
    category: 'browser',
    maxPoints: 5,
    severity: 'medium',
    tier: 'essential',
    description:
      'Disables MIME type sniffing, forcing browsers to respect the declared Content-Type of responses.',
    whyItMatters:
      'Without nosniff, browsers may execute uploaded files as scripts based on content sniffing, enabling XSS and drive-by downloads.',
    exampleValue: 'nosniff',
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      if (value.toLowerCase().trim() !== 'nosniff')
        return { isWeak: true, reason: 'X-Content-Type-Options should be set to "nosniff".', penalty: 2 };
      return { isWeak: false, penalty: 0 };
    },
  },
  {
    key: 'referrer-policy',
    prettyName: 'Referrer-Policy',
    category: 'browser',
    maxPoints: 5,
    severity: 'low',
    tier: 'recommended',
    description:
      'Controls how much referrer information is included with outgoing requests, protecting user privacy.',
    whyItMatters:
      'Without a Referrer-Policy, browsers may leak full URLs (including query parameters) to third-party destinations.',
    exampleValue: 'strict-origin-when-cross-origin',
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      const safe = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      if (safe.includes(lower)) return { isWeak: false, penalty: 0 };
      if (lower === 'unsafe-url' || lower === 'no-referrer-when-downgrade')
        return { isWeak: true, reason: 'Referrer-Policy allows referrer leakage to third parties.', penalty: 2 };
      return { isWeak: false, penalty: 0 };
    },
  },
  {
    key: 'permissions-policy',
    prettyName: 'Permissions-Policy',
    category: 'browser',
    maxPoints: 10,
    severity: 'medium',
    tier: 'recommended',
    description:
      'Controls which browser features and APIs (camera, microphone, geolocation, etc.) the page and embedded frames can access.',
    whyItMatters:
      'Without Permissions-Policy, any embedded content may request access to powerful browser features, expanding the attack surface.',
    exampleValue: 'geolocation=(), camera=(), microphone=()',
  },
  {
    key: 'cross-origin-embedder-policy',
    prettyName: 'Cross-Origin-Embedder-Policy',
    category: 'browser',
    maxPoints: 5,
    severity: 'info',
    tier: 'optional',
    description:
      'Requires cross-origin resources to opt-in via CORS, enabling a secure context for powerful APIs like SharedArrayBuffer.',
    whyItMatters:
      'COEP prevents cross-origin resources from being loaded without explicit permission, mitigating Spectre-class attacks.',
    exampleValue: 'require-corp',
    isOptional: true,
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      if (lower === 'require-corp' || lower === 'credentialless') return { isWeak: false, penalty: 0 };
      if (lower === 'unsafe-none')
        return { isWeak: true, reason: 'COEP set to unsafe-none provides no isolation.', penalty: 3 };
      return { isWeak: true, reason: 'Unrecognized COEP value.', penalty: 3 };
    },
  },
  {
    key: 'cross-origin-opener-policy',
    prettyName: 'Cross-Origin-Opener-Policy',
    category: 'browser',
    maxPoints: 5,
    severity: 'info',
    tier: 'optional',
    description:
      'Isolates the browsing context from cross-origin documents, preventing them from accessing your window object.',
    whyItMatters:
      'COOP prevents cross-origin documents from interacting with your page, defending against cross-origin attacks.',
    exampleValue: 'same-origin',
    isOptional: true,
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      const firstToken = lower.split(';')[0].trim();
      if (firstToken === 'same-origin' || firstToken === 'same-origin-allow-popups')
        return { isWeak: false, penalty: 0 };
      if (firstToken === 'unsafe-none' || firstToken === 'same-origin-plus-coep')
        return { isWeak: true, reason: 'COOP value provides minimal cross-origin isolation.', penalty: 3 };
      return { isWeak: true, reason: 'Unrecognized COOP value.', penalty: 3 };
    },
  },
  {
    key: 'cross-origin-resource-policy',
    prettyName: 'Cross-Origin-Resource-Policy',
    category: 'browser',
    maxPoints: 3,
    severity: 'info',
    tier: 'optional',
    description:
      'Restricts who can embed a resource, providing a defense-in-depth against cross-origin information leakage.',
    whyItMatters:
      'CORP prevents your resources from being loaded by arbitrary sites, reducing the risk of cross-origin attacks.',
    exampleValue: 'same-origin',
    isOptional: true,
    checkWeakness: (value) => {
      if (!value) return { isWeak: false, penalty: 0 };
      const lower = value.toLowerCase().trim();
      const firstToken = lower.split(';')[0].trim();
      if (firstToken === 'same-origin' || firstToken === 'same-site') return { isWeak: false, penalty: 0 };
      if (firstToken === 'cross-origin')
        return { isWeak: true, reason: 'CORP cross-origin allows any site to embed this resource.', penalty: 2 };
      return { isWeak: false, penalty: 0 };
    },
  },
  {
    key: 'origin-agent-cluster',
    prettyName: 'Origin-Agent-Cluster',
    category: 'browser',
    maxPoints: 2,
    severity: 'info',
    tier: 'optional',
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
    tier: 'optional',
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
    tier: 'optional',
    description:
      'Instructs the browser to clear site data (cookies, storage, cache) — useful for logout flows.',
    whyItMatters:
      'Clear-Site-Data ensures sensitive data is purged on logout, reducing the risk of session残留 attacks.',
    exampleValue: '"cache", "cookies", "storage"',
    isOptional: true,
  },
];

export function normalizeUrl(raw: string): string {
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

// Cookie names that suggest the cookie carries session/auth/credential
// state. For these, a missing HttpOnly flag is a real weakness — the
// cookie could be stolen by an XSS payload. For everything else (feature
// flags, non-sensitive preferences, analytics/consent identifiers), sites
// often make cookies intentionally readable by JavaScript, so a missing
// HttpOnly flag is informational rather than a vulnerability.
const SENSITIVE_COOKIE_PATTERN =
  /(session|sess|auth|token|jwt|login|credential|csrf|xsrf|^sid$|_sid$|account|user_id|uid)/i;

function parseSetCookie(header: string): CookieInfo | null {
  if (!header) return null;
  const parts = header.split(';').map((p) => p.trim());
  const namePart = parts[0] || '';
  const name = namePart.split('=')[0] || '';
  const nameLower = name.toLowerCase();
  const lower = header.toLowerCase();
  const secure = lower.includes('secure');
  const httpOnly = lower.includes('httponly');
  let sameSite = 'None';
  const ssMatch = lower.match(/samesite=(lax|strict|none)/);
  if (ssMatch) sameSite = ssMatch[1].charAt(0).toUpperCase() + ssMatch[1].slice(1);

  // The __Secure- and __Host- name prefixes are a browser-enforced
  // guarantee: browsers refuse to set these cookies at all unless the
  // Secure attribute is present (and for __Host-, unless Path=/ and no
  // Domain attribute). A site using these prefixes is already opting in to
  // stronger cookie handling, and the prefix itself is not evidence the
  // cookie needs HttpOnly too.
  const hasSecurePrefix = nameLower.startsWith('__secure-') || nameLower.startsWith('_secure-');
  const hasHostPrefix = nameLower.startsWith('__host-');
  const looksSensitive = SENSITIVE_COOKIE_PATTERN.test(nameLower);

  const weaknesses: string[] = [];
  const informational: string[] = [];

  if (!secure) {
    weaknesses.push(
      hasSecurePrefix || hasHostPrefix
        ? 'Missing Secure flag (required by its __Secure-/__Host- name prefix — browsers should reject this cookie)'
        : 'Missing Secure flag — the cookie can be sent over plain HTTP'
    );
  }

  if (!httpOnly) {
    if (looksSensitive) {
      weaknesses.push('Missing HttpOnly flag on a cookie that looks like it holds session/auth data');
    } else {
      informational.push('No HttpOnly flag — this cookie is readable by JavaScript, which may be intentional for a non-sensitive cookie');
    }
  }

  if (!ssMatch) {
    informational.push('No SameSite attribute set (browsers default to Lax, but setting it explicitly is best practice)');
  } else if (sameSite === 'None' && !secure) {
    weaknesses.push('SameSite=None without Secure — modern browsers will reject this cookie');
  } else if (sameSite === 'None') {
    informational.push('SameSite=None allows cross-site sending; this is safe here because Secure is also set');
  }

  return { name, secure, httpOnly, sameSite, looksSensitive, weaknesses, informational };
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

// Classifies how one URL in a redirect chain differs from the previous one,
// so the UI can distinguish a protocol upgrade (http -> https) from a plain
// domain change (e.g. apex -> www) or a path/query change. A single hop can
// combine several changes at once (e.g. http://example.com ->
// https://www.example.com/) — in that case protocol upgrade takes priority
// since it's the most security-relevant distinction.
function classifyRedirect(fromUrl: string, toUrl: string): RedirectType {
  let from: URL;
  let to: URL;
  try {
    from = new URL(fromUrl);
    to = new URL(toUrl);
  } catch {
    return 'other';
  }
  const stripWww = (h: string) => h.replace(/^www\./i, '');
  const fromHost = stripWww(from.hostname.toLowerCase());
  const toHost = stripWww(to.hostname.toLowerCase());

  if (from.protocol === 'http:' && to.protocol === 'https:' ) {
    return 'protocol-upgrade';
  }
  if (fromHost !== toHost) {
    return 'domain-change';
  }
  if (from.hostname.toLowerCase() !== to.hostname.toLowerCase()) {
    return 'www-change';
  }
  if (from.pathname !== to.pathname || from.search !== to.search) {
    return 'path-change';
  }
  return 'other';
}

// Real sites frequently need more than one hop to go from plain HTTP to
// HTTPS — e.g. http://example.com -> http://www.example.com (still HTTP,
// a domain redirect) -> https://www.example.com (the actual upgrade).
// Checking only the first hop (as before) misreports this common pattern
// as "not redirecting to HTTPS" even though the site does upgrade. This
// follows the full chain, the same way the main scan does, and succeeds as
// soon as any hop lands on HTTPS.
async function checkHttpToHttpsUpgrade(hostname: string): Promise<boolean> {
  let currentUrl = `http://${hostname}`;
  let hops = 0;
  try {
    while (hops <= MAX_REDIRECTS) {
      if (currentUrl.startsWith('https://')) return true;
      const res = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': USER_AGENT },
      });
      if (res.status < 300 || res.status >= 400) return false;
      const location = res.headers.get('location');
      if (!location) return false;
      currentUrl = new URL(location, currentUrl).href;
      hops++;
    }
    return currentUrl.startsWith('https://');
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
  const redirectFromHttp = await checkHttpToHttpsUpgrade(hostname);
  const hstsLower = (hstsValue || '').toLowerCase();
  const maxAgeMatch = hstsLower.match(/max-age=(\d+)/);
  const hstsPreloadReady =
    hstsLower.includes('preload') &&
    hstsLower.includes('includesubdomains') &&
    Boolean(maxAgeMatch?.[1] && parseInt(maxAgeMatch[1], 10) >= 31536000);
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

interface HeaderAnalysis {
  headerInfos: SecurityHeader[];
  scoreByCategory: Record<Category, number>;
  vulnerabilities: Vulnerabilities;
}

function analyzeHeaders(headers: Headers, httpsEnabled: boolean): HeaderAnalysis {
  const lower = new Map<string, string>();
  headers.forEach((value, key) => {
    if (!lower.has(key.toLowerCase())) lower.set(key.toLowerCase(), value);
  });

  const scoreByCategory: Record<Category, number> = {
    transport: 0,
    content: 0,
    browser: 0,
    cookies: 0,
    infrastructure: 0,
  };
  const vulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const headerInfos: SecurityHeader[] = [];

  // A CSP with a frame-ancestors directive already provides clickjacking
  // protection and is the modern replacement for X-Frame-Options. Don't
  // treat a missing X-Frame-Options as a real gap when that's covered.
  const cspValue = (lower.get('content-security-policy') || lower.get('content-security-policy-report-only') || '').toLowerCase();
  const cspHasFrameAncestors = cspValue.includes('frame-ancestors');

  for (const spec of HEADER_SPECS) {
    const value = lower.get(spec.key) ?? '';
    const present = Boolean(value);
    const weakness = spec.checkWeakness ? spec.checkWeakness(value) : { isWeak: false, penalty: 0 };
    let status: HeaderStatus;
    let pointsAwarded = 0;
    // Per-instance severity override — starts from the spec's default but
    // can be softened for context-dependent cases (HSTS on a non-HTTPS
    // site, X-Frame-Options when CSP frame-ancestors already covers it).
    let severity: Severity = spec.severity;
    let weaknessReason = weakness.reason;

    // HSTS only means anything once HTTPS is actually working. Flagging it
    // as a separate high-severity vulnerability on top of "Enable HTTPS" is
    // redundant and inflates the vulnerability count.
    const hstsNotApplicable = spec.key === 'strict-transport-security' && !httpsEnabled;
    // Clickjacking is already covered by CSP frame-ancestors.
    const frameProtectionCovered = spec.key === 'x-frame-options' && !present && cspHasFrameAncestors;

    if (spec.key === 'content-security-policy' && !present && lower.has('content-security-policy-report-only')) {
      status = 'report-only';
      severity = 'info';
      vulns.info++;
    } else if (spec.key === 'content-security-policy-report-only' && present) {
      status = 'report-only';
      pointsAwarded = spec.maxPoints;
    } else if (hstsNotApplicable) {
      status = 'missing';
      severity = 'info';
      weaknessReason = 'HTTPS is not enabled, so HSTS would have no effect yet — fix HTTPS first.';
      vulns.info++;
    } else if (frameProtectionCovered) {
      status = 'missing';
      severity = 'info';
      weaknessReason = "Clickjacking is already mitigated by the Content-Security-Policy frame-ancestors directive; X-Frame-Options is optional here.";
      pointsAwarded = spec.maxPoints * 0.6;
      vulns.info++;
    } else if (!present) {
      status = 'missing';
      if (!spec.isOptional) {
        if (severity === 'critical') vulns.critical++;
        else if (severity === 'high') vulns.high++;
        else if (severity === 'medium') vulns.medium++;
        else if (severity === 'low') vulns.low++;
        else vulns.info++;
      } else {
        vulns.info++;
      }
    } else if (weakness.isWeak) {
      status = 'weak';
      pointsAwarded = Math.max(spec.maxPoints - weakness.penalty, spec.maxPoints * 0.4);
      if (severity === 'high' || severity === 'critical') vulns.medium++;
      else if (severity === 'medium') vulns.low++;
      else vulns.info++;
    } else {
      status = 'present';
      pointsAwarded = spec.maxPoints;
    }

    if (spec.isLegacy && spec.maxPoints === 0) pointsAwarded = 0;

    const earned = Math.round(pointsAwarded * 10) / 10;
    scoreByCategory[spec.category] += earned;

    headerInfos.push({
      name: spec.prettyName,
      value: value || 'Not set',
      status,
      description: spec.description,
      whyItMatters: spec.whyItMatters,
      exampleValue: spec.exampleValue,
      severity,
      tier: spec.tier,
      isWeak: weakness.isWeak,
      weaknessReason,
      pointsAwarded: earned,
      maxPoints: spec.maxPoints,
      category: spec.category,
    });
  }

  const vulnerabilities: Vulnerabilities = {
    count: vulns.critical + vulns.high + vulns.medium + vulns.low + vulns.info,
    ...vulns,
  };

  return { headerInfos, scoreByCategory, vulnerabilities };
}

interface CookieAnalysis {
  score: number;
  maxScore: number;
}

function analyzeCookies(cookies: CookieInfo[]): CookieAnalysis {
  if (cookies.length === 0) return { score: 0, maxScore: 0 };
  const maxScore = 10;
  const secureCount = cookies.filter((c) => c.secure).length;
  // HttpOnly is only weighted against cookies that look like they carry
  // session/auth state — a site full of non-sensitive, intentionally
  // JS-readable cookies shouldn't be marked down for that. If nothing looks
  // sensitive, fall back to judging all cookies so the signal isn't lost
  // entirely.
  const sensitiveCookies = cookies.filter((c) => c.looksSensitive);
  const httpOnlyRelevant = sensitiveCookies.length > 0 ? sensitiveCookies : cookies;
  const httpOnlyCount = httpOnlyRelevant.filter((c) => c.httpOnly).length;
  const sameSiteOkCount = cookies.filter((c) => c.sameSite !== 'None' || c.secure).length;
  const score =
    (secureCount / cookies.length) * 5 +
    (httpOnlyCount / httpOnlyRelevant.length) * 3 +
    (sameSiteOkCount / cookies.length) * 2;
  return { score: Math.round(score * 10) / 10, maxScore };
}

function getServerInfo(
  headers: Headers,
  httpStatus: number,
  redirectChain: RedirectStep[],
  finalUrl: string
): ServerInfo {
  const server = headers.get('server') || '';
  const xPoweredBy = headers.get('x-powered-by') || '';
  const poweredBy = headers.get('powered-by') || '';
  const compression = headers.get('content-encoding') || 'none';
  return {
    server,
    poweredBy,
    xPoweredBy,
    compression,
    finalStatusCode: httpStatus,
    redirectCount: redirectChain.length - 1,
    redirectChain,
    mixedContent: false,
  };
}

function computeScore(
  scoreByCategory: Record<Category, number>,
  httpsInfo: HttpsInfo,
  cookieScore: number,
  cookieMax: number,
  serverInfo: ServerInfo
): { total: number; breakdown: ScoreBreakdown } {
  const transport =
    scoreByCategory.transport +
    (httpsInfo.enabled ? 10 : 0) +
    (httpsInfo.redirectFromHttp ? 5 : 0) +
    (httpsInfo.hstsPreloadReady ? 5 : 0);
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

  // The category maximums intentionally sum to more than 100 (e.g. a site
  // can't realistically max out both the enforcing-CSP and
  // report-only-CSP sub-scores at once), so the final score is capped at
  // 100. Report maxTotal as 100 to match what's actually shown — showing
  // the raw, unreachable category-sum here just confuses the percentage.
  const maxTotal = 100;
  const total = Math.min(transport + content + browser + cookies + infrastructure, 100);

  return {
    total,
    breakdown: {
      transport: Math.round(transport * 10) / 10,
      content: Math.round(content * 10) / 10,
      browser: Math.round(browser * 10) / 10,
      cookies,
      infrastructure: Math.round(infrastructure * 10) / 10,
      total: Math.round(total * 10) / 10,
      maxTotal,
    },
  };
}

export function gradeFromScore(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

interface RecTemplate {
  title: string;
  description: string;
  whyItMatters: string;
  impact: string;
  exampleImplementation: string;
  references: string[];
}

const REC_TEMPLATES: Record<string, RecTemplate> = {
  'strict-transport-security': {
    title: 'Add Strict-Transport-Security (HSTS) header',
    description:
      'HSTS is missing or weak. Add it to force browsers to always use HTTPS and prevent protocol downgrade attacks.',
    whyItMatters:
      'Without HSTS, a man-in-the-middle attacker can force a downgrade to HTTP and intercept or tamper with traffic.',
    impact: 'Protects against man-in-the-middle and SSL stripping attacks.',
    exampleImplementation: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
  },
  'content-security-policy': {
    title: 'Add a Content-Security-Policy header',
    description:
      'CSP is missing or weak. Without it, your site is more vulnerable to XSS and data injection attacks.',
    whyItMatters:
      'CSP is the most effective defense against XSS. Without it, any injected script can execute and steal data or credentials.',
    impact: 'Significantly reduces risk of Cross-Site Scripting (XSS) attacks.',
    exampleImplementation: "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
  },
  'x-frame-options': {
    title: 'Add X-Frame-Options header',
    description:
      'X-Frame-Options is missing. Add it to prevent clickjacking by stopping your page from being embedded in iframes.',
    whyItMatters:
      'Without frame protection, attackers can overlay your page with malicious UI to trick users into clicking hidden actions.',
    impact: 'Prevents clickjacking attacks on your users.',
    exampleImplementation: 'X-Frame-Options: DENY',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
  },
  'x-content-type-options': {
    title: 'Add X-Content-Type-Options header',
    description:
      "X-Content-Type-Options is missing. Set it to 'nosniff' to prevent browsers from MIME-type sniffing.",
    whyItMatters:
      'Without nosniff, browsers may execute uploaded files as scripts based on content sniffing, enabling XSS and drive-by downloads.',
    impact: 'Reduces risk of content type confusion attacks.',
    exampleImplementation: 'X-Content-Type-Options: nosniff',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
  },
  'referrer-policy': {
    title: 'Add Referrer-Policy header',
    description:
      'Referrer-Policy is missing or weak. Add it to control how much referrer information is shared with external sites.',
    whyItMatters:
      'Without a Referrer-Policy, browsers may leak full URLs (including query parameters) to third-party destinations.',
    impact: 'Protects user privacy by limiting referrer data leakage.',
    exampleImplementation: 'Referrer-Policy: strict-origin-when-cross-origin',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
  },
  'permissions-policy': {
    title: 'Add Permissions-Policy header',
    description:
      'Permissions-Policy is missing. Add it to restrict access to browser features like camera, microphone, and geolocation.',
    whyItMatters:
      'Without Permissions-Policy, any embedded content may request access to powerful browser features, expanding the attack surface.',
    impact: 'Limits attack surface by restricting powerful browser APIs.',
    exampleImplementation: 'Permissions-Policy: geolocation=(), camera=(), microphone=()',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
  },
  'cross-origin-embedder-policy': {
    title: 'Add Cross-Origin-Embedder-Policy header',
    description:
      'COEP is missing. Add it to require cross-origin resources to opt-in via CORS, enabling a secure context.',
    whyItMatters:
      'COEP prevents cross-origin resources from being loaded without explicit permission, mitigating Spectre-class attacks.',
    impact: 'Enables advanced APIs like SharedArrayBuffer and mitigates side-channel attacks.',
    exampleImplementation: 'Cross-Origin-Embedder-Policy: require-corp',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy'],
  },
  'cross-origin-opener-policy': {
    title: 'Add Cross-Origin-Opener-Policy header',
    description:
      'COOP is missing or weak. Add it to isolate your browsing context from cross-origin documents.',
    whyItMatters:
      'COOP prevents cross-origin documents from interacting with your page, defending against cross-origin attacks.',
    impact: 'Isolates your page from cross-origin windows, reducing attack surface.',
    exampleImplementation: 'Cross-Origin-Opener-Policy: same-origin',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'],
  },
  'cross-origin-resource-policy': {
    title: 'Add Cross-Origin-Resource-Policy header',
    description:
      'CORP is missing or weak. Add it to restrict who can embed this resource, providing defense-in-depth.',
    whyItMatters:
      'CORP prevents your resources from being loaded by arbitrary sites, reducing the risk of cross-origin attacks.',
    impact: 'Prevents cross-origin information leakage.',
    exampleImplementation: 'Cross-Origin-Resource-Policy: same-origin',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy'],
  },
};

function tierPrefix(tier: HeaderTier): string {
  if (tier === 'optional') return 'Optional hardening: ';
  if (tier === 'recommended') return 'Recommended: ';
  return '';
}

function buildRecommendations(
  headerInfos: SecurityHeader[],
  httpsInfo: HttpsInfo,
  cookies: CookieInfo[],
  serverInfo: ServerInfo
): Recommendation[] {
  const recs: Recommendation[] = [];
  let idx = 1;

  // Headers whose "missing" status is already explained by something else
  // (HSTS before HTTPS is enabled at all; X-Frame-Options when CSP
  // frame-ancestors already covers clickjacking) don't need their own
  // recommendation — that would just duplicate the real underlying issue.
  const alreadyExplained = new Set(['Strict-Transport-Security', 'X-Frame-Options']);
  const problematic = headerInfos.filter((h) => {
    if (h.status !== 'missing' && h.status !== 'weak') return false;
    if (h.severity === 'info' && alreadyExplained.has(h.name)) return false;
    return true;
  });
  problematic.sort((a, b) => {
    const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });

  const specByPrettyName = new Map(HEADER_SPECS.map((s) => [s.prettyName, s]));
  for (const header of problematic) {
    const spec = specByPrettyName.get(header.name);
    const template = spec ? REC_TEMPLATES[spec.key] : undefined;
    if (!template || !spec) continue;
    recs.push({
      id: `rec-${idx++}`,
      title: `${tierPrefix(spec.tier)}${template.title}`,
      description: template.description,
      whyItMatters: template.whyItMatters,
      impact: template.impact,
      exampleImplementation: template.exampleImplementation,
      severity: header.severity,
      tier: spec.tier,
      references: template.references,
    });
  }

  const weakCookies = cookies.filter((c) => c.weaknesses.length > 0);
  if (weakCookies.length > 0) {
    const names = weakCookies.map((c) => c.name || '(unnamed)').join(', ');
    const allIssues = Array.from(new Set(weakCookies.flatMap((c) => c.weaknesses)));
    recs.push({
      id: `rec-${idx++}`,
      title: 'Secure your cookies',
      description: `${weakCookies.length} of ${cookies.length} cookie(s) have real weaknesses (${names}): ${allIssues.join('; ')}.`,
      whyItMatters:
        'Cookies missing Secure or HttpOnly where they matter can be intercepted over plain HTTP or stolen via XSS. Proper flags prevent these attacks.',
      impact: 'Prevents session hijacking, cookie theft, and CSRF attacks.',
      exampleImplementation: 'Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
      severity: 'medium',
      tier: 'essential',
    });
  }

  if (serverInfo.server || serverInfo.xPoweredBy || serverInfo.poweredBy) {
    recs.push({
      id: `rec-${idx++}`,
      title: 'Hide server version information',
      description:
        'The Server and/or X-Powered-By headers expose implementation details that help attackers fingerprint your stack.',
      whyItMatters:
        'Version information lets attackers identify known vulnerabilities in your specific server or framework version.',
      impact: 'Reduces information leakage and makes targeted exploitation harder.',
      exampleImplementation: 'Remove or obscure the Server and X-Powered-By response headers in your web server config.',
      references: ['https://owasp.org/www-project-secure-headers/'],
      severity: 'low',
      tier: 'recommended',
    });
  }

  if (!httpsInfo.enabled) {
    recs.push({
      id: `rec-${idx++}`,
      title: 'Enable HTTPS',
      description:
        'Your site does not serve over HTTPS. Obtain an SSL certificate and redirect all HTTP traffic to HTTPS.',
      whyItMatters: 'HTTPS is foundational for web security and user trust.',
      impact: 'HTTPS is foundational for web security and user trust.',
      exampleImplementation: "Obtain a certificate from Let's Encrypt and redirect HTTP to HTTPS.",
      references: ['https://letsencrypt.org/'],
      severity: 'critical',
      tier: 'essential',
    });
  } else if (!httpsInfo.redirectFromHttp) {
    recs.push({
      id: `rec-${idx++}`,
      title: 'Redirect HTTP traffic to HTTPS',
      description:
        'HTTPS is available, but plain HTTP requests are not being redirected to HTTPS. Visitors who type the address without "https://" (or follow an old http:// link) stay on an unencrypted connection.',
      whyItMatters:
        'Without a redirect, users can be silently downgraded to HTTP by a network attacker (SSL stripping), exposing their traffic.',
      impact: 'Ensures every visitor ends up on an encrypted connection regardless of how they arrived.',
      exampleImplementation: 'Configure your web server or load balancer to 301-redirect all http:// requests to the https:// equivalent.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
      severity: 'medium',
      tier: 'essential',
    });
  }

  return recs;
}

export class ScanError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ScanError';
    this.status = status;
  }
}

function mapFetchError(message: string, hostname: string): ScanError {
  if (/ssl|certificate|cert|tls/i.test(message)) {
    return new ScanError(
      `SSL/TLS verification failed for ${hostname}. The certificate may be invalid, expired, or self-signed.`,
      422
    );
  }
  if (/timeout|abort/i.test(message)) {
    return new ScanError(`Request to ${hostname} timed out. The site may be slow or unresponsive.`, 504);
  }
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) {
    return new ScanError(`Could not resolve ${hostname}. The domain may not exist or DNS lookup failed.`, 502);
  }
  if (/ECONNREFUSED|ECONNRESET|fetch failed/i.test(message)) {
    return new ScanError(`Could not connect to ${hostname}. The site may be offline or refusing connections.`, 502);
  }
  return new ScanError(`Could not reach ${hostname}. Please check the URL and try again.`, 502);
}

export async function runScan(rawUrl: string): Promise<ScanResult> {
  const startTime = Date.now();
  const url = normalizeUrl(rawUrl);
  const parsed = new URL(url);
  const hostname = parsed.hostname;

  const mergedHeaders = new Headers();
  const redirectChain: RedirectStep[] = [];
  let currentUrl = url;
  let redirectCount = 0;
  let finalResponse: Response | null = null;

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
      const previousUrl = redirectChain.length > 0 ? redirectChain[redirectChain.length - 1].url : null;
      redirectChain.push({
        url: currentUrl,
        status: res.status,
        https: currentUrl.startsWith('https://'),
        redirectType: previousUrl ? classifyRedirect(previousUrl, currentUrl) : 'initial',
      });

      if (res.status >= 300 && res.status < 400) {
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
    throw mapFetchError((err as Error).message ?? '', hostname);
  }

  if (redirectCount > MAX_REDIRECTS) {
    throw new ScanError(`Too many redirects for ${hostname}. The site may have a redirect loop.`, 502);
  }

  if (!finalResponse) {
    throw new ScanError(`Could not fetch ${hostname}. Please check the URL and try again.`, 502);
  }

  const httpStatus = finalResponse.status;
  if (httpStatus >= 400) {
    throw new ScanError(`The site ${hostname} returned an HTTP ${httpStatus} error.`, 502);
  }

  const httpsOk = httpStatus > 0 && httpStatus < 500 && currentUrl.startsWith('https://');
  const hstsValue = mergedHeaders.get('strict-transport-security') ?? '';
  const httpsInfo = await getHttpsInfo(hostname, httpsOk, hstsValue);
  const { headerInfos, scoreByCategory, vulnerabilities } = analyzeHeaders(mergedHeaders, httpsOk);
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

  return {
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
}
