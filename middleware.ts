import { NextRequest, NextResponse } from 'next/server';

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

function isProtectedPath(pathname: string): boolean {
  return (
    pathname === '/dashboard' ||
    pathname.startsWith('/dashboard/') ||
    pathname === '/monitor' ||
    pathname.startsWith('/monitor/') ||
    pathname === '/scan-history' ||
    pathname.startsWith('/scan-history/') ||
    pathname === '/api/dashboard' ||
    pathname === '/api/scans' ||
    pathname.startsWith('/api/scans/') ||
    pathname === '/api/sites' ||
    pathname.startsWith('/api/sites/')
  );
}

export function buildCsp(nonce: string): string {
  // script-src uses a per-request nonce instead of 'unsafe-inline'/
  // 'unsafe-eval'. 'strict-dynamic' is additive for browsers that support
  // it; browsers that don't simply ignore that token and fall back to
  // 'self' + the nonce, so this doesn't narrow anything for older clients.
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data: https:",
    "connect-src 'self' https:",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}

function withSecurityHeaders(response: NextResponse, nonce: string): NextResponse {
  response.headers.set('Content-Security-Policy', buildCsp(nonce));
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  // 'credentialless' (rather than 'require-corp') so cross-origin resources
  // that don't send a CORP header still load — this page has no reason to
  // send credentials to third-party origins, so the tighter isolation
  // benefit still applies without the risk of breaking image/font loads.
  response.headers.set('Cross-Origin-Embedder-Policy', 'credentialless');
  response.headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

export function middleware(request: NextRequest): NextResponse {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', buildCsp(nonce));
  const nextInit = { request: { headers: requestHeaders } };

  if (!isProtectedPath(request.nextUrl.pathname)) {
    return withSecurityHeaders(NextResponse.next(nextInit), nonce);
  }

  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    return withSecurityHeaders(NextResponse.json({ detail: 'Admin access is not configured.' }, { status: 503 }), nonce);
  }

  const authorization = request.headers.get('authorization');
  if (!authorization?.startsWith('Basic ')) {
    return withSecurityHeaders(new NextResponse('Authentication required.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="WebShield Admin", charset="UTF-8"' },
    }), nonce);
  }

  let decoded = '';
  try {
    decoded = atob(authorization.slice(6));
  } catch {
    return withSecurityHeaders(new NextResponse('Invalid authentication.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="WebShield Admin"' },
    }), nonce);
  }

  const separator = decoded.indexOf(':');
  const providedUsername = separator >= 0 ? decoded.slice(0, separator) : '';
  const providedPassword = separator >= 0 ? decoded.slice(separator + 1) : '';

  if (!constantTimeEqual(providedUsername, username) || !constantTimeEqual(providedPassword, password)) {
    return withSecurityHeaders(new NextResponse('Invalid credentials.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="WebShield Admin", charset="UTF-8"' },
    }), nonce);
  }

  return withSecurityHeaders(NextResponse.next(nextInit), nonce);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
  runtime: 'nodejs',
};
