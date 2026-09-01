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

function withSecurityHeaders(response: NextResponse): NextResponse {
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

export function middleware(request: NextRequest): NextResponse {
  if (!isProtectedPath(request.nextUrl.pathname)) {
    return withSecurityHeaders(NextResponse.next());
  }

  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    return withSecurityHeaders(NextResponse.json({ detail: 'Admin access is not configured.' }, { status: 503 }));
  }

  const authorization = request.headers.get('authorization');
  if (!authorization?.startsWith('Basic ')) {
    return withSecurityHeaders(new NextResponse('Authentication required.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="WebShield Admin", charset="UTF-8"' },
    }));
  }

  let decoded = '';
  try {
    decoded = atob(authorization.slice(6));
  } catch {
    return withSecurityHeaders(new NextResponse('Invalid authentication.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="WebShield Admin"' },
    }));
  }

  const separator = decoded.indexOf(':');
  const providedUsername = separator >= 0 ? decoded.slice(0, separator) : '';
  const providedPassword = separator >= 0 ? decoded.slice(separator + 1) : '';

  if (!constantTimeEqual(providedUsername, username) || !constantTimeEqual(providedPassword, password)) {
    return withSecurityHeaders(new NextResponse('Invalid credentials.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="WebShield Admin", charset="UTF-8"' },
    }));
  }

  return withSecurityHeaders(NextResponse.next());
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
  runtime: 'nodejs',
};
