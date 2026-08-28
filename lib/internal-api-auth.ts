import { timingSafeEqual } from 'node:crypto';

function secureEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
}

export function hasInternalApiAccess(headers: Headers): boolean {
  const secret = process.env.WEBSHIELD_INTERNAL_API_SECRET;
  if (!secret) return false;

  const bearer = headers.get('authorization');
  const provided =
    headers.get('x-webshield-secret') ||
    (bearer?.startsWith('Bearer ') ? bearer.slice(7) : '');

  return Boolean(provided) && secureEqual(provided, secret);
}
