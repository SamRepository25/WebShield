import { Redis } from '@upstash/redis';

const WINDOW_SECONDS = 60;
const LIMIT = 20;

const memory = new Map<string, { count: number; resetAt: number }>();

function getRedis(): Redis | null {
  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) return null;
  return new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
}

export async function checkRateLimit(identifier: string): Promise<{ allowed: boolean; retryAfter: number }> {
  const redis = getRedis();
  if (redis) {
    const key = `webshield:scan:${identifier}`;
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, WINDOW_SECONDS);
    return {
      allowed: count <= LIMIT,
      retryAfter: count > LIMIT ? WINDOW_SECONDS : 0,
    };
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('Distributed rate limiting is not configured.');
  }

  const now = Date.now();
  const current = memory.get(identifier);
  if (!current || current.resetAt <= now) {
    memory.set(identifier, { count: 1, resetAt: now + WINDOW_SECONDS * 1000 });
    return { allowed: true, retryAfter: 0 };
  }

  current.count += 1;
  return {
    allowed: current.count <= LIMIT,
    retryAfter: current.count > LIMIT ? Math.ceil((current.resetAt - now) / 1000) : 0,
  };
}
