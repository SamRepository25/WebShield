import os
import time
from threading import Lock

try:
    from upstash_redis import Redis
except ImportError:
    Redis = None

LIMIT = 20
WINDOW_SECONDS = 60
_memory = {}
_lock = Lock()
_redis = None

if Redis and os.getenv("UPSTASH_REDIS_REST_URL") and os.getenv("UPSTASH_REDIS_REST_TOKEN"):
    _redis = Redis(
        url=os.environ["UPSTASH_REDIS_REST_URL"],
        token=os.environ["UPSTASH_REDIS_REST_TOKEN"],
    )


def check_rate_limit(identifier: str) -> tuple[bool, int]:
    if _redis:
        key = f"webshield:backend:scan:{identifier}"
        count = int(_redis.incr(key))
        if count == 1:
            _redis.expire(key, WINDOW_SECONDS)
        return count <= LIMIT, WINDOW_SECONDS if count > LIMIT else 0

    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        raise RuntimeError("Distributed rate limiting is not configured.")

    now = time.time()
    with _lock:
        current = _memory.get(identifier)
        if not current or current[1] <= now:
            _memory[identifier] = [1, now + WINDOW_SECONDS]
            return True, 0
        current[0] += 1
        return current[0] <= LIMIT, max(1, int(current[1] - now)) if current[0] > LIMIT else 0
