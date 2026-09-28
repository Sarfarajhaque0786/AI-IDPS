from fastapi import Request, HTTPException

from app.database.connection import redis_client

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


def rate_limit_login(request: Request):
    ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:login:{ip}"

    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, WINDOW_SECONDS)
        if count > MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Please try again in a minute.",
            )
    except HTTPException:
        raise
    except Exception:
        pass