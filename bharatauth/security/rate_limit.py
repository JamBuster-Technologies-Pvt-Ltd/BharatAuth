# bharatauth/security/rate_limit.py
"""
Per-IP rate limiting using Redis fixed-window counters.

Design principles:
- Runs BEFORE the route body (coarse IP gate).
- Cannot distinguish success from failure — that's the lockout layer's job.
- FAILS OPEN: if Redis is unavailable, requests are allowed through.
  Auth correctness is maintained by the DB-backed lockout layer.
- FastAPI-compatible via the rate_limit() dependency factory.

Usage as FastAPI dependency:
    @router.post("/login", dependencies=[Depends(rate_limit("login", 20, 900))])

Usage imperatively (non-FastAPI):
    check_rate_limit(key="login", identifier="192.168.1.1", limit=20, window_seconds=900)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Request

from bharatauth.exceptions import RateLimitError

logger = logging.getLogger("bharatauth.security.rate_limit")

# ── Redis client (lazy import — optional dependency) ──────────────────
_redis_client = None
_redis_available = False


def _get_redis():
    global _redis_client, _redis_available
    if _redis_client is not None:
        return _redis_client if _redis_available else None

    try:
        from bharatauth.config import get_config
        cfg = get_config()
        if not cfg.redis_url:
            _redis_available = False
            return None

        import redis  # type: ignore[import]
        _redis_client = redis.from_url(cfg.redis_url, decode_responses=True)
        _redis_client.ping()
        _redis_available = True
        logger.info("BharatAuth: Redis rate limiting enabled.")
        return _redis_client
    except Exception as e:
        _redis_available = False
        logger.warning(
            f"BharatAuth: Redis unavailable ({e}). "
            "Rate limiting disabled — DB-backed lockout still active."
        )
        return None


def check_rate_limit(
    key: str,
    identifier: str,
    limit: int,
    window_seconds: int,
) -> None:
    """
    Check and increment a rate limit counter.
    Raises RateLimitError if the limit is exceeded.
    Silently passes if Redis is unavailable (fail-open).
    """
    r = _get_redis()
    if r is None:
        return  # Fail open

    redis_key = f"ba:rl:{key}:{identifier}"
    try:
        pipe = r.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window_seconds)
        count, _ = pipe.execute()

        if count > limit:
            raise RateLimitError(
                f"Rate limit exceeded. Max {limit} requests per "
                f"{window_seconds // 60} minutes."
            )
    except RateLimitError:
        raise
    except Exception as e:
        logger.warning(f"BharatAuth: Rate limit check failed ({e}). Allowing request.")


def rate_limit(key: str, limit: int, window_seconds: int):
    """
    FastAPI dependency factory for route-level rate limiting.

    Usage:
        @router.post("/otp/request", dependencies=[Depends(rate_limit("otp_request", 5, 300))])
        def otp_request(...):
    """
    async def _dependency(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        check_rate_limit(
            key=key,
            identifier=ip,
            limit=limit,
            window_seconds=window_seconds,
        )

    return _dependency
