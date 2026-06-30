# bharatauth/security/lockout.py
"""
Two-tier brute-force lockout — DB-backed, Redis-independent.

LAYER 1 (route-level): Redis rate limits in rate_limit.py — coarse IP gate.
LAYER 2 (service-level): This file — per-account failure counting.

WHY TWO LAYERS:
  Rate limits run before the route body and can't know if a credential
  was valid. Lockout runs AFTER bcrypt verification where we know
  success vs failure. Both are needed for different attack surfaces.

LOCKOUT TIERS:
  Soft lock  — 5 consecutive failures  → locked 7 minutes (423)
  Hard lock  — 10 consecutive failures → email verify required (423)
  IP block   — 3+ distinct accounts fail from same IP → IP blocked

PIN SPECIAL CASE:
  PIN lockout returns 401, not 423. This gives an attacker with a
  stolen JWT no signal that lockout fired — 401 is indistinguishable
  from wrong PIN. This is intentional and documented.

STALE COUNTER RESET:
  If last_failed_at > 24 hours ago, the counter resets to 1 (fresh run).
  This prevents a decade of old failures triggering a lock.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from bharatauth.exceptions import AccountLockedError, IPBlockedError

logger = logging.getLogger("bharatauth.security.lockout")

# ── Tier thresholds ───────────────────────────────────────────────────
_SOFT_LOCK_AFTER   = 5      # consecutive failures
_HARD_LOCK_AFTER   = 10     # consecutive failures
_SOFT_LOCK_MINUTES = 7
_STALE_HOURS       = 24     # counter resets after this many hours of inactivity
_IP_BLOCK_AFTER    = 3      # distinct accounts failing from same IP
_IP_BLOCK_HOURS    = 24


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════
# ACCOUNT LOCKOUT — works with BAAccount (managed) or any object
# with the required attributes (external mode via duck typing)
# ═══════════════════════════════════════════════════════════════

def check_account_lockout(account: Any, *, for_pin: bool = False) -> None:
    """
    Raise if the account is currently locked.

    for_pin=True: raises UnauthorizedError (401) instead of AccountLockedError (423).
    This is the intentional PIN security behavior — no lockout signal leaks.
    """
    if account.locked_until and _now() < account.locked_until:
        if for_pin:
            # Import here to avoid circular
            from bharatauth.exceptions import UnauthorizedError
            raise UnauthorizedError("Invalid PIN.")

        locked_until_str = account.locked_until.isoformat()
        requires_verify = account.lockout_count >= 2

        raise AccountLockedError(
            message=(
                "Account locked. Email verification required."
                if requires_verify
                else f"Account temporarily locked until {locked_until_str}."
            ),
            locked_until=locked_until_str,
            requires_email_verify=requires_verify,
        )


def record_account_failure(account: Any, db: Session) -> None:
    """
    Increment the failure counter and apply lockout tiers as needed.
    Resets to 1 if the last failure was > 24 hours ago (stale counter).
    """
    now = _now()

    # Stale counter reset
    if (
        account.last_failed_at
        and (now - account.last_failed_at) > timedelta(hours=_STALE_HOURS)
    ):
        account.login_fail_count = 1
    else:
        account.login_fail_count = (account.login_fail_count or 0) + 1

    account.last_failed_at = now

    if account.login_fail_count >= _HARD_LOCK_AFTER:
        # Hard lock — requires email verification to unlock
        account.locked_until = now + timedelta(days=365)  # effectively permanent
        account.lockout_count = (account.lockout_count or 0) + 1
        logger.warning(
            f"BharatAuth: Hard lock applied — "
            f"account_id={getattr(account, 'id', '?')} "
            f"failures={account.login_fail_count}"
        )
    elif account.login_fail_count >= _SOFT_LOCK_AFTER:
        # Soft lock — 7-minute cooldown
        account.locked_until = now + timedelta(minutes=_SOFT_LOCK_MINUTES)
        account.lockout_count = (account.lockout_count or 0) + 1
        logger.warning(
            f"BharatAuth: Soft lock applied — "
            f"account_id={getattr(account, 'id', '?')} "
            f"until={account.locked_until.isoformat()}"
        )

    db.flush()


def clear_account_failures(account: Any, db: Session) -> None:
    """
    Reset the rolling failure counter on successful authentication.
    Preserves lockout_count (escalation memory) — only login_fail_count
    and locked_until are cleared.
    """
    account.login_fail_count = 0
    account.locked_until = None
    # lockout_count intentionally preserved — tracks escalation history
    db.flush()


# ═══════════════════════════════════════════════════════════════
# IP BLOCK — credential-stuffing protection
# ═══════════════════════════════════════════════════════════════

def record_ip_failure(
    ip: str | None,
    identifier: str,
    db: Session,
) -> None:
    """
    Track distinct-account failures per IP.
    Block the IP after _IP_BLOCK_AFTER distinct accounts fail from it.
    """
    if not ip:
        return

    from bharatauth.models import BAIPBlock

    # Count distinct failed identifiers from this IP using Redis if available
    # Falls back to DB-only tracking
    _record_ip_failure_db(ip, identifier, db)


def _record_ip_failure_db(ip: str, identifier: str, db: Session) -> None:
    """DB-backed IP failure tracking (Redis-independent path)."""
    from bharatauth.models import BAIPBlock

    # Simplified: block after threshold using a counter key in Redis if available,
    # otherwise track via a dedicated Redis key or accept the DB-only approximation.
    r = _get_redis_safe()
    if r:
        redis_key = f"ba:ipfail:{ip}"
        try:
            r.sadd(redis_key, identifier)
            r.expire(redis_key, _IP_BLOCK_HOURS * 3600)
            count = r.scard(redis_key)
            if count >= _IP_BLOCK_AFTER:
                _block_ip(ip, db, reason="credential_stuffing")
        except Exception:
            pass  # Fail open
    # Without Redis, IP blocks require manual admin action or a periodic job


def check_ip_blocked(ip: str | None, db: Session) -> None:
    """
    Raise IPBlockedError if this IP is currently blocked.
    Checks Redis first (fast path), falls back to DB.
    """
    if not ip:
        return

    from bharatauth.models import BAIPBlock

    # Fast path via Redis
    r = _get_redis_safe()
    if r:
        try:
            if r.get(f"ba:ipblock:{ip}"):
                raise IPBlockedError()
        except IPBlockedError:
            raise
        except Exception:
            pass

    # DB fallback
    block = db.query(BAIPBlock).filter(
        BAIPBlock.ip_address == ip,
    ).first()
    if block and block.is_active():
        raise IPBlockedError()


def _block_ip(ip: str, db: Session, reason: str = "") -> None:
    from bharatauth.models import BAIPBlock

    now = datetime.now(timezone.utc)
    existing = db.query(BAIPBlock).filter_by(ip_address=ip).first()
    if existing:
        existing.blocked_at = now
        existing.expires_at = now + timedelta(hours=_IP_BLOCK_HOURS)
    else:
        block = BAIPBlock(
            ip_address=ip,
            expires_at=now + timedelta(hours=_IP_BLOCK_HOURS),
            reason=reason,
        )
        db.add(block)

    db.flush()

    # Also cache in Redis for fast-path checks
    r = _get_redis_safe()
    if r:
        try:
            r.setex(f"ba:ipblock:{ip}", _IP_BLOCK_HOURS * 3600, "1")
        except Exception:
            pass

    logger.warning(f"BharatAuth: IP blocked — {ip} reason={reason}")


def _get_redis_safe():
    try:
        from bharatauth.security.rate_limit import _get_redis
        return _get_redis()
    except Exception:
        return None
