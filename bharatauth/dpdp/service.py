# bharatauth/dpdp/service.py
"""
DPDP consent service.

Records are written with:
  user_id       — opaque string (works in both managed and external mode)
  category      — one of the six DPDP categories (configurable)
  granted       — True (consent given) or False (withdrawn)
  notice_version — version of the privacy notice shown to the user
  ip_address    — IP at time of consent (proves informed consent location)
  user_agent    — User-Agent at time of consent
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from bharatauth.config import get_config
from bharatauth.exceptions import ConsentRequiredError, ValidationError
from bharatauth.models import BAConsentLog

logger = logging.getLogger("bharatauth.dpdp")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _validate_category(category: str) -> str:
    cfg = get_config()
    category = category.strip().lower()
    if category not in cfg.dpdp_categories:
        raise ValidationError(
            f"Unknown consent category '{category}'. "
            f"Valid categories: {', '.join(cfg.dpdp_categories)}"
        )
    return category


def record_consent(
    db: Session,
    *,
    user_id: str,
    category: str,
    granted: bool,
    notice_version: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Record a single consent decision.

    Creates an immutable row in ba_consent_log.
    The most recent row per category is the current state.

    Args:
        user_id:        The user's ID (string in both modes).
        category:       One of the six DPDP categories.
        granted:        True = consent given, False = withdrawn.
        notice_version: The privacy notice version shown to the user.
                        Defaults to BharatAuthConfig.dpdp_notice_version.
        ip_address:     Client IP at consent time.
        user_agent:     Client User-Agent at consent time.
    """
    cfg = get_config()
    category = _validate_category(category)
    version = notice_version or cfg.dpdp_notice_version

    log = BAConsentLog(
        user_id=str(user_id),
        consent_category=category,
        granted=granted,
        notice_version=version,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(log)
    db.commit()

    logger.info(
        f"BharatAuth DPDP: consent recorded — "
        f"user_id={user_id} category={category} granted={granted} "
        f"notice={version}"
    )

    return {
        "success": True,
        "category": category,
        "granted": granted,
        "notice_version": version,
        "recorded_at": log.created_at.isoformat(),
    }


def record_bulk_consent(
    db: Session,
    *,
    user_id: str,
    consents: list[dict],
    notice_version: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Record multiple consent decisions in one call (e.g., at registration).

    Args:
        consents: List of {"category": str, "granted": bool}
    """
    cfg = get_config()
    version = notice_version or cfg.dpdp_notice_version

    recorded = []
    for item in consents:
        category = _validate_category(item["category"])
        granted = bool(item["granted"])

        log = BAConsentLog(
            user_id=str(user_id),
            consent_category=category,
            granted=granted,
            notice_version=version,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(log)
        recorded.append({"category": category, "granted": granted})

    db.commit()
    logger.info(
        f"BharatAuth DPDP: bulk consent recorded — "
        f"user_id={user_id} count={len(recorded)} notice={version}"
    )

    return {"success": True, "recorded": recorded, "notice_version": version}


def validate_registration_consent(consents: list[dict]) -> None:
    """
    Validate that all required categories are granted.
    Call this BEFORE creating the user at registration.
    Raises ConsentRequiredError if any category is missing or false.

    Args:
        consents: List of {"category": str, "granted": bool}
    """
    cfg = get_config()
    required = set(cfg.dpdp_categories)
    submitted = {
        item["category"].strip().lower(): item["granted"]
        for item in consents
    }

    missing = required - set(submitted.keys())
    if missing:
        raise ConsentRequiredError(
            f"Missing consent categories: {', '.join(sorted(missing))}"
        )

    not_granted = [cat for cat, val in submitted.items() if cat in required and not val]
    if not_granted:
        raise ConsentRequiredError(
            f"All consent categories must be granted. Not granted: "
            f"{', '.join(sorted(not_granted))}"
        )


def get_consents(db: Session, *, user_id: str) -> dict:
    """
    Return the current consent state for all categories.

    Uses DISTINCT ON to get the most recent row per category.
    Categories with no row are returned with granted=False (legacy accounts).

    Returns:
        {
            "success": True,
            "data": [
                {
                    "category": "identity",
                    "granted": True,
                    "notice_version": "1.0.0",
                    "consented_at": "2024-01-15T10:30:00+00:00"
                },
                ...
            ]
        }
    """
    cfg = get_config()

    rows = db.execute(
        text("""
            SELECT DISTINCT ON (consent_category)
                consent_category,
                granted,
                notice_version,
                created_at
            FROM ba_consent_log
            WHERE user_id = :user_id
            ORDER BY consent_category, created_at DESC
        """),
        {"user_id": str(user_id)},
    ).fetchall()

    latest = {
        row._mapping["consent_category"]: {
            "granted": row._mapping["granted"],
            "notice_version": row._mapping["notice_version"],
            "consented_at": _iso(row._mapping["created_at"]),
        }
        for row in rows
    }

    result = []
    for category in cfg.dpdp_categories:
        state = latest.get(category, {})
        result.append({
            "category": category,
            "granted": state.get("granted", False),
            "notice_version": state.get("notice_version", cfg.dpdp_notice_version),
            "consented_at": state.get("consented_at"),
        })

    return {"success": True, "data": result}


def withdraw_consent(
    db: Session,
    *,
    user_id: str,
    category: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    """
    Withdraw consent for a single category.

    Appends a new BAConsentLog row with granted=False.
    The prior granted row is NEVER modified — audit trail is preserved.
    DPDP §6: withdrawal must be as easy as granting.

    Args:
        user_id:   The user's ID.
        category:  The category to withdraw.
    """
    return record_consent(
        db,
        user_id=user_id,
        category=category,
        granted=False,
        ip_address=ip_address,
        user_agent=user_agent,
    )


def export_user_data(db: Session, *, user_id: str) -> dict:
    """
    DPDP Right of Access — export all auth data BharatAuth holds for a user.

    Returns a structured dict containing:
      - sessions (active)
      - consent history (full audit trail)
      - otp tokens (metadata only, no hashes)

    This covers BharatAuth's ba_* tables only. Adopters must extend
    this with their own application data (Person, Address, Posts, etc.).
    """
    from bharatauth.models import BAOTPToken, BASession

    sessions = db.query(BASession).filter(
        BASession.user_id == str(user_id)
    ).order_by(BASession.created_at.desc()).all()

    consent_logs = db.query(BAConsentLog).filter(
        BAConsentLog.user_id == str(user_id)
    ).order_by(BAConsentLog.created_at.asc()).all()

    otp_tokens = db.query(BAOTPToken).filter(
        BAOTPToken.user_id == str(user_id)
    ).order_by(BAOTPToken.created_at.desc()).all()

    return {
        "user_id": str(user_id),
        "exported_at": _now().isoformat(),
        "sessions": [
            {
                "id": s.id,
                "device_info": s.device_info,
                "ip_address": s.ip_address,
                "is_public_device": s.is_public_device,
                "is_verified_device": s.is_verified_device,
                "created_at": _iso(s.created_at),
                "expires_at": _iso(s.expires_at),
                "revoked": s.revoked,
                "revoked_at": _iso(s.revoked_at),
            }
            for s in sessions
        ],
        "consent_history": [
            {
                "category": log.consent_category,
                "granted": log.granted,
                "notice_version": log.notice_version,
                "ip_address": log.ip_address,
                "recorded_at": _iso(log.created_at),
            }
            for log in consent_logs
        ],
        "auth_events": [
            {
                "purpose": t.purpose.value,
                "created_at": _iso(t.created_at),
                "expires_at": _iso(t.expires_at),
                "used_at": _iso(t.used_at),
            }
            for t in otp_tokens
        ],
    }


# Patch: standalone version that works without configure() being called
_STANDALONE_CATEGORIES = [
    "identity", "contact", "location",
    "security", "communications", "analytics",
]


def validate_registration_consent(consents: list[dict]) -> None:  # type: ignore[no-redef]
    """
    Validate that all required DPDP categories are granted.
    Works before configure() is called (uses default categories).
    Raises ConsentRequiredError if any category is missing or ungrated.
    """
    try:
        required = set(get_config().dpdp_categories)
    except RuntimeError:
        required = set(_STANDALONE_CATEGORIES)

    submitted = {item["category"].strip().lower(): item["granted"] for item in consents}

    missing = required - set(submitted.keys())
    if missing:
        raise ConsentRequiredError(
            f"Missing consent categories: {', '.join(sorted(missing))}"
        )
    not_granted = [c for c, v in submitted.items() if c in required and not v]
    if not_granted:
        raise ConsentRequiredError(
            f"Not granted: {', '.join(sorted(not_granted))}"
        )
