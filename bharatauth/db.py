# bharatauth/db.py
"""
Database engine and session management for BharatAuth.

In managed mode:  BharatAuth creates its own engine from database_url.
In external mode: adopter can pass db_session_factory directly.

Either way, get_db() is the single entrypoint used by all services.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Generator, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ── ORM base (all ba_ models inherit from this) ───────────────────────
class BharatAuthBase(DeclarativeBase):
    pass


# ── Internal state ────────────────────────────────────────────────────
_SessionLocal: Optional[sessionmaker] = None  # type: ignore[type-arg]
_external_factory: Optional[Callable[[], Any]] = None


def init_db(config: Any) -> None:
    """
    Called by configure(). Sets up the session factory.
    In managed mode: creates engine from database_url, creates ba_ tables.
    In external mode: stores the adopter's session factory.
    """
    global _SessionLocal, _external_factory

    if config.db_session_factory is not None:
        # External factory supplied directly — use it as-is.
        _external_factory = config.db_session_factory
        return

    engine = create_engine(
        config.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )

    _SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    if config.mode == "managed":
        # Create ba_ tables if they don't exist.
        # In production: run `alembic upgrade head` instead.
        from bharatauth.models import register_models  # noqa: F401 — ensures models are imported
        BharatAuthBase.metadata.create_all(engine)


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """
    Context manager that yields a SQLAlchemy Session.

    Usage in services:
        with get_db() as db:
            result = db.query(...)

    Usage as FastAPI dependency (via get_db_dep):
        db: Session = Depends(get_db_dep)
    """
    if _external_factory is not None:
        # External mode: delegate lifecycle to adopter's factory.
        session = _external_factory()
        try:
            yield session
        finally:
            # Don't close — adopter manages lifecycle.
            pass
        return

    if _SessionLocal is None:
        raise RuntimeError(
            "BharatAuth DB not initialised. Did you call bharatauth.configure()?"
        )

    session: Session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_dep() -> Generator[Session, None, None]:
    """
    FastAPI dependency version of get_db (uses yield, not context manager).
    Use this with Depends() in route definitions.
    """
    if _external_factory is not None:
        session = _external_factory()
        try:
            yield session
        finally:
            pass
        return

    if _SessionLocal is None:
        raise RuntimeError(
            "BharatAuth DB not initialised. Did you call bharatauth.configure()?"
        )

    session: Session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
