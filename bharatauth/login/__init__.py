# bharatauth/login/__init__.py
"""
Password-based login, session refresh, and logout.

  from bharatauth.login import login, refresh, logout, logout_all

All functions accept a SQLAlchemy Session as first arg.
"""

from bharatauth.login.service import (
    login,
    refresh_session,
    logout,
    logout_all,
    list_sessions,
    get_current_user_id,
)

__all__ = [
    "login",
    "refresh_session",
    "logout",
    "logout_all",
    "list_sessions",
    "get_current_user_id",
]
