# bharatauth/security/__init__.py
"""
Security utilities.

  from bharatauth.security import rate_limit, check_ip_blocked
  from bharatauth.security.lockout import record_failure, clear_failures, check_lockout
"""

from bharatauth.security.rate_limit import rate_limit, check_rate_limit
from bharatauth.security.lockout import (
    record_account_failure,
    clear_account_failures,
    check_account_lockout,
    record_ip_failure,
    check_ip_blocked,
)

__all__ = [
    "rate_limit",
    "check_rate_limit",
    "record_account_failure",
    "clear_account_failures",
    "check_account_lockout",
    "record_ip_failure",
    "check_ip_blocked",
]
