# bharatauth/exceptions.py
"""
BharatAuth exception hierarchy.

All exceptions map to HTTP status codes so the FastAPI router
can translate them automatically. Non-FastAPI adopters can catch
BharatAuthError and inspect .status_code directly.
"""


class BharatAuthError(Exception):
    """Base class for all BharatAuth exceptions."""
    status_code: int = 500
    default_message: str = "An authentication error occurred."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


# ── 400 Bad Request ───────────────────────────────────────────────────
class BadRequestError(BharatAuthError):
    status_code = 400
    default_message = "Bad request."


# ── 401 Unauthorized ──────────────────────────────────────────────────
class UnauthorizedError(BharatAuthError):
    """Invalid credentials, expired token, wrong PIN."""
    status_code = 401
    default_message = "Invalid credentials."


class TokenExpiredError(UnauthorizedError):
    default_message = "Token has expired."


class InvalidTokenError(UnauthorizedError):
    default_message = "Invalid token."


# ── 403 Forbidden ─────────────────────────────────────────────────────
class ForbiddenError(BharatAuthError):
    """Account suspended, access denied."""
    status_code = 403
    default_message = "Access denied."


class AccountSuspendedError(ForbiddenError):
    default_message = "Your account has been suspended. Please contact support."


class EmailNotVerifiedError(ForbiddenError):
    default_message = "Email address is not verified."


class ConsentRequiredError(ForbiddenError):
    """All DPDP categories must be granted before registration can complete."""
    default_message = "All consent categories must be granted to proceed."


# ── 404 Not Found ─────────────────────────────────────────────────────
class NotFoundError(BharatAuthError):
    status_code = 404
    default_message = "Resource not found."


# ── 409 Conflict ──────────────────────────────────────────────────────
class ConflictError(BharatAuthError):
    """Duplicate email, username already taken, etc."""
    status_code = 409
    default_message = "A conflict occurred."


# ── 422 Validation ────────────────────────────────────────────────────
class ValidationError(BharatAuthError):
    status_code = 422
    default_message = "Validation failed."


# ── 423 Locked ────────────────────────────────────────────────────────
class AccountLockedError(BharatAuthError):
    """
    Soft lock (7-min cooldown) or hard lock (email verify required).
    Returns 423 for password/OTP endpoints.
    Returns 401 for PIN endpoint — intentional, leaks no lockout signal.
    """
    status_code = 423
    default_message = "Account is temporarily locked. Please try again later."

    def __init__(
        self,
        message: str | None = None,
        locked_until: str | None = None,
        requires_email_verify: bool = False,
    ) -> None:
        super().__init__(message)
        self.locked_until = locked_until
        self.requires_email_verify = requires_email_verify


# ── 429 Rate Limited ─────────────────────────────────────────────────
class RateLimitError(BharatAuthError):
    status_code = 429
    default_message = "Too many requests. Please slow down."


class IPBlockedError(RateLimitError):
    default_message = "This IP address has been temporarily blocked due to suspicious activity."


# ── 500 Internal ─────────────────────────────────────────────────────
class EmailSendError(BharatAuthError):
    status_code = 500
    default_message = "Failed to send email."


class ConfigurationError(BharatAuthError):
    status_code = 500
    default_message = "BharatAuth is misconfigured."
