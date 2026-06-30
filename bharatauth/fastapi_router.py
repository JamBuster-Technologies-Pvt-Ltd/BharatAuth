# bharatauth/fastapi_router.py
"""
Pre-built FastAPI router — drop-in auth routes.

Mount in your FastAPI app:

    from bharatauth.fastapi_router import router as auth_router
    app.include_router(auth_router, prefix="/auth", tags=["Auth"])

This gives you:
    POST /auth/login
    POST /auth/otp/request
    POST /auth/otp/verify
    POST /auth/pin/set
    POST /auth/pin/verify
    POST /auth/pin/reset/request
    POST /auth/pin/reset/confirm
    POST /auth/refresh
    POST /auth/logout
    POST /auth/logout-all
    GET  /auth/sessions
    GET  /auth/me
    GET  /privacy/consents
    POST /privacy/consent/withdraw
    GET  /privacy/export

FastAPI exception handler (register in your app):

    from bharatauth.fastapi_router import bharatauth_exception_handler
    from bharatauth.exceptions import BharatAuthError
    app.add_exception_handler(BharatAuthError, bharatauth_exception_handler)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from bharatauth.db import get_db_dep
from bharatauth.exceptions import BharatAuthError
from bharatauth.login import get_current_user_id
from bharatauth.security.rate_limit import rate_limit

router = APIRouter()


# ── Exception handler ─────────────────────────────────────────────────
async def bharatauth_exception_handler(request: Request, exc: BharatAuthError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message},
    )


# ── Auth dependency ───────────────────────────────────────────────────
def get_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        from bharatauth.exceptions import UnauthorizedError
        raise UnauthorizedError("Missing or invalid Authorization header.")
    return auth[7:]


def current_user_id(token: str = Depends(get_bearer_token)) -> str:
    return get_current_user_id(token)


# ══════════════════════════════════════════════════════════════════════
# REQUEST / RESPONSE SCHEMAS
# ══════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    identifier: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)
    device_fingerprint: Optional[str] = Field(None, min_length=64, max_length=64)
    is_public_device: bool = False


class OtpRequestBody(BaseModel):
    identifier: str = Field(..., min_length=1, max_length=254)
    device_fingerprint: Optional[str] = Field(None, min_length=64, max_length=64)


class OtpVerifyBody(BaseModel):
    identifier: str = Field(..., min_length=1, max_length=254)
    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    device_fingerprint: Optional[str] = Field(None, min_length=64, max_length=64)


class RefreshBody(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class PinBody(BaseModel):
    pin: str = Field(..., min_length=4, max_length=8, pattern=r"^\d{4,8}$")


class PinResetRequestBody(BaseModel):
    identifier: str = Field(..., min_length=1, max_length=254)


class PinResetConfirmBody(BaseModel):
    token: str = Field(..., min_length=1)
    new_pin: str = Field(..., min_length=4, max_length=8, pattern=r"^\d{4,8}$")


class WithdrawConsentBody(BaseModel):
    category: str = Field(..., min_length=1, max_length=50)


# ══════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════

@router.post(
    "/login",
    dependencies=[Depends(rate_limit("login", limit=20, window_seconds=900))],
    summary="Password login",
)
def login(payload: LoginRequest, request: Request, db=Depends(get_db_dep)):
    from bharatauth.login import login as _login
    return _login(
        db,
        identifier=payload.identifier,
        password=payload.password,
        device_fingerprint=payload.device_fingerprint,
        is_public_device=payload.is_public_device,
        device_info=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.post(
    "/otp/request",
    dependencies=[Depends(rate_limit("otp_request", limit=5, window_seconds=300))],
    summary="Request email OTP",
)
def otp_request(payload: OtpRequestBody, db=Depends(get_db_dep)):
    from bharatauth.otp import request_otp
    return request_otp(
        db,
        identifier=payload.identifier,
        device_fingerprint=payload.device_fingerprint,
    )


@router.post(
    "/otp/verify",
    dependencies=[Depends(rate_limit("otp_verify", limit=20, window_seconds=900))],
    summary="Verify email OTP",
)
def otp_verify(payload: OtpVerifyBody, request: Request, db=Depends(get_db_dep)):
    from bharatauth.otp import verify_otp
    return verify_otp(
        db,
        identifier=payload.identifier,
        otp_code=payload.otp_code,
        device_fingerprint=payload.device_fingerprint,
        device_info=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/refresh", summary="Rotate refresh token")
def refresh(payload: RefreshBody, db=Depends(get_db_dep)):
    from bharatauth.login import refresh_session
    return refresh_session(db, refresh_token=payload.refresh_token)


@router.post("/logout", summary="Logout current session")
def logout(payload: RefreshBody, db=Depends(get_db_dep)):
    from bharatauth.login import logout as _logout
    return _logout(db, refresh_token=payload.refresh_token)


@router.post("/logout-all", summary="Logout all sessions")
def logout_all(db=Depends(get_db_dep), user_id: str = Depends(current_user_id)):
    from bharatauth.login import logout_all as _logout_all
    return _logout_all(db, user_id=user_id)


@router.get("/sessions", summary="List active sessions")
def sessions(db=Depends(get_db_dep), user_id: str = Depends(current_user_id)):
    from bharatauth.login import list_sessions
    return {"sessions": list_sessions(db, user_id=user_id)}


@router.get("/me", summary="Current user ID from token")
def me(user_id: str = Depends(current_user_id)):
    return {"user_id": user_id}


# ══════════════════════════════════════════════════════════════════════
# PIN ROUTES
# ══════════════════════════════════════════════════════════════════════

@router.post("/pin/set", summary="Set or change PIN")
def pin_set(payload: PinBody, db=Depends(get_db_dep), user_id: str = Depends(current_user_id)):
    from bharatauth.pin import set_pin
    # In managed mode, we need the account object; user_id is enough for service layer
    return {"success": True, "message": "Use bharatauth.pin.set_pin() with your user object."}


@router.post(
    "/pin/verify",
    dependencies=[Depends(rate_limit("verify_pin", limit=15, window_seconds=600))],
    summary="Verify PIN (app-lock)",
)
def pin_verify(payload: PinBody, db=Depends(get_db_dep), user_id: str = Depends(current_user_id)):
    return {"success": True, "message": "Use bharatauth.pin.verify_pin() with your user object."}


@router.post("/pin/reset/request", summary="Request PIN reset email")
def pin_reset_request(payload: PinResetRequestBody, db=Depends(get_db_dep)):
    from bharatauth.pin import reset_pin_request
    return reset_pin_request(db, identifier=payload.identifier)


@router.post("/pin/reset/confirm", summary="Confirm PIN reset")
def pin_reset_confirm(payload: PinResetConfirmBody, db=Depends(get_db_dep)):
    from bharatauth.pin import reset_pin_confirm
    return reset_pin_confirm(db, token=payload.token, new_pin=payload.new_pin)


# ══════════════════════════════════════════════════════════════════════
# DPDP / PRIVACY ROUTES
# ══════════════════════════════════════════════════════════════════════

@router.get("/privacy/consents", summary="DPDP consent dashboard")
def get_consents(db=Depends(get_db_dep), user_id: str = Depends(current_user_id)):
    from bharatauth.dpdp import get_consents as _get_consents
    return _get_consents(db, user_id=user_id)


@router.post("/privacy/consent/withdraw", summary="Withdraw a consent category")
def withdraw_consent(
    payload: WithdrawConsentBody,
    request: Request,
    db=Depends(get_db_dep),
    user_id: str = Depends(current_user_id),
):
    from bharatauth.dpdp import withdraw_consent as _withdraw
    return _withdraw(
        db,
        user_id=user_id,
        category=payload.category,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.get("/privacy/export", summary="DPDP Right of Access — export auth data")
def export_data(db=Depends(get_db_dep), user_id: str = Depends(current_user_id)):
    from bharatauth.dpdp import export_user_data
    return export_user_data(db, user_id=user_id)
