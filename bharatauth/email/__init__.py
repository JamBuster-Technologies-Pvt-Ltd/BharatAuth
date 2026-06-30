# bharatauth/email/__init__.py
"""
Email sending for BharatAuth.

Default backend: SMTP (configured via BharatAuthConfig).
Custom backend: pass email_backend= to configure() with any callable
matching the EmailBackend protocol.

  from bharatauth.email import EmailService

  EmailService.send_otp(to="user@example.com", otp_code="483920", display_name="Ravi")
  EmailService.send_verification(to="user@example.com", token_url="https://...")
  EmailService.send_password_reset(to="user@example.com", token_url="https://...")
  EmailService.send_new_device_alert(to="user@example.com", device_info="iPhone / Mumbai")
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Protocol

from bharatauth.config import get_config
from bharatauth.exceptions import EmailSendError

logger = logging.getLogger("bharatauth.email")


class EmailBackend(Protocol):
    """Protocol for custom email backends."""
    def send(self, *, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        ...


class SMTPEmailBackend:
    """Default SMTP backend. Uses BharatAuthConfig settings."""

    def send(
        self,
        *,
        to: str,
        subject: str,
        body_text: str,
        body_html: str | None = None,
    ) -> None:
        cfg = get_config()
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.smtp_from
        msg["To"] = to

        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            msg.attach(MIMEText(body_html, "html", "utf-8"))

        try:
            if cfg.smtp_tls:
                server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port)

            if cfg.smtp_user and cfg.smtp_password:
                server.login(cfg.smtp_user, cfg.smtp_password)

            server.sendmail(cfg.smtp_from, [to], msg.as_string())
            server.quit()
        except Exception as e:
            raise EmailSendError(f"SMTP send failed: {e}") from e


# ── Active backend (swappable) ────────────────────────────────────────
_backend: EmailBackend = SMTPEmailBackend()


def set_email_backend(backend: EmailBackend) -> None:
    """Swap the email backend. Call after configure()."""
    global _backend
    _backend = backend


class EmailService:
    """High-level email operations for BharatAuth flows."""

    @staticmethod
    def send_otp(*, to: str, otp_code: str, display_name: str = "") -> None:
        name = display_name or "there"
        try:
            _backend.send(
                to=to,
                subject="Your sign-in code",
                body_text=(
                    f"Hi {name},\n\n"
                    f"Your sign-in code is: {otp_code}\n\n"
                    "This code expires in 10 minutes.\n"
                    "If you didn't request this, ignore this email.\n\n"
                    "— BharatAuth"
                ),
            )
        except EmailSendError:
            # OTP email failure is non-fatal — log and continue.
            # The enumeration-safe response is returned regardless.
            logger.warning(f"BharatAuth: OTP email failed for {to}")

    @staticmethod
    def send_verification(*, to: str, token_url: str, display_name: str = "") -> None:
        name = display_name or "there"
        _backend.send(
            to=to,
            subject="Verify your email address",
            body_text=(
                f"Hi {name},\n\n"
                "Please verify your email address by clicking the link below:\n"
                f"{token_url}\n\n"
                "This link expires in 24 hours.\n\n"
                "— BharatAuth"
            ),
        )

    @staticmethod
    def send_password_reset(*, to: str, token_url: str, display_name: str = "") -> None:
        name = display_name or "there"
        _backend.send(
            to=to,
            subject="Reset your password",
            body_text=(
                f"Hi {name},\n\n"
                "We received a request to reset your password.\n"
                f"Click the link below to proceed:\n{token_url}\n\n"
                "This link expires in 60 minutes.\n"
                "If you didn't request this, ignore this email — "
                "your password has not been changed.\n\n"
                "— BharatAuth"
            ),
        )

    @staticmethod
    def send_new_device_alert(*, to: str, device_info: str = "", display_name: str = "") -> None:
        name = display_name or "there"
        device = device_info or "an unrecognised device"
        try:
            _backend.send(
                to=to,
                subject="New sign-in detected",
                body_text=(
                    f"Hi {name},\n\n"
                    f"A new sign-in was detected from: {device}\n\n"
                    "If this was you, no action is needed.\n"
                    "If this wasn't you, please secure your account immediately.\n\n"
                    "— BharatAuth"
                ),
            )
        except EmailSendError:
            logger.warning(f"BharatAuth: New device alert email failed for {to}")

    @staticmethod
    def send_pin_reset(*, to: str, token_url: str, display_name: str = "") -> None:
        name = display_name or "there"
        _backend.send(
            to=to,
            subject="Reset your PIN",
            body_text=(
                f"Hi {name},\n\n"
                "We received a request to reset your app PIN.\n"
                f"Click the link below to proceed:\n{token_url}\n\n"
                "This link expires in 30 minutes.\n\n"
                "— BharatAuth"
            ),
        )
