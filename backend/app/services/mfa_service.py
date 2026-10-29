"""TOTP multi-factor authentication enrollment and verification.

TOTP secrets are stored Fernet-encrypted (``MFA_ENCRYPTION_KEY``), so a database dump alone
does not reveal them. Codes are accepted from the previous, current and next 30-second step
(``valid_window=1``), and each accepted (user, code) pair is remembered in Redis for 90
seconds, which covers that whole acceptance window, so a sniffed code cannot be replayed.
"""

import base64
import io
import logging
import re
from dataclasses import dataclass

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.redis import key
from app.models.user import User

logger = logging.getLogger(__name__)

TOTP_VALID_WINDOW = 1
TOTP_REPLAY_TTL_SECONDS = 90
_CODE_PATTERN = re.compile(r"^[0-9]{6}$")


class MfaStateError(Exception):
    """MFA enrollment requested in a state that does not allow it."""


@dataclass(frozen=True, slots=True)
class MfaSetup:
    otpauth_uri: str
    qr_code_png_base64: str


def _fernet() -> Fernet:
    return Fernet(get_settings().mfa_encryption_key.get_secret_value())


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def _qr_png_base64(data: str) -> str:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    buffer = io.BytesIO()
    qr.make_image().save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def begin_setup(db: Session, user: User) -> MfaSetup:
    """Generate and store a new (not yet enabled) secret. Re-running replaces it."""
    if user.mfa_enabled:
        raise MfaStateError("MFA is already enabled")
    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=get_settings().app_name)
    return MfaSetup(otpauth_uri=uri, qr_code_png_base64=_qr_png_base64(uri))


def confirm_setup(db: Session, redis: Redis, user: User, code: str) -> bool:
    """Enable MFA if ``code`` is valid for the pending secret. Returns False otherwise."""
    if user.mfa_enabled:
        raise MfaStateError("MFA is already enabled")
    if user.mfa_secret_encrypted is None:
        raise MfaStateError("MFA setup has not been started")
    if not verify_totp(redis, user, code):
        return False
    user.mfa_enabled = True
    db.commit()
    return True


def verify_totp(redis: Redis, user: User, code: str) -> bool:
    """Check a TOTP code against the user's secret and reject replays of accepted codes."""
    if user.mfa_secret_encrypted is None or not _CODE_PATTERN.fullmatch(code):
        return False
    try:
        secret = decrypt_secret(user.mfa_secret_encrypted)
    except InvalidToken:
        logger.error("stored MFA secret for user %s cannot be decrypted", user.id)
        return False
    # pyotp compares with hmac.compare_digest internally.
    if not pyotp.TOTP(secret).verify(code, valid_window=TOTP_VALID_WINDOW):
        return False
    # SET NX is atomic: of two concurrent requests with the same code, only one succeeds.
    first_use = redis.set(
        key("totp-used", str(user.id), code), "1", nx=True, ex=TOTP_REPLAY_TTL_SECONDS
    )
    return bool(first_use)
