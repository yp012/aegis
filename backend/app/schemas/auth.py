"""Pydantic schemas: auth."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.models.enums import Clearance, Role
from app.schemas.user import ClearanceLabel

# Upper bound keeps a single Argon2 call from being fed megabytes of input.
Password = Annotated[str, Field(min_length=12, max_length=128)]
TotpCode = Annotated[str, Field(pattern=r"^[0-9]{6}$")]
FullName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(_Request):
    email: EmailStr
    full_name: FullName
    password: Password
    role: Role = Role.Personnel
    clearance: ClearanceLabel = Clearance.Reliability


class LoginRequest(_Request):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]


class MfaLoginRequest(_Request):
    mfa_token: Annotated[str, Field(min_length=1, max_length=4096)]
    code: TotpCode


class MfaCodeRequest(_Request):
    code: TotpCode


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int


class MfaChallengeResponse(BaseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int


class MfaSetupResponse(BaseModel):
    otpauth_uri: str
    qr_code_png_base64: str


class MfaStatusResponse(BaseModel):
    mfa_enabled: bool
