"""Application settings loaded exclusively from environment variables."""

from functools import lru_cache
from typing import Literal, Self

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_MIN_SECRET_LENGTH = 32
_PLACEHOLDER_PREFIX = "CHANGE_ME"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # Never echo (possibly real) secret values into startup logs on validation failure.
        hide_input_in_errors=True,
    )

    app_name: str = "Aegis"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    cors_origins: str = Field(
        default="http://localhost:5173",
        description="Comma-separated list of allowed CORS origins.",
    )

    database_url: str
    redis_url: str

    jwt_secret: SecretStr
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_minutes: int = Field(default=10, ge=1, le=60)
    refresh_token_days: int = Field(default=7, ge=1, le=30)
    cookie_secure: bool = True

    badge_hmac_secret: SecretStr
    badge_ttl_minutes: int = Field(default=480, ge=1, le=60 * 24)

    mfa_encryption_key: SecretStr = Field(
        description="URL-safe base64 Fernet key used to encrypt TOTP secrets at rest.",
    )

    rate_limit_enabled: bool = True
    rate_limit_default_requests: int = Field(default=100, ge=1)
    rate_limit_default_window_seconds: int = Field(default=60, ge=1)
    rate_limit_login_requests: int = Field(default=5, ge=1)
    rate_limit_login_window_seconds: int = Field(default=60, ge=1)

    @field_validator("jwt_secret", "badge_hmac_secret", "mfa_encryption_key")
    @classmethod
    def _secret_min_length(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw.startswith(_PLACEHOLDER_PREFIX):
            raise ValueError("still set to the .env.example placeholder; generate a real secret")
        if len(raw) < _MIN_SECRET_LENGTH:
            raise ValueError(f"must be at least {_MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("mfa_encryption_key")
    @classmethod
    def _valid_fernet_key(cls, value: SecretStr) -> SecretStr:
        try:
            Fernet(value.get_secret_value())
        except (ValueError, TypeError) as exc:
            raise ValueError("must be a valid Fernet key (32 url-safe base64 bytes)") from exc
        return value

    @model_validator(mode="after")
    def _production_hardening(self) -> Self:
        if self.environment == "production" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
