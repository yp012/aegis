"""Application settings loaded exclusively from environment variables."""

import ipaddress
from functools import lru_cache
from typing import Literal, Self
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_MIN_SECRET_LENGTH = 32
_PLACEHOLDER_PREFIX = "CHANGE_ME"


_SETTINGS_CONFIG = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    case_sensitive=False,
    extra="ignore",
    # Compose passes optional variables as `${VAR:-}`; treat empty as unset so defaults apply.
    env_ignore_empty=True,
    # Never echo (possibly real) secret values into startup logs on validation failure.
    hide_input_in_errors=True,
)


def _check_secret(raw: str) -> None:
    if raw.startswith(_PLACEHOLDER_PREFIX):
        raise ValueError("still set to the .env.example placeholder; generate a real secret")
    if len(raw) < _MIN_SECRET_LENGTH:
        raise ValueError(f"must be at least {_MIN_SECRET_LENGTH} characters")


class Settings(BaseSettings):
    """Runtime settings for the API process."""

    model_config = _SETTINGS_CONFIG

    app_name: str = "Aegis"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    cors_origins: str = Field(
        default="http://localhost:5173",
        description="Comma-separated list of allowed CORS origins.",
    )
    trusted_proxies: str = Field(
        default="",
        description=(
            "Comma-separated IPs/CIDRs of reverse proxies whose X-Forwarded-For is trusted. "
            "Empty means the TCP peer address is always used."
        ),
    )

    # The API connects as the restricted `aegis_app` role, never as the schema owner.
    app_database_url: str
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
    rate_limit_default_requests: int = Field(default=120, ge=1)
    rate_limit_default_window_seconds: int = Field(default=60, ge=1)
    rate_limit_login_requests: int = Field(default=5, ge=1)
    rate_limit_login_window_seconds: int = Field(default=60, ge=1)

    @field_validator("jwt_secret", "badge_hmac_secret", "mfa_encryption_key")
    @classmethod
    def _secret_min_length(cls, value: SecretStr) -> SecretStr:
        _check_secret(value.get_secret_value())
        return value

    @field_validator("mfa_encryption_key")
    @classmethod
    def _valid_fernet_key(cls, value: SecretStr) -> SecretStr:
        try:
            Fernet(value.get_secret_value())
        except (ValueError, TypeError) as exc:
            raise ValueError("must be a valid Fernet key (32 url-safe base64 bytes)") from exc
        return value

    @field_validator("cors_origins")
    @classmethod
    def _strict_cors_origins(cls, value: str) -> str:
        for origin in (o.strip() for o in value.split(",")):
            if not origin:
                continue
            parts = urlsplit(origin)
            # Credentialed CORS with a wildcard or a path/query would be ambiguous or unsafe.
            if (
                parts.scheme not in {"http", "https"}
                or not parts.netloc
                or "*" in origin
                or parts.path
                or parts.query
                or parts.fragment
            ):
                raise ValueError(f"invalid CORS origin {origin!r}; use scheme://host[:port]")
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_trusted_proxies(cls, value: str) -> str:
        _parse_networks(value)
        return value

    @model_validator(mode="after")
    def _production_hardening(self) -> Self:
        if self.environment == "production" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def trusted_proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return _parse_networks(self.trusted_proxies)


def _parse_networks(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        return [ipaddress.ip_network(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as exc:
        raise ValueError("TRUSTED_PROXIES must be comma-separated IP addresses or CIDRs") from exc


class MigrationSettings(BaseSettings):
    """Settings for Alembic only. Kept separate so the API never needs owner credentials."""

    model_config = _SETTINGS_CONFIG

    # Schema-owner connection used to run DDL.
    database_url: str
    # Password the migrations assign to the restricted `aegis_app` login role.
    app_db_password: SecretStr

    @field_validator("app_db_password")
    @classmethod
    def _password_strength(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        _check_secret(raw)
        # SCRAM normalises non-ASCII passwords with SASLprep; restricting to printable ASCII
        # keeps the verifier computed in app/db/scram.py identical to the server's.
        if not (raw.isascii() and raw.isprintable()):
            raise ValueError("must contain printable ASCII characters only")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_migration_settings() -> MigrationSettings:
    return MigrationSettings()
