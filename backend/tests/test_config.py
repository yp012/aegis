"""Fail-fast validation of security-relevant settings."""

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.core.config import MigrationSettings, Settings, get_migration_settings


def test_defaults_match_policy() -> None:
    settings = Settings()
    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_minutes == 10
    assert settings.refresh_token_days == 7
    assert settings.cookie_secure is True
    assert settings.rate_limit_enabled is True


@pytest.mark.parametrize("var", ["JWT_SECRET", "BADGE_HMAC_SECRET", "MFA_ENCRYPTION_KEY"])
def test_short_secrets_rejected(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.setenv(var, "x" * 31)
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings()


@pytest.mark.parametrize("var", ["JWT_SECRET", "BADGE_HMAC_SECRET", "MFA_ENCRYPTION_KEY"])
def test_missing_secrets_rejected(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize("var", ["JWT_SECRET", "BADGE_HMAC_SECRET", "MFA_ENCRYPTION_KEY"])
def test_env_example_placeholders_rejected(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    # The .env.example placeholders are long enough to pass the length check on their own.
    monkeypatch.setenv(var, "CHANGE_ME_at_least_32_characters_long_random_value")
    with pytest.raises(ValidationError, match="placeholder"):
        Settings()


def test_invalid_fernet_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", "not-a-fernet-key-but-long-enough-to-pass-length")
    with pytest.raises(ValidationError, match="valid Fernet key"):
        Settings()


def test_generated_fernet_key_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", key)
    assert Settings().mfa_encryption_key.get_secret_value() == key


def test_secrets_not_exposed_in_repr() -> None:
    settings = Settings()
    rendered = repr(settings)
    assert settings.jwt_secret.get_secret_value() not in rendered
    assert settings.mfa_encryption_key.get_secret_value() not in rendered


def test_insecure_cookies_rejected_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings()


def test_insecure_cookies_allowed_in_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    assert Settings().cookie_secure is False


def test_validation_errors_do_not_echo_secret_input(monkeypatch: pytest.MonkeyPatch) -> None:
    leaked = "real-looking-but-invalid-fernet-material-0123456789"
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", leaked)
    with pytest.raises(ValidationError) as excinfo:
        Settings()
    assert leaked[:12] not in str(excinfo.value)


def test_api_settings_use_restricted_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+psycopg://aegis_app:pw@db:5432/aegis")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://owner:pw@db:5432/aegis")
    settings = Settings()
    assert settings.app_database_url.startswith("postgresql+psycopg://aegis_app:")
    assert not hasattr(settings, "database_url")


def test_api_settings_require_app_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_DATABASE_URL", raising=False)
    with pytest.raises(ValidationError, match="app_database_url"):
        Settings(_env_file=None)


def test_api_settings_do_not_need_owner_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("APP_DB_PASSWORD", raising=False)
    assert Settings(_env_file=None).app_database_url


def test_empty_optional_env_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # docker-compose passes unset optional variables as empty strings.
    monkeypatch.setenv("ACCESS_TOKEN_MINUTES", "")
    monkeypatch.setenv("ENVIRONMENT", "")
    settings = Settings()
    assert settings.access_token_minutes == 10
    assert settings.environment == "development"


def test_migration_settings_load(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_DB_PASSWORD", "m" * 40)
    settings = MigrationSettings()
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.app_db_password.get_secret_value() == "m" * 40
    assert "m" * 40 not in repr(settings)


def test_migration_settings_do_not_need_api_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("JWT_SECRET", "BADGE_HMAC_SECRET", "MFA_ENCRYPTION_KEY", "APP_DATABASE_URL"):
        monkeypatch.delenv(var, raising=False)
    assert MigrationSettings(_env_file=None).database_url


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("x" * 31, "at least 32 characters"),
        ("CHANGE_ME_app_db_password_but_long_enough", "placeholder"),
        ("é" * 40, "printable ASCII"),
        ("tab\there-and-long-enough-to-pass-the-length", "printable ASCII"),
    ],
)
def test_weak_app_db_password_rejected(
    monkeypatch: pytest.MonkeyPatch, value: str, message: str
) -> None:
    monkeypatch.setenv("APP_DB_PASSWORD", value)
    with pytest.raises(ValidationError, match=message):
        MigrationSettings()


def test_missing_app_db_password_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_DB_PASSWORD", raising=False)
    with pytest.raises(ValidationError, match="app_db_password"):
        MigrationSettings(_env_file=None)


def test_migration_settings_cached() -> None:
    assert get_migration_settings() is get_migration_settings()
