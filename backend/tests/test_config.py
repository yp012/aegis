"""Fail-fast validation of security-relevant settings."""

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.core.config import Settings


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
