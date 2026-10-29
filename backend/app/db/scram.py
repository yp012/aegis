"""Client-side SCRAM-SHA-256 password verifiers for PostgreSQL roles.

Passing a pre-computed verifier to ``CREATE/ALTER ROLE ... PASSWORD`` means the plaintext
password never reaches the server, so it cannot leak through ``log_statement``,
``pg_stat_activity`` or error messages. Format and derivation follow RFC 5802 / RFC 7677
and match PostgreSQL's ``scram_build_secret``.
"""

import base64
import hashlib
import hmac
import re
import secrets

DEFAULT_ITERATIONS = 4096
SALT_BYTES = 16

VERIFIER_PATTERN = re.compile(
    r"^SCRAM-SHA-256\$(?P<iterations>[1-9][0-9]*):(?P<salt>[A-Za-z0-9+/=]+)"
    r"\$(?P<stored_key>[A-Za-z0-9+/=]+):(?P<server_key>[A-Za-z0-9+/=]+)$"
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def scram_sha256_verifier(
    password: str,
    *,
    salt: bytes | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> str:
    """Return a ``SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>`` verifier string."""
    if not (password.isascii() and password.isprintable()):
        # Non-ASCII input would need SASLprep to match the server's normalisation.
        raise ValueError("password must contain printable ASCII characters only")
    if iterations < 1:
        raise ValueError("iterations must be positive")
    salt = secrets.token_bytes(SALT_BYTES) if salt is None else salt

    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    return f"SCRAM-SHA-256${iterations}:{_b64(salt)}${_b64(stored_key)}:{_b64(server_key)}"
