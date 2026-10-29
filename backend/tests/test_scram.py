"""Tests for the client-side SCRAM-SHA-256 verifier builder."""

import base64
import hashlib
import hmac

import pytest

from app.db.scram import DEFAULT_ITERATIONS, SALT_BYTES, VERIFIER_PATTERN, scram_sha256_verifier


def test_verifier_format() -> None:
    verifier = scram_sha256_verifier("correct-horse-battery-staple")
    match = VERIFIER_PATTERN.fullmatch(verifier)
    assert match is not None
    assert int(match["iterations"]) == DEFAULT_ITERATIONS
    assert len(base64.b64decode(match["salt"])) == SALT_BYTES
    assert len(base64.b64decode(match["stored_key"])) == 32
    assert len(base64.b64decode(match["server_key"])) == 32


def test_verifier_does_not_contain_password() -> None:
    password = "plaintext-must-not-appear-anywhere"
    assert password not in scram_sha256_verifier(password)


def test_random_salt_per_call() -> None:
    assert scram_sha256_verifier("same-password") != scram_sha256_verifier("same-password")


def test_deterministic_with_fixed_salt() -> None:
    salt = bytes(range(16))
    first = scram_sha256_verifier("pencil", salt=salt, iterations=4096)
    assert first == scram_sha256_verifier("pencil", salt=salt, iterations=4096)
    assert first.startswith("SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$")


def test_stored_key_authenticates_client_proof() -> None:
    # Replays the RFC 5802 check the server performs: ClientKey recovered from a proof must
    # hash to StoredKey. This proves the verifier is usable, not just well-formed.
    password, salt, iterations = "pencil", b"0123456789abcdef", 4096
    match = VERIFIER_PATTERN.fullmatch(scram_sha256_verifier(password, salt=salt))
    assert match is not None
    stored_key = base64.b64decode(match["stored_key"])
    server_key = base64.b64decode(match["server_key"])

    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    auth_message = b"n=,r=nonce,r=nonce-server,s=salt,i=4096,c=biws,r=nonce-server"
    client_signature = hmac.new(stored_key, auth_message, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_signature, strict=True))

    recovered = bytes(a ^ b for a, b in zip(proof, client_signature, strict=True))
    assert hmac.compare_digest(hashlib.sha256(recovered).digest(), stored_key)
    expected_server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    assert hmac.compare_digest(server_key, expected_server_key)


@pytest.mark.parametrize("password", ["pässword", "line\nbreak"])
def test_rejects_non_printable_ascii(password: str) -> None:
    with pytest.raises(ValueError, match="printable ASCII"):
        scram_sha256_verifier(password)


def test_rejects_non_positive_iterations() -> None:
    with pytest.raises(ValueError, match="iterations"):
        scram_sha256_verifier("pw", iterations=0)
