"""Tests for proxy-compatible token encryption."""

import configparser
import os
import sys
from base64 import b64decode, urlsafe_b64encode

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from custom_components.oauth_mail.config_flow import Cryptographer


def test_cryptographer_round_trip_uses_proxy_compatible_settings() -> None:
    """Encrypt and decrypt values using stored salt and iterations."""
    account_name = "user@example.com"
    password = "proxy-password"
    config = configparser.ConfigParser(interpolation=None)
    config.add_section(account_name)

    cryptographer = Cryptographer(config, account_name, password)
    encrypted_access_token = cryptographer.encrypt("access-token")
    encrypted_refresh_token = cryptographer.encrypt("refresh-token")

    assert encrypted_access_token != "access-token"
    assert encrypted_refresh_token != "refresh-token"
    assert len(b64decode(cryptographer.salt.encode("utf-8"))) == 16
    assert cryptographer.iterations == Cryptographer.ITERATIONS

    config.set(account_name, "token_salt", cryptographer.salt)
    config.set(account_name, "token_iterations", str(cryptographer.iterations))

    reloaded = Cryptographer(config, account_name, password)

    assert reloaded.decrypt(encrypted_access_token) == "access-token"
    assert reloaded.decrypt(encrypted_refresh_token) == "refresh-token"


def test_cryptographer_rotates_legacy_iterations() -> None:
    """Values encrypted with legacy iterations are marked for rotation."""
    account_name = "user@example.com"
    password = "proxy-password"
    config = configparser.ConfigParser(interpolation=None)
    config.add_section(account_name)
    config.set(account_name, "token_iterations", str(Cryptographer.LEGACY_ITERATIONS))

    cryptographer = Cryptographer(config, account_name, password)
    config.set(account_name, "token_salt", cryptographer.salt)

    legacy_salt = b64decode(cryptographer.salt.encode("utf-8"))
    legacy_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=legacy_salt,
        iterations=Cryptographer.LEGACY_ITERATIONS,
        backend=default_backend(),
    ).derive(password.encode("utf-8"))
    encrypted_value = Fernet(urlsafe_b64encode(legacy_key)).encrypt(b"legacy-token").decode("utf-8")

    current_cryptographer = Cryptographer(config, account_name, password)

    assert current_cryptographer.requires_rotation(encrypted_value) is True
    rotated_value = current_cryptographer.rotate(encrypted_value)
    assert current_cryptographer.decrypt(rotated_value) == "legacy-token"