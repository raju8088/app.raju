"""Authenticated encryption for workspace API credentials.

The deployment encryption key is deliberately independent of Django SECRET_KEY.
Losing it makes stored upstream credentials unreadable; keep it in the secret
manager and include its recovery procedure in the deployment runbook.
"""

import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.core.exceptions import ImproperlyConfigured


def _cipher() -> MultiFernet:
    value = os.environ.get("OMNIDIM_ENCRYPTION_KEY", "")
    if not value:
        raise ImproperlyConfigured("OMNIDIM_ENCRYPTION_KEY must be configured to store or read API credentials.")
    try:
        previous = [key.strip() for key in os.environ.get("OMNIDIM_ENCRYPTION_PREVIOUS_KEYS", "").split(",") if key.strip()]
        return MultiFernet([Fernet(key.encode("ascii")) for key in [value, *previous]])
    except (ValueError, UnicodeError) as exc:
        raise ImproperlyConfigured("The encryption key and any previous keys must be valid Fernet keys.") from exc


def encrypt_api_key(plaintext: str) -> str:
    if not isinstance(plaintext, str):
        raise TypeError("API credentials must be text.")
    cipher = _cipher()
    if not plaintext:
        return ""
    return cipher.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_api_key(ciphertext: str) -> str:
    cipher = _cipher()
    if not ciphertext:
        return ""
    try:
        return cipher.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise ImproperlyConfigured("The workspace API credential cannot be decrypted with the configured key.") from exc


def rotate_api_key(ciphertext: str) -> str:
    """Re-encrypt a credential with the primary key, retaining its original age."""
    cipher = _cipher()
    if not ciphertext:
        return ""
    try:
        return cipher.rotate(ciphertext.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise ImproperlyConfigured("The workspace API credential cannot be rotated with the configured keys.") from exc
