"""TOTP (RFC 6238) helpers."""

from __future__ import annotations

import binascii
import time
from urllib.parse import parse_qs, urlparse

import pyotp


def normalize_secret(secret: str) -> str:
    """Accept a base32 secret (spaces/lowercase ok) or an otpauth:// URI."""
    s = secret.strip()
    if s.lower().startswith("otpauth://"):
        params = parse_qs(urlparse(s).query)
        s = params.get("secret", [""])[0]
    return s.replace(" ", "").replace("-", "").upper()


def validate_secret(secret: str) -> bool:
    s = normalize_secret(secret)
    if not s:
        return False
    try:
        pyotp.TOTP(s).now()
    except (binascii.Error, ValueError):
        return False
    return True


def current_code(secret: str, at: float | None = None) -> tuple[str, int]:
    """Return (6-digit code, seconds until it changes)."""
    totp = pyotp.TOTP(normalize_secret(secret))
    now = time.time() if at is None else at
    remaining = totp.interval - int(now) % totp.interval
    return totp.at(now), remaining
