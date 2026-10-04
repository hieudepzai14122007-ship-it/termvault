"""TOTP (RFC 6238) helpers."""

from __future__ import annotations

import binascii
import time
from urllib.parse import parse_qs, urlparse

import pyotp


def normalize_secret(secret: str) -> str:
    """Accept base32 or a SHA1 / six-digit / 30-second TOTP URI.

    The stored field is a bare seed, so accepting other URI settings would
    silently discard them and produce incorrect codes.
    """
    if not isinstance(secret, str) or len(secret) > 8192:
        raise ValueError("invalid 2FA secret")
    s = secret.strip()
    if s.lower().startswith("otpauth://"):
        uri = urlparse(s)
        if uri.netloc.lower() != "totp" or uri.fragment:
            raise ValueError("only TOTP links are supported")
        params = parse_qs(uri.query, keep_blank_values=True, max_num_fields=32)
        for name in ("secret", "algorithm", "digits", "period"):
            if name in params and len(params[name]) != 1:
                raise ValueError("ambiguous TOTP settings")
        if (params.get("algorithm", ["SHA1"])[0].upper() != "SHA1"
                or params.get("digits", ["6"])[0] != "6"
                or params.get("period", ["30"])[0] != "30"
                or "counter" in params):
            raise ValueError("TOTP requires SHA1, 6 digits and a 30-second period")
        s = params.get("secret", [""])[0]
        if not s:
            raise ValueError("TOTP secret is required")
    return s.replace(" ", "").replace("-", "").upper()


def validate_secret(secret: str) -> bool:
    try:
        s = normalize_secret(secret)
        if not s:
            return False
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
