"""Key derivation (Argon2id) and authenticated encryption (AES-256-GCM)."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from argon2.exceptions import Argon2Error
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

DEFAULT_KDF = {
    "name": "argon2id",
    "time_cost": 3,
    "memory_cost": 524288,  # KiB = 512 MiB; about 0.5s per guess on a fast desktop
    "parallelism": 4,
}


# Bounds for settings read from a vault file. Without them a tampered file could
# demand, say, 4 TiB of memory or a billion passes and hang or crash the app.
KDF_LIMITS = {
    "time_cost": (1, 20),
    "memory_cost": (8, 2 * 1024 * 1024),  # KiB: up to 2 GiB (8 KiB is Argon2's own floor)
    "parallelism": (1, 16),
}


class DecryptionError(Exception):
    """Raised when the password is wrong or the vault file was tampered with."""


def validate_kdf(kdf: Any) -> dict[str, Any]:
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id":
        raise DecryptionError("vault file has unsupported key settings")
    clean: dict[str, Any] = {"name": "argon2id"}
    for field, (low, high) in KDF_LIMITS.items():
        value = kdf.get(field)
        # bool is a subclass of int; reject it explicitly.
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise DecryptionError("vault file has invalid key settings")
        clean[field] = value
    if clean["memory_cost"] < 8 * clean["parallelism"]:
        raise DecryptionError("vault file has invalid key settings")
    return clean


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def derive_key(password: str, salt: bytes, kdf: dict[str, Any] = DEFAULT_KDF) -> bytes:
    kdf = validate_kdf(kdf)
    try:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=kdf["time_cost"],
            memory_cost=kdf["memory_cost"],
            parallelism=kdf["parallelism"],
            hash_len=KEY_LEN,
            type=Type.ID,
        )
    except Argon2Error as exc:  # e.g. not enough memory
        raise DecryptionError("could not derive the key from this vault's settings") from exc


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def _header(kdf: dict[str, Any], salt: bytes) -> dict[str, Any]:
    return {"version": FORMAT_VERSION, "kdf": dict(kdf), "salt": _b64e(salt)}


def _aad(header: dict[str, Any]) -> bytes:
    # Canonical JSON so the same header always yields the same AAD bytes.
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt(plaintext: bytes, key: bytes, salt: bytes, kdf: dict[str, Any] = DEFAULT_KDF) -> dict[str, Any]:
    """Encrypt and return the full on-disk document (header + nonce + ciphertext)."""
    header = _header(kdf, salt)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(header))
    return {**header, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}


def read_header(doc: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Return (kdf params, salt) from an on-disk document."""
    try:
        if doc["version"] != FORMAT_VERSION:
            raise DecryptionError(f"unsupported vault version: {doc['version']!r}")
        return validate_kdf(doc["kdf"]), _b64d(doc["salt"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DecryptionError("vault file is malformed") from exc


def decrypt(doc: dict[str, Any], key: bytes) -> bytes:
    try:
        header = {"version": doc["version"], "kdf": doc["kdf"], "salt": doc["salt"]}
        nonce = _b64d(doc["nonce"])
        ciphertext = _b64d(doc["ciphertext"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DecryptionError("vault file is malformed") from exc
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _aad(header))
    except InvalidTag as exc:
        raise DecryptionError("wrong password or corrupted vault") from exc
