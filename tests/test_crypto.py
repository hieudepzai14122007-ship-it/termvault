import pytest

from termvault import crypto
from conftest import FAST_KDF


def _setup():
    salt = crypto.new_salt()
    key = crypto.derive_key("pw-pw-pw-pw-pw", salt, FAST_KDF)
    return salt, key


def test_round_trip():
    salt, key = _setup()
    doc = crypto.encrypt(b"secret data", key, salt, FAST_KDF)
    assert crypto.decrypt(doc, key) == b"secret data"


def test_fresh_nonce_each_time():
    salt, key = _setup()
    a = crypto.encrypt(b"x", key, salt, FAST_KDF)
    b = crypto.encrypt(b"x", key, salt, FAST_KDF)
    assert a["nonce"] != b["nonce"]
    assert a["ciphertext"] != b["ciphertext"]


def test_wrong_key_fails():
    salt, key = _setup()
    doc = crypto.encrypt(b"secret", key, salt, FAST_KDF)
    wrong = crypto.derive_key("not-the-password", salt, FAST_KDF)
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(doc, wrong)


def test_ciphertext_tamper_detected():
    import base64
    salt, key = _setup()
    doc = crypto.encrypt(b"secret", key, salt, FAST_KDF)
    raw = bytearray(base64.b64decode(doc["ciphertext"]))
    raw[0] ^= 0x01
    doc["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(doc, key)


def test_header_tamper_detected():
    salt, key = _setup()
    doc = crypto.encrypt(b"secret", key, salt, FAST_KDF)
    doc["kdf"] = {**doc["kdf"], "time_cost": 99}
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(doc, key)


def test_malformed_doc():
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt({"version": 1}, b"\0" * 32)
