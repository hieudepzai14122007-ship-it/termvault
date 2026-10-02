import pytest

from termvault import totp

# RFC 6238 Appendix B, SHA-1 seed "12345678901234567890" (base32 below), last 6 digits.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.mark.parametrize("t,code", [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
])
def test_rfc6238_vectors(t, code):
    assert totp.current_code(RFC_SECRET, at=t)[0] == code


def test_seconds_left():
    assert totp.current_code(RFC_SECRET, at=59)[1] == 1
    assert totp.current_code(RFC_SECRET, at=60)[1] == 30


def test_normalize_and_uri():
    assert totp.normalize_secret("gezd gnbv-gy3t") == "GEZDGNBVGY3T"
    uri = f"otpauth://totp/Example:me?secret={RFC_SECRET.lower()}&issuer=Example"
    assert totp.normalize_secret(uri) == RFC_SECRET
    assert totp.current_code(uri, at=59)[0] == "287082"


def test_validate():
    assert totp.validate_secret(RFC_SECRET)
    assert not totp.validate_secret("")
    assert not totp.validate_secret("not base32 !!!")
