import math
import string

import pytest

from termvault import generator


def test_wordlist_loaded():
    words = generator.wordlist()
    assert len(words) == 1296 and len(set(words)) == 1296
    assert all(w.isalpha() or "-" in w for w in words)


@pytest.mark.parametrize("length", [8, 20, 64])
def test_password_length_and_classes(length):
    for _ in range(50):
        pw = generator.generate_password(length)
        assert len(pw) == length
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in generator.SYMBOLS for c in pw)


def test_password_respects_options():
    pw = generator.generate_password(40, upper=False, symbols=False, avoid_ambiguous=True)
    assert set(pw) <= set(string.ascii_lowercase + string.digits) - generator.AMBIGUOUS


def test_password_errors():
    with pytest.raises(ValueError):
        generator.generate_password(20, lower=False, upper=False, digits=False, symbols=False)
    with pytest.raises(ValueError):
        generator.generate_password(3)  # can't fit 4 required classes
    with pytest.raises(ValueError):
        generator.generate_password(500)


def test_passwords_are_random():
    assert len({generator.generate_password(16) for _ in range(100)}) == 100


def test_passphrase():
    words = set(generator.wordlist())
    pp = generator.generate_passphrase(6, separator=".")
    parts = pp.split(".")
    assert len(parts) == 6 and all(p in words for p in parts)


def test_passphrase_options():
    pp = generator.generate_passphrase(4, separator=" ", capitalize=True, add_number=True)
    parts = pp.split(" ")
    assert all(p[0].isupper() for p in parts)
    assert sum(ch.isdigit() for ch in pp) == 1


def test_entropy():
    assert generator.password_entropy(10, upper=False, digits=False, symbols=False) == pytest.approx(10 * math.log2(26))
    assert generator.passphrase_entropy(5) == pytest.approx(5 * math.log2(1296))
