"""Cryptographically secure password and passphrase generation."""

from __future__ import annotations

import math
import secrets
import string
from functools import lru_cache
from importlib import resources

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o|`'\"")


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    text = resources.files("termvault").joinpath("eff_short_wordlist.txt").read_text(encoding="utf-8")
    return tuple(w.strip() for w in text.splitlines() if w.strip() and not w.startswith("#"))


def _charsets(lower: bool, upper: bool, digits: bool, symbols: bool, avoid_ambiguous: bool) -> list[str]:
    sets = []
    if lower:
        sets.append(string.ascii_lowercase)
    if upper:
        sets.append(string.ascii_uppercase)
    if digits:
        sets.append(string.digits)
    if symbols:
        sets.append(SYMBOLS)
    if avoid_ambiguous:
        sets = ["".join(c for c in s if c not in AMBIGUOUS) for s in sets]
    return sets


def generate_password(length: int = 20, lower: bool = True, upper: bool = True, digits: bool = True,
                      symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    sets = _charsets(lower, upper, digits, symbols, avoid_ambiguous)
    if not sets:
        raise ValueError("pick at least one character set")
    if not len(sets) <= length <= 128:
        raise ValueError(f"length must be between {len(sets)} and 128")
    alphabet = "".join(sets)
    # Rejection-sample until every chosen set appears, so the output stays uniform
    # over all passwords that satisfy the rule.
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in s for c in pw) for s in sets):
            return pw


def password_entropy(length: int, lower: bool = True, upper: bool = True, digits: bool = True,
                     symbols: bool = True, avoid_ambiguous: bool = False) -> float:
    size = len("".join(_charsets(lower, upper, digits, symbols, avoid_ambiguous)))
    return length * math.log2(size) if size else 0.0


def generate_passphrase(words: int = 6, separator: str = "-", capitalize: bool = False,
                        add_number: bool = False) -> str:
    if not 3 <= words <= 20:
        raise ValueError("words must be between 3 and 20")
    chosen = [secrets.choice(wordlist()) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    if add_number:
        i = secrets.randbelow(words)
        chosen[i] += str(secrets.randbelow(10))
    return separator.join(chosen)


def passphrase_entropy(words: int, add_number: bool = False) -> float:
    bits = words * math.log2(len(wordlist()))
    if add_number:
        bits += math.log2(10) + math.log2(words)
    return bits
