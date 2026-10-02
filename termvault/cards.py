"""Credit card helpers: Luhn check, brand detection, formatting, expiry."""

from __future__ import annotations

import datetime as dt
import re

EXPIRING_SOON_DAYS = 60


def digits_only(number: str) -> str:
    return re.sub(r"\D", "", number)


def luhn_valid(number: str) -> bool:
    digits = digits_only(number)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def brand(number: str) -> str:
    n = digits_only(number)
    if not n:
        return ""
    if n.startswith(("34", "37")):
        return "Amex"
    if n.startswith("4"):
        return "Visa"
    if n[:2] in {"51", "52", "53", "54", "55"} or (len(n) >= 4 and 2221 <= int(n[:4]) <= 2720):
        return "Mastercard"
    if n.startswith(("6011", "65")) or (len(n) >= 3 and 644 <= int(n[:3]) <= 649):
        return "Discover"
    if len(n) >= 4 and 3528 <= int(n[:4]) <= 3589:
        return "JCB"
    if n.startswith(("36", "38", "300", "301", "302", "303", "304", "305")):
        return "Diners Club"
    if n.startswith("62"):
        return "UnionPay"
    return "Card"


def _groups(n: str) -> list[str]:
    if brand(n) == "Amex" and len(n) == 15:
        return [n[:4], n[4:10], n[10:]]
    return [n[i:i + 4] for i in range(0, len(n), 4)]


def format_number(number: str) -> str:
    return " ".join(_groups(digits_only(number)))


def mask_number(number: str) -> str:
    n = digits_only(number)
    return f"•••• {n[-4:]}" if len(n) > 4 else n


def parse_expiry(text: str) -> tuple[int, int] | None:
    """Parse MM/YY, MM/YYYY, MMYY or MM-YY into (month, four-digit year)."""
    m = re.fullmatch(r"\s*(\d{1,2})\s*[/\-. ]?\s*(\d{2}|\d{4})\s*", text)
    if not m:
        return None
    month, year = int(m.group(1)), int(m.group(2))
    if not 1 <= month <= 12:
        return None
    if year < 100:
        year += 2000
    return month, year


def normalize_expiry(text: str) -> str:
    parsed = parse_expiry(text)
    if parsed is None:
        raise ValueError(f"invalid expiry: {text!r}")
    month, year = parsed
    return f"{month:02d}/{year % 100:02d}"


def expiry_status(text: str, today: dt.date | None = None) -> str:
    """Return "ok", "soon", "expired", or "" if there's no valid expiry."""
    parsed = parse_expiry(text) if text else None
    if parsed is None:
        return ""
    month, year = parsed
    today = today or dt.date.today()
    # A card is valid through the last day of its expiry month.
    first_of_next = dt.date(year + (month == 12), month % 12 + 1, 1)
    if today >= first_of_next:
        return "expired"
    if (first_of_next - today).days <= EXPIRING_SOON_DAYS:
        return "soon"
    return "ok"
