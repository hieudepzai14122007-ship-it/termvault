"""Password strength scoring and the vault health audit."""

from __future__ import annotations

import datetime as dt
import time
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache

from zxcvbn import zxcvbn

from . import cards
from .models import Entry

STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"]
WEAK_SCORE = 2  # zxcvbn score <= this is flagged
OLD_DAYS = 365
_MAX_SCORED_LEN = 100  # zxcvbn gets slow on very long input; 100 chars is plenty strong anyway


@dataclass(frozen=True)
class Strength:
    score: int  # 0..4
    label: str
    warning: str
    crack_time: str


@lru_cache(maxsize=256)
def strength(password: str) -> Strength:
    if not password:
        return Strength(0, "Empty", "", "")
    r = zxcvbn(password[:_MAX_SCORED_LEN])
    fb = r["feedback"]
    warning = fb.get("warning") or (fb.get("suggestions") or [""])[0]
    return Strength(r["score"], STRENGTH_LABELS[r["score"]], warning,
                    r["crack_times_display"]["offline_slow_hashing_1e4_per_second"])


@dataclass(frozen=True)
class Issue:
    entry_id: str
    title: str
    kind: str  # weak | reused | old | expired | expiring
    detail: str


SEVERITY = {"expired": 0, "reused": 1, "weak": 2, "expiring": 3, "old": 4}


def audit(entries: list[Entry], now: float | None = None, today: dt.date | None = None) -> list[Issue]:
    now = time.time() if now is None else now
    issues: list[Issue] = []
    logins = [e for e in entries if e.type == "login" and e.password]

    by_password: dict[str, list[Entry]] = defaultdict(list)
    for e in logins:
        by_password[e.password].append(e)

    for e in logins:
        s = strength(e.password)
        if s.score <= WEAK_SCORE:
            detail = f"{s.label} (cracked in {s.crack_time})"
            if s.warning:
                detail += f": {s.warning}"
            issues.append(Issue(e.id, e.title, "weak", detail))
        others = [o.title for o in by_password[e.password] if o.id != e.id]
        if others:
            issues.append(Issue(e.id, e.title, "reused", "Same password as " + ", ".join(sorted(others))))
        age_days = int((now - e.password_changed) // 86400)
        if age_days >= OLD_DAYS:
            issues.append(Issue(e.id, e.title, "old", f"Password unchanged for {age_days} days"))

    for e in entries:
        if e.type != "card":
            continue
        status = cards.expiry_status(e.card_expiry, today)
        if status == "expired":
            issues.append(Issue(e.id, e.title, "expired", f"Card expired {e.card_expiry}"))
        elif status == "soon":
            issues.append(Issue(e.id, e.title, "expiring", f"Card expires {e.card_expiry}"))

    issues.sort(key=lambda i: (SEVERITY[i.kind], i.title.lower()))
    return issues
