"""Vault entry types."""

from __future__ import annotations

import time
import uuid
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

EntryType = Literal["login", "note", "card"]

TYPE_LABELS = {"login": "Login", "note": "Secure note", "card": "Credit card"}


def _now() -> float:
    return time.time()


@dataclass(repr=False)
class Entry:
    type: EntryType
    title: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: float = field(default_factory=_now)
    updated: float = field(default_factory=_now)
    favorite: bool = False
    # login fields
    username: str = ""
    password: str = ""
    password_changed: float = field(default_factory=_now)
    url: str = ""
    notes: str = ""  # shared by logins and cards
    totp_secret: str = ""
    # note fields
    body: str = ""
    # card fields
    card_name: str = ""
    card_number: str = ""  # digits only
    card_expiry: str = ""  # MM/YY
    card_cvv: str = ""
    card_pin: str = ""

    def __repr__(self) -> str:
        return "Entry(<redacted>)"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Entry":
        if not isinstance(data, dict):
            raise ValueError("invalid entry")
        known = {f for f in cls.__dataclass_fields__}
        values = {k: v for k, v in data.items() if k in known}
        # Vaults written before password_changed existed: best guess is the last edit.
        values.setdefault("password_changed", values.get("updated", _now()))
        if not isinstance(values.get("type"), str) or values["type"] not in TYPE_LABELS:
            raise ValueError("invalid entry type")
        if not isinstance(values.get("title"), str):
            raise ValueError("invalid entry title")
        timestamps = {"created", "updated", "password_changed"}
        for name, value in values.items():
            if name in timestamps:
                if type(value) not in (int, float) or not 0 <= value <= 253402300799:
                    raise ValueError("invalid entry timestamp")
                if not math.isfinite(value):
                    raise ValueError("invalid entry timestamp")
            elif name == "favorite":
                if type(value) is not bool:
                    raise ValueError("invalid favorite flag")
            elif not isinstance(value, str) or len(value) > 1024 * 1024:
                raise ValueError("invalid entry text")
        if "id" in values and (not values["id"] or len(values["id"]) > 128):
            raise ValueError("invalid entry id")
        return cls(**values)

    def matches(self, query: str) -> bool:
        q = query.strip().lower()
        if not q:
            return True
        if self.type == "note":
            haystack = [self.title, self.body]
        elif self.type == "card":
            from .cards import brand  # local import avoids a cycle at module load
            haystack = [self.title, self.card_name, brand(self.card_number), self.notes]
        else:
            haystack = [self.title, self.username, self.url, self.notes]
        return any(q in s.lower() for s in haystack)


def new_login(title: str, username: str = "", password: str = "", url: str = "",
              notes: str = "", totp_secret: str = "") -> Entry:
    return Entry(type="login", title=title, username=username, password=password,
                 url=url, notes=notes, totp_secret=totp_secret)


def new_note(title: str, body: str = "") -> Entry:
    return Entry(type="note", title=title, body=body)


def new_card(title: str, card_name: str = "", card_number: str = "", card_expiry: str = "",
             card_cvv: str = "", card_pin: str = "", notes: str = "") -> Entry:
    return Entry(type="card", title=title, card_name=card_name, card_number=card_number,
                 card_expiry=card_expiry, card_cvv=card_cvv, card_pin=card_pin, notes=notes)
