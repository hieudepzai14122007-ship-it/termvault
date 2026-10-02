"""Escalating lockout after wrong master-password attempts made through the app.

The counter is kept in two places and the higher value wins, so neither restarting
the app, renaming or copying the vault, nor deleting one file resets it:

1. ~/.termvault/attempts.json, keyed by the vault's fingerprint (a hash of its random
   salt). A renamed or copied vault has the same salt, so it shares the counter.
2. Inside vault.json itself, as a "guard" field next to the encryption header. Copies
   of the file carry their counter with them. The field isn't encrypted; decryption
   ignores it.

This stops someone guessing at your keyboard. It can't stop offline cracking tools,
which work on a copy of vault.json and never run this code; against those, only the
cost of Argon2 and the strength of the master password help. Anyone who controls your
Windows account can also edit both places, so this is a deterrent, not a wall.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

FREE_ATTEMPTS = 3  # wrong guesses allowed before lockouts start (for typos)
BASE_DELAY = 30.0  # seconds; doubles with each further wrong guess
MAX_DELAY = 15 * 60.0

_EMPTY = {"failures": 0, "locked_until": 0.0}


def default_store_path() -> Path:
    return Path.home() / ".termvault" / "attempts.json"


def delay_after(failures: int) -> float:
    if failures <= FREE_ATTEMPTS:
        return 0.0
    return min(BASE_DELAY * 2 ** (failures - FREE_ATTEMPTS - 1), MAX_DELAY)


def _clean(state: object) -> dict:
    try:
        return {"failures": int(state["failures"]), "locked_until": float(state["locked_until"])}
    except (KeyError, TypeError, ValueError):
        return dict(_EMPTY)


def _write_json(path: Path, data: object, indent: int | None = None) -> None:
    tmp = path.with_suffix(path.suffix + ".guardtmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class AttemptGuard:
    def __init__(self, vault_path: Path, store_path: Path | None = None) -> None:
        self.vault_path = Path(vault_path)
        self.store_path = Path(store_path) if store_path else default_store_path()
        self._counted_fp: str | None = None

    # ---- the two storage places ------------------------------------------

    def _vault_doc(self) -> dict | None:
        try:
            doc = json.loads(self.vault_path.read_text(encoding="utf-8"))
            return doc if isinstance(doc, dict) and "salt" in doc else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _fingerprint(doc: dict) -> str:
        return hashlib.sha256(str(doc["salt"]).encode("utf-8")).hexdigest()[:32]

    def _store(self) -> dict:
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _load(self) -> dict:
        doc = self._vault_doc()
        if doc is None:
            return dict(_EMPTY)
        a = _clean(self._store().get(self._fingerprint(doc)))
        b = _clean(doc.get("guard"))
        return {"failures": max(a["failures"], b["failures"]),
                "locked_until": max(a["locked_until"], b["locked_until"])}

    def _save(self, state: dict | None) -> None:
        """Write state to both places (None clears it). Failures here are ignored:
        the guard must never stop you unlocking your own vault."""
        doc = self._vault_doc()
        if doc is None:
            return
        fp = self._fingerprint(doc)
        try:
            store = self._store()
            if state is None:
                store.pop(fp, None)
                if self._counted_fp:
                    store.pop(self._counted_fp, None)  # in case the salt changed since
            else:
                store[fp] = state
                self._counted_fp = fp
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            _write_json(self.store_path, store)
        except OSError:
            pass
        try:
            if state is None:
                if "guard" not in doc:
                    return
                doc.pop("guard")
            else:
                doc["guard"] = state
            _write_json(self.vault_path, doc, indent=1)
        except OSError:
            pass

    # ---- public API ------------------------------------------------------

    @property
    def failures(self) -> int:
        return self._load()["failures"]

    def remaining(self, now: float | None = None) -> float:
        """Seconds until the next attempt is allowed (0 if allowed now)."""
        now = time.time() if now is None else now
        # Clamp, so winding the clock back can't make the wait longer than the maximum.
        return max(0.0, min(self._load()["locked_until"] - now, MAX_DELAY))

    def record_failure(self, now: float | None = None) -> float:
        """Count an attempt as wrong and return the lockout it triggers, in seconds.

        Call this BEFORE checking the password and reset() if it turns out right, so
        killing the app in the middle of a check still counts as a wrong attempt.
        """
        now = time.time() if now is None else now
        state = self._load()
        state["failures"] += 1
        delay = delay_after(state["failures"])
        state["locked_until"] = now + delay
        self._save(state)
        return delay

    def reset(self) -> None:
        self._save(None)
