"""The encrypted vault file: create, open, save, lock, and CRUD on entries."""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from . import crypto
from .health import strength
from .models import Entry

MIN_MASTER_LEN = 12
MIN_MASTER_SCORE = 3  # zxcvbn "Good"


def master_password_problem(password: str) -> str | None:
    """Explain why a new master password is unacceptable, or return None if it's fine."""
    if len(password) < MIN_MASTER_LEN:
        return f"Master password must be at least {MIN_MASTER_LEN} characters."
    s = strength(password)
    if s.score < MIN_MASTER_SCORE:
        msg = f"Too easy to guess ({s.label.lower()}, a cracking tool would need {s.crack_time})."
        if s.warning:
            msg += f" {s.warning}"
        return msg + " Try 4 or more random words."
    return None


def _weaker(kdf: dict[str, Any], target: dict[str, Any]) -> bool:
    return (int(kdf.get("memory_cost", 0)) < int(target["memory_cost"])
            or int(kdf.get("time_cost", 0)) < int(target["time_cost"]))


def default_vault_path() -> Path:
    # Deliberately not %APPDATA%: the Microsoft Store build of Python silently redirects
    # writes there into its own package folder, which is wiped if Python is uninstalled.
    return Path.home() / ".termvault" / "vault.json"


class VaultLockedError(Exception):
    pass


class Vault:
    """An unlocked vault holds the derived key and plaintext entries in memory."""

    def __init__(self, path: Path, kdf: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        # target_kdf is what new or upgraded vaults use; kdf is what the open file uses.
        self.target_kdf = dict(kdf or crypto.DEFAULT_KDF)
        self.kdf = dict(self.target_kdf)
        self.kdf_upgraded = False
        self._key: bytes | None = None
        self._salt: bytes | None = None
        self._entries: dict[str, Entry] = {}

    # ---- lifecycle -------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def create(self, password: str) -> None:
        if self.exists():
            raise FileExistsError(self.path)
        problem = master_password_problem(password)
        if problem:
            raise ValueError(problem)
        self.kdf = dict(self.target_kdf)
        self._salt = crypto.new_salt()
        self._key = crypto.derive_key(password, self._salt, self.kdf)
        self._entries = {}
        self.save()

    def unlock(self, password: str, upgrade: bool = True) -> None:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise crypto.DecryptionError("vault file is malformed") from exc
        kdf, salt = crypto.read_header(doc)
        key = crypto.derive_key(password, salt, kdf)
        plaintext = crypto.decrypt(doc, key)
        data = json.loads(plaintext.decode("utf-8"))
        self.kdf, self._salt, self._key = kdf, salt, key
        self._entries = {e["id"]: Entry.from_dict(e) for e in data.get("entries", [])}
        self.kdf_upgraded = False
        if upgrade and _weaker(kdf, self.target_kdf):
            self._upgrade_kdf(password)

    def _upgrade_kdf(self, password: str) -> None:
        """Re-encrypt a vault made with weaker Argon2 settings using the current ones."""
        try:
            self._rekey(password, self.target_kdf)
            self.kdf_upgraded = True
        except OSError:
            pass  # _rekey rolled back; keep working with the old settings

    def lock(self) -> None:
        self._key = None
        self._salt = None
        self._entries = {}

    def change_master(self, old_password: str, new_password: str) -> None:
        self._require_unlocked()
        problem = master_password_problem(new_password)
        if problem:
            raise ValueError(problem)
        # Verify the old password against the file before re-keying.
        check = Vault(self.path)
        check.unlock(old_password, upgrade=False)
        check.lock()
        kdf = self.target_kdf if _weaker(self.kdf, self.target_kdf) else self.kdf
        self._rekey(new_password, kdf)

    def _rekey(self, password: str, kdf: dict[str, Any]) -> None:
        """Switch to a new password and/or KDF, re-encrypting the vault AND its backup.

        A normal save copies the old file to .bak. Doing that here would leave a backup
        that still opens with the old password (or the old, weaker KDF), which an attacker
        would simply target instead. So the backup is re-encrypted with the new key too,
        keeping its contents (one step of undo) when it can be read.
        """
        assert self._key is not None
        backup = self._backup_path()
        backup_plaintext: bytes | None = None
        if backup.exists():
            try:
                # The backup was made by an earlier save, so it uses the current key.
                doc = json.loads(backup.read_text(encoding="utf-8"))
                backup_plaintext = crypto.decrypt(doc, self._key)
            except (OSError, ValueError, crypto.DecryptionError):
                backup_plaintext = None  # unreadable: replace it with the current vault

        old = (self.kdf, self._salt, self._key)
        self.kdf = dict(kdf)
        self._salt = crypto.new_salt()
        self._key = crypto.derive_key(password, self._salt, self.kdf)
        current = self._plaintext()
        try:
            self._write(self.path, current)
        except OSError:
            # The file still has the old key; keep using it so the next save matches.
            self.kdf, self._salt, self._key = old
            raise
        try:
            self._write(backup, backup_plaintext if backup_plaintext is not None else current)
        except OSError:
            # Never leave a backup behind that opens with the old password.
            try:
                backup.unlink()
            except OSError:
                pass

    def save(self) -> None:
        self._require_unlocked()
        plaintext = self._plaintext()
        if self.path.exists():
            shutil.copy2(self.path, self._backup_path())
        self._write(self.path, plaintext)

    def _backup_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".bak")

    def _plaintext(self) -> bytes:
        payload = {"entries": [e.to_dict() for e in self._entries.values()]}
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def _write(self, path: Path, plaintext: bytes) -> None:
        """Encrypt with the current key and write atomically (temp file, then rename)."""
        assert self._key is not None and self._salt is not None
        doc = crypto.encrypt(plaintext, self._key, self._salt, self.kdf)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ---- entries ---------------------------------------------------------

    def _require_unlocked(self) -> None:
        if self._key is None:
            raise VaultLockedError("vault is locked")

    def entries(self, query: str = "") -> list[Entry]:
        self._require_unlocked()
        found = [e for e in self._entries.values() if e.matches(query)]
        return sorted(found, key=lambda e: (not e.favorite, e.title.lower()))

    def get(self, entry_id: str) -> Entry:
        self._require_unlocked()
        return self._entries[entry_id]

    def add(self, entry: Entry) -> Entry:
        self._require_unlocked()
        self._entries[entry.id] = entry
        self.save()
        return entry

    def update(self, entry: Entry) -> Entry:
        self._require_unlocked()
        if entry.id not in self._entries:
            raise KeyError(entry.id)
        entry.updated = time.time()
        self._entries[entry.id] = entry
        self.save()
        return entry

    def delete(self, entry_id: str) -> None:
        self._require_unlocked()
        del self._entries[entry_id]
        self.save()

    def toggle_favorite(self, entry_id: str) -> Entry:
        entry = self.get(entry_id)
        entry.favorite = not entry.favorite
        return self.update(entry)
