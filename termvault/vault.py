"""Encrypted local vault with validated, serialized and transactional updates."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from functools import wraps
from pathlib import Path
from typing import Any

from . import crypto
from .fileio import CommitUncertainError, atomic_write, read_bounded, sync_directory, check_regular
from .health import strength
from .lockfile import VaultLock
from .models import Entry

MIN_MASTER_LEN = 12
MIN_MASTER_SCORE = 3
MAX_ENTRIES = 10000


def master_password_problem(password: str) -> str | None:
    if not isinstance(password, str) or not MIN_MASTER_LEN <= len(password) <= 2048:
        return f"Master password must be {MIN_MASTER_LEN} to 2048 characters."
    s = strength(password)
    if s.score < MIN_MASTER_SCORE:
        msg = f"Too easy to guess ({s.label.lower()}, a cracking tool would need {s.crack_time})."
        if s.warning:
            msg += f" {s.warning}"
        return msg + " Try 4 or more random words."
    return None


def _weaker(kdf: dict[str, Any], target: dict[str, Any]) -> bool:
    return any(kdf[field] < target[field] for field in ("memory_cost", "time_cost"))


def _upgrade_settings(kdf: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    # Parallelism is a tuning parameter, not a simple strength ordering.
    return {**kdf, "memory_cost": max(kdf["memory_cost"], target["memory_cost"]),
            "time_cost": max(kdf["time_cost"], target["time_cost"])}


def default_vault_path() -> Path:
    return Path.home() / ".termvault" / "vault.json"


class VaultLockedError(Exception):
    pass


class VaultConflictError(OSError):
    """The on-disk vault changed since this session opened it."""


def _transactional(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self._transaction():
            return fn(self, *args, **kwargs)
    return wrapped


def _synchronized(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self._mutex:
            return fn(self, *args, **kwargs)
    return wrapped


def _parse_json(raw: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("invalid JSON number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise crypto.DecryptionError("vault file is malformed") from exc


def _decode_entries(plaintext: bytes) -> dict[str, Entry]:
    data = _parse_json(plaintext)
    try:
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            raise ValueError("invalid entry list")
        if len(data["entries"]) > MAX_ENTRIES:
            raise ValueError("too many entries")
        entries = {}
        for item in data["entries"]:
            if not isinstance(item, dict) or "id" not in item:
                raise ValueError("entry id is required")
            entry = Entry.from_dict(item)
            if entry.id in entries:
                raise ValueError("duplicate entry id")
            entries[entry.id] = entry
        return entries
    except (ValueError, TypeError) as exc:
        raise crypto.DecryptionError("vault contains invalid entries") from exc


def _revision(doc: dict) -> bytes:
    # The keyboard-attempt guard is intentionally unauthenticated and mutable.
    envelope = {k: doc[k] for k in ("version", "kdf", "salt", "nonce", "ciphertext")}
    return hashlib.sha256(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()).digest()


class Vault:
    def __init__(self, path: Path, kdf: dict[str, Any] | None = None,
                 *, allow_expensive_kdf: bool = False) -> None:
        path = Path(path).absolute()
        # Resolve parent aliases, but retain the leaf so symlink vaults are rejected.
        self.path = path.parent.resolve() / path.name
        self.target_kdf = crypto.validate_kdf(dict(kdf or crypto.DEFAULT_KDF))
        self.kdf = dict(self.target_kdf)
        self.allow_expensive_kdf = allow_expensive_kdf
        self.kdf_upgraded = False
        self.backup_warning: str | None = None
        self._key: bytes | None = None
        self._salt: bytes | None = None
        self._entries: dict[str, Entry] = {}
        self._revision: bytes | None = None
        self._mutex = threading.RLock()
        self._transaction_depth = 0
        self._creating = False

    @contextmanager
    def _transaction(self):
        with self._mutex:
            outer = self._transaction_depth == 0
            lock = VaultLock(self.path.with_name(self.path.name + ".write")) if outer else None
            if lock is not None:
                lock.acquire()
            self._transaction_depth += 1
            try:
                yield
            finally:
                self._transaction_depth -= 1
                if lock is not None:
                    lock.release()

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def _read_doc(self, path: Path) -> dict:
        try:
            doc = _parse_json(read_bounded(path, crypto.MAX_VAULT_BYTES))
        except ValueError as exc:
            raise crypto.DecryptionError("vault file exceeds the size limit") from exc
        crypto.validate_envelope(doc)
        return doc

    def _derive(self, password: str, salt: bytes, kdf: dict) -> bytes:
        return crypto.derive_key(password, salt, kdf, allow_expensive=self.allow_expensive_kdf)

    @_transactional
    def create(self, password: str) -> None:
        if self.exists():
            raise FileExistsError(self.path)
        problem = master_password_problem(password)
        if problem:
            raise ValueError(problem)
        salt = crypto.new_salt()
        key = self._derive(password, salt, self.target_kdf)
        self.kdf, self._salt, self._key = dict(self.target_kdf), salt, key
        self._entries = {}
        self._revision = None
        self._creating = True
        try:
            self.save()
        except Exception:
            self.lock()
            raise
        finally:
            self._creating = False

    @_transactional
    def unlock(self, password: str, upgrade: bool = True) -> None:
        # A failed unlock always leaves the object locked.
        self.lock()
        doc = self._read_doc(self.path)
        kdf, salt = crypto.read_header(doc)
        key = self._derive(password, salt, kdf)
        entries = _decode_entries(crypto.decrypt(doc, key))
        self.kdf, self._salt, self._key = kdf, salt, key
        self._entries, self._revision = entries, _revision(doc)
        self.kdf_upgraded = False
        self.backup_warning = None
        if upgrade and _weaker(kdf, self.target_kdf):
            self._upgrade_kdf(password)

    def _upgrade_kdf(self, password: str) -> None:
        try:
            self._rekey(password, _upgrade_settings(self.kdf, self.target_kdf))
            self.kdf_upgraded = True
        except (OSError, crypto.DecryptionError):
            # Ordinary pre-commit failures retain the old settings. Ambiguous
            # committed writes lock the session and must be reported to the caller.
            if not self.unlocked:
                raise
            self.backup_warning = "Automatic key upgrade failed; current settings retained."

    @_synchronized
    def lock(self) -> None:
        self._key = None
        self._salt = None
        self._entries = {}
        self._revision = None

    def _check_revision(self) -> dict:
        try:
            doc = self._read_doc(self.path)
        except (OSError, crypto.DecryptionError) as exc:
            raise VaultConflictError("vault changed or became unreadable; reopen it before saving") from exc
        if self._revision != _revision(doc):
            raise VaultConflictError("vault changed in another session; reopen it before saving")
        return doc

    @_transactional
    def change_master(self, old_password: str, new_password: str) -> None:
        self._require_unlocked()
        problem = master_password_problem(new_password)
        if problem:
            raise ValueError(problem)
        doc = self._check_revision()
        kdf, salt = crypto.read_header(doc)
        crypto.decrypt(doc, self._derive(old_password, salt, kdf))
        self._rekey(new_password, _upgrade_settings(self.kdf, self.target_kdf))

    def _rekey(self, password: str, kdf: dict[str, Any]) -> None:
        self._require_unlocked()
        self._check_revision()
        backup = self._backup_path()
        backup_plaintext = None
        if backup.exists() or backup.is_symlink():
            check_regular(backup)
            try:
                backup_plaintext = crypto.decrypt(self._read_doc(backup), self._key)
                _decode_entries(backup_plaintext)
            except (OSError, crypto.DecryptionError):
                backup_plaintext = None

        # Derive and encryptability-check before touching state or removing backup.
        new_kdf, new_salt = crypto.validate_kdf(kdf), crypto.new_salt()
        new_key = self._derive(password, new_salt, new_kdf)
        current = self._plaintext()
        crypto.encrypt(current, new_key, new_salt, new_kdf)
        previous = self.kdf, self._salt, self._key
        self.backup_warning = None
        if backup.exists():
            backup.unlink()  # Failure aborts before the main password changes.
            sync_directory(backup.parent)
        self.kdf, self._salt, self._key = new_kdf, new_salt, new_key
        try:
            self._write(self.path, current)
        except CommitUncertainError:
            self.lock()
            raise
        except Exception:
            self.kdf, self._salt, self._key = previous
            raise
        try:
            self._revision = _revision(self._read_doc(self.path))
        except Exception:
            self.lock()
            raise
        try:
            self._write(backup, backup_plaintext if backup_plaintext is not None else current)
        except OSError:
            # The old backup was already removed. A failed replacement can only
            # leave new-key ciphertext; it cannot resurrect an old-password copy.
            self.backup_warning = "Password changed, but the backup could not be durably saved."

    @_transactional
    def save(self) -> None:
        self._persist(self._entries)

    def _persist(self, entries: dict[str, Entry]) -> None:
        self._require_unlocked()
        plaintext = self._plaintext(entries)
        if not self._creating:
            self._check_revision()
            atomic_write(self._backup_path(), read_bounded(self.path, crypto.MAX_VAULT_BYTES))
        try:
            self._write(self.path, plaintext)
        except CommitUncertainError:
            self.lock()
            raise
        try:
            self._revision = _revision(self._read_doc(self.path))
        except Exception:
            self.lock()
            raise
        self._entries = entries

    def _backup_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".bak")

    def _plaintext(self, entries: dict[str, Entry] | None = None) -> bytes:
        selected = self._entries if entries is None else entries
        if len(selected) > MAX_ENTRIES:
            raise ValueError("too many vault entries")
        payload = {"entries": [Entry.from_dict(e.to_dict()).to_dict() for e in selected.values()]}
        raw = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(raw) > crypto.MAX_PLAINTEXT_BYTES:
            raise ValueError("vault payload exceeds the size limit")
        return raw

    def _write(self, path: Path, plaintext: bytes) -> None:
        self._require_unlocked()
        doc = crypto.encrypt(plaintext, self._key, self._salt, self.kdf)
        raw = json.dumps(doc, indent=1, allow_nan=False).encode("utf-8")
        if len(raw) > crypto.MAX_VAULT_BYTES:
            raise ValueError("vault file exceeds the size limit")
        atomic_write(path, raw, exclusive=self._creating and path == self.path)

    def _require_unlocked(self) -> None:
        if self._key is None:
            raise VaultLockedError("vault is locked")

    @_synchronized
    def entries(self, query: str = "") -> list[Entry]:
        self._require_unlocked()
        found = [replace(e) for e in self._entries.values() if e.matches(query)]
        return sorted(found, key=lambda e: (not e.favorite, e.title.lower()))

    @_synchronized
    def get(self, entry_id: str) -> Entry:
        self._require_unlocked()
        return replace(self._entries[entry_id])

    @_transactional
    def add(self, entry: Entry) -> Entry:
        self._require_unlocked()
        candidate = Entry.from_dict(entry.to_dict())
        if candidate.id in self._entries:
            raise ValueError("entry id already exists")
        self._persist({**self._entries, candidate.id: candidate})
        return replace(candidate)

    @_transactional
    def update(self, entry: Entry) -> Entry:
        self._require_unlocked()
        candidate = Entry.from_dict(entry.to_dict())
        if candidate.id not in self._entries:
            raise KeyError(candidate.id)
        candidate.updated = time.time()
        if candidate.password != self._entries[candidate.id].password:
            candidate.password_changed = candidate.updated
        self._persist({**self._entries, candidate.id: candidate})
        return replace(candidate)

    @_transactional
    def delete(self, entry_id: str) -> None:
        self._require_unlocked()
        entries = dict(self._entries)
        del entries[entry_id]
        self._persist(entries)

    @_transactional
    def toggle_favorite(self, entry_id: str) -> Entry:
        entry = self.get(entry_id)
        entry.favorite = not entry.favorite
        return self.update(entry)
