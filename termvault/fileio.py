"""Bounded reads and private, atomic ciphertext writes.

The parent directory must be controlled by the user. This does not protect
against an attacker running as that user or an administrator.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


class CommitUncertainError(OSError):
    """Replacement happened, but flushing its directory failed. Reopen the vault."""


def private_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.stat()
    if os.name == "posix":
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise PermissionError("vault directory must be owned by you and not writable by others")


def check_regular(path: Path, *, missing_ok: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PermissionError("vault files must be regular files without extra hard links")
    if os.name == "posix" and info.st_uid != os.getuid():
        raise PermissionError("vault file must be owned by you")


def read_bounded(path: Path, limit: int) -> bytes:
    private_parent(path)
    check_regular(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError("vault file is not a private regular file")
        if os.name == "posix":
            if info.st_uid != os.getuid():
                raise PermissionError("vault file must be owned by you")
            os.fchmod(f.fileno(), 0o600)  # Tighten legacy files as well as new writes.
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("vault file exceeds the size limit")
    return data


def sync_directory(parent: Path) -> None:
    if os.name != "posix":
        return  # Windows has no portable directory-fsync API in Python.
    fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    private_parent(path)
    check_regular(path, missing_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        check_regular(path, missing_ok=True)
        if exclusive:
            # Linking publishes without overwriting a vault created concurrently.
            os.link(tmp, path)
            tmp.unlink()
        else:
            os.replace(tmp, path)
        try:
            sync_directory(path.parent)
        except OSError as exc:
            raise CommitUncertainError("vault write committed; durability is uncertain, reopen the vault") from exc
    finally:
        tmp.unlink(missing_ok=True)
