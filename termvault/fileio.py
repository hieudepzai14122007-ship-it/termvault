"""Bounded reads and private, atomic ciphertext writes.

The parent directory must be controlled by the user. This does not protect
against an attacker running as that user or an administrator.
"""

from __future__ import annotations

import os
import secrets
import stat
import tempfile
from pathlib import Path

_WINDOWS = os.name == "nt"


class CommitUncertainError(OSError):
    """Replacement happened, but flushing its directory failed. Reopen the vault."""


def private_parent(path: Path) -> None:
    if _WINDOWS:
        from .windows_permissions import private_parent as windows_parent
        windows_parent(path)
        return
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


def open_private(path: Path, flags: int) -> int:
    """Open/create an owned regular file with verified platform permissions."""
    private_parent(path)
    check_regular(path, missing_ok=bool(flags & os.O_CREAT))
    if _WINDOWS:
        from .windows_permissions import open_private as windows_open
        return windows_open(path, flags)
    fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (os.name == "posix" and info.st_uid != os.getuid())):
            raise PermissionError("vault file must be an owned regular file without extra hard links")
        if os.name == "posix":
            os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


def secure_existing_file(path: Path, *, missing_ok: bool = False) -> None:
    """Tighten an owned legacy file without reading its contents."""
    try:
        fd = open_private(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    os.close(fd)


def read_bounded(path: Path, limit: int) -> bytes:
    fd = open_private(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
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
    if _WINDOWS:
        # An ACL must be supplied at creation, before even an empty temporary
        # file is visible; chmod/mkstemp do not provide that on Windows.
        for _ in range(16):
            name = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
            try:
                fd = open_private(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                  | getattr(os, "O_BINARY", 0))
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("could not create a private temporary vault file")
    else:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(name)
    committed = False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        check_regular(path, missing_ok=True)
        if exclusive:
            # Linking publishes without overwriting a vault created concurrently.
            os.link(tmp, path)
            committed = True
            tmp.unlink()
        else:
            os.replace(tmp, path)
            committed = True
        try:
            sync_directory(path.parent)
        except OSError as exc:
            raise CommitUncertainError("vault write committed; durability is uncertain, reopen the vault") from exc
    except OSError as exc:
        if committed and not isinstance(exc, CommitUncertainError):
            raise CommitUncertainError("vault write committed; completion is uncertain, reopen the vault") from exc
        raise
    finally:
        # A cleanup error must never turn a committed replacement into an
        # apparent pre-commit failure, or hide the original write exception.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
