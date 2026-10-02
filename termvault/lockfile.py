"""One tvault window per vault.

Two windows on the same vault would silently overwrite each other's changes, since
whichever saves last replaces the whole file. An OS-level lock on vault.json.lock
prevents that. The OS drops the lock when the process ends, even if it crashes, so
a stale lock can never keep you out.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import IO


class VaultInUseError(Exception):
    pass


class VaultLock:
    # Windows releases a dead process's file locks asynchronously, usually within a
    # moment. Waiting briefly means restarting right after a crash isn't refused.
    WAIT_SECONDS = 2.0

    def __init__(self, vault_path: Path) -> None:
        vault_path = Path(vault_path)
        self.path = vault_path.with_name(vault_path.name + ".lock")
        self._file: IO[bytes] | None = None

    def acquire(self) -> None:
        if self._file is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = open(self.path, "a+b")
        deadline = time.monotonic() + self.WAIT_SECONDS
        while True:
            try:
                self._lock(f)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    f.close()
                    raise VaultInUseError(
                        f"{self.path.with_suffix('')} is already open in another tvault window") from exc
                time.sleep(0.1)
        self._file = f
        # Informational only; the OS lock is what matters.
        f.seek(0)
        f.truncate()
        f.write(str(os.getpid()).encode())
        f.flush()

    @staticmethod
    def _lock(f: IO[bytes]) -> None:
        if sys.platform == "win32":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def release(self) -> None:
        if self._file is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt
                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            self._file.close()
            self._file = None
