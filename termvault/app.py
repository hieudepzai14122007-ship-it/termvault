"""Textual application entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from textual import events
from textual.app import App
from textual.binding import Binding
from textual.css.query import NoMatches
from textual.timer import Timer

from . import clipboard
from .guard import AttemptGuard
from .lockfile import VaultInUseError, VaultLock
from .memguard import protect_process
from .protection import ProtectionError, require_protection, scan_file
from .screens.main import MainScreen
from .screens.unlock import UnlockScreen
from .vault import Vault, default_vault_path

DEFAULT_IDLE_LOCK = 300  # seconds
DEFAULT_CLIPBOARD_CLEAR = 20  # seconds
PROTECTED_IDLE_LOCK = 60
PROTECTED_CLIPBOARD_CLEAR = 10
PROTECTION_POLL_SECONDS = 30
MAX_CLIPBOARD_RETRIES = 3

ACTIVITY_EVENTS = (events.Key, events.Paste, events.MouseDown,
                   events.MouseScrollDown, events.MouseScrollUp)


class TermVaultApp(App):
    TITLE = "termvault"
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [Binding("ctrl+l", "lock", "Lock", priority=True)]

    def __init__(self, vault_path: Path, idle_lock: int = DEFAULT_IDLE_LOCK,
                 kdf: dict[str, Any] | None = None,
                 clear_after: int = DEFAULT_CLIPBOARD_CLEAR,
                 protected_mode: bool = False) -> None:
        super().__init__()
        self.vault = Vault(vault_path, kdf=kdf)
        self.guard = AttemptGuard(vault_path)
        self.protected_mode = protected_mode
        self.idle_lock = (min(idle_lock, PROTECTED_IDLE_LOCK) if idle_lock > 0 else PROTECTED_IDLE_LOCK) \
            if protected_mode else idle_lock
        self.clear_after = (min(clear_after, PROTECTED_CLIPBOARD_CLEAR) if clear_after > 0 else PROTECTED_CLIPBOARD_CLEAR) \
            if protected_mode else clear_after
        self._protection_check_running = False
        self._unlock_generation = 0
        self._locking = False
        self._last_activity = time.monotonic()
        self._clipboard_value: str | None = None
        self._clipboard_timer: Timer | None = None
        self._clipboard_retries = 0
        self.memory_protection_error: str | None = None
        self.memory_protection_verified = False

    def on_mount(self) -> None:
        self.push_screen(UnlockScreen())
        if self.memory_protection_error:
            self.notify(f"Memory protection is off: {self.memory_protection_error}",
                        severity="warning", timeout=10)
        if self.idle_lock > 0:
            self.set_interval(5, self._check_idle)
        if self.protected_mode:
            self.set_interval(PROTECTION_POLL_SECONDS, self._start_protection_check)
            self.notify("Defender checks enabled; these checks cannot prove this computer is malware-free.",
                        timeout=10)

    async def check_before_unlock(self) -> None:
        if self.protected_mode:
            if self.memory_protection_error or not self.memory_protection_verified:
                raise ProtectionError("Process memory protection failed. Protected mode refuses to unlock.")
            await asyncio.to_thread(require_protection, self.vault.path.parent)

    def unlock_in_background(self, action, password: str, generation: int) -> None:
        if generation != self._unlock_generation:
            return
        try:
            action(password)
        finally:
            # This runs even if the coroutine awaiting this thread was cancelled
            # or the UI has stopped and can no longer process its result.
            if generation != self._unlock_generation:
                self.vault.lock()

    async def on_unmount(self) -> None:
        self._unlock_generation += 1
        # A to_thread operation cannot be killed by cancelling its awaiter.
        # Wait for the vault mutex, then drop any key it finished deriving.
        await asyncio.to_thread(self.vault.lock)
        self.clear_clipboard()

    def _start_protection_check(self) -> None:
        if self.vault.unlocked and not self._protection_check_running:
            self.run_worker(self._poll_protection(), group="protection", exclusive=True)

    async def _poll_protection(self) -> None:
        if self._protection_check_running or not self.vault.unlocked:
            return
        self._protection_check_running = True
        try:
            await asyncio.to_thread(require_protection, self.vault.path.parent)
        except Exception:
            # Unknown/error status is a reason to lock, never a clean-machine verdict.
            await self.action_lock()
            self.notify("Locked: Defender requirements failed or could not be verified. "
                        "Check Windows Security before unlocking.", severity="error", timeout=15)
        finally:
            self._protection_check_running = False

    async def on_event(self, event: events.Event) -> None:
        # Only deliberate input counts as activity; the mouse merely passing over the
        # terminal (MouseMove) must not keep the vault unlocked.
        if isinstance(event, ACTIVITY_EVENTS):
            self._last_activity = time.monotonic()
        await super().on_event(event)

    def _fatal_error(self) -> None:
        """Textual's crash report prints every local variable (show_locals=True), which
        can include the master password or decrypted entries, and it stays in terminal
        scrollback. Same report, minus the variables."""
        from rich.segment import Segments
        from rich.traceback import Traceback

        self.bell()
        traceback = Traceback(show_locals=False, width=None)
        self._exit_renderables.append(Segments(self.console.render(traceback, self.console.options)))
        self._close_messages_no_wait()

    def _check_idle(self) -> None:
        if self.vault.unlocked and time.monotonic() - self._last_activity > self.idle_lock:
            self.run_worker(self.action_lock())
            self.notify("Locked after inactivity")

    def on_unlocked(self) -> None:
        self._last_activity = time.monotonic()
        self.switch_screen(MainScreen())
        if self.vault.kdf_upgraded:
            self.notify("Vault re-encrypted with stronger key protection")

    async def action_lock(self) -> None:
        self._unlock_generation += 1
        if isinstance(self.screen, UnlockScreen):
            self.screen.clear_passwords()
        self.clear_clipboard()
        if not self.vault.unlocked and isinstance(self.screen, UnlockScreen):
            return
        if self._locking:
            return
        self._locking = True
        try:
            # Hide plaintext immediately, before waiting for a password-change
            # worker that may currently hold the vault mutex.
            try:
                while len(self.screen_stack) > 2:
                    await self.pop_screen()
                if not isinstance(self.screen, UnlockScreen):
                    await self.switch_screen(UnlockScreen())
                if isinstance(self.screen, UnlockScreen):
                    self.screen._set_enabled(False)
            except NoMatches:
                # Suppress disappearing lock-screen widgets during teardown,
                # but propagate a failed transition that leaves a live entry
                # screen visible. Textual then exits after the finally block.
                if self.is_running and self.screen.is_attached and not isinstance(self.screen, UnlockScreen):
                    raise
        finally:
            # A UI error must not skip dropping the key and plaintext references.
            try:
                await asyncio.to_thread(self.vault.lock)
            finally:
                self._locking = False
                if self.is_running and isinstance(self.screen, UnlockScreen) and self.screen.is_attached:
                    with suppress(NoMatches):
                        if not self.screen._start_lockout_if_needed():
                            self.screen._set_enabled(True)

    def copy_to_clipboard(self, text: str) -> None:
        # Textual's default implementation sends OSC 52 and retains plaintext
        # in App._clipboard. Editor shortcuts must use our cleanup path too.
        self.copy_secret(text, "Selection")

    def paste_text(self) -> str | None:
        try:
            return clipboard.paste()
        except clipboard.ClipboardError:
            self.notify("Paste refused: the clipboard backend is unavailable.", severity="error")
            return None

    @property
    def clipboard(self) -> str:
        # Read on demand instead of keeping a second, indefinite secret cache.
        value = self.paste_text()
        return value if value is not None else ""

    def copy_secret(self, value: str, label: str) -> bool:
        if "\0" in value:
            self.notify("Copy refused: this value contains a null character.", severity="error")
            return False
        try:
            clipboard.copy(value)
        except clipboard.ClipboardError:
            self.notify("Copy refused: the clipboard backend failed or cannot support automatic clearing.",
                        severity="error", timeout=10)
            return False
        # Only a successful native copy replaces ownership and its timer.
        # A failed copy may have left the previously copied secret untouched.
        if self._clipboard_timer is not None:
            self._clipboard_timer.stop()
            self._clipboard_timer = None
        self._clipboard_value = value
        self._clipboard_retries = 0
        if self.clear_after > 0 and self._clipboard_value is not None:
            self._clipboard_timer = self.set_timer(self.clear_after, self._auto_clear)
            self.notify(f"{label} copied, clears in {self.clear_after}s")
        else:
            self.notify(f"{label} copied to clipboard")
        return True

    def _auto_clear(self) -> None:
        if self.clear_clipboard():
            self.notify("Clipboard cleared")

    def clear_clipboard(self) -> bool:
        """Wipe the clipboard if it still holds what we copied. Returns True if wiped.

        If you've copied something else since, it's left alone.
        """
        if self._clipboard_timer is not None:
            self._clipboard_timer.stop()
            self._clipboard_timer = None
        value = self._clipboard_value
        if value is None:
            return False
        try:
            cleared = clipboard.clear_if_matches(value)
        except clipboard.ClipboardError:
            self._clipboard_retries += 1
            if self.is_running and self._clipboard_retries <= MAX_CLIPBOARD_RETRIES:
                self._clipboard_timer = self.set_timer(1, self._auto_clear)
            else:
                self._clipboard_value = None
                self.notify("Clipboard could not be cleared. Clear it manually.",
                            severity="warning", timeout=15)
            return False
        self._clipboard_value = None
        self._clipboard_retries = 0
        return cleared


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tvault", description="termvault: terminal password manager")
    parser.add_argument("--vault", type=Path, default=default_vault_path(),
                        help="path to the vault file (default: %(default)s)")
    parser.add_argument("--lock-after", type=int, default=DEFAULT_IDLE_LOCK, metavar="SECONDS",
                        help="auto-lock after this many idle seconds, 0 to disable (default: %(default)s)")
    parser.add_argument("--clear-after", type=int, default=DEFAULT_CLIPBOARD_CLEAR, metavar="SECONDS",
                        help="clear copied secrets from the clipboard after this many seconds, "
                             "0 to disable (default: %(default)s)")
    parser.add_argument("--protected", action="store_true",
                        help="require active Microsoft Defender, a protected vault folder and process protection; "
                             "cap idle lock at 60s and clipboard clearing at 10s (Windows)")
    parser.add_argument("--scan-file", type=Path, metavar="PATH",
                        help="run a detection-only Defender scan of one file, then exit (Windows)")
    args = parser.parse_args(argv)
    if args.lock_after < 0 or args.clear_after < 0:
        parser.error("timer values must be nonnegative")
    if args.scan_file is not None:
        try:
            result = scan_file(args.scan_file)
        except ProtectionError as exc:
            print(f"tvault: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(result.message)
        raise SystemExit(0 if result.completed_without_detection else 2)
    if args.protected:
        try:
            require_protection(args.vault.absolute().parent.resolve())
        except ProtectionError as exc:
            print(f"tvault: protected mode refused: {exc}", file=sys.stderr)
            raise SystemExit(2)
    # Before any secret is in memory: keep other programs from reading it.
    try:
        protect_process()
        protection_error = None
    except OSError as exc:
        protection_error = str(exc)
        if args.protected:
            print("tvault: protected mode refused: process memory protection failed.", file=sys.stderr)
            raise SystemExit(2)
    lock = VaultLock(args.vault)
    try:
        lock.acquire()
    except VaultInUseError as exc:
        print(f"tvault: {exc}. Close it there first.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"tvault: storage refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
    app = TermVaultApp(args.vault, idle_lock=args.lock_after, clear_after=args.clear_after,
                       protected_mode=args.protected)
    app.memory_protection_error = protection_error
    app.memory_protection_verified = protection_error is None and sys.platform == "win32"
    try:
        app.run()
    finally:
        app.clear_clipboard()  # don't leave a secret behind on quit
        lock.release()


if __name__ == "__main__":
    main()
