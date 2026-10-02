"""Textual application entry point."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

import pyperclip
from textual import events
from textual.app import App
from textual.binding import Binding
from textual.timer import Timer

from .guard import AttemptGuard
from .lockfile import VaultInUseError, VaultLock
from .screens.main import MainScreen
from .screens.unlock import UnlockScreen
from .vault import Vault, default_vault_path

DEFAULT_IDLE_LOCK = 300  # seconds
DEFAULT_CLIPBOARD_CLEAR = 20  # seconds

ACTIVITY_EVENTS = (events.Key, events.Paste, events.MouseDown,
                   events.MouseScrollDown, events.MouseScrollUp)


class TermVaultApp(App):
    TITLE = "termvault"
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [Binding("ctrl+l", "lock", "Lock", priority=True)]

    def __init__(self, vault_path: Path, idle_lock: int = DEFAULT_IDLE_LOCK,
                 kdf: dict[str, Any] | None = None,
                 clear_after: int = DEFAULT_CLIPBOARD_CLEAR) -> None:
        super().__init__()
        self.vault = Vault(vault_path, kdf=kdf)
        self.guard = AttemptGuard(vault_path)
        self.idle_lock = idle_lock
        self.clear_after = clear_after
        self._last_activity = time.monotonic()
        self._clipboard_value: str | None = None
        self._clipboard_timer: Timer | None = None

    def on_mount(self) -> None:
        self.push_screen(UnlockScreen())
        if self.idle_lock > 0:
            self.set_interval(5, self._check_idle)

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
        if not self.vault.unlocked:
            return
        self.vault.lock()
        self.clear_clipboard()
        # Drop any open dialogs (edit forms may hold secrets), then show the unlock screen.
        while len(self.screen_stack) > 2:
            await self.pop_screen()
        await self.switch_screen(UnlockScreen())

    def copy_secret(self, value: str, label: str) -> None:
        if self._clipboard_timer is not None:
            self._clipboard_timer.stop()
            self._clipboard_timer = None
        try:
            pyperclip.copy(value)
            self._clipboard_value = value
        except pyperclip.PyperclipException:
            self.copy_to_clipboard(value)  # OSC 52 fallback; can't be read back or cleared
            self._clipboard_value = None
        if self.clear_after > 0 and self._clipboard_value is not None:
            self._clipboard_timer = self.set_timer(self.clear_after, self._auto_clear)
            self.notify(f"{label} copied, clears in {self.clear_after}s")
        else:
            self.notify(f"{label} copied to clipboard")

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
        value, self._clipboard_value = self._clipboard_value, None
        if value is None:
            return False
        try:
            if pyperclip.paste() == value:
                pyperclip.copy("")
                return True
        except pyperclip.PyperclipException:
            pass
        return False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tvault", description="termvault: terminal password manager")
    parser.add_argument("--vault", type=Path, default=default_vault_path(),
                        help="path to the vault file (default: %(default)s)")
    parser.add_argument("--lock-after", type=int, default=DEFAULT_IDLE_LOCK, metavar="SECONDS",
                        help="auto-lock after this many idle seconds, 0 to disable (default: %(default)s)")
    parser.add_argument("--clear-after", type=int, default=DEFAULT_CLIPBOARD_CLEAR, metavar="SECONDS",
                        help="clear copied secrets from the clipboard after this many seconds, "
                             "0 to disable (default: %(default)s)")
    args = parser.parse_args(argv)
    lock = VaultLock(args.vault)
    try:
        lock.acquire()
    except VaultInUseError as exc:
        print(f"tvault: {exc}. Close it there first.", file=sys.stderr)
        sys.exit(1)
    app = TermVaultApp(args.vault, idle_lock=args.lock_after, clear_after=args.clear_after)
    try:
        app.run()
    finally:
        app.clear_clipboard()  # don't leave a secret behind on quit
        lock.release()


if __name__ == "__main__":
    main()
