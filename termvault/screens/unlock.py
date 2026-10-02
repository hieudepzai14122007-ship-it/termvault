"""Create-vault / unlock screen."""

from __future__ import annotations

import asyncio
import math

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Button, Input, Label, Static

from ..crypto import DecryptionError
from ..guard import FREE_ATTEMPTS, delay_after
from ..vault import MIN_MASTER_LEN, master_password_problem
from .widgets import strength_meter


class UnlockScreen(Screen):
    def __init__(self) -> None:
        super().__init__()
        self._countdown: Timer | None = None
        self._lockout_prefix = ""

    @property
    def creating(self) -> bool:
        return not self.app.vault.exists()

    def compose(self) -> ComposeResult:
        vault = self.app.vault
        with Vertical(id="unlock-box", classes="dialog"):
            yield Static("termvault", id="unlock-title")
            yield Label(str(vault.path), classes="dim")
            if self.creating:
                yield Label(f"No vault found. Choose a strong master password: at least "
                            f"{MIN_MASTER_LEN} characters, ideally 4 or more random words.")
                yield Input(placeholder="Master password", password=True, id="pw")
                yield Label("", id="master-strength", classes="hint")
                yield Input(placeholder="Confirm master password", password=True, id="pw2")
                yield Button("Create vault", variant="primary", id="go")
            else:
                yield Input(placeholder="Master password", password=True, id="pw")
                yield Button("Unlock", variant="primary", id="go")
            yield Label("", id="unlock-error", classes="errmsg")

    def on_mount(self) -> None:
        self.query_one("#pw", Input).focus()
        if not self.creating:
            self._start_lockout_if_needed()

    def _error(self, msg: str) -> None:
        self.query_one("#unlock-error", Label).update(msg)

    def _set_enabled(self, enabled: bool) -> None:
        self.query_one("#pw", Input).disabled = not enabled
        self.query_one("#go", Button).disabled = not enabled
        if enabled:
            self.query_one("#pw", Input).focus()

    # ---- lockout ---------------------------------------------------------

    def _start_lockout_if_needed(self, prefix: str = "") -> bool:
        if self.app.guard.remaining() <= 0:
            return False
        self._lockout_prefix = prefix
        self._set_enabled(False)
        self._tick_lockout()
        if self._countdown is None:
            self._countdown = self.set_interval(1, self._tick_lockout)
        return True

    def _tick_lockout(self) -> None:
        if not self.is_attached:
            return
        left = self.app.guard.remaining()
        if left <= 0:
            if self._countdown is not None:
                self._countdown.stop()
                self._countdown = None
            self._error(self._lockout_prefix + "You can try again now.")
            self._set_enabled(True)
            return
        failures = self.app.guard.failures
        self._error(f"{self._lockout_prefix}{failures} wrong attempts. "
                    f"Locked for {math.ceil(left)}s.")

    # ---- events ----------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pw" and self.query("#master-strength"):
            self.query_one("#master-strength", Label).update(strength_meter(event.value))

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pw" and self.query("#pw2"):
            self.query_one("#pw2", Input).focus()
        else:
            await self._submit()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "go":
            await self._submit()

    async def _submit(self) -> None:
        vault = self.app.vault
        guard = self.app.guard
        pw_input = self.query_one("#pw", Input)
        pw = pw_input.value
        button = self.query_one("#go", Button)
        if button.disabled:
            return

        if self.creating:
            problem = master_password_problem(pw)
            if problem:
                self._error(problem)
                return
            if pw != self.query_one("#pw2", Input).value:
                self._error("Passwords do not match.")
                return
            action = vault.create
        else:
            if self._start_lockout_if_needed():
                return
            action = vault.unlock

        button.disabled = True
        self._error("Working...")
        if not self.creating:
            # Count the attempt as wrong up front; a successful unlock resets it. That way
            # force-quitting during the check doesn't give a free guess.
            guard.record_failure()
        try:
            # Argon2 is deliberately slow; keep the UI responsive.
            await asyncio.to_thread(action, pw)
        except DecryptionError as exc:
            await asyncio.sleep(1)  # a small fixed cost on every wrong guess
            pw_input.value = ""
            button.disabled = False
            msg = str(exc).capitalize() + ". "
            if not self._start_lockout_if_needed(msg):
                left = FREE_ATTEMPTS - guard.failures
                if left > 0:
                    msg += f"{left} more {'try' if left == 1 else 'tries'} before a lockout."
                else:
                    msg += f"The next wrong attempt locks the vault for {delay_after(guard.failures + 1):.0f}s."
                self._error(msg)
                pw_input.focus()
            return
        except (OSError, ValueError) as exc:
            self._error(f"Error: {exc}")
            button.disabled = False
            return
        except Exception as exc:
            # Never crash here: a crash report from this frame could show the password.
            # Only the error type is shown, never its details.
            pw_input.value = ""
            self._error(f"Unexpected error ({type(exc).__name__}). The vault was not opened.")
            button.disabled = False
            return

        guard.reset()
        weak = action is vault.unlock and master_password_problem(pw) is not None
        self.app.on_unlocked()
        if weak:
            # Vaults made before the strength rule may still have a guessable master password.
            self.app.notify("Your master password is easy to guess. Change it with Ctrl+P.",
                            severity="warning", timeout=15)
