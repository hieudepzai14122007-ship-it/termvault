"""Change the master password (re-encrypts the vault with a new salt and key)."""

from __future__ import annotations

import asyncio

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label

from ..crypto import DecryptionError
from ..vault import MIN_MASTER_LEN, master_password_problem
from .widgets import strength_meter


class ChangeMasterScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Change master password", classes="heading")
            yield Input(placeholder="Current master password", password=True, id="old")
            yield Input(placeholder=f"New master password (min {MIN_MASTER_LEN})", password=True, id="new")
            yield Label("", id="new-strength", classes="hint")
            yield Input(placeholder="Confirm new master password", password=True, id="new2")
            yield Label("", id="cm-error", classes="errmsg")
            with Horizontal(classes="buttons"):
                yield Button("Change", variant="primary", id="go")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#old", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "new":
            self.query_one("#new-strength", Label).update(strength_meter(event.value))

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        order = ["old", "new", "new2"]
        idx = order.index(event.input.id)
        if idx < len(order) - 1:
            self.query_one(f"#{order[idx + 1]}", Input).focus()
        else:
            await self._submit()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "go":
            await self._submit()
        else:
            self.dismiss(False)

    async def _submit(self) -> None:
        old = self.query_one("#old", Input).value
        new = self.query_one("#new", Input).value
        new2 = self.query_one("#new2", Input).value
        error = self.query_one("#cm-error", Label)
        problem = master_password_problem(new)
        if problem:
            error.update(problem)
            return
        if new != new2:
            error.update("New passwords do not match.")
            return
        error.update("Working...")
        try:
            await asyncio.to_thread(self.app.vault.change_master, old, new)
        except DecryptionError:
            await asyncio.sleep(1)
            error.update("Current password is wrong.")
            return
        except (OSError, ValueError) as exc:
            error.update(f"Error: {exc}")
            return
        self.dismiss(True)
