"""Add/edit form for a login, secure note, or credit card."""

from __future__ import annotations

import re
import time
from dataclasses import replace

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label

from .. import cards, totp
from ..models import TYPE_LABELS, Entry
from .generator import GeneratorScreen
from .widgets import strength_meter, PrivateInput as Input, PrivateTextArea as TextArea

SECRET_FIELDS = "#password, #totp, #cvv, #pin"


class EditScreen(ModalScreen["Entry | None"]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("ctrl+r", "reveal", "Show/hide secrets"),
        Binding("ctrl+g", "generate", "Generate password"),
    ]

    def __init__(self, entry: Entry) -> None:
        super().__init__()
        self.entry = entry
        self.is_new = not entry.title

    def compose(self) -> ComposeResult:
        e = self.entry
        kind = TYPE_LABELS[e.type].lower()
        heading = f"New {kind}" if self.is_new else f"Edit {kind}"
        with Vertical(classes="dialog wide"):
            yield Label(heading, classes="heading")
            with VerticalScroll(id="form"):
                yield Label("Title")
                yield Input(e.title, id="title")
                if e.type == "login":
                    yield Label("Username")
                    yield Input(e.username, id="username")
                    yield Label("Password  (ctrl+g generate, ctrl+r show/hide)")
                    yield Input(e.password, password=True, id="password")
                    yield Label("", id="strength", classes="hint")
                    yield Label("Website URL")
                    yield Input(e.url, id="url")
                    yield Label("2FA secret (base32 or otpauth:// link, optional)")
                    yield Input(e.totp_secret, password=True, id="totp")
                    yield Label("Notes")
                    yield TextArea(e.notes, id="notes")
                elif e.type == "card":
                    yield Label("Cardholder name")
                    yield Input(e.card_name, id="card_name")
                    yield Label("Card number")
                    yield Input(cards.format_number(e.card_number), id="card_number")
                    yield Label("", id="card-check", classes="hint")
                    with Horizontal(classes="row"):
                        with Vertical(classes="col"):
                            yield Label("Expiry (MM/YY)")
                            yield Input(e.card_expiry, max_length=7, id="expiry")
                        with Vertical(classes="col"):
                            yield Label("CVV")
                            yield Input(e.card_cvv, password=True, max_length=4, id="cvv")
                        with Vertical(classes="col"):
                            yield Label("PIN (optional)")
                            yield Input(e.card_pin, password=True, max_length=12, id="pin")
                    yield Label("Notes")
                    yield TextArea(e.notes, id="notes")
                else:
                    yield Label("Note")
                    yield TextArea(e.body, id="body")
            yield Label("", id="edit-error", classes="errmsg")
            with Horizontal(classes="buttons"):
                yield Button("Save (ctrl+s)", variant="primary", id="save")
                yield Button("Cancel (esc)", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#title", Input).focus()
        self._update_hints()

    # ---- live hints ------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id in ("password", "card_number"):
            self._update_hints()

    def _update_hints(self) -> None:
        if self.entry.type == "login":
            pw = self.query_one("#password", Input).value
            self.query_one("#strength", Label).update(strength_meter(pw))
        elif self.entry.type == "card":
            number = cards.digits_only(self.query_one("#card_number", Input).value)
            label = self.query_one("#card-check", Label)
            if not number:
                label.update("")
            elif cards.luhn_valid(number):
                label.update(Text(f"✓ {cards.brand(number)}, number looks valid", style="green"))
            elif len(number) < 12:
                label.update(Text(f"{cards.brand(number)}...", style="dim"))
            else:
                label.update(Text("✗ Number doesn't pass the check-digit test. Check for a typo.", style="red"))

    # ---- actions ---------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        else:
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_reveal(self) -> None:
        for field in self.query(SECRET_FIELDS).results(Input):
            field.password = not field.password

    def action_generate(self) -> None:
        if self.entry.type != "login":
            return

        def done(value: str | None) -> None:
            if value:
                field = self.query_one("#password", Input)
                field.value = value
                field.focus()

        self.app.push_screen(GeneratorScreen(can_use=True), done)

    def _fail(self, message: str, selector: str) -> None:
        self.query_one("#edit-error", Label).update(message)
        self.query_one(selector).focus()

    def action_save(self) -> None:
        def val(selector: str) -> str:
            return self.query_one(selector, Input).value

        title = val("#title").strip()
        if not title:
            return self._fail("Title is required.", "#title")

        if self.entry.type == "login":
            secret = val("#totp").strip()
            if secret:
                if not totp.validate_secret(secret):
                    return self._fail("2FA must be valid base32 or a TOTP link using SHA1, "
                                      "6 digits and a 30-second period.", "#totp")
                secret = totp.normalize_secret(secret)
            password = val("#password")
            result = replace(
                self.entry,
                title=title,
                username=val("#username").strip(),
                password=password,
                url=val("#url").strip(),
                totp_secret=secret,
                notes=self.query_one("#notes", TextArea).text,
            )
            if password != self.entry.password:
                result.password_changed = time.time()
        elif self.entry.type == "card":
            number = cards.digits_only(val("#card_number"))
            if number and not cards.luhn_valid(number):
                return self._fail("Card number doesn't pass the check-digit test.", "#card_number")
            expiry = val("#expiry").strip()
            if expiry:
                try:
                    expiry = cards.normalize_expiry(expiry)
                except ValueError:
                    return self._fail("Expiry must look like MM/YY.", "#expiry")
            cvv, pin = val("#cvv").strip(), val("#pin").strip()
            if cvv and not re.fullmatch(r"\d{3,4}", cvv):
                return self._fail("CVV must be 3 or 4 digits.", "#cvv")
            if pin and not re.fullmatch(r"\d{4,12}", pin):
                return self._fail("PIN must be 4 to 12 digits.", "#pin")
            result = replace(
                self.entry,
                title=title,
                card_name=val("#card_name").strip(),
                card_number=number,
                card_expiry=expiry,
                card_cvv=cvv,
                card_pin=pin,
                notes=self.query_one("#notes", TextArea).text,
            )
        else:
            result = replace(self.entry, title=title, body=self.query_one("#body", TextArea).text)
        self.dismiss(result)
