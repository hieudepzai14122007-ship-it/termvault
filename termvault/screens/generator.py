"""Password / passphrase generator modal."""

from __future__ import annotations

import string

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, RadioButton, RadioSet, Static

from .. import generator
from ..health import strength
from .widgets import STRENGTH_STYLES


def colorize(value: str) -> Text:
    t = Text()
    for ch in value:
        if ch in string.digits:
            t.append(ch, style="cyan")
        elif ch in string.ascii_letters:
            t.append(ch)
        else:
            t.append(ch, style="magenta")
    return t


class GeneratorScreen(ModalScreen["str | None"]):
    """Returns the generated value when `can_use` (opened from a form), else None."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+r", "regenerate", "Regenerate"),
        Binding("ctrl+s", "accept", "Use"),
    ]

    def __init__(self, can_use: bool = False) -> None:
        super().__init__()
        self.can_use = can_use
        self.value = ""

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide", id="gen-box"):
            yield Label("Password generator", classes="heading")
            with RadioSet(id="mode"):
                yield RadioButton("Random password", value=True, id="mode-password")
                yield RadioButton("Passphrase (words)", id="mode-passphrase")
            with Vertical(id="pw-opts"):
                with Horizontal(classes="row"):
                    yield Label("Length", classes="field-label")
                    yield Input("20", type="integer", max_length=3, id="length")
                    yield Checkbox("Avoid look-alikes (I l 1 O 0)", False, id="ambiguous")
                with Horizontal(classes="row"):
                    yield Checkbox("a-z", True, id="lower")
                    yield Checkbox("A-Z", True, id="upper")
                    yield Checkbox("0-9", True, id="digits")
                    yield Checkbox("!@#", True, id="symbols")
            with Vertical(id="pp-opts"):
                with Horizontal(classes="row"):
                    yield Label("Words", classes="field-label")
                    yield Input("6", type="integer", max_length=2, id="words")
                    yield Label("Separator", classes="field-label")
                    yield Input("-", max_length=3, id="sep")
                with Horizontal(classes="row"):
                    yield Checkbox("Capitalize", False, id="cap")
                    yield Checkbox("Add a number", False, id="num")
            yield Static(id="gen-output")
            yield Label("", id="gen-info")
            yield Label("", id="gen-error", classes="errmsg")
            with Horizontal(classes="buttons"):
                yield Button("Regenerate (ctrl+r)", id="regen")
                if self.can_use:
                    yield Button("Use (ctrl+s)", variant="primary", id="use")
                else:
                    yield Button("Copy (ctrl+s)", variant="primary", id="copy")
                yield Button("Cancel (esc)", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#pp-opts").display = False
        self.action_regenerate()
        self.query_one("#regen", Button).focus()

    @property
    def passphrase_mode(self) -> bool:
        return self.query_one("#mode-passphrase", RadioButton).value

    def _int(self, selector: str, default: int) -> int:
        try:
            return int(self.query_one(selector, Input).value)
        except ValueError:
            return default

    def action_regenerate(self) -> None:
        error = self.query_one("#gen-error", Label)
        def checked(i: str) -> bool:
            return self.query_one(f"#{i}", Checkbox).value
        try:
            if self.passphrase_mode:
                words = self._int("#words", 6)
                add_number = checked("num")
                self.value = generator.generate_passphrase(
                    words, self.query_one("#sep", Input).value, checked("cap"), add_number)
                bits = generator.passphrase_entropy(words, add_number)
            else:
                opts = dict(lower=checked("lower"), upper=checked("upper"), digits=checked("digits"),
                            symbols=checked("symbols"), avoid_ambiguous=checked("ambiguous"))
                length = self._int("#length", 20)
                self.value = generator.generate_password(length, **opts)
                bits = generator.password_entropy(length, **opts)
        except ValueError as exc:
            error.update(str(exc).capitalize() + ".")
            return
        error.update("")
        self.query_one("#gen-output", Static).update(colorize(self.value))
        s = strength(self.value)
        info = Text(f"{bits:.0f} bits of entropy  ·  ")
        info.append(s.label, style=STRENGTH_STYLES[s.score])
        self.query_one("#gen-info", Label).update(info)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self.query_one("#pw-opts").display = not self.passphrase_mode
        self.query_one("#pp-opts").display = self.passphrase_mode
        self.action_regenerate()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        self.action_regenerate()

    def on_input_changed(self, event: Input.Changed) -> None:
        self.action_regenerate()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "regen":
            self.action_regenerate()
        elif event.button.id in ("use", "copy"):
            self.action_accept()
        else:
            self.action_cancel()

    def action_accept(self) -> None:
        if not self.value:
            return
        if self.can_use:
            self.dismiss(self.value)
        else:
            self.app.copy_secret(self.value, "Generated password")
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
