"""Small rendering helpers shared by several screens."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Input, TextArea

from ..health import strength

STRENGTH_STYLES = ["bold red", "red", "yellow", "green", "bold green"]


class PrivateInput(Input):
    """Do not delete a selection when its clipboard copy/paste was refused."""

    def action_cut(self) -> None:
        if self.selected_text and self.app.copy_secret(self.selected_text, "Selection"):
            self.delete_selection()

    def action_paste(self) -> None:
        value = self.app.paste_text()
        if value:
            self.replace(value, *self.selection)


class PrivateTextArea(TextArea):
    def action_cut(self) -> None:
        if self.read_only:
            return
        start, end = sorted(self.selection)
        if start == end:
            # Match Textual's cut-current-line shortcut, including the newline.
            start, end = (start[0], 0), (start[0] + 1, 0)
        text = self.document.get_text_range(start, end)
        if text and self.app.copy_secret(text, "Selection"):
            result = self.delete(start, end)
            self.move_cursor(result.end_location)

    def action_paste(self) -> None:
        if self.read_only:
            return
        value = self.app.paste_text()
        if value:
            result = self.replace(value, *self.selection)
            self.move_cursor(result.end_location)


def strength_meter(password: str) -> Text:
    """A one-line bar like "Strength ███░░ Good  <warning>", or empty for no password."""
    if not password:
        return Text("")
    s = strength(password)
    bar = "█" * (s.score + 1) + "░" * (4 - s.score)
    text = Text("Strength ")
    text.append(f"{bar} {s.label}", style=STRENGTH_STYLES[s.score])
    if s.warning:
        text.append(f"  {s.warning}", style="dim")
    return text
