"""Small rendering helpers shared by several screens."""

from __future__ import annotations

from rich.text import Text

from ..health import strength

STRENGTH_STYLES = ["bold red", "red", "yellow", "green", "bold green"]


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
