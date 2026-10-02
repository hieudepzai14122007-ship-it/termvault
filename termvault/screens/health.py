"""Password health report: weak, reused, and old passwords, plus expiring cards."""

from __future__ import annotations

from collections import Counter

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Label, Static

from ..health import audit

KIND_LABELS = {
    "expired": ("Expired card", "bold red"),
    "reused": ("Reused", "bold red"),
    "weak": ("Weak", "red"),
    "expiring": ("Expiring card", "yellow"),
    "old": ("Old", "yellow"),
}


class HealthScreen(ModalScreen["str | None"]):
    """Returns the id of the entry the user picked, or None."""

    BINDINGS = [Binding("escape,q", "close", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label("Password health", classes="heading")
            yield Static(id="health-summary")
            yield DataTable(id="health-table", cursor_type="row", zebra_stripes=True)
            yield Label("Enter: go to entry  ·  Esc: close", classes="dim")

    def on_mount(self) -> None:
        entries = self.app.vault.entries()
        self.issues = audit(entries)
        table = self.query_one("#health-table", DataTable)
        summary = self.query_one("#health-summary", Static)

        checked = [e for e in entries if (e.type == "login" and e.password) or e.type == "card"]
        flagged = {i.entry_id for i in self.issues}
        if not checked:
            summary.update(Text("Nothing to check yet: add a login or a card.", style="dim"))
            table.display = False
            return

        score = round(100 * (len(checked) - len(flagged)) / len(checked))
        style = "bold green" if score >= 90 else "bold yellow" if score >= 60 else "bold red"
        text = Text("Health score ")
        text.append(f"{score}%", style=style)
        text.append(f"   {len(checked) - len(flagged)} of {len(checked)} items have no problems\n")
        counts = Counter(i.kind for i in self.issues)
        for kind, (label, kstyle) in KIND_LABELS.items():
            if counts[kind]:
                text.append(f"{counts[kind]} {label.lower()}", style=kstyle)
                text.append("   ")
        summary.update(text)

        if not self.issues:
            table.display = False
            summary.update(text + Text("\n\nNo weak, reused or old passwords. Nice.", style="green"))
            return
        table.add_columns("Entry", "Issue", "Detail")
        for i, issue in enumerate(self.issues):
            label, kstyle = KIND_LABELS[issue.kind]
            table.add_row(issue.title, Text(label, style=kstyle), issue.detail, key=str(i))
        table.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.dismiss(self.issues[int(event.row_key.value)].entry_id)

    def action_close(self) -> None:
        self.dismiss(None)
