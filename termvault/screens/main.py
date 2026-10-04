"""Main screen: searchable entry list on the left, details on the right."""

from __future__ import annotations

import time

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Button, Footer, Label, ListItem, ListView, Static

from .. import cards, totp
from ..health import strength
from ..models import TYPE_LABELS, Entry, new_card, new_login, new_note
from ..crypto import DecryptionError
from ..vault import VaultLockedError
from .change_master import ChangeMasterScreen
from .confirm import ConfirmScreen
from .edit import EditScreen
from .generator import GeneratorScreen
from .health import HealthScreen
from .widgets import STRENGTH_STYLES, PrivateInput as Input

MASK = "•" * 10
ICONS = {"login": "\U0001F511", "note": "\U0001F4DD", "card": "\U0001F4B3"}
HIDDEN = "•" * 8 + "  hidden"
KEY_HINTS = {
    "login": "c copy password · u copy username · t copy 2FA code · s reveal",
    "card": "c copy number · u copy name · v copy CVV · s reveal",
    "note": "s reveal · e edit",
}


class EntryItem(ListItem):
    def __init__(self, entry: Entry) -> None:
        star = "★ " if entry.favorite else ""
        label = Text(f"{ICONS[entry.type]} {star}")
        label.append(entry.title)
        super().__init__(Label(label))
        self.entry_id = entry.id


def render_entry(e: Entry, show_secret: bool) -> Text:
    t = Text()
    t.append(("★ " if e.favorite else "") + e.title, style="bold")
    t.append("\n" + TYPE_LABELS[e.type] + "\n\n", style="dim")

    def label(name: str) -> None:
        t.append(f"{name:<10}", style="bold cyan")

    def row(name: str, value: str, style: str = "") -> None:
        label(name)
        t.append(value or "—", style=style if value else "dim")
        t.append("\n")

    def secret(value: str, mask: str = MASK) -> str:
        return (value if show_secret else mask) if value else ""

    if e.type == "login":
        row("Username", e.username)
        row("Password", secret(e.password))
        if e.password:
            s = strength(e.password)
            row("Strength", s.label, STRENGTH_STYLES[s.score])
        row("Website", e.url, "underline")
        if e.totp_secret:
            if not show_secret:
                row("2FA code", HIDDEN, "dim")
            else:
                try:
                    code, left = totp.current_code(e.totp_secret)
                    label("2FA code")
                    t.append(f"{code[:3]} {code[3:]}", style="bold green" if left > 5 else "bold red")
                    t.append(f"  ({left}s)\n", style="dim")
                except Exception:
                    row("2FA code", "invalid secret", "red")
    elif e.type == "card":
        row("Name", e.card_name)
        number = cards.format_number(e.card_number) if show_secret else cards.mask_number(e.card_number)
        row("Number", number if e.card_number else "")
        row("Brand", cards.brand(e.card_number))
        label("Expires")
        if e.card_expiry:
            t.append(e.card_expiry)
            status = cards.expiry_status(e.card_expiry)
            if status == "expired":
                t.append("  expired", style="bold red")
            elif status == "soon":
                t.append("  expires soon", style="yellow")
        else:
            t.append("—", style="dim")
        t.append("\n")
        row("CVV", secret(e.card_cvv, "•••"))
        row("PIN", secret(e.card_pin, "••••"))
    else:
        if not e.body:
            t.append("(empty)\n", style="dim")
        elif show_secret:
            t.append(e.body + "\n")
        else:
            t.append(HIDDEN + "\n", style="dim")

    if e.type != "note" and e.notes:
        t.append("\nNotes\n", style="bold cyan")
        if show_secret:
            t.append(e.notes + "\n")
        else:
            t.append(HIDDEN + "\n", style="dim")

    t.append("\nUpdated " + time.strftime("%Y-%m-%d %H:%M", time.localtime(e.updated)), style="dim")
    t.append("\n\n" + KEY_HINTS[e.type], style="dim italic")
    return t


class MainScreen(Screen):
    BINDINGS = [
        Binding("n", "new_login", "New login"),
        Binding("N", "new_note", "New note"),
        Binding("k", "new_card", "New card"),
        Binding("e", "edit", "Edit"),
        Binding("d", "delete", "Delete"),
        Binding("c", "copy_primary", "Copy"),
        Binding("s", "toggle_show", "Reveal"),
        Binding("g", "generator", "Generate"),
        Binding("h", "health", "Health"),
        Binding("q", "app.quit", "Quit"),
        Binding("u", "copy_secondary", "Copy user/name", show=False),
        Binding("t", "copy_totp", "Copy 2FA", show=False),
        Binding("v", "copy_cvv", "Copy CVV", show=False),
        Binding("f", "favorite", "Fav", show=False),
        Binding("slash", "focus_search", "Search", show=False),
        Binding("ctrl+p", "change_master", "Master pw", show=False),
    ]

    REVEAL_SECONDS = 30  # revealed secrets hide themselves again after this long

    def __init__(self) -> None:
        super().__init__()
        self.selected_id: str | None = None
        self.show_secret = False
        self._hide_at = 0.0

    @property
    def vault(self):
        return self.app.vault

    def compose(self) -> ComposeResult:
        # A plain title bar rather than textual's Header, whose delayed title update
        # crashes if the screen is removed right away (e.g. auto-lock just after unlock).
        yield Static("termvault", id="titlebar")
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Input(placeholder="/ Search...", id="search")
                yield ListView(id="entries")
            with VerticalScroll(id="detail"):
                yield Static(id="detail-body")
                yield Button("Reveal (s)", id="reveal")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)
        self.reload()
        try:
            self.query_one("#entries", ListView).focus()
        except NoMatches:
            pass  # removed as soon as it opened (locked or quit right after unlocking)

    # ---- list & detail ---------------------------------------------------

    def reload(self, select_id: str | None = None) -> None:
        self.run_worker(self._reload(select_id), exclusive=True, group="reload")

    async def _reload(self, select_id: str | None) -> None:
        # Locking can tear this screen down at any await below; stop quietly if so.
        try:
            await self._do_reload(select_id)
        except NoMatches:
            pass

    async def _do_reload(self, select_id: str | None) -> None:
        if not self.vault.unlocked:
            return
        query = self.query_one("#search", Input).value
        entries = self.vault.entries(query)
        lv = self.query_one("#entries", ListView)
        await lv.clear()
        await lv.extend(EntryItem(e) for e in entries)
        if not self.is_attached or not self.vault.unlocked:
            return
        target = select_id or self.selected_id
        ids = [e.id for e in entries]
        if entries:
            lv.index = ids.index(target) if target in ids else 0
            self._select(ids[lv.index])
        else:
            self._select(None)

    def _select(self, entry_id: str | None) -> None:
        if entry_id != self.selected_id:
            self.show_secret = False
        self.selected_id = entry_id
        self._render_detail()

    def _current(self) -> Entry | None:
        if self.selected_id is None or not self.vault.unlocked:
            return None
        try:
            return self.vault.get(self.selected_id)
        except KeyError:
            return None

    def _render_detail(self) -> None:
        try:
            body = self.query_one("#detail-body", Static)
            button = self.query_one("#reveal", Button)
        except NoMatches:
            return  # screen is being torn down (the vault just locked)
        e = self._current()
        button.display = e is not None
        if e is None:
            if self.query_one("#search", Input).value:
                body.update(Text("No matches.", style="dim"))
            else:
                body.update(Text("Your vault is empty.\n\nPress n to add a login, N for a secure note, "
                                 "or k for a credit card.", style="dim"))
            return
        body.update(render_entry(e, self.show_secret))
        if self.show_secret:
            left = max(0, round(self._hide_at - time.monotonic()))
            button.label = f"Hide (s), auto-hides in {left}s"
            button.variant = "warning"
        else:
            button.label = "Reveal (s)"
            button.variant = "default"

    def _tick(self) -> None:
        if not self.is_attached:
            return
        if self.show_secret and time.monotonic() >= self._hide_at:
            self.show_secret = False
            self._render_detail()
            return
        e = self._current()
        if e is not None and (e.totp_secret or self.show_secret):
            self._render_detail()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "reveal":
            self.action_toggle_show()
            self.query_one("#entries", ListView).focus()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if isinstance(event.item, EntryItem):
            self._select(event.item.entry_id)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.action_edit()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self.reload()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search":
            self.query_one("#entries", ListView).focus()

    def on_key(self, event) -> None:
        search = self.query_one("#search", Input)
        if search.has_focus and event.key in ("escape", "down"):
            self.query_one("#entries", ListView).focus()
            event.stop()

    # ---- actions ---------------------------------------------------------

    def _save(self, fn, *args) -> bool:
        try:
            fn(*args)
            return True
        except (OSError, ValueError, DecryptionError, VaultLockedError) as exc:
            self.notify(f"Could not save vault: {exc}", severity="error")
            if not self.vault.unlocked:
                self.app.run_worker(self.app.action_lock())
            return False

    def _open_editor(self, entry: Entry, is_new: bool) -> None:
        def done(result: Entry | None) -> None:
            if result is None or not self.vault.unlocked:
                return
            if self._save(self.vault.add if is_new else self.vault.update, result):
                self.notify(f"Saved '{result.title}'")
                self.reload(result.id)

        self.app.push_screen(EditScreen(entry), done)

    def action_new_login(self) -> None:
        self._open_editor(new_login(""), is_new=True)

    def action_new_note(self) -> None:
        self._open_editor(new_note(""), is_new=True)

    def action_new_card(self) -> None:
        self._open_editor(new_card(""), is_new=True)

    def action_edit(self) -> None:
        e = self._current()
        if e:
            self._open_editor(Entry.from_dict(e.to_dict()), is_new=False)

    def action_delete(self) -> None:
        e = self._current()
        if not e:
            return

        def done(yes: bool | None) -> None:
            if yes and self.vault.unlocked:
                if self._save(self.vault.delete, e.id):
                    self.notify(f"Deleted '{e.title}'")
                    self.selected_id = None
                    self.reload()

        self.app.push_screen(ConfirmScreen(f"Delete '{e.title}'? This cannot be undone."), done)

    def _copy(self, value: str, label: str) -> None:
        if not value:
            self.notify(f"No {label.lower()} to copy", severity="warning")
            return
        self.app.copy_secret(value, label)

    def action_copy_primary(self) -> None:
        e = self._current()
        if e and e.type == "login":
            self._copy(e.password, "Password")
        elif e and e.type == "card":
            self._copy(e.card_number, "Card number")

    def action_copy_secondary(self) -> None:
        e = self._current()
        if e and e.type == "login":
            self._copy(e.username, "Username")
        elif e and e.type == "card":
            self._copy(e.card_name, "Cardholder name")

    def action_copy_totp(self) -> None:
        e = self._current()
        if e and e.type == "login":
            try:
                code = totp.current_code(e.totp_secret)[0] if e.totp_secret else ""
            except ValueError:
                self.notify("Cannot copy 2FA code: edit the invalid or unsupported secret.", severity="error")
                return
            self._copy(code, "2FA code")

    def action_copy_cvv(self) -> None:
        e = self._current()
        if e and e.type == "card":
            self._copy(e.card_cvv, "CVV")

    def action_toggle_show(self) -> None:
        if self._current() is None:
            return
        self.show_secret = not self.show_secret
        self._hide_at = time.monotonic() + self.REVEAL_SECONDS
        self._render_detail()

    def action_favorite(self) -> None:
        e = self._current()
        if e and self._save(self.vault.toggle_favorite, e.id):
            self.reload(e.id)

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_change_master(self) -> None:
        def done(changed: bool | None) -> None:
            if changed:
                self.notify("Master password changed")

        self.app.push_screen(ChangeMasterScreen(), done)

    def action_generator(self) -> None:
        self.app.push_screen(GeneratorScreen(can_use=False))

    def action_health(self) -> None:
        def done(entry_id: str | None) -> None:
            if not entry_id or not self.vault.unlocked:
                return
            self.selected_id = entry_id
            self.query_one("#search", Input).value = ""
            self.reload(entry_id)
            self.query_one("#entries", ListView).focus()

        self.app.push_screen(HealthScreen(), done)
