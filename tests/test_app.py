"""End-to-end UI tests using Textual's Pilot."""

import json
import time

from textual.widgets import Input, ListView, Static, TextArea

from termvault.app import TermVaultApp
from termvault.screens.confirm import ConfirmScreen
from termvault.screens.edit import EditScreen
from termvault.screens.main import MainScreen
from termvault.screens.unlock import UnlockScreen
from termvault.vault import Vault
from conftest import FAST_KDF, MASTER

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


async def wait_for(pilot, cond, timeout=10.0):
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise AssertionError("timed out waiting for UI condition")
        await pilot.pause(0.05)


def entry_titles(app):
    return [e.title for e in app.vault.entries()]


def detail_text(app):
    return str(app.screen.query_one("#detail-body", Static).render())


async def create_vault(pilot):
    app = pilot.app
    await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
    app.screen.query_one("#pw", Input).value = MASTER
    app.screen.query_one("#pw2", Input).value = MASTER
    app.screen.query_one("#pw2", Input).focus()
    await pilot.press("enter")
    await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))


async def test_full_flow(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    copied = []
    app.copy_secret = lambda value, label: copied.append((label, value))

    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        assert vault_path.exists()

        # Add a login via the form.
        await pilot.press("n")
        await wait_for(pilot, lambda: isinstance(app.screen, EditScreen))
        s = app.screen
        s.query_one("#title", Input).value = "GitHub"
        s.query_one("#username", Input).value = "octocat"
        s.query_one("#password", Input).value = "s3cret-pass"
        s.query_one("#url", Input).value = "https://github.com"
        s.query_one("#totp", Input).value = RFC_SECRET.lower()
        s.query_one("#notes", TextArea).text = "work account"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        await wait_for(pilot, lambda: len(app.screen.query_one("#entries", ListView).children) == 1)
        assert entry_titles(app) == ["GitHub"]

        # Password masked by default, revealed with "s"; 2FA code shown.
        text = detail_text(app)
        assert "octocat" in text and "s3cret-pass" not in text and "2FA code" in text
        await pilot.press("s")
        assert "s3cret-pass" in detail_text(app)

        # Copy password, username, TOTP.
        await pilot.press("c", "u", "t")
        labels = [l for l, _ in copied]
        assert labels == ["Password", "Username", "2FA code"]
        assert copied[0][1] == "s3cret-pass" and copied[1][1] == "octocat"
        assert len(copied[2][1]) == 6 and copied[2][1].isdigit()

        # Add a secure note.
        await pilot.press("N")
        await wait_for(pilot, lambda: isinstance(app.screen, EditScreen))
        app.screen.query_one("#title", Input).value = "Wifi"
        app.screen.query_one("#body", TextArea).text = "SSID home"
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        await wait_for(pilot, lambda: len(app.screen.query_one("#entries", ListView).children) == 2)

        # Search filters the list.
        await pilot.press("slash", "w", "i", "f")
        await wait_for(pilot, lambda: len(app.screen.query_one("#entries", ListView).children) == 1)
        await pilot.press("escape")  # back to the list
        assert "SSID home" not in detail_text(app)  # hidden until revealed
        await pilot.press("s")
        assert "SSID home" in detail_text(app)
        app.screen.query_one("#search", Input).value = ""
        await wait_for(pilot, lambda: len(app.screen.query_one("#entries", ListView).children) == 2)

        # Lock, then unlock with the wrong and right password.
        await pilot.press("ctrl+l")
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        assert not app.vault.unlocked
        app.screen.query_one("#pw", Input).value = "definitely wrong"
        await pilot.press("enter")
        await wait_for(pilot, lambda: "wrong password" in str(app.screen.query_one("#unlock-error").render()).lower(), timeout=15)
        app.screen.query_one("#pw", Input).value = MASTER
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        assert sorted(entry_titles(app)) == ["GitHub", "Wifi"]

        # Delete with confirmation.
        await wait_for(pilot, lambda: len(app.screen.query_one("#entries", ListView).children) == 2)
        await pilot.press("d")
        await wait_for(pilot, lambda: isinstance(app.screen, ConfirmScreen))
        await pilot.press("y")
        await wait_for(pilot, lambda: len(app.vault.entries()) == 1)

    # Everything persisted to disk.
    v = Vault(vault_path, kdf=FAST_KDF)
    v.unlock(MASTER)
    assert len(v.entries()) == 1


async def test_lock_closes_open_dialog(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        await pilot.press("n")
        await wait_for(pilot, lambda: isinstance(app.screen, EditScreen))
        await pilot.press("ctrl+l")
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        assert len(app.screen_stack) == 2


async def test_idle_auto_lock(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=300)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        app._last_activity -= 1000  # pretend we've been idle
        app._check_idle()
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        assert not app.vault.unlocked


async def test_create_mismatch(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        app.screen.query_one("#pw", Input).value = MASTER
        app.screen.query_one("#pw2", Input).value = MASTER + "x"
        app.screen.query_one("#pw2", Input).focus()
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, UnlockScreen)
        assert not vault_path.exists()


# ---- cards, clipboard, generator, health ---------------------------------

from textual.widgets import DataTable, Label

from termvault.models import new_login
from termvault.screens.generator import GeneratorScreen
from termvault.screens.health import HealthScreen


def entry_count(app):
    return len(app.screen.query_one("#entries", ListView).children)


async def test_card_flow(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    copied = []
    app.copy_secret = lambda value, label: copied.append((label, value))
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        await pilot.press("k")
        await wait_for(pilot, lambda: isinstance(app.screen, EditScreen))
        s = app.screen
        s.query_one("#title", Input).value = "Test Visa"
        s.query_one("#card_name", Input).value = "Jane Doe"
        s.query_one("#card_number", Input).value = "4111 1111 1111 1112"  # bad check digit
        s.query_one("#expiry", Input).value = "9/2030"
        s.query_one("#cvv", Input).value = "123"
        await pilot.pause(0.1)
        assert "check-digit" in str(s.query_one("#card-check", Label).render())
        await pilot.press("ctrl+s")
        await pilot.pause(0.1)
        assert isinstance(app.screen, EditScreen)  # rejected
        assert "check-digit" in str(s.query_one("#edit-error", Label).render())

        s.query_one("#card_number", Input).value = "4111 1111 1111 1111"
        await pilot.pause(0.1)
        assert "Visa" in str(s.query_one("#card-check", Label).render())
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        await wait_for(pilot, lambda: entry_count(app) == 1)

        card = app.vault.entries()[0]
        assert card.card_number == "4111111111111111" and card.card_expiry == "09/30"
        text = detail_text(app)
        assert "•••• 1111" in text and "Visa" in text and "123" not in text
        await pilot.press("s")
        assert "4111 1111 1111 1111" in detail_text(app) and "123" in detail_text(app)

        await pilot.press("c", "u", "v")
        assert copied == [("Card number", "4111111111111111"), ("Cardholder name", "Jane Doe"), ("CVV", "123")]


class FakeClipboard:
    def __init__(self):
        self.value = ""

    def copy(self, v):
        self.value = v

    def paste(self):
        return self.value

    def clear(self):
        self.value = ""


async def test_clipboard_auto_clear(vault_path, monkeypatch):
    from termvault import clipboard
    clip = FakeClipboard()
    monkeypatch.setattr(clipboard, "copy", clip.copy)
    monkeypatch.setattr(clipboard, "paste", clip.paste)
    monkeypatch.setattr(clipboard, "clear", clip.clear)

    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0, clear_after=0.3)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        app.vault.add(new_login("Site", "me", "pw-to-clear"))
        app.screen.reload()
        await wait_for(pilot, lambda: entry_count(app) == 1)

        await pilot.press("c")
        assert clip.value == "pw-to-clear"
        await wait_for(pilot, lambda: clip.value == "", timeout=3)

        # If the user copies something else meanwhile, leave it alone.
        await pilot.press("c")
        clip.value = "user's own text"
        await pilot.pause(0.6)
        assert clip.value == "user's own text"

        # Locking clears it immediately.
        app.clear_after = 60
        await pilot.press("u")
        assert clip.value == "me"
        await pilot.press("ctrl+l")
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        assert clip.value == ""


async def test_warns_when_memory_protection_is_off(vault_path, monkeypatch):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    app.memory_protection_error = "memory protection: SetSecurityInfo failed (error 5)"
    seen = []
    monkeypatch.setattr(app, "notify", lambda message, **kw: seen.append(message))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
    assert any("Memory protection is off" in m for m in seen)


async def test_generator_fills_password_field(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        await pilot.press("n")
        await wait_for(pilot, lambda: isinstance(app.screen, EditScreen))
        await pilot.press("ctrl+g")
        await wait_for(pilot, lambda: isinstance(app.screen, GeneratorScreen))
        gen = app.screen
        first = gen.value
        assert len(first) == 20
        await pilot.press("ctrl+r")
        assert gen.value != first
        # Switch to passphrase mode.
        gen.query_one("#mode-passphrase").value = True
        await pilot.pause(0.1)
        assert len(gen.value.split("-")) == 6
        generated = gen.value
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, EditScreen))
        assert app.screen.query_one("#password", Input).value == generated
        assert "Strength" in str(app.screen.query_one("#strength", Label).render())


async def test_generator_from_main_copies(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    copied = []
    app.copy_secret = lambda value, label: copied.append((label, value))
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        await pilot.press("g")
        await wait_for(pilot, lambda: isinstance(app.screen, GeneratorScreen))
        value = app.screen.value
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        assert copied == [("Generated password", value)]


async def test_health_screen_jumps_to_entry(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        app.vault.add(new_login("Alpha strong", password="x7#Kp2!qLm9@vR4z"))
        weak = app.vault.add(new_login("Zulu weak", password="password1"))
        app.screen.reload()
        await wait_for(pilot, lambda: entry_count(app) == 2)

        await pilot.press("h")
        await wait_for(pilot, lambda: isinstance(app.screen, HealthScreen))
        table = app.screen.query_one("#health-table", DataTable)
        assert table.row_count == 1
        assert "50%" in str(app.screen.query_one("#health-summary").render())
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        await wait_for(pilot, lambda: app.screen.selected_id == weak.id)
        assert "Zulu weak" in detail_text(app)


# ---- reveal button & lockout ----------------------------------------------

from textual.widgets import Button

from termvault.guard import FREE_ATTEMPTS
from termvault.models import new_note


async def test_notes_hidden_until_revealed(vault_path, monkeypatch):
    monkeypatch.setattr(MainScreen, "REVEAL_SECONDS", 1)
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        app.vault.add(new_note("Diary", "my secret thoughts"))
        app.vault.add(new_login("Site", "me", "pw-123", notes="security answer: blue"))
        app.screen.reload()
        await wait_for(pilot, lambda: entry_count(app) == 2)

        # Note body hidden by default; clicking the Reveal button shows it.
        assert "my secret thoughts" not in detail_text(app) and "hidden" in detail_text(app)
        await pilot.click("#reveal")
        assert "my secret thoughts" in detail_text(app)
        assert "auto-hides" in str(app.screen.query_one("#reveal", Button).label)
        # ...and it hides itself again.
        await wait_for(pilot, lambda: "my secret thoughts" not in detail_text(app), timeout=4)
        assert str(app.screen.query_one("#reveal", Button).label) == "Reveal (s)"

        # Login notes are hidden too, and moving to another entry re-hides.
        await pilot.press("s")
        assert "my secret thoughts" in detail_text(app)
        await pilot.press("down")
        await wait_for(pilot, lambda: "Site" in detail_text(app))
        assert "security answer" not in detail_text(app) and "pw-123" not in detail_text(app)
        await pilot.press("s")
        assert "security answer: blue" in detail_text(app) and "pw-123" in detail_text(app)


async def test_lockout_after_wrong_attempts(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        await pilot.press("ctrl+l")
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        error = lambda: str(app.screen.query_one("#unlock-error").render())

        # Pretend the free attempts are used up, then miss once more.
        for _ in range(FREE_ATTEMPTS):
            app.guard.record_failure()
        app.screen.query_one("#pw", Input).value = "definitely wrong"
        await pilot.press("enter")
        await wait_for(pilot, lambda: "Locked for" in error(), timeout=5)
        assert app.screen.query_one("#pw", Input).disabled

        # Even the right password is refused while locked out.
        app.screen.query_one("#pw", Input).value = MASTER
        await app.screen._submit()
        assert isinstance(app.screen, UnlockScreen) and not app.vault.unlocked
        assert app.screen.query_one("#pw", Input).disabled

        # When the lockout ends, the right password works and the counter resets.
        # (Fast-forward the guard's clock past the 30s lockout instead of waiting.)
        import types, time as real_time
        import termvault.guard as guard_module
        guard_module.time = types.SimpleNamespace(time=lambda: real_time.time() + 31)
        try:
            await wait_for(pilot, lambda: not app.screen.query_one("#pw", Input).disabled, timeout=5)
            app.screen.query_one("#pw", Input).value = MASTER
            await pilot.press("enter")
            await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
        finally:
            guard_module.time = real_time
        assert app.guard.failures == 0


async def test_create_rejects_weak_master(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        pw = app.screen.query_one("#pw", Input)
        pw.focus()
        await pilot.press(*"password123456")
        await pilot.pause(0.1)
        assert "Very weak" in str(app.screen.query_one("#master-strength").render()) \
            or "Weak" in str(app.screen.query_one("#master-strength").render())
        app.screen.query_one("#pw2", Input).value = "password123456"
        app.screen.query_one("#pw2", Input).focus()
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert "Too easy to guess" in str(app.screen.query_one("#unlock-error").render())
        assert not vault_path.exists()


async def test_restart_does_not_reset_lockout(vault_path):
    async def session():
        app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
        async with app.run_test(size=(120, 40)) as pilot:
            await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
            await pilot.pause(0.1)
            return app, app.screen

    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        for i in range(FREE_ATTEMPTS + 1):
            app.screen.query_one("#pw", Input).value = f"wrong {i}"
            await app.screen._submit()
        assert app.screen.query_one("#pw", Input).disabled

    # Quit and start again: still locked, and the right password can't get in.
    app2 = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app2.run_test(size=(120, 40)) as pilot:
        await wait_for(pilot, lambda: isinstance(app2.screen, UnlockScreen))
        await pilot.pause(0.1)
        assert app2.screen.query_one("#pw", Input).disabled
        assert "Locked for" in str(app2.screen.query_one("#unlock-error").render())
        app2.screen.query_one("#pw", Input).value = MASTER
        await app2.screen._submit()
        assert not app2.vault.unlocked


async def test_attempt_counted_before_check(vault_path):
    """Force-quitting during the password check must not give a free guess."""
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    seen = []
    real_unlock = app.vault.unlock

    def spy_unlock(pw, *a, **kw):
        seen.append(app.guard.failures)  # what's on disk while the check is running
        return real_unlock(pw, *a, **kw)

    app.vault.unlock = spy_unlock
    async with app.run_test(size=(120, 40)) as pilot:
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        app.screen.query_one("#pw", Input).value = "wrong"
        await app.screen._submit()
        app.screen.query_one("#pw", Input).value = MASTER
        await app.screen._submit()
        await wait_for(pilot, lambda: isinstance(app.screen, MainScreen))
    assert seen == [1, 2]  # already counted while checking
    assert app.guard.failures == 0  # reset after the right password


async def test_mouse_movement_does_not_count_as_activity(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=300)
    async with app.run_test(size=(120, 40)) as pilot:
        await create_vault(pilot)
        app._last_activity = 0.0
        await pilot.hover("#detail", offset=(5, 5))
        await pilot.hover("#detail", offset=(20, 10))
        await pilot.pause(0.1)
        assert app._last_activity == 0.0
        await pilot.press("down")
        assert app._last_activity > 0.0


async def test_tampered_vault_shows_error_not_crash(vault_path):
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    doc = json.loads(vault_path.read_text())
    doc["kdf"]["time_cost"] = 0
    vault_path.write_text(json.dumps(doc))
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    async with app.run_test(size=(120, 40)) as pilot:
        await wait_for(pilot, lambda: isinstance(app.screen, UnlockScreen))
        app.screen.query_one("#pw", Input).value = MASTER
        await app.screen._submit()
        assert "invalid key settings" in str(app.screen.query_one("#unlock-error").render())
        assert not app.vault.unlocked
