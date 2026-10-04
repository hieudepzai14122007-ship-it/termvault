"""Windows ACL policy and secret-exposure regressions (synthetic data only)."""

import ctypes
import os
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from textual.widgets import Static

from termvault import clipboard, fileio, totp, windows_permissions as wp
from termvault.app import TermVaultApp
from termvault.models import new_login, new_note
from termvault.screens.edit import EditScreen
from termvault.screens.main import MainScreen, render_entry
from termvault.vault import Vault
from conftest import FAST_KDF, MASTER

USER = "S-1-5-21-100-200-300-1001"
OTHER = "S-1-5-21-100-200-300-1002"
EVERYONE = "S-1-1-0"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def private_security(user=USER):
    return wp.Security(user, wp.SE_DACL_PROTECTED,
                       (wp.Ace(0, 0, wp.FILE_ALL_ACCESS, user),
                        wp.Ace(0, 0, wp.FILE_ALL_ACCESS, wp.SYSTEM_SID)))


@pytest.mark.parametrize("mutation", [0x2, 0x4, 0x10, 0x40, 0x100, 0x10000,
                                      0x40000, 0x80000, 0x10000000, 0x40000000])
def test_other_account_cannot_modify_storage_directory(mutation):
    security = wp.Security(USER, 0, (wp.Ace(0, 0, mutation, OTHER),))
    with pytest.raises(PermissionError, match="writable by other"):
        wp.validate_directory(security, USER)


@pytest.mark.parametrize("rule", [
    wp.Ace(0, 0, 0x001200A9, EVERYONE),  # read/traverse does not grant file writes
    wp.Ace(0, wp.INHERIT_ONLY_ACE, wp.FILE_ALL_ACCESS, EVERYONE),
    wp.Ace(1, 0, wp.FILE_ALL_ACCESS, EVERYONE),
    wp.Ace(0, 0, wp.FILE_ALL_ACCESS, wp.ADMINISTRATORS_SID),
])
def test_safe_directory_rules_are_accepted(rule):
    wp.validate_directory(wp.Security(USER, 0, (rule,)), USER)


@pytest.mark.parametrize("security", [
    wp.Security(OTHER, 0, ()), wp.Security(USER, 0, None),
    wp.Security(USER, 0, (wp.Ace(5, 0, 0, USER),)),
])
def test_unverifiable_directories_are_refused(security):
    with pytest.raises(PermissionError):
        wp.validate_directory(security, USER)


@pytest.mark.parametrize("security", [
    wp.Security(OTHER, wp.SE_DACL_PROTECTED, private_security().aces),
    wp.Security(USER, 0, private_security().aces),
    wp.Security(USER, wp.SE_DACL_PROTECTED, None),
    wp.Security(USER, wp.SE_DACL_PROTECTED,
                private_security().aces + (wp.Ace(0, 0, 1, OTHER),)),
    wp.Security(USER, wp.SE_DACL_PROTECTED, (wp.Ace(0, 0, wp.FILE_ALL_ACCESS, USER),)),
    wp.Security(USER, wp.SE_DACL_PROTECTED,
                (wp.Ace(0, 0x10, wp.FILE_ALL_ACCESS, USER), private_security().aces[1])),
])
def test_file_acl_must_really_be_private(security):
    with pytest.raises(PermissionError):
        wp.validate_private_file(security, USER)


def fake_api(snapshots, *, set_status=0, null_descriptor=False):
    from ctypes import wintypes

    calls = []
    @contextmanager
    def descriptor():
        yield ctypes.c_void_p(100)
    def get_dacl(sd, present, dacl, defaulted):
        present._obj.value = True
        dacl._obj.value = None if null_descriptor else 200
        return True
    def set_dacl(*args):
        calls.append(args)
        return set_status
    def error(operation, code):
        return PermissionError(f"{operation}: {code}")
    state = iter(snapshots)
    return SimpleNamespace(
        c=ctypes, w=wintypes, user=USER,
        check_handle=lambda handle: None, security=lambda handle: next(state),
        descriptor=descriptor, error=error,
        advapi=SimpleNamespace(GetSecurityDescriptorDacl=get_dacl, SetSecurityInfo=set_dacl),
    ), calls


def test_legacy_file_acl_is_replaced_and_verified():
    old = wp.Security(USER, 0, (wp.Ace(0, 0, wp.FILE_ALL_ACCESS, EVERYONE),))
    api, calls = fake_api([old, private_security()])
    wp._WinAPI.secure_file(api, 123)
    assert len(calls) == 1 and calls[0][2] == 0x80000004
    assert calls[0][5].value  # Never pass a null DACL, which grants everyone access.


@pytest.mark.parametrize("case", ["foreign_owner", "write_failed", "not_applied", "null_acl"])
def test_permission_failure_never_reports_success(case):
    old = wp.Security(OTHER if case == "foreign_owner" else USER, 0, ())
    api, calls = fake_api([old, old], set_status=5 if case == "write_failed" else 0,
                          null_descriptor=case == "null_acl")
    with pytest.raises(PermissionError):
        wp._WinAPI.secure_file(api, 123)
    if case in ("foreign_owner", "null_acl"):
        assert not calls


@pytest.mark.parametrize("attributes,links,volume,type_,refused", [
    (0, 1, 8, 1, False), (0x400, 1, 8, 1, True), (0, 2, 8, 1, True),
    (0x10, 1, 8, 1, True), (0, 1, 0, 1, True), (0, 1, 8, 3, True),
])
def test_file_handles_require_regular_acl_enforcing_storage(attributes, links, volume, type_, refused):
    class Info(ctypes.Structure):
        _fields_ = [("attributes", ctypes.c_uint32), ("links", ctypes.c_uint32)]
    def file_info(handle, info):
        info._obj.attributes, info._obj.links = attributes, links
        return True
    def volume_info(handle, name, name_size, serial, component, flags, fsname, fs_size):
        flags._obj.value = volume
        return True
    api = SimpleNamespace(c=ctypes, w=SimpleNamespace(DWORD=ctypes.c_uint32), FileInfo=Info,
        kernel=SimpleNamespace(GetFileType=lambda handle: type_,
                               GetFileInformationByHandle=file_info,
                               GetVolumeInformationByHandleW=volume_info))
    if refused:
        with pytest.raises(PermissionError):
            wp._WinAPI.check_handle(api, 123)
    else:
        wp._WinAPI.check_handle(api, 123)


def test_cli_storage_permission_failure_is_actionable(vault_path, monkeypatch, capsys):
    from termvault import app as app_module

    monkeypatch.setattr(app_module, "protect_process", lambda: None)
    monkeypatch.setattr(app_module.VaultLock, "acquire", lambda self:
                        (_ for _ in ()).throw(PermissionError("use a private folder")))
    with pytest.raises(SystemExit) as exc:
        app_module.main(["--vault", str(vault_path)])
    assert exc.value.code == 2
    assert "storage refused" in capsys.readouterr().err


def test_failed_backup_permission_check_prevents_unlock(vault_path, monkeypatch):
    vault = Vault(vault_path, kdf=FAST_KDF)
    vault.create(MASTER)
    vault.add(new_login("synthetic", password="fake secret"))
    def deny(path, **kwargs):
        raise PermissionError("backup permissions unavailable")
    monkeypatch.setattr("termvault.vault.secure_existing_file", deny)
    with pytest.raises(PermissionError):
        vault.unlock(MASTER)
    assert not vault.unlocked


def test_legacy_backup_permissions_tightened_on_open(vault_path):
    vault = Vault(vault_path, kdf=FAST_KDF)
    vault.create(MASTER)
    vault.add(new_login("synthetic"))
    backup = vault._backup_path()
    if os.name == "posix":
        backup.chmod(0o644)
    vault.lock()
    vault.unlock(MASTER)
    if os.name == "posix":
        assert backup.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("protected", [False, True])
def test_no_terminal_clipboard_fallback_in_any_mode(vault_path, monkeypatch, protected):
    app = TermVaultApp(vault_path, protected_mode=protected)
    notices = []
    monkeypatch.setattr(app, "notify", lambda message, **kw: notices.append(message))
    monkeypatch.setattr(app, "copy_to_clipboard", lambda value: pytest.fail("OSC52 leaked a secret"))
    def fail(value):
        raise clipboard.ClipboardError("unavailable")
    monkeypatch.setattr(clipboard, "copy", fail)
    app.copy_secret("synthetic password", "Password")
    assert app._clipboard_value is None and app._clipboard_timer is None
    assert any("Copy refused" in text for text in notices)


def test_masked_entry_does_not_generate_or_show_totp(monkeypatch):
    entry = new_login("synthetic", totp_secret=RFC_SECRET)
    monkeypatch.setattr(totp, "current_code", lambda secret: pytest.fail("Hidden code was generated"))
    text = str(render_entry(entry, False))
    assert "2FA code" in text and "hidden" in text and RFC_SECRET not in text


async def test_totp_reveal_timeout_selection_and_lock(vault_path, monkeypatch):
    monkeypatch.setattr(totp, "current_code", lambda secret: ("287082", 1))
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    copied = []
    app.copy_secret = lambda value, label: copied.append((value, label))
    async with app.run_test(size=(100, 30)) as pilot:
        app.vault.create(MASTER)
        first = app.vault.add(new_login("A", totp_secret=RFC_SECRET))
        second = app.vault.add(new_login("B", totp_secret=RFC_SECRET))
        app.on_unlocked()
        await pilot.pause()
        screen = app.screen
        def detail():
            return str(screen.query_one("#detail-body", Static).render())
        screen._select(first.id)
        assert "287 082" not in detail()
        await pilot.press("t")  # Direct copy still works without exposing it on screen.
        assert copied == [("287082", "2FA code")]
        assert "287 082" not in detail()
        await pilot.press("s")
        assert "287 082" in detail()
        screen._hide_at = 0
        screen._tick()
        assert "287 082" not in detail()
        screen.action_toggle_show()
        assert "287 082" in detail()
        screen._select(second.id)
        assert "287 082" not in detail()
        await app.action_lock()
        assert not app.vault.unlocked and not isinstance(app.screen, MainScreen)


@pytest.mark.parametrize("kind", ["input", "text_area"])
async def test_editor_clipboard_failure_preserves_text(vault_path, monkeypatch, kind):
    from textual.widgets import Input, TextArea

    def fail(*args):
        raise clipboard.ClipboardError("unavailable")
    monkeypatch.setattr(clipboard, "copy", fail)
    monkeypatch.setattr(clipboard, "paste", fail)
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    async with app.run_test() as pilot:
        screen = EditScreen(new_login("synthetic", password="fake password", notes="fake note"))
        await app.push_screen(screen)
        await pilot.pause()
        if kind == "input":
            widget = screen.query_one("#password", Input)
            before = widget.value
            widget.selection = type(widget.selection)(0, len(before))
        else:
            widget = screen.query_one("#notes", TextArea)
            before = widget.text
            widget.selection = type(widget.selection)((0, 0), (0, len(before)))
        widget.action_copy()
        widget.action_cut()
        widget.action_paste()
        assert (widget.value if kind == "input" else widget.text) == before
        assert app._clipboard == "" and app._clipboard_value is None


@pytest.mark.parametrize("kind", ["input", "text_area_selection", "text_area_line"])
async def test_editor_copy_cut_paste_use_cleanup_without_framework_cache(vault_path, monkeypatch, kind):
    from textual.widgets import Input, TextArea

    state = [""]
    monkeypatch.setattr(clipboard, "copy", lambda value: state.__setitem__(0, value))
    monkeypatch.setattr(clipboard, "paste", lambda: state[0])
    def clear(expected):
        if state[0] != expected:
            return False
        state[0] = ""
        return True
    monkeypatch.setattr(clipboard, "clear_if_matches", clear)
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    async with app.run_test() as pilot:
        screen = EditScreen(new_login("synthetic", password="fake password", notes="fake note"))
        await app.push_screen(screen)
        await pilot.pause()
        if kind == "input":
            widget = screen.query_one("#password", Input)
            before = widget.value
            widget.selection = type(widget.selection)(0, len(before))
        else:
            widget = screen.query_one("#notes", TextArea)
            before = widget.text
            end = (0, 0) if kind.endswith("line") else (0, len(before))
            widget.selection = type(widget.selection)((0, 0), end)
        if kind != "text_area_line":
            widget.action_copy()
            assert state[0] == before
        widget.action_cut()
        assert (widget.value if kind == "input" else widget.text) == ""
        assert state[0] == before and app._clipboard == ""
        assert app._clipboard_value == before and app._clipboard_timer is not None
        widget.action_paste()
        assert (widget.value if kind == "input" else widget.text) == before
        assert app.clear_clipboard()
        assert app.clipboard == "" and app._clipboard == ""


async def test_note_line_cut_keeps_other_lines_and_can_be_undone(vault_path, monkeypatch):
    from textual.widgets import TextArea

    state = []
    monkeypatch.setattr(clipboard, "copy", state.append)
    monkeypatch.setattr(clipboard, "clear_if_matches", lambda expected: True)
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    async with app.run_test() as pilot:
        screen = EditScreen(new_note("synthetic", "first line\nlast line"))
        await app.push_screen(screen)
        await pilot.pause()
        area = screen.query_one("#body", TextArea)
        area.selection = type(area.selection)((0, 0), (0, 0))
        area.action_cut()
        assert state == ["first line\n"] and area.text == "last line"
        area.action_undo()
        assert area.text == "first line\nlast line"


@pytest.mark.parametrize("missing_widgets", [False, True])
async def test_ui_lock_failure_cannot_leave_key_unlocked(vault_path, monkeypatch, missing_widgets):
    from textual.css.query import NoMatches

    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    async with app.run_test() as pilot:
        app.vault.create(MASTER)
        app.vault.add(new_login("synthetic", password="fake password"))
        app.on_unlocked()
        await pilot.pause()
        async def fail(screen):
            if missing_widgets:
                raise NoMatches("removed during teardown")
            raise RuntimeError("screen transition failed")
        monkeypatch.setattr(app, "switch_screen", fail)
        with pytest.raises(NoMatches if missing_widgets else RuntimeError):
            await app.action_lock()
        assert not app.vault.unlocked and not app._locking


# These exercise the real Win32 ABI and filesystem, rather than mock policy.
@pytest.mark.skipif(sys.platform != "win32", reason="native Windows filesystem ACLs")
def test_native_windows_storage_acl_lifecycle(tmp_path, monkeypatch):
    import msvcrt

    api = wp._api()
    path = tmp_path / "new-private-folder" / "vault.json"
    observed = []
    original = fileio.open_private
    def observe(path, flags):
        fd = original(path, flags)
        if path.suffix == ".tmp":
            wp.validate_private_file(api.security(msvcrt.get_osfhandle(fd)), api.user)
            assert os.fstat(fd).st_size == 0
            assert not os.get_inheritable(fd)
            observed.append(path)
        return fd
    monkeypatch.setattr(fileio, "open_private", observe)
    vault = Vault(path, kdf=FAST_KDF)
    vault.create(MASTER)
    vault.add(new_login("synthetic", password="fake secret"))
    vault.lock()
    vault.unlock(MASTER)
    for stored in path.parent.iterdir():
        fd = original(stored, os.O_RDONLY | os.O_BINARY)
        try:
            wp.validate_private_file(api.security(msvcrt.get_osfhandle(fd)), api.user)
        finally:
            os.close(fd)
    assert observed and not any(p.exists() for p in observed)


@contextmanager
def wide_descriptor(api):
    sd = api.w.LPVOID()
    sddl = f"O:{api.user}D:P(A;;FA;;;{api.user})(A;;FA;;;SY)(A;;FA;;;WD)"
    assert api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, api.c.byref(sd), None)
    try:
        yield sd
    finally:
        api.kernel.LocalFree(sd)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows filesystem ACLs")
def test_native_windows_rejects_shared_folder_without_rewriting_it(tmp_path):
    api = wp._api()
    directory = tmp_path / "shared"
    with wide_descriptor(api) as sd:
        attrs = api.Attributes(api.c.sizeof(api.Attributes), sd, False)
        assert api.kernel.CreateDirectoryW(str(directory), api.c.byref(attrs))
    handle = api._open(directory, 0x20000, 3, directory=True)
    try:
        before = api.security(handle)
        with pytest.raises(PermissionError, match="writable by other"):
            fileio.atomic_write(directory / "vault.json", b"synthetic ciphertext")
        assert api.security(handle) == before
        assert not list(directory.iterdir())
    finally:
        api.kernel.CloseHandle(handle)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows filesystem ACLs")
def test_native_windows_tightens_owned_legacy_file_and_rejects_hardlink(tmp_path):
    api = wp._api()
    path = tmp_path / "legacy.json"
    with wide_descriptor(api) as sd:
        attrs = api.Attributes(api.c.sizeof(api.Attributes), sd, False)
        handle = api._open(path, 0xC0060000, 1, api.c.byref(attrs))
        api.kernel.CloseHandle(handle)
    fileio.secure_existing_file(path)
    handle = api._open(path, 0x20000, 3)
    try:
        wp.validate_private_file(api.security(handle), api.user)
    finally:
        api.kernel.CloseHandle(handle)
    link = tmp_path / "extra.json"
    os.link(path, link)
    with pytest.raises(PermissionError):
        fileio.read_bounded(path, 100)
