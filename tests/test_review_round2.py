"""Reproductions for clipboard, cancellation, parser and commit-state bugs."""
import asyncio
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import Input, Static

from termvault import clipboard, crypto, fileio, totp
from termvault.app import TermVaultApp
from termvault.guard import AttemptGuard
from termvault.models import new_login, new_note
from termvault.screens.main import MainScreen
from termvault.screens.unlock import UnlockScreen
from termvault.vault import Vault
from conftest import FAST_KDF, MASTER

NEW_MASTER = 'brand new master pw'
RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


@pytest.mark.parametrize('protected', [False, True])
def test_failed_copy_keeps_previous_clear_timer(tmp_path, monkeypatch, protected):
    app = TermVaultApp(tmp_path/'vault.json', protected_mode=protected)
    timer = SimpleNamespace(stop=lambda: pytest.fail('Old clearing timer was cancelled'))
    app._clipboard_timer = timer
    app._clipboard_value = 'previous secret'
    monkeypatch.setattr(app, 'notify', lambda *a, **kw: None)
    monkeypatch.setattr(app, 'copy_to_clipboard', lambda value: None)
    def fail(value):
        raise clipboard.ClipboardError('busy')
    monkeypatch.setattr(clipboard, 'copy', fail)
    app.copy_secret('next secret', 'Password')
    assert app._clipboard_value == 'previous secret'
    assert app._clipboard_timer is timer


def test_copy_with_nul_is_refused_before_any_backend(tmp_path, monkeypatch):
    app = TermVaultApp(tmp_path/'vault.json')
    notices = []
    monkeypatch.setattr(app, 'notify', lambda msg, **kw: notices.append(msg))
    monkeypatch.setattr(clipboard, 'copy', lambda value: pytest.fail('Native backend called'))
    monkeypatch.setattr(app, 'copy_to_clipboard', lambda value: pytest.fail('Fallback called'))
    app.copy_secret('prefix\0hidden', 'Password')
    assert notices


@pytest.mark.parametrize('source', ['vault', 'store'])
def test_deep_guard_json_does_not_crash(vault_path, isolated_guard_store, source):
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    target = vault_path if source == 'vault' else isolated_guard_store
    target.write_text('['*10000 + '0' + ']'*10000)
    guard = AttemptGuard(vault_path)
    assert guard.failures == 0
    guard.record_failure()


@pytest.mark.parametrize('extra', [
    '&algorithm=SHA256', '&digits=8', '&period=60', '&secret='+RFC_SECRET,
    '&digits=6&digits=8', '&period=',
])
def test_nondefault_or_ambiguous_totp_uri_is_rejected(extra):
    uri = 'otpauth://totp/account?secret='+RFC_SECRET+extra
    assert not totp.validate_secret(uri)
    with pytest.raises(ValueError):
        totp.normalize_secret(uri)


@pytest.mark.parametrize('uri', [
    'otpauth://hotp/account?secret='+RFC_SECRET+'&counter=0',
    'otpauth://[/account?secret='+RFC_SECRET,
])
def test_wrong_or_malformed_otp_type_does_not_crash_validation(uri):
    assert not totp.validate_secret(uri)


def test_default_totp_uri_remains_compatible():
    uri = 'otpauth://totp/account?secret='+RFC_SECRET+'&algorithm=SHA1&digits=6&period=30'
    assert totp.normalize_secret(uri) == RFC_SECRET
    assert totp.current_code(uri, at=59) == ('287082', 1)


def test_rekey_cleanup_failure_cannot_restore_old_in_memory_key(vault_path, monkeypatch):
    vault = Vault(vault_path, kdf=FAST_KDF)
    vault.create(MASTER)
    vault.add(new_note('kept'))
    real_unlink = Path.unlink
    def fail_temp(path, *a, **kw):
        if path.suffix == '.tmp':
            raise PermissionError('cleanup denied after rename')
        return real_unlink(path, *a, **kw)
    monkeypatch.setattr(Path, 'unlink', fail_temp)
    vault.change_master(MASTER, NEW_MASTER)
    assert vault.unlocked
    monkeypatch.undo()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    with pytest.raises(crypto.DecryptionError):
        reopened.unlock(MASTER, upgrade=False)
    reopened.unlock(NEW_MASTER, upgrade=False)
    assert reopened.entries()[0].title == 'kept'
    vault.add(new_note('next save uses new key'))


def test_cleanup_error_does_not_hide_uncertain_commit(tmp_path, monkeypatch):
    path = tmp_path/'file'
    def deny(*a, **kw):
        raise PermissionError('cleanup denied')
    monkeypatch.setattr(Path, 'unlink', deny)
    monkeypatch.setattr(fileio, 'sync_directory', lambda p: (_ for _ in ()).throw(OSError('flush failed')))
    with pytest.raises(fileio.CommitUncertainError):
        fileio.atomic_write(path, b'ciphertext')
    assert path.read_bytes() == b'ciphertext'


@pytest.mark.parametrize('creating', [False, True])
async def test_lock_during_password_work_cancels_unlock(vault_path, monkeypatch, creating):
    if not creating:
        Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    started, release = threading.Event(), threading.Event()
    action = app.vault.create if creating else app.vault.unlock
    def slow(password):
        started.set()
        assert release.wait(5), 'Test worker was not released'
        action(password)
    monkeypatch.setattr(app.vault, 'create' if creating else 'unlock', slow)
    async with app.run_test() as pilot:
        screen = app.screen
        screen.query_one('#pw', Input).value = MASTER
        if creating:
            screen.query_one('#pw2', Input).value = MASTER
        submit = asyncio.create_task(screen._submit())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            await app.action_lock()
        finally:
            release.set()
        await asyncio.wait_for(submit, 5)
        await pilot.pause()
        assert isinstance(app.screen, UnlockScreen)
        assert not app.vault.unlocked
        assert app.screen.query_one('#pw', Input).value == ''


async def test_lock_during_protection_query_does_not_start_kdf(vault_path, monkeypatch):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, idle_lock=0)
    started, release = asyncio.Event(), asyncio.Event()
    async def wait():
        started.set()
        await release.wait()
    monkeypatch.setattr(app, 'check_before_unlock', wait)
    monkeypatch.setattr(app.vault, 'create', lambda pw: pytest.fail('Cancelled attempt started KDF'))
    async with app.run_test() as pilot:
        screen = app.screen
        screen.query_one('#pw', Input).value = MASTER
        screen.query_one('#pw2', Input).value = MASTER
        submit = asyncio.create_task(screen._submit())
        await asyncio.wait_for(started.wait(), 2)
        await app.action_lock()
        release.set()
        await asyncio.wait_for(submit, 2)
        assert not app.vault.unlocked and not vault_path.exists()


async def test_app_shutdown_drops_unlocked_entries(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    async with app.run_test():
        app.vault.create(MASTER)
        app.vault.add(new_note('fake', 'fake secret'))
    assert not app.vault.unlocked and app.vault._entries == {}


async def test_invalid_stored_totp_copy_shows_error_not_crash(vault_path, monkeypatch):
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    app.vault.create(MASTER)
    entry = app.vault.add(new_login('legacy', totp_secret='invalid!!!'))
    notices = []
    monkeypatch.setattr(app, 'notify', lambda msg, **kw: notices.append(msg))
    monkeypatch.setattr(app, 'copy_secret', lambda *a: pytest.fail('Invalid OTP copied'))
    async with app.run_test() as pilot:
        app.on_unlocked()
        await pilot.pause()
        app.screen.selected_id = entry.id
        app.screen.action_copy_totp()
        assert notices


async def test_invalid_generator_settings_cannot_use_previous_value(vault_path):
    from termvault.screens.generator import GeneratorScreen
    from textual.widgets import Checkbox
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    async with app.run_test() as pilot:
        screen = GeneratorScreen(can_use=True)
        await app.push_screen(screen)
        await pilot.pause()
        assert screen.value
        for name in ('lower', 'upper', 'digits', 'symbols'):
            screen.query_one('#'+name, Checkbox).value = False
        await pilot.pause()
        screen.action_regenerate()
        assert screen.value == ''
        assert str(screen.query_one('#gen-output', Static).render()) == ''
        screen.action_accept()
        assert app.screen is screen


async def test_busy_clipboard_clear_is_retried(vault_path, monkeypatch):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, clear_after=60)
    value = ['']
    calls = []
    monkeypatch.setattr(clipboard, 'copy', lambda text: value.__setitem__(0, text))
    def clear(expected):
        calls.append(expected)
        if len(calls) == 1:
            raise clipboard.ClipboardError('temporarily busy')
        assert value[0] == expected
        value[0] = ''
        return True
    monkeypatch.setattr(clipboard, 'clear_if_matches', clear)
    async with app.run_test():
        app.copy_secret('fake secret', 'Password')
        assert not app.clear_clipboard()
        assert app._clipboard_value == 'fake secret' and app._clipboard_timer is not None
        app._auto_clear()
        assert value[0] == '' and app._clipboard_value is None
        assert len(calls) == 2


async def test_clipboard_retry_budget_warns_and_drops_tracking(vault_path, monkeypatch):
    app = TermVaultApp(vault_path, kdf=FAST_KDF, clear_after=60)
    notices = []
    monkeypatch.setattr(app, 'notify', lambda msg, **kw: notices.append(msg))
    monkeypatch.setattr(clipboard, 'copy', lambda text: None)
    def busy(expected):
        raise clipboard.ClipboardError('busy')
    monkeypatch.setattr(clipboard, 'clear_if_matches', busy)
    async with app.run_test():
        app.copy_secret('fake secret', 'Password')
        for _ in range(4):
            assert not app.clear_clipboard()
        assert app._clipboard_value is None and app._clipboard_timer is None
        assert any('manually' in msg for msg in notices)


def test_clipboard_api_rejects_null_before_pyperclip(monkeypatch):
    if sys.platform == 'win32':
        pytest.skip('This Linux regression spies on pyperclip')
    monkeypatch.setattr(clipboard.pyperclip, 'copy', lambda value: pytest.fail('NUL published'))
    with pytest.raises(clipboard.ClipboardError):
        clipboard.copy('prefix\0suffix')


def test_exclusive_publish_cleanup_failure_is_an_uncertain_commit(tmp_path, monkeypatch):
    path = tmp_path/'file'
    monkeypatch.setattr(Path, 'unlink', lambda *a, **kw: (_ for _ in ()).throw(PermissionError('denied')))
    with pytest.raises(fileio.CommitUncertainError):
        fileio.atomic_write(path, b'ciphertext', exclusive=True)
    assert path.read_bytes() == b'ciphertext'


async def test_cancelled_awaiter_cannot_leave_worker_unlocked(vault_path, monkeypatch):
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    real_unlock = app.vault.unlock
    def slow(password):
        started.set()
        assert release.wait(5)
        real_unlock(password)
    real_background = app.unlock_in_background
    def background(*args):
        try:
            real_background(*args)
        finally:
            finished.set()
    monkeypatch.setattr(app.vault, 'unlock', slow)
    monkeypatch.setattr(app, 'unlock_in_background', background)
    async with app.run_test():
        screen = app.screen
        screen.query_one('#pw', Input).value = MASTER
        task = asyncio.create_task(screen._submit())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
        assert await asyncio.to_thread(finished.wait, 2)
        assert not app.vault.unlocked
        assert screen.query_one('#pw', Input).value == ''


@pytest.mark.parametrize('expected,clears', [('fake secret', True), ('other text', False)])
def test_windows_compare_and_clear_uses_one_clipboard_lock(monkeypatch, expected, clears):
    import ctypes
    import importlib.util
    state = {'open': False, 'opens': 0, 'cleared': False}
    class Function:
        def __init__(self, name):
            self.name = name
        def __call__(self, *args):
            if self.name == 'OpenClipboard':
                assert not state['open']
                state['open'] = True
                state['opens'] += 1
            elif self.name == 'CloseClipboard':
                state['open'] = False
            elif self.name == 'EmptyClipboard':
                assert state['open'], 'Clearing must share the comparison lock'
                state['cleared'] = True
            return 1
    class Library:
        def __getattr__(self, name):
            function = Function(name)
            setattr(self, name, function)
            return function
    spec = importlib.util.spec_from_file_location('termvault.mock_windows_clipboard', clipboard.__file__)
    module = importlib.util.module_from_spec(spec)
    with monkeypatch.context() as windows:
        windows.setattr(sys, 'platform', 'win32')
        windows.setattr(ctypes, 'WinDLL', lambda *a, **kw: Library(), raising=False)
        spec.loader.exec_module(module)
    def get(fmt):
        assert state['open']
        return ('fake secret\0').encode('utf-16-le')
    monkeypatch.setattr(module, '_get', get)
    assert module.clear_if_matches(expected) is clears
    assert state['opens'] == 1 and not state['open']
    assert state['cleared'] is clears


@pytest.mark.parametrize('length', [73, 100, 2048])
def test_long_password_strength_does_not_crash_or_truncate_storage(vault_path, length):
    from termvault.health import strength
    password = 'x7#Kp2!qLm9@vR4z' * ((length + 15)//16)
    password = password[:length]
    assert strength(password).score in range(5)
    vault = Vault(vault_path, kdf=FAST_KDF)
    vault.create(MASTER)
    entry = vault.add(new_login('long', password=password))
    vault.lock()
    vault.unlock(MASTER)
    assert vault.get(entry.id).password == password


def test_nested_non_string_guard_salt_is_rejected(vault_path):
    import json
    vault_path.write_text('{"version":1,"salt":' + '['*2000+'0'+']'*2000 +
                          ',"kdf":' + json.dumps(FAST_KDF) + '}')
    assert AttemptGuard(vault_path).failures == 0


async def test_lock_hides_ui_before_waiting_for_vault_mutex(vault_path):
    app = TermVaultApp(vault_path, kdf=FAST_KDF)
    started, release = threading.Event(), threading.Event()
    def hold_mutex():
        with app.vault._mutex:
            started.set()
            assert release.wait(5)
    async with app.run_test() as pilot:
        app.vault.create(MASTER)
        app.vault.add(new_note('fake', 'fake secret'))
        app.on_unlocked()
        await pilot.pause()
        holder = asyncio.create_task(asyncio.to_thread(hold_mutex))
        assert await asyncio.to_thread(started.wait, 2)
        locking = asyncio.create_task(app.action_lock())
        try:
            # Do not run Pilot's full idle wait: the held mutex intentionally
            # prevents completion. The screen switch must happen independently.
            for _ in range(100):
                if isinstance(app.screen, UnlockScreen):
                    break
                await asyncio.sleep(0.005)
            assert isinstance(app.screen, UnlockScreen)
            assert app._locking
            app.screen.query_one('#pw', Input).value = MASTER
            await app.screen._submit()
            assert app.screen._busy is False
        finally:
            release.set()
        await asyncio.wait_for(holder, 2)
        await asyncio.wait_for(locking, 2)
        assert not app.vault.unlocked and not app._locking
