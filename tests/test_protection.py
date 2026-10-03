"""Defender-policy and integration tests. Windows calls are mocked on Linux.

These tests verify our decisions and invocation safety, not Defender's native
antivirus effectiveness or actual Windows folder enforcement.
"""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from termvault import protection
from termvault.protection import ProtectionError


def healthy():
    return {
        'AMServiceEnabled': True, 'AntivirusEnabled': True,
        'RealTimeProtectionEnabled': True, 'BehaviorMonitorEnabled': True,
        'IoavProtectionEnabled': True, 'AMRunningMode': 'Normal',
        'SignatureAgeHours': 1.5, 'KnownActiveThreatCount': 0,
    }


def test_good_defender_status_is_only_policy_pass():
    status = protection.validate_status(healthy())
    assert status.signature_age_hours == 1.5 and status.known_active_threats == 0


@pytest.mark.parametrize('field,value', [
    ('AMServiceEnabled', False), ('AntivirusEnabled', False),
    ('RealTimeProtectionEnabled', False), ('RealTimeProtectionEnabled', 'true'),
    ('BehaviorMonitorEnabled', None), ('IoavProtectionEnabled', False),
    ('AMRunningMode', 'Passive Mode'), ('AMRunningMode', None),
    ('SignatureAgeHours', 49), ('SignatureAgeHours', -1),
    ('SignatureAgeHours', float('nan')), ('SignatureAgeHours', True),
    ('SignatureAgeHours', float('inf')), ('KnownActiveThreatCount', 1),
    ('KnownActiveThreatCount', -1), ('KnownActiveThreatCount', False),
    ('KnownActiveThreatCount', '0'),
])
def test_bad_or_unknown_status_fails_closed(field, value):
    with pytest.raises(ProtectionError):
        protection.validate_status({**healthy(), field: value})


def test_non_windows_not_reported_as_protected(monkeypatch):
    monkeypatch.setattr(protection.sys, 'platform', 'linux')
    with pytest.raises(ProtectionError, match='requires Windows'):
        protection.require_defender()


@pytest.mark.parametrize('change', [
    {'ControlledFolderAccessMode': 0}, {'ControlledFolderAccessMode': 2},
    {'ControlledFolderAccessMode': True}, {'FolderExplicitlyCovered': False},
    {'FolderExplicitlyCovered': 'true'}, {'BroadInterpreterExceptionCount': 1},
    {'BroadInterpreterExceptionCount': None},
])
def test_folder_requirements_are_enforced(monkeypatch, tmp_path, change):
    status = {'ControlledFolderAccessMode': 1, 'FolderExplicitlyCovered': True,
              'BroadInterpreterExceptionCount': 0}
    monkeypatch.setattr(protection, '_powershell', lambda *args, **kw: {**status, **change})
    with pytest.raises(ProtectionError):
        protection.require_protected_folder(tmp_path)


def test_folder_query_passes_path_as_data(monkeypatch, tmp_path):
    folder = tmp_path / "quotes'; Write-Host injected; #"
    calls = []
    def query(script, **kwargs):
        calls.append((script, kwargs))
        return {'ControlledFolderAccessMode': 1, 'FolderExplicitlyCovered': True,
                'BroadInterpreterExceptionCount': 0}
    monkeypatch.setattr(protection, '_powershell', query)
    protection.require_protected_folder(folder)
    assert str(folder) not in calls[0][0]
    assert calls[0][1]['extra_env']['TERMVAULT_VAULT_FOLDER'] == str(folder.resolve())
    assert 'GetFullPath' in calls[0][0]
    assert "StartsWith($root + '\\'" in calls[0][0]


def fake_tools(tmp_path, monkeypatch):
    windows = tmp_path / 'Windows'
    powershell = windows / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    powershell.parent.mkdir(parents=True)
    powershell.write_text('test placeholder')
    programs = tmp_path / 'Program Files'
    scanner = programs / 'Windows Defender/MpCmdRun.exe'
    scanner.parent.mkdir(parents=True)
    scanner.write_text('test placeholder')
    monkeypatch.setattr(protection, '_windows_paths', lambda: (windows, programs))
    return powershell, scanner


def test_powershell_uses_fixed_executable_and_no_shell(tmp_path, monkeypatch):
    powershell, scanner = fake_tools(tmp_path, monkeypatch)
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(healthy()))
    monkeypatch.setattr(protection.subprocess, 'run', run)
    protection.require_defender()
    command, kwargs = calls[0]
    assert command[0] == str(powershell)
    assert '-NoProfile' in command and '-NonInteractive' in command
    assert kwargs['shell'] is False and kwargs['timeout'] == protection.STATUS_TIMEOUT
    assert 'Import-Module -Name $module' in command[-1]


@pytest.mark.parametrize('result', [
    SimpleNamespace(returncode=1, stdout=''),
    SimpleNamespace(returncode=0, stdout='not JSON'),
    SimpleNamespace(returncode=0, stdout='[]'),
])
def test_query_error_never_becomes_healthy(tmp_path, monkeypatch, result):
    fake_tools(tmp_path, monkeypatch)
    monkeypatch.setattr(protection.subprocess, 'run', lambda *a, **kw: result)
    with pytest.raises(ProtectionError):
        protection.require_defender()


def test_query_timeout_fails_closed(tmp_path, monkeypatch):
    fake_tools(tmp_path, monkeypatch)
    def fail(*args, **kwargs):
        raise subprocess.TimeoutExpired('powershell', 20)
    monkeypatch.setattr(protection.subprocess, 'run', fail)
    with pytest.raises(ProtectionError, match='timed out'):
        protection.require_defender()


@pytest.mark.parametrize('code,completed', [(0, True), (2, False)])
def test_scan_does_not_execute_target_and_does_not_remediate(tmp_path, monkeypatch, code, completed):
    _, scanner = fake_tools(tmp_path, monkeypatch)
    target = tmp_path / "download $danger'; file.exe"
    target.write_text('test placeholder')
    monkeypatch.setattr(protection, 'require_defender', lambda: None)
    monkeypatch.setattr(protection, '_powershell', lambda *a, **kw: {'TrustedMicrosoftSignature': True})
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=code)
    monkeypatch.setattr(protection.subprocess, 'run', run)
    result = protection.scan_file(target)
    assert result.completed_without_detection is completed
    command, kwargs = calls[0]
    assert command[0] == str(scanner) and command[0] != str(target)
    assert command[command.index('-File') + 1] == str(target.resolve())
    assert '-DisableRemediation' in command and kwargs['shell'] is False
    if code == 2:
        assert 'scan error' in result.message


def test_untrusted_scanner_never_runs(tmp_path, monkeypatch):
    fake_tools(tmp_path, monkeypatch)
    target = tmp_path / 'download.exe'
    target.write_text('test placeholder')
    monkeypatch.setattr(protection, 'require_defender', lambda: None)
    monkeypatch.setattr(protection, '_powershell', lambda *a, **kw: {'TrustedMicrosoftSignature': False})
    monkeypatch.setattr(protection.subprocess, 'run', lambda *a, **kw: pytest.fail('scanner executed'))
    with pytest.raises(ProtectionError, match='signature'):
        protection.scan_file(target)


@pytest.mark.parametrize('failure', ['timeout', 'unknown-code'])
def test_incomplete_scan_never_reported_as_clean(tmp_path, monkeypatch, failure):
    fake_tools(tmp_path, monkeypatch)
    target = tmp_path / 'download.exe'
    target.write_text('test placeholder')
    monkeypatch.setattr(protection, 'require_defender', lambda: None)
    monkeypatch.setattr(protection, '_powershell', lambda *a, **kw: {'TrustedMicrosoftSignature': True})
    def run(*a, **kw):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired('scanner', 300)
        return SimpleNamespace(returncode=50)
    monkeypatch.setattr(protection.subprocess, 'run', run)
    with pytest.raises(ProtectionError, match='unknown'):
        protection.scan_file(target)


async def test_protected_app_refuses_unverified_memory_protection(tmp_path):
    from termvault.app import TermVaultApp
    app = TermVaultApp(tmp_path / 'vault.json', protected_mode=True)
    with pytest.raises(ProtectionError, match='memory protection'):
        await app.check_before_unlock()


def test_protected_mode_caps_timers_and_refuses_osc52(tmp_path, monkeypatch):
    from termvault.app import TermVaultApp
    from termvault import clipboard
    app = TermVaultApp(tmp_path / 'vault.json', idle_lock=0, clear_after=0, protected_mode=True)
    assert app.idle_lock == 60 and app.clear_after == 10
    notices = []
    monkeypatch.setattr(app, 'notify', lambda message, **kw: notices.append(message))
    monkeypatch.setattr(app, 'copy_to_clipboard', lambda value: pytest.fail('OSC52 sent a secret'))
    def unavailable(value):
        raise clipboard.ClipboardError('unavailable')
    monkeypatch.setattr(clipboard, 'copy', unavailable)
    app.copy_secret('fake-test-secret', 'Password')
    assert notices and 'refused' in notices[-1]


async def test_monitor_locks_on_failed_check(tmp_path, monkeypatch):
    from termvault.app import TermVaultApp
    from termvault.models import new_note
    from conftest import FAST_KDF, MASTER
    app = TermVaultApp(tmp_path / 'vault.json', kdf=FAST_KDF, protected_mode=True)
    app.vault.create(MASTER)
    app.vault.add(new_note('fake'))
    def fail(folder):
        raise ProtectionError('antivirus stopped')
    monkeypatch.setattr('termvault.app.require_protection', fail)
    locked = []
    async def lock():
        app.vault.lock()
        locked.append(True)
    monkeypatch.setattr(app, 'action_lock', lock)
    monkeypatch.setattr(app, 'notify', lambda *a, **kw: None)
    await app._poll_protection()
    assert locked and not app.vault.unlocked and not app._protection_check_running


async def test_normal_mode_does_not_require_windows(tmp_path, monkeypatch):
    from termvault.app import TermVaultApp
    app = TermVaultApp(tmp_path / 'vault.json')
    monkeypatch.setattr('termvault.app.require_protection', lambda *a: pytest.fail('Defender queried'))
    await app.check_before_unlock()


async def test_failed_protection_check_keeps_unlock_screen_locked(vault_path, monkeypatch):
    from termvault.app import TermVaultApp
    from termvault.screens.unlock import UnlockScreen
    from textual.widgets import Input, Button, Label
    from conftest import FAST_KDF, MASTER
    app = TermVaultApp(vault_path, kdf=FAST_KDF, protected_mode=True)
    app.memory_protection_verified = True  # Test fixture, not a native Windows check.
    def fail(folder):
        raise ProtectionError('Defender is disabled')
    monkeypatch.setattr('termvault.app.require_protection', fail)
    monkeypatch.setattr(app.vault, 'create', lambda pw: pytest.fail('Vault created without protection'))
    async with app.run_test() as pilot:
        assert isinstance(app.screen, UnlockScreen)
        app.screen.query_one('#pw', Input).value = MASTER
        app.screen.query_one('#pw2', Input).value = MASTER
        await app.screen._submit()
        assert not app.vault.unlocked and not vault_path.exists()
        assert app.screen.query_one('#pw', Input).value == ''
        assert app.screen.query_one('#pw2', Input).value == ''
        assert not app.screen.query_one('#go', Button).disabled
        assert 'disabled' in str(app.screen.query_one('#unlock-error', Label).render())


def test_cli_protected_mode_refuses_before_ui(tmp_path, monkeypatch):
    from termvault.app import main
    calls = []
    def fail(folder):
        calls.append(folder)
        raise ProtectionError('disabled')
    monkeypatch.setattr('termvault.app.require_protection', fail)
    monkeypatch.setattr('termvault.app.protect_process', lambda: pytest.fail('Reached UI startup'))
    with pytest.raises(SystemExit) as exc:
        main(['--protected', '--vault', str(tmp_path / 'vault.json')])
    assert exc.value.code == 2 and calls == [tmp_path.resolve()]


def test_scan_cli_never_opens_vault(tmp_path, monkeypatch, capsys):
    from termvault.app import main
    from termvault.protection import ScanResult
    target = tmp_path / 'download.exe'
    monkeypatch.setattr('termvault.app.scan_file', lambda path: ScanResult(False, 'detection or error'))
    monkeypatch.setattr('termvault.app.protect_process', lambda: pytest.fail('Vault startup reached'))
    with pytest.raises(SystemExit) as exc:
        main(['--scan-file', str(target)])
    assert exc.value.code == 2 and 'detection or error' in capsys.readouterr().out
