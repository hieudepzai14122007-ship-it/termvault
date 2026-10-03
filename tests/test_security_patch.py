"""Failure and adversarial-input regressions for the hardening patch."""
import base64
import json
import os
from dataclasses import replace

import pytest

from termvault import crypto, fileio
from termvault.health import strength
from termvault.models import Entry, new_login, new_note
from termvault.vault import Vault, VaultConflictError
from conftest import FAST_KDF, MASTER

NEW_MASTER = 'brand new master pw'


def make(path):
    vault = Vault(path, kdf=FAST_KDF)
    vault.create(MASTER)
    return vault


@pytest.mark.parametrize('field,value', [
    ('salt', 123), ('salt', None), ('salt', 'é'), ('salt', ''),
    ('nonce', []), ('nonce', ''), ('nonce', base64.b64encode(b'x' * 8).decode()),
    ('ciphertext', {}), ('ciphertext', ''), ('version', True), ('version', 1.0),
])
def test_invalid_envelope_rejected_before_kdf(vault_path, monkeypatch, field, value):
    make(vault_path)
    doc = json.loads(vault_path.read_bytes())
    doc[field] = value
    vault_path.write_text(json.dumps(doc))
    def forbidden(*args, **kwargs):
        pytest.fail('Argon2 must not execute for a malformed envelope')
    monkeypatch.setattr(crypto, 'hash_secret_raw', forbidden)
    vault = Vault(vault_path, kdf=FAST_KDF)
    with pytest.raises(crypto.DecryptionError):
        vault.unlock(MASTER)
    assert not vault.unlocked


def test_expensive_kdf_rejected_before_execution(monkeypatch):
    monkeypatch.setattr(crypto, 'hash_secret_raw', lambda **kw: pytest.fail('KDF executed'))
    with pytest.raises(crypto.DecryptionError, match='resource limit'):
        crypto.derive_key(MASTER, b'x' * 16, {**FAST_KDF, 'time_cost': 20})


@pytest.mark.parametrize('payload', [
    {}, {'entries': None}, {'entries': [None]},
    {'entries': [{'type': 'login', 'title': 'x'}]},
    {'entries': [new_note('x').to_dict(), {'id': 'bad', 'type': 'login', 'title': 123}]},
])
def test_invalid_payload_never_partially_unlocks(vault_path, payload):
    vault = make(vault_path)
    vault._write(vault_path, json.dumps(payload).encode())
    with pytest.raises(crypto.DecryptionError):
        vault.unlock(MASTER)
    assert not vault.unlocked and vault._entries == {} and vault._salt is None


def test_duplicate_ids_rejected(vault_path):
    vault = make(vault_path)
    entry = new_note('x').to_dict()
    vault._write(vault_path, json.dumps({'entries': [entry, entry]}).encode())
    with pytest.raises(crypto.DecryptionError):
        vault.unlock(MASTER)
    assert not vault.unlocked


@pytest.mark.parametrize('change', [
    {'favorite': 'false'}, {'created': True}, {'updated': float('nan')},
    {'password': None}, {'type': 'unknown'}, {'id': ''}, {'title': 123},
])
def test_entry_types_checked(change):
    with pytest.raises(ValueError):
        Entry.from_dict({**new_login('x').to_dict(), **change})


def test_no_secret_repr_or_strength_cache():
    entry = new_login('secret-title', password='secret-password', notes='secret-notes')
    assert repr(entry) == 'Entry(<redacted>)'
    assert not hasattr(strength, 'cache_info')


def test_defensive_copies(vault_path):
    vault = make(vault_path)
    source = new_note('original', 'secret')
    returned = vault.add(source)
    source.title = 'source mutation'
    returned.title = 'return mutation'
    vault.get(source.id).title = 'get mutation'
    vault.entries()[0].title = 'list mutation'
    assert vault.get(source.id).title == 'original'


@pytest.mark.parametrize('operation', ['add', 'update', 'delete', 'favorite'])
def test_failed_crud_preserves_committed_state(vault_path, monkeypatch, operation):
    vault = make(vault_path)
    entry = vault.add(new_note('original'))
    before = vault_path.read_bytes()
    def fail(*args):
        raise OSError('simulated full disk')
    monkeypatch.setattr(vault, '_write', fail)
    with pytest.raises(OSError):
        if operation == 'add':
            vault.add(new_note('new'))
        elif operation == 'update':
            vault.update(replace(entry, title='changed'))
        elif operation == 'delete':
            vault.delete(entry.id)
        else:
            vault.toggle_favorite(entry.id)
    assert vault.entries() == [entry]
    assert vault_path.read_bytes() == before


def test_stale_session_cannot_restore_old_key(vault_path):
    first = make(vault_path)
    stale = Vault(vault_path, kdf=FAST_KDF)
    stale.unlock(MASTER)
    first.change_master(MASTER, NEW_MASTER)
    before = vault_path.read_bytes()
    with pytest.raises(VaultConflictError):
        stale.add(new_note('stale write'))
    assert before == vault_path.read_bytes()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    reopened.unlock(NEW_MASTER)


def test_guard_change_does_not_invalidate_session(vault_path):
    vault = make(vault_path)
    doc = json.loads(vault_path.read_bytes())
    doc['guard'] = {'failures': 1, 'locked_until': 0}
    vault_path.write_text(json.dumps(doc))
    vault.add(new_note('still works'))


def test_kdf_failure_does_not_mutate_rekey_state(vault_path, monkeypatch):
    vault = make(vault_path)
    old = vault.kdf.copy(), vault._salt, vault._key
    before = vault_path.read_bytes()
    monkeypatch.setattr(vault, '_derive', lambda *args: (_ for _ in ()).throw(crypto.DecryptionError('memory')))
    with pytest.raises(crypto.DecryptionError):
        vault._rekey(NEW_MASTER, FAST_KDF)
    assert (vault.kdf, vault._salt, vault._key) == old
    assert vault_path.read_bytes() == before


def test_backup_unlink_failure_aborts_rotation(vault_path, monkeypatch):
    vault = make(vault_path)
    vault.add(new_note('x'))
    before = vault_path.read_bytes()
    backup = vault._backup_path()
    real_unlink = type(backup).unlink
    def fail(path, *args, **kwargs):
        if path == backup:
            raise PermissionError('blocked deletion')
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(type(backup), 'unlink', fail)
    with pytest.raises(PermissionError):
        vault.change_master(MASTER, NEW_MASTER)
    assert vault_path.read_bytes() == before
    assert vault.unlocked


def test_main_write_failure_during_rotation_leaves_old_vault(vault_path, monkeypatch):
    vault = make(vault_path)
    vault.add(new_note('x'))
    def fail(*args):
        raise OSError('main write failed')
    monkeypatch.setattr(vault, '_write', fail)
    with pytest.raises(OSError):
        vault.change_master(MASTER, NEW_MASTER)
    assert not vault._backup_path().exists()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    reopened.unlock(MASTER)
    assert reopened.entries()[0].title == 'x'


def test_mixed_kdf_upgrade_keeps_higher_memory(vault_path):
    Vault(vault_path, kdf={**FAST_KDF, 'memory_cost': 4096}).create(MASTER)
    vault = Vault(vault_path, kdf={**FAST_KDF, 'memory_cost': 2048, 'time_cost': 2})
    vault.unlock(MASTER)
    assert vault.kdf['memory_cost'] == 4096 and vault.kdf['time_cost'] == 2


def test_duplicate_add_cannot_overwrite(vault_path):
    vault = make(vault_path)
    entry = vault.add(new_note('x'))
    with pytest.raises(ValueError):
        vault.add(replace(entry, title='overwritten'))
    assert vault.get(entry.id).title == 'x'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permissions')
def test_files_are_private_and_fixed_temp_symlink_is_ignored(vault_path):
    target = vault_path.parent / 'unrelated.txt'
    target.write_text('untouched')
    vault_path.with_suffix('.json.tmp').symlink_to(target)
    vault = make(vault_path)
    vault.add(new_note('x'))
    assert target.read_text() == 'untouched'
    assert vault_path.stat().st_mode & 0o777 == 0o600
    assert vault._backup_path().stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != 'posix', reason='symlinks')
def test_backup_symlink_fails_closed(vault_path):
    vault = make(vault_path)
    target = vault_path.parent / 'target'
    target.write_text('untouched')
    vault._backup_path().symlink_to(target)
    with pytest.raises(PermissionError):
        vault.add(new_note('x'))
    assert target.read_text() == 'untouched' and vault.entries() == []


def test_directory_flush_failure_locks_ambiguous_commit(vault_path, monkeypatch):
    vault = make(vault_path)
    def fail(*args):
        raise OSError('directory flush failed')
    # Use the main-file writer directly via create to avoid failing at the backup.
    other = Vault(vault_path.with_name('other.json'), kdf=FAST_KDF)
    monkeypatch.setattr(fileio, 'sync_directory', fail)
    with pytest.raises(fileio.CommitUncertainError):
        other.create(MASTER)
    assert not other.unlocked
    monkeypatch.undo()
    reopened = Vault(other.path, kdf=FAST_KDF)
    reopened.unlock(MASTER)


def test_oversized_file_rejected_without_kdf(vault_path, monkeypatch):
    with vault_path.open('wb') as f:
        f.truncate(crypto.MAX_VAULT_BYTES + 1)
    monkeypatch.setattr(crypto, 'hash_secret_raw', lambda **kw: pytest.fail('KDF executed'))
    with pytest.raises(crypto.DecryptionError, match='size limit'):
        Vault(vault_path, kdf=FAST_KDF).unlock(MASTER)


def test_process_crash_after_main_rotation_leaves_no_old_backup(vault_path):
    import subprocess
    import sys
    import textwrap
    vault = make(vault_path)
    vault.add(new_note('kept'))
    source = textwrap.dedent(f'''
        import os
        from pathlib import Path
        from termvault.vault import Vault
        vault = Vault(Path({str(vault_path)!r}), kdf={FAST_KDF!r})
        vault.unlock({MASTER!r}, upgrade=False)
        original = vault._write
        def interrupted(path, plaintext):
            if path == vault._backup_path():
                os._exit(73)
            original(path, plaintext)
        vault._write = interrupted
        vault.change_master({MASTER!r}, {NEW_MASTER!r})
    ''')
    result = subprocess.run([sys.executable, '-c', source], timeout=10)
    assert result.returncode == 73
    assert not vault._backup_path().exists()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    with pytest.raises(crypto.DecryptionError):
        reopened.unlock(MASTER, upgrade=False)
    reopened.unlock(NEW_MASTER, upgrade=False)
    assert reopened.entries()[0].title == 'kept'


def test_process_crash_before_main_rotation_keeps_old_vault(vault_path):
    import subprocess
    import sys
    import textwrap
    vault = make(vault_path)
    vault.add(new_note('kept'))
    source = textwrap.dedent(f'''
        import os
        from pathlib import Path
        from termvault.vault import Vault
        vault = Vault(Path({str(vault_path)!r}), kdf={FAST_KDF!r})
        vault.unlock({MASTER!r}, upgrade=False)
        vault._write = lambda *args: os._exit(74)
        vault.change_master({MASTER!r}, {NEW_MASTER!r})
    ''')
    result = subprocess.run([sys.executable, '-c', source], timeout=10)
    assert result.returncode == 74
    assert not vault._backup_path().exists()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    reopened.unlock(MASTER, upgrade=False)
    assert reopened.entries()[0].title == 'kept'


def test_backup_write_failure_reports_warning(vault_path, monkeypatch):
    vault = make(vault_path)
    vault.add(new_note('kept'))
    original = vault._write
    def fail_backup(path, plaintext):
        if path == vault._backup_path():
            raise OSError('backup failure')
        return original(path, plaintext)
    monkeypatch.setattr(vault, '_write', fail_backup)
    vault.change_master(MASTER, NEW_MASTER)
    assert vault.backup_warning and not vault._backup_path().exists()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    reopened.unlock(NEW_MASTER, upgrade=False)


def test_bad_guard_counters_do_not_allocate_huge_powers(vault_path):
    from termvault.guard import AttemptGuard, MAX_DELAY, delay_after
    make(vault_path)
    assert delay_after(10**100) == MAX_DELAY
    doc = json.loads(vault_path.read_bytes())
    doc['guard'] = {'failures': 10**100, 'locked_until': float('nan')}
    vault_path.write_text(json.dumps(doc))
    assert AttemptGuard(vault_path).failures == 0


def test_failed_save_after_main_replace_forces_reopen(vault_path, monkeypatch):
    vault = make(vault_path)
    real_sync = fileio.sync_directory
    calls = []
    def fail_main_sync(parent):
        calls.append(parent)
        if len(calls) == 2:  # backup first, main second
            raise OSError('failed flush after committed main')
        real_sync(parent)
    monkeypatch.setattr(fileio, 'sync_directory', fail_main_sync)
    with pytest.raises(fileio.CommitUncertainError):
        vault.add(new_note('committed'))
    assert not vault.unlocked
    monkeypatch.undo()
    reopened = Vault(vault_path, kdf=FAST_KDF)
    reopened.unlock(MASTER, upgrade=False)
    assert reopened.entries()[0].title == 'committed'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permissions')
def test_legacy_vault_permissions_tightened_on_read(vault_path):
    vault = make(vault_path)
    vault.lock()
    vault_path.chmod(0o644)
    vault.unlock(MASTER, upgrade=False)
    assert vault_path.stat().st_mode & 0o777 == 0o600
