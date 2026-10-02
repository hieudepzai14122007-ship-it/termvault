import json
import shutil

import pytest

from termvault.guard import FREE_ATTEMPTS, MAX_DELAY, AttemptGuard, delay_after
from termvault.vault import Vault
from conftest import FAST_KDF, MASTER

NOW = 1_000_000.0


@pytest.fixture
def vault(vault_path):
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    return vault_path


def lock_out(guard, now=NOW):
    """Use up the free attempts plus one, triggering the first lockout."""
    for _ in range(FREE_ATTEMPTS + 1):
        guard.record_failure(now)


def test_delay_schedule():
    assert [delay_after(n) for n in range(1, FREE_ATTEMPTS + 1)] == [0.0] * FREE_ATTEMPTS
    assert delay_after(FREE_ATTEMPTS + 1) == 30
    assert delay_after(FREE_ATTEMPTS + 2) == 60
    assert delay_after(FREE_ATTEMPTS + 3) == 120
    assert delay_after(100) == MAX_DELAY


def test_failures_trigger_lockout(vault):
    g = AttemptGuard(vault)
    for _ in range(FREE_ATTEMPTS):
        assert g.record_failure(NOW) == 0
        assert g.remaining(NOW) == 0
    assert g.record_failure(NOW) == 30
    assert g.remaining(NOW) == 30
    assert g.remaining(NOW + 30) == 0


def test_restart_keeps_counter(vault):
    lock_out(AttemptGuard(vault))
    g2 = AttemptGuard(vault)  # e.g. after quitting and starting tvault again
    assert g2.failures == FREE_ATTEMPTS + 1
    assert g2.remaining(NOW + 10) == 20


def test_renamed_copy_shares_counter(vault):
    lock_out(AttemptGuard(vault))
    copy = vault.with_name("innocent.json")
    shutil.copy(vault, copy)
    assert AttemptGuard(copy).remaining(NOW) == 30


def test_copy_to_another_pc_carries_counter(vault, tmp_path):
    lock_out(AttemptGuard(vault))
    other_dir = tmp_path / "usb"
    other_dir.mkdir()
    shutil.copy(vault, other_dir / "vault.json")
    # A different user folder (fresh attempts.json): the count travels inside the file.
    g = AttemptGuard(other_dir / "vault.json", store_path=tmp_path / "other-home.json")
    assert g.remaining(NOW) == 30


def test_deleting_one_place_is_not_enough(vault, isolated_guard_store):
    lock_out(AttemptGuard(vault))
    isolated_guard_store.unlink()
    assert AttemptGuard(vault).remaining(NOW) == 30  # still in vault.json

    lock_out(AttemptGuard(vault))
    doc = json.loads(vault.read_text())
    del doc["guard"]
    vault.write_text(json.dumps(doc))
    assert AttemptGuard(vault).remaining(NOW) > 0  # still in attempts.json


def test_vault_still_opens_with_guard_field(vault):
    lock_out(AttemptGuard(vault))
    assert "guard" in json.loads(vault.read_text())
    v = Vault(vault, kdf=FAST_KDF)
    v.unlock(MASTER)  # the unencrypted guard field doesn't affect decryption
    assert v.entries() == []


def test_reset_clears_both_places(vault, isolated_guard_store):
    g = AttemptGuard(vault)
    lock_out(g)
    g.reset()
    assert g.failures == 0 and g.remaining() == 0
    assert "guard" not in json.loads(vault.read_text())
    assert json.loads(isolated_guard_store.read_text()) == {}
    g.reset()  # nothing to clear: still fine


def test_reset_after_rekey_clears_old_entry(vault, isolated_guard_store):
    g = AttemptGuard(vault)
    g.record_failure(NOW)
    # A successful unlock that upgrades the KDF gives the vault a new salt.
    Vault(vault, kdf={**FAST_KDF, "memory_cost": 2048}).unlock(MASTER)
    g.reset()
    assert json.loads(isolated_guard_store.read_text()) == {}


def test_no_vault_means_no_lockout(vault_path):
    g = AttemptGuard(vault_path)
    assert g.failures == 0 and g.remaining() == 0
    assert g.record_failure() == 0  # nothing to count against; doesn't crash


def test_corrupt_store_is_ignored(vault, isolated_guard_store):
    isolated_guard_store.write_text("not json")
    g = AttemptGuard(vault)
    assert g.failures == 0
    g.record_failure(NOW)
    assert g.failures == 1


def test_clock_rollback_is_clamped(vault):
    g = AttemptGuard(vault)
    lock_out(g)
    # Clock wound back a year: the wait still can't exceed the maximum.
    assert g.remaining(now=NOW - 365 * 86400) == MAX_DELAY
