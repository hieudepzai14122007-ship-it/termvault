import json

import pytest

from termvault import crypto
from termvault.models import new_login, new_note
from termvault.vault import Vault, VaultLockedError
from conftest import FAST_KDF, MASTER


def make(vault_path):
    v = Vault(vault_path, kdf=FAST_KDF)
    v.create(MASTER)
    return v


def test_create_and_reopen(vault_path):
    v = make(vault_path)
    e = v.add(new_login("GitHub", "me", "hunter2hunter2", "https://github.com"))
    v.add(new_note("Wifi", "SSID: home\npass: abc"))
    v.lock()

    v2 = Vault(vault_path, kdf=FAST_KDF)
    v2.unlock(MASTER)
    assert {x.title for x in v2.entries()} == {"GitHub", "Wifi"}
    assert v2.get(e.id).password == "hunter2hunter2"


def test_file_has_no_plaintext(vault_path):
    v = make(vault_path)
    v.add(new_login("GitHub", "me", "hunter2hunter2"))
    text = vault_path.read_text()
    assert "hunter2" not in text and "GitHub" not in text


def test_wrong_password(vault_path):
    make(vault_path).lock()
    with pytest.raises(crypto.DecryptionError):
        Vault(vault_path, kdf=FAST_KDF).unlock("wrong password!!")


def test_short_master_rejected(vault_path):
    with pytest.raises(ValueError):
        Vault(vault_path, kdf=FAST_KDF).create("short")


def test_locked_access_raises(vault_path):
    v = make(vault_path)
    v.lock()
    with pytest.raises(VaultLockedError):
        v.entries()


def test_backup_created_and_atomic(vault_path):
    v = make(vault_path)
    v.add(new_note("one"))
    bak = vault_path.with_suffix(".json.bak")
    assert bak.exists()
    assert not vault_path.with_suffix(".json.tmp").exists()
    # The backup is a valid vault from the previous save (zero entries).
    b = Vault(bak, kdf=FAST_KDF)
    b.unlock(MASTER)
    assert b.entries() == []


def test_search_and_favorites(vault_path):
    v = make(vault_path)
    a = v.add(new_login("Amazon", "shopper"))
    v.add(new_login("Bank", "saver", url="https://bank.example"))
    z = v.add(new_note("Zebra notes", "remember the bank pin"))
    assert [e.title for e in v.entries()] == ["Amazon", "Bank", "Zebra notes"]
    v.toggle_favorite(z.id)
    assert v.entries()[0].id == z.id
    assert {e.title for e in v.entries("bank")} == {"Bank", "Zebra notes"}
    assert [e.id for e in v.entries("SHOP")] == [a.id]


def test_update_and_delete(vault_path):
    v = make(vault_path)
    e = v.add(new_login("Old"))
    e.title = "New"
    v.update(e)
    v.lock()
    v.unlock(MASTER)
    assert v.get(e.id).title == "New"
    v.delete(e.id)
    assert v.entries() == []


def test_change_master(vault_path):
    v = make(vault_path)
    v.add(new_note("keep me"))
    with pytest.raises(crypto.DecryptionError):
        v.change_master("not the old one", "brand new master pw")
    v.change_master(MASTER, "brand new master pw")
    v.lock()
    with pytest.raises(crypto.DecryptionError):
        Vault(vault_path, kdf=FAST_KDF).unlock(MASTER)
    v.unlock("brand new master pw")
    assert v.entries()[0].title == "keep me"


def test_corrupt_json(vault_path):
    vault_path.write_text("{not json")
    with pytest.raises(crypto.DecryptionError):
        Vault(vault_path, kdf=FAST_KDF).unlock(MASTER)


# ---- master password protection -------------------------------------------

from termvault.vault import master_password_problem

STRONGER_FAST = {**FAST_KDF, "memory_cost": 2048, "time_cost": 2}


def test_weak_master_rejected(vault_path):
    assert "Too easy to guess" in master_password_problem("password123456")
    assert master_password_problem(MASTER) is None
    with pytest.raises(ValueError, match="Too easy"):
        Vault(vault_path, kdf=FAST_KDF).create("password123456")
    assert not vault_path.exists()


def test_weak_new_master_rejected_on_change(vault_path):
    v = make(vault_path)
    with pytest.raises(ValueError, match="Too easy"):
        v.change_master(MASTER, "password123456")
    v.lock()
    v.unlock(MASTER)  # unchanged


def test_kdf_upgraded_on_unlock(vault_path):
    make(vault_path).add(new_note("survives"))
    v = Vault(vault_path, kdf=STRONGER_FAST)
    v.unlock(MASTER)
    assert v.kdf_upgraded
    on_disk = json.loads(vault_path.read_text())["kdf"]
    assert on_disk["memory_cost"] == 2048 and on_disk["time_cost"] == 2
    # Still opens, and nothing is lost.
    v2 = Vault(vault_path, kdf=STRONGER_FAST)
    v2.unlock(MASTER)
    assert not v2.kdf_upgraded
    assert v2.entries()[0].title == "survives"


def test_stronger_file_is_not_downgraded(vault_path):
    Vault(vault_path, kdf=STRONGER_FAST).create(MASTER)
    v = Vault(vault_path, kdf=FAST_KDF)
    v.unlock(MASTER)
    assert not v.kdf_upgraded
    assert json.loads(vault_path.read_text())["kdf"]["memory_cost"] == 2048


def test_change_master_check_does_not_rewrite_file(vault_path):
    make(vault_path)
    before = vault_path.read_bytes()
    v = Vault(vault_path, kdf=FAST_KDF)
    v.unlock(MASTER)
    v.target_kdf = STRONGER_FAST  # pretend defaults got stronger since unlock
    with pytest.raises(crypto.DecryptionError):
        v.change_master("not the old one", "brand new master pw")
    assert vault_path.read_bytes() == before


# ---- backup is re-encrypted on re-key ------------------------------------

NEW_MASTER = "brand new master pw"


def open_backup(vault_path, password):
    b = Vault(vault_path.with_suffix(".json.bak"), kdf=FAST_KDF)
    b.unlock(password, upgrade=False)
    return b


def test_change_master_reencrypts_backup(vault_path):
    v = make(vault_path)
    v.add(new_note("A"))
    v.add(new_note("B"))  # backup now holds the state with just A
    v.change_master(MASTER, NEW_MASTER)

    with pytest.raises(crypto.DecryptionError):
        open_backup(vault_path, MASTER)  # old password no longer opens anything
    b = open_backup(vault_path, NEW_MASTER)
    assert [e.title for e in b.entries()] == ["A"]  # one step of undo kept
    assert not vault_path.with_suffix(".json.tmp").exists()
    assert not vault_path.with_suffix(".json.bak.tmp").exists()


def test_upgrade_reencrypts_backup(vault_path):
    v = make(vault_path)
    v.add(new_note("A"))
    v.add(new_note("B"))
    v.lock()
    Vault(vault_path, kdf=STRONGER_FAST).unlock(MASTER)

    bak_kdf = json.loads(vault_path.with_suffix(".json.bak").read_text())["kdf"]
    assert bak_kdf["memory_cost"] == 2048 and bak_kdf["time_cost"] == 2
    assert [e.title for e in open_backup(vault_path, MASTER).entries()] == ["A"]


def test_unreadable_backup_replaced_on_rekey(vault_path):
    v = make(vault_path)
    v.add(new_note("A"))
    vault_path.with_suffix(".json.bak").write_text("garbage")
    v.change_master(MASTER, NEW_MASTER)
    assert [e.title for e in open_backup(vault_path, NEW_MASTER).entries()] == ["A"]


def test_backup_from_an_older_password_replaced(vault_path):
    # A .bak left over from before this fix, encrypted with some other password.
    other = Vault(vault_path.with_suffix(".json.bak"), kdf=FAST_KDF)
    other.create("some older master password")
    v = Vault(vault_path, kdf=FAST_KDF)
    v.path.unlink(missing_ok=True)
    v.create(MASTER)
    v.change_master(MASTER, NEW_MASTER)
    with pytest.raises(crypto.DecryptionError):
        open_backup(vault_path, "some older master password")
    open_backup(vault_path, NEW_MASTER)


def test_failed_backup_write_removes_old_backup(vault_path, monkeypatch):
    v = make(vault_path)
    v.add(new_note("A"))
    real_write = Vault._write

    def flaky_write(self, path, plaintext):
        if path.name.endswith(".bak"):
            raise OSError("disk full")
        real_write(self, path, plaintext)

    monkeypatch.setattr(Vault, "_write", flaky_write)
    v.change_master(MASTER, NEW_MASTER)
    assert not vault_path.with_suffix(".json.bak").exists()


def test_failed_main_write_keeps_old_password(vault_path, monkeypatch):
    v = make(vault_path)
    v.add(new_note("A"))

    def broken_write(self, path, plaintext):
        raise OSError("disk full")

    monkeypatch.setattr(Vault, "_write", broken_write)
    with pytest.raises(OSError):
        v.change_master(MASTER, NEW_MASTER)
    monkeypatch.undo()
    v.add(new_note("B"))  # a later save must still use the OLD password
    v.lock()
    v.unlock(MASTER)
    assert {e.title for e in v.entries()} == {"A", "B"}
