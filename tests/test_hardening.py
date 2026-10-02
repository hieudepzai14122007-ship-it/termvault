"""Regression tests for the security review fixes."""

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from termvault import crypto
from termvault.lockfile import VaultInUseError, VaultLock
from termvault.vault import Vault
from conftest import FAST_KDF, MASTER

ROOT = Path(__file__).resolve().parent.parent
SECRET = "FAKE-secret-should-never-print"


def run_py(code: str, timeout: float = 60) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], capture_output=True,
                          text=True, encoding="utf-8", env=env, timeout=timeout)


# ---- 1. crash reports must not include local variables ---------------------

def test_crash_report_does_not_leak_secrets(tmp_path):
    """Run the real app (headless), crash it in a frame holding a secret, check output."""
    result = run_py(f"""
        import termvault.guard as gm
        from pathlib import Path
        from textual.widgets import Input
        from termvault.app import TermVaultApp
        from termvault.screens.main import MainScreen
        from termvault.vault import Vault
        from termvault.models import new_login

        d = Path({str(tmp_path)!r})
        gm.default_store_path = lambda: d / "attempts.json"
        kdf = {FAST_KDF!r}
        v = Vault(d / "vault.json", kdf=kdf)
        v.create({MASTER!r})
        v.add(new_login("Site", "me", {SECRET!r}))

        def broken_copy(self):
            password = self._current().password  # a secret in this frame's locals
            raise RuntimeError("simulated bug")
        MainScreen.action_copy_primary = broken_copy

        async def auto(pilot):
            await pilot.pause(0.3)
            pilot.app.screen.query_one("#pw", Input).value = {MASTER!r}
            await pilot.press("enter")
            for _ in range(50):
                await pilot.pause(0.1)
                if isinstance(pilot.app.screen, MainScreen):
                    break
            await pilot.pause(0.5)
            await pilot.press("c")
            await pilot.pause(0.5)

        TermVaultApp(d / "vault.json", kdf=kdf, idle_lock=0).run(headless=True, auto_pilot=auto)
    """)
    output = result.stdout + result.stderr
    assert "simulated bug" in output, output[-2000:]  # the crash did happen and was reported
    assert SECRET not in output
    assert MASTER not in output


# ---- 2. tampered key settings fail cleanly ----------------------------------

@pytest.mark.parametrize("change", [
    {"time_cost": 0}, {"time_cost": 10**9}, {"memory_cost": 2**40}, {"memory_cost": 4},
    {"parallelism": 0}, {"parallelism": 1000}, {"time_cost": True}, {"time_cost": "3"},
    {"name": "argon2i"}, {"memory_cost": None},
])
def test_tampered_kdf_rejected_without_running_argon2(vault_path, change):
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    doc = json.loads(vault_path.read_text())
    doc["kdf"].update(change)
    vault_path.write_text(json.dumps(doc))
    start = time.monotonic()
    with pytest.raises(crypto.DecryptionError):
        Vault(vault_path, kdf=FAST_KDF).unlock(MASTER)
    assert time.monotonic() - start < 2  # rejected up front, not after a huge computation


def test_kdf_not_a_dict(vault_path):
    Vault(vault_path, kdf=FAST_KDF).create(MASTER)
    doc = json.loads(vault_path.read_text())
    doc["kdf"] = "argon2id"
    vault_path.write_text(json.dumps(doc))
    with pytest.raises(crypto.DecryptionError):
        Vault(vault_path, kdf=FAST_KDF).unlock(MASTER)


def test_default_kdf_is_within_limits():
    assert crypto.validate_kdf(crypto.DEFAULT_KDF) == crypto.DEFAULT_KDF


# ---- 3. one window per vault -------------------------------------------------

def test_second_lock_refused_until_released(vault_path, monkeypatch):
    monkeypatch.setattr(VaultLock, "WAIT_SECONDS", 0.2)
    a, b = VaultLock(vault_path), VaultLock(vault_path)
    a.acquire()
    with pytest.raises(VaultInUseError):
        b.acquire()
    a.release()
    b.acquire()
    b.release()


def test_different_vaults_dont_block_each_other(tmp_path):
    a, b = VaultLock(tmp_path / "one.json"), VaultLock(tmp_path / "two.json")
    a.acquire()
    b.acquire()
    a.release()
    b.release()


def test_second_tvault_process_refuses_to_start(vault_path):
    holder = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(f"""
            import sys, time
            from termvault.lockfile import VaultLock
            lock = VaultLock({str(vault_path)!r})  # keep a reference, or GC releases it
            lock.acquire()
            print("locked", flush=True)
            time.sleep(60)
        """)],
        env={**os.environ, "PYTHONPATH": str(ROOT)}, stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        result = run_py(f"""
            from termvault.app import main
            main(["--vault", {str(vault_path)!r}])
        """, timeout=20)
        assert result.returncode == 1
        assert "already open in another tvault window" in result.stderr
    finally:
        holder.kill()
        holder.wait()
    # The killed process's lock is released by the OS: no stale lock.
    lock = VaultLock(vault_path)
    lock.acquire()
    lock.release()
