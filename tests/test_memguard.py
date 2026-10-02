"""Other programs running as you must not be able to read tvault's memory."""

import ctypes
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows process access lists")

ROOT = Path(__file__).resolve().parent.parent

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WRITE_DAC = 0x00040000
ERROR_ACCESS_DENIED = 5

if sys.platform == "win32":
    from ctypes import wintypes as wt
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.OpenProcess.restype = wt.HANDLE
    k32.CloseHandle.argtypes = [wt.HANDLE]


def open_process(pid: int, access: int):
    """(handle or None, last error)"""
    handle = k32.OpenProcess(access, False, pid)
    return handle, ctypes.get_last_error()


def start_child(protect: bool) -> tuple[subprocess.Popen, int]:
    code = textwrap.dedent(f"""
        import os, sys, time
        from termvault.memguard import protect_process
        if {protect}:
            protect_process()
        print(os.getpid(), flush=True)
        time.sleep(60)
    """)
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, env=env)
    # The interpreter may run as a child of a launcher, so ask it for its own PID.
    return proc, int(proc.stdout.readline())


def test_memory_readers_are_refused():
    proc, pid = start_child(protect=True)
    try:
        # What ProcDump, Process Hacker and debuggers need: refused.
        for access in (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, PROCESS_VM_READ):
            handle, err = open_process(pid, access)
            assert not handle and err == ERROR_ACCESS_DENIED
        # Rewriting the access list to undo the protection: refused too.
        handle, err = open_process(pid, WRITE_DAC)
        assert not handle and err == ERROR_ACCESS_DENIED
        # Seeing and ending your own process still works.
        handle, err = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
        assert handle, f"error {err}"
        k32.CloseHandle(handle)
        out = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        proc.wait(timeout=10)
    finally:
        proc.kill()


def test_unprotected_process_is_readable():
    """Control: without the protection, the same read is allowed."""
    proc, pid = start_child(protect=False)
    try:
        handle, err = open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
        assert handle, f"error {err}"
        k32.CloseHandle(handle)
    finally:
        proc.kill()


def test_app_works_inside_protected_process(tmp_path):
    """Unlocking, saving and the UI all still work with the protection on."""
    code = textwrap.dedent(f"""
        import asyncio
        from pathlib import Path
        from textual.widgets import Input
        from termvault.memguard import protect_process
        from termvault.app import TermVaultApp
        from termvault.vault import Vault
        from termvault.models import Entry
        from termvault import guard

        protect_process()
        guard.default_store_path = lambda: Path(r"{tmp_path}") / "attempts.json"
        kdf = {{"name": "argon2id", "time_cost": 1, "memory_cost": 1024, "parallelism": 1}}
        path = Path(r"{tmp_path}") / "vault.json"
        v = Vault(path, kdf=kdf)
        v.create("correct horse battery staple")
        v.add(Entry(type="login", title="Site", password="pw"))
        v.save()

        async def run():
            app = TermVaultApp(path, kdf=kdf, idle_lock=0)
            async with app.run_test() as pilot:
                await pilot.pause(0.2)
                app.screen.query_one("#pw", Input).value = "correct horse battery staple"
                app.screen.query_one("#pw", Input).focus()
                await pilot.press("enter")
                for _ in range(200):
                    if app.vault.unlocked:
                        break
                    await pilot.pause(0.05)
                return [e.title for e in app.vault.entries()]

        print(asyncio.run(run()))
    """)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         encoding="utf-8", env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().endswith("['Site']")
