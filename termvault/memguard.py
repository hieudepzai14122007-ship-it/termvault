"""Keep other programs from reading tvault's memory (Windows).

While the vault is unlocked, your decrypted entries are in this process's memory. By
default, any program running under your Windows account may read the memory of your
other processes. That's how tools like ProcDump and Process Hacker dump it.

At start-up tvault replaces its process's access list (its DACL) with one that only lets
you see the process and end it, so Task Manager, taskkill and Stop-Process still work but
memory readers get "access denied". Windows normally lets the owner of a process rewrite its access list,
which would undo this in one step; an OWNER RIGHTS entry takes that right away.
KeePassXC protects itself in much the same way.

This is a speed bump, not a wall. An administrator (or malware that becomes one) can
still read the memory, and malware running as you can log your keystrokes or read what
the terminal window shows. It stops ordinary, unelevated memory-dumping tools.
"""

from __future__ import annotations

import sys

# Access you keep to your own tvault process: see it, wait for it, end it. taskkill and
# Stop-Process also ask for PROCESS_QUERY_INFORMATION; none of these can read memory.
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
READ_CONTROL = 0x00020000
PROCESS_ALL_ACCESS = 0x001FFFFF
USER_ACCESS = (PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
               | SYNCHRONIZE)


def protect_process() -> None:
    """Restrict access to the current process. Raises OSError on failure.

    Does nothing outside Windows.
    """
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes as wt

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wt.HANDLE
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.LocalFree.argtypes = [wt.HLOCAL]
    kernel32.LocalFree.restype = wt.HLOCAL
    advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD,
                                             ctypes.POINTER(wt.DWORD)]
    advapi32.ConvertSidToStringSidW.argtypes = [wt.LPVOID, ctypes.POINTER(wt.LPWSTR)]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wt.LPCWSTR, wt.DWORD, ctypes.POINTER(wt.LPVOID), ctypes.POINTER(wt.ULONG)]
    advapi32.GetSecurityDescriptorDacl.argtypes = [wt.LPVOID, ctypes.POINTER(wt.BOOL),
                                                   ctypes.POINTER(wt.LPVOID), ctypes.POINTER(wt.BOOL)]
    advapi32.SetSecurityInfo.argtypes = [wt.HANDLE, ctypes.c_int, wt.DWORD, wt.LPVOID,
                                         wt.LPVOID, wt.LPVOID, wt.LPVOID]
    advapi32.SetSecurityInfo.restype = wt.DWORD

    def fail(what: str) -> OSError:
        return OSError(f"memory protection: {what} failed (error {ctypes.get_last_error()})")

    TOKEN_QUERY = 0x0008
    TOKEN_USER_CLASS = 1
    SE_KERNEL_OBJECT = 6
    DACL_SECURITY_INFORMATION = 0x00000004
    PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

    process = kernel32.GetCurrentProcess()

    # Who am I? (The user's SID, as a string like S-1-5-21-...)
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
        raise fail("OpenProcessToken")
    try:
        size = wt.DWORD()
        advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, buf, size, ctypes.byref(size)):
            raise fail("GetTokenInformation")
    finally:
        kernel32.CloseHandle(token)
    user_sid = ctypes.cast(buf, ctypes.POINTER(wt.LPVOID))[0]  # TOKEN_USER.User.Sid
    sid_str = wt.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(user_sid, ctypes.byref(sid_str)):
        raise fail("ConvertSidToStringSidW")
    try:
        user = sid_str.value
    finally:
        kernel32.LocalFree(ctypes.cast(sid_str, wt.HLOCAL))

    # D:P = a protected access list that ignores inherited entries.
    #   you          -> see, wait for and end the process; nothing else (no memory reads)
    #   SYSTEM (SY)  -> everything, as Windows itself expects
    #   OWNER RIGHTS -> read the list only, so you can't silently rewrite it
    sddl = (f"D:P(A;;0x{USER_ACCESS:x};;;{user})"
            f"(A;;0x{PROCESS_ALL_ACCESS:x};;;SY)"
            f"(A;;0x{READ_CONTROL:x};;;OW)")
    sd = wt.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
        raise fail("building the access list")
    try:
        present, defaulted = wt.BOOL(), wt.BOOL()
        dacl = wt.LPVOID()
        if not advapi32.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl),
                                                  ctypes.byref(defaulted)):
            raise fail("GetSecurityDescriptorDacl")
        err = advapi32.SetSecurityInfo(process, SE_KERNEL_OBJECT,
                                       DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                       None, None, dacl, None)
        if err:
            raise OSError(f"memory protection: SetSecurityInfo failed (error {err})")
    finally:
        kernel32.LocalFree(sd)
