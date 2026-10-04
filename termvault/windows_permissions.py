"""Handle-based Windows privacy ACLs for TermVault storage.

Files are created with a protected DACL, not briefly published with inherited
permissions. Existing user-owned files are tightened and checked again. An
existing directory is inspected, never reconfigured: other ordinary accounts
must not be able to replace its contents. Administrators and same-user programs
are outside this protection. Run on a filesystem that supports Windows ACLs.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
OWNER_RIGHTS_SID = "S-1-3-4"
FILE_ALL_ACCESS = 0x001F01FF
SE_DACL_PROTECTED = 0x1000
INHERIT_ONLY_ACE = 0x08
# Include generic rights: not every ACL has had them mapped to file rights yet.
DIRECTORY_MUTATION = 0x000D0156 | 0x10000000 | 0x40000000


@dataclass(frozen=True)
class Ace:
    kind: int
    flags: int
    mask: int
    sid: str


@dataclass(frozen=True)
class Security:
    owner: str
    control: int
    aces: tuple[Ace, ...] | None


def validate_directory(security: Security, user: str) -> None:
    if security.owner != user or security.aces is None:
        raise PermissionError("vault folder must be owned by you and have a verifiable Windows ACL")
    trusted = {user, SYSTEM_SID, ADMINISTRATORS_SID, OWNER_RIGHTS_SID}
    for ace in security.aces:
        if ace.kind not in (0, 1):
            raise PermissionError("vault folder has unsupported Windows access rules")
        if ace.flags & INHERIT_ONLY_ACE or ace.kind == 1:
            continue
        if ace.sid not in trusted and ace.mask & DIRECTORY_MUTATION:
            raise PermissionError("vault folder is writable by other accounts; use a private folder")


def validate_private_file(security: Security, user: str) -> None:
    expected = {user, SYSTEM_SID}
    if (security.owner != user or not security.control & SE_DACL_PROTECTED
            or security.aces is None or len(security.aces) != 2
            or {a.sid for a in security.aces} != expected
            or any(a.kind != 0 or a.flags != 0 or a.mask != FILE_ALL_ACCESS
                   for a in security.aces)):
        raise PermissionError("could not establish private Windows permissions for the vault file")


class _WinAPI:
    def __init__(self) -> None:
        import ctypes as c
        from ctypes import wintypes as w

        self.c, self.w = c, w
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.advapi = c.WinDLL("advapi32", use_last_error=True)

        class Attributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

        class FileInfo(c.Structure):
            _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                        ("accessed", w.FILETIME), ("written", w.FILETIME),
                        ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD),
                        ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]

        class AclInfo(c.Structure):
            _fields_ = [("count", w.DWORD), ("used", w.DWORD), ("free", w.DWORD)]

        class AceHeader(c.Structure):
            _fields_ = [("kind", c.c_ubyte), ("flags", c.c_ubyte), ("size", w.WORD)]

        self.Attributes, self.FileInfo = Attributes, FileInfo
        self.AclInfo, self.AceHeader = AclInfo, AceHeader

        def bind(dll, name, args, result):
            fn = getattr(dll, name)
            fn.argtypes, fn.restype = args, result

        bind(self.kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD,
             c.POINTER(Attributes), w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
        bind(self.kernel, "CreateDirectoryW", [w.LPCWSTR, c.POINTER(Attributes)], w.BOOL)
        bind(self.kernel, "CloseHandle", [w.HANDLE], w.BOOL)
        bind(self.kernel, "LocalFree", [w.HLOCAL], w.HLOCAL)
        bind(self.kernel, "GetCurrentProcess", [], w.HANDLE)
        bind(self.kernel, "GetFileType", [w.HANDLE], w.DWORD)
        bind(self.kernel, "GetFileInformationByHandle", [w.HANDLE, c.POINTER(FileInfo)], w.BOOL)
        bind(self.kernel, "GetVolumeInformationByHandleW", [w.HANDLE, w.LPWSTR, w.DWORD,
             c.POINTER(w.DWORD), c.POINTER(w.DWORD), c.POINTER(w.DWORD),
             w.LPWSTR, w.DWORD], w.BOOL)
        bind(self.advapi, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL)
        bind(self.advapi, "GetTokenInformation", [w.HANDLE, c.c_int, w.LPVOID,
             w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
        bind(self.advapi, "ConvertSidToStringSidW", [w.LPVOID, c.POINTER(w.LPWSTR)], w.BOOL)
        bind(self.advapi, "IsValidSid", [w.LPVOID], w.BOOL)
        bind(self.advapi, "GetLengthSid", [w.LPVOID], w.DWORD)
        bind(self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
             [w.LPCWSTR, w.DWORD, c.POINTER(w.LPVOID), c.POINTER(w.ULONG)], w.BOOL)
        bind(self.advapi, "GetSecurityDescriptorDacl", [w.LPVOID, c.POINTER(w.BOOL),
             c.POINTER(w.LPVOID), c.POINTER(w.BOOL)], w.BOOL)
        bind(self.advapi, "GetSecurityDescriptorControl", [w.LPVOID, c.POINTER(w.WORD),
             c.POINTER(w.DWORD)], w.BOOL)
        bind(self.advapi, "GetSecurityInfo", [w.HANDLE, c.c_int, w.DWORD,
             c.POINTER(w.LPVOID), c.POINTER(w.LPVOID), c.POINTER(w.LPVOID),
             c.POINTER(w.LPVOID), c.POINTER(w.LPVOID)], w.DWORD)
        bind(self.advapi, "SetSecurityInfo", [w.HANDLE, c.c_int, w.DWORD,
             w.LPVOID, w.LPVOID, w.LPVOID, w.LPVOID], w.DWORD)
        bind(self.advapi, "GetAclInformation", [w.LPVOID, w.LPVOID, w.DWORD, c.c_int], w.BOOL)
        bind(self.advapi, "GetAce", [w.LPVOID, w.DWORD, c.POINTER(w.LPVOID)], w.BOOL)
        self.user = self._current_user()

    def error(self, operation: str, code: int | None = None) -> OSError:
        code = self.c.get_last_error() if code is None else code
        # Preserve FileNotFoundError/FileExistsError for normal storage control flow.
        error = self.c.WinError(code)
        error.strerror = f"Windows vault permissions: {operation}: {error.strerror}"
        return error

    def _sid_string(self, sid) -> str:
        c, w = self.c, self.w
        if not sid or not self.advapi.IsValidSid(sid):
            raise PermissionError("vault has an invalid Windows owner or access rule")
        out = w.LPWSTR()
        if not self.advapi.ConvertSidToStringSidW(sid, c.byref(out)):
            raise self.error("read SID")
        try:
            return out.value
        finally:
            self.kernel.LocalFree(c.cast(out, w.HLOCAL))

    def _current_user(self) -> str:
        c, w = self.c, self.w
        token = w.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008, c.byref(token)):
            raise self.error("read current account")
        try:
            size = w.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, c.byref(size))
            if not 0 < size.value <= 65536:
                raise PermissionError("could not read the Windows account identity")
            buf = c.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 1, buf, size, c.byref(size)):
                raise self.error("read current account")
            return self._sid_string(c.cast(buf, c.POINTER(w.LPVOID))[0])
        finally:
            self.kernel.CloseHandle(token)

    @contextmanager
    def descriptor(self, *, directory: bool = False):
        c, w = self.c, self.w
        flags = "OICI" if directory else ""
        sddl = f"O:{self.user}D:P(A;{flags};FA;;;{self.user})(A;{flags};FA;;;SY)"
        sd = w.LPVOID()
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None):
            raise self.error("build private ACL")
        try:
            yield sd
        finally:
            self.kernel.LocalFree(sd)

    def security(self, handle) -> Security:
        c, w = self.c, self.w
        owner, dacl, sd = w.LPVOID(), w.LPVOID(), w.LPVOID()
        status = self.advapi.GetSecurityInfo(handle, 1, 0x00000001 | 0x00000004,
                                           c.byref(owner), None, c.byref(dacl), None, c.byref(sd))
        if status:
            raise self.error("read file ACL", status)
        try:
            control, revision = w.WORD(), w.DWORD()
            if not self.advapi.GetSecurityDescriptorControl(sd, c.byref(control), c.byref(revision)):
                raise self.error("read ACL protection")
            aces = None
            if dacl:
                info = self.AclInfo()
                if not self.advapi.GetAclInformation(dacl, c.byref(info), c.sizeof(info), 2):
                    raise self.error("read access rules")
                if info.count > 128:
                    raise PermissionError("vault ACL has too many access rules")
                entries = []
                for i in range(info.count):
                    ptr = w.LPVOID()
                    if not self.advapi.GetAce(dacl, i, c.byref(ptr)):
                        raise self.error("read access rule")
                    header = c.cast(ptr, c.POINTER(self.AceHeader)).contents
                    if header.kind not in (0, 1) or header.size < 16:
                        raise PermissionError("vault has unsupported Windows access rules")
                    sid = ptr.value + 8
                    if not self.advapi.IsValidSid(sid) or self.advapi.GetLengthSid(sid) > header.size - 8:
                        raise PermissionError("vault has an invalid Windows access rule")
                    mask = c.cast(ptr.value + 4, c.POINTER(w.DWORD))[0]
                    entries.append(Ace(header.kind, header.flags, mask, self._sid_string(sid)))
                aces = tuple(entries)
            return Security(self._sid_string(owner), control.value, aces)
        finally:
            self.kernel.LocalFree(sd)

    def check_handle(self, handle, *, directory: bool = False) -> None:
        info = self.FileInfo()
        if self.kernel.GetFileType(handle) != 1:
            raise PermissionError("vault storage must be an ordinary disk file or folder")
        if not self.kernel.GetFileInformationByHandle(handle, self.c.byref(info)):
            raise self.error("inspect vault storage")
        if (info.attributes & 0x400 or bool(info.attributes & 0x10) != directory
                or (not directory and info.links != 1)):
            raise PermissionError("vault storage must not be a reparse point or multiply linked file")
        flags = self.w.DWORD()
        if not self.kernel.GetVolumeInformationByHandleW(handle, None, 0, None, None,
                                                          self.c.byref(flags), None, 0):
            raise self.error("verify filesystem ACL support")
        if not flags.value & 0x00000008:  # FILE_PERSISTENT_ACLS
            raise PermissionError("vault storage must support persistent Windows ACLs; use local NTFS")

    def secure_file(self, handle) -> None:
        self.check_handle(handle)
        initial = self.security(handle)
        if initial.owner != self.user:
            raise PermissionError("vault file must be owned by your Windows account")
        try:
            validate_private_file(initial, self.user)
            return
        except PermissionError:
            pass  # An owned legacy file may have inherited broader permissions.
        c, w = self.c, self.w
        with self.descriptor() as sd:
            present, defaulted, dacl = w.BOOL(), w.BOOL(), w.LPVOID()
            if (not self.advapi.GetSecurityDescriptorDacl(sd, c.byref(present), c.byref(dacl),
                                                        c.byref(defaulted))
                    or not present.value or not dacl.value):
                raise PermissionError("could not build a private Windows ACL")
            status = self.advapi.SetSecurityInfo(handle, 1, 0x80000000 | 0x00000004,
                                                 None, None, dacl, None)
            if status:
                raise self.error("restrict file ACL", status)
        validate_private_file(self.security(handle), self.user)

    def _open(self, path: Path, access: int, disposition: int, attributes=None, *, directory=False):
        flags = 0x00200000 | (0x02000000 if directory else 0x00000080)
        handle = self.kernel.CreateFileW(str(path), access, 0x7, attributes, disposition, flags, None)
        if handle == self.c.c_void_p(-1).value or handle is None:
            raise self.error("open vault storage")
        return handle

    def ensure_directory(self, directory: Path) -> None:
        directory = directory.absolute()
        pending = []
        current = directory
        while not current.exists():
            pending.append(current)
            if current == current.parent:
                raise PermissionError("vault folder has no accessible parent")
            current = current.parent
        if pending:
            # Refuse unsafe/unsupported storage before creating any directories.
            anchor = self._open(current, 0x00020080, 3, directory=True)
            try:
                self.check_handle(anchor, directory=True)
                validate_directory(self.security(anchor), self.user)
            finally:
                self.kernel.CloseHandle(anchor)
        with self.descriptor(directory=True) as sd:
            attrs = self.Attributes(self.c.sizeof(self.Attributes), sd, False)
            for folder in reversed(pending):
                if not self.kernel.CreateDirectoryW(str(folder), self.c.byref(attrs)):
                    error = self.c.get_last_error()
                    if error != 183:
                        raise self.error("create private vault folder", error)
        handle = self._open(directory, 0x00020080, 3, directory=True)
        try:
            self.check_handle(handle, directory=True)
            validate_directory(self.security(handle), self.user)
        finally:
            self.kernel.CloseHandle(handle)

    def open_file(self, path: Path, flags: int) -> int:
        import msvcrt

        if ":" in path.name:
            raise PermissionError("vault paths must not name Windows alternate data streams")
        write = bool(flags & os.O_RDWR)
        if flags & os.O_TRUNC or flags & os.O_WRONLY:
            raise ValueError("unsupported private file open flags")
        disposition = 1 if flags & os.O_EXCL else 4 if flags & os.O_CREAT else 3
        access = 0x80000000 | 0x00020000 | 0x00040000  # READ + READ_CONTROL + WRITE_DAC
        if write:
            access |= 0x40000000
        with self.descriptor() as sd:
            attrs = self.Attributes(self.c.sizeof(self.Attributes), sd, False)
            handle = self._open(path, access, disposition, self.c.byref(attrs))
        try:
            self.secure_file(handle)
            # open_osfhandle transfers ownership. O_NOINHERIT prevents child leaks.
            fd = msvcrt.open_osfhandle(handle, (os.O_RDWR if write else os.O_RDONLY)
                                      | os.O_BINARY | os.O_NOINHERIT)
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        return fd


@lru_cache(maxsize=1)
def _api() -> _WinAPI:
    return _WinAPI()


def private_parent(path: Path) -> None:
    _api().ensure_directory(path.parent)


def open_private(path: Path, flags: int) -> int:
    return _api().open_file(path, flags)
