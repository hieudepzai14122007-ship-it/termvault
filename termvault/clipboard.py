"""Clipboard access that keeps copied secrets out of Windows clipboard history.

On Windows, everything you copy is normally also saved by clipboard history (Win+V)
and, if it's turned on, synced to your other devices by the cloud clipboard. Windows
skips an item when it carries these extra clipboard formats, the same ones KeePass and
other password managers set:

- ExcludeClipboardContentFromMonitorProcessing: keep it out of clipboard history, cloud
  sync and clipboard monitors altogether
- CanIncludeInClipboardHistory = 0 and CanUploadToCloudClipboard = 0: the same, one
  feature at a time
- Clipboard Viewer Ignore: honored by some third-party clipboard managers

On other systems this falls back to pyperclip.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import Iterator


class ClipboardError(Exception):
    pass


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes as wt

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    DWORD_ZERO = (0).to_bytes(4, "little")

    PRIVACY_FORMATS = (
        ("ExcludeClipboardContentFromMonitorProcessing", DWORD_ZERO),
        ("CanIncludeInClipboardHistory", DWORD_ZERO),
        ("CanUploadToCloudClipboard", DWORD_ZERO),
        ("Clipboard Viewer Ignore", DWORD_ZERO),
    )

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Declare every signature: without them ctypes passes handles as 32-bit ints, which
    # silently breaks on 64-bit Windows.
    _user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                        wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
    _user32.CreateWindowExW.restype = wt.HWND
    _user32.DestroyWindow.argtypes = [wt.HWND]
    _user32.DestroyWindow.restype = wt.BOOL
    _user32.OpenClipboard.argtypes = [wt.HWND]
    _user32.OpenClipboard.restype = wt.BOOL
    _user32.CloseClipboard.argtypes = []
    _user32.CloseClipboard.restype = wt.BOOL
    _user32.EmptyClipboard.argtypes = []
    _user32.EmptyClipboard.restype = wt.BOOL
    _user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
    _user32.SetClipboardData.restype = wt.HANDLE
    _user32.GetClipboardData.argtypes = [wt.UINT]
    _user32.GetClipboardData.restype = wt.HANDLE
    _user32.RegisterClipboardFormatW.argtypes = [wt.LPCWSTR]
    _user32.RegisterClipboardFormatW.restype = wt.UINT
    _kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wt.HGLOBAL
    _kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
    _kernel32.GlobalLock.restype = wt.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
    _kernel32.GlobalUnlock.restype = wt.BOOL
    _kernel32.GlobalSize.argtypes = [wt.HGLOBAL]
    _kernel32.GlobalSize.restype = ctypes.c_size_t
    _kernel32.GlobalFree.argtypes = [wt.HGLOBAL]
    _kernel32.GlobalFree.restype = wt.HGLOBAL

    @contextmanager
    def _opened() -> Iterator[None]:
        # The clipboard needs an owner window; a hidden one is enough.
        hwnd = _user32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None)
        if not hwnd:
            raise ClipboardError(f"could not create a clipboard window (error {ctypes.get_last_error()})")
        try:
            # Another program may have the clipboard open for a moment; wait briefly.
            deadline = time.monotonic() + 0.5
            while not _user32.OpenClipboard(hwnd):
                if time.monotonic() >= deadline:
                    raise ClipboardError("the clipboard is in use by another program")
                time.sleep(0.01)
            try:
                yield
            finally:
                _user32.CloseClipboard()
        finally:
            _user32.DestroyWindow(hwnd)

    def _put(fmt: int, data: bytes) -> None:
        handle = _kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not handle:
            raise ClipboardError("out of memory")
        ptr = _kernel32.GlobalLock(handle)
        if not ptr:
            _kernel32.GlobalFree(handle)
            raise ClipboardError("out of memory")
        ctypes.memmove(ptr, data, len(data))
        _kernel32.GlobalUnlock(handle)
        if not _user32.SetClipboardData(fmt, handle):
            _kernel32.GlobalFree(handle)  # on success the clipboard owns it instead
            raise ClipboardError(f"could not write to the clipboard (error {ctypes.get_last_error()})")

    def _get(fmt: int) -> bytes | None:
        """Raw clipboard data in format fmt, or None. The clipboard must be open."""
        handle = _user32.GetClipboardData(fmt)
        if not handle:
            return None
        ptr = _kernel32.GlobalLock(handle)
        if not ptr:
            return None
        try:
            return ctypes.string_at(ptr, _kernel32.GlobalSize(handle))
        finally:
            _kernel32.GlobalUnlock(handle)

    def read_format(name: str) -> bytes | None:
        """Raw data for a registered clipboard format, or None if absent."""
        with _opened():
            return _get(_user32.RegisterClipboardFormatW(name))

    def copy(text: str) -> None:
        with _opened():
            if not _user32.EmptyClipboard():
                raise ClipboardError("could not clear the clipboard")
            # Set every privacy marker before publishing the secret. A failed
            # marker must not leave plaintext behind in an unmarked clipboard.
            for name, value in PRIVACY_FORMATS:
                fmt = _user32.RegisterClipboardFormatW(name)
                if not fmt:
                    raise ClipboardError("could not register clipboard privacy formats")
                _put(fmt, value)
            _put(CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))

    def paste() -> str:
        with _opened():
            data = _get(CF_UNICODETEXT)
        if not data:
            return ""
        text = data.decode("utf-16-le", errors="replace")
        return text.split("\0", 1)[0]

    def clear() -> None:
        with _opened():
            if not _user32.EmptyClipboard():
                raise ClipboardError("could not clear the clipboard")

else:
    import pyperclip

    def copy(text: str) -> None:
        try:
            pyperclip.copy(text)
        except pyperclip.PyperclipException as exc:
            raise ClipboardError(str(exc)) from exc

    def paste() -> str:
        try:
            return pyperclip.paste()
        except pyperclip.PyperclipException as exc:
            raise ClipboardError(str(exc)) from exc

    def clear() -> None:
        copy("")
