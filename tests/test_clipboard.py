"""The real Windows clipboard: copied secrets must be kept out of clipboard history."""

import sys

import pytest

from termvault import clipboard

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows clipboard formats")


@pytest.fixture
def real_clipboard():
    """Use the real clipboard, putting back whatever text was there before."""
    import pyperclip
    try:
        saved = clipboard.paste()
    except clipboard.ClipboardError:
        saved = ""
    yield
    if saved:
        pyperclip.copy(saved)


def test_copy_marks_item_private(real_clipboard):
    clipboard.copy("FAKE-copied-secret ✓")
    assert clipboard.paste() == "FAKE-copied-secret ✓"
    # Present at all: clipboard history, cloud sync and monitors skip the item.
    assert clipboard.read_format("ExcludeClipboardContentFromMonitorProcessing") is not None
    assert clipboard.read_format("Clipboard Viewer Ignore") is not None
    # DWORD 0 means "no".
    for name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
        data = clipboard.read_format(name)
        assert data is not None and int.from_bytes(data[:4], "little") == 0, name


def test_clear_empties_clipboard(real_clipboard):
    clipboard.copy("FAKE-to-be-cleared")
    clipboard.clear()
    assert clipboard.paste() == ""
    assert clipboard.read_format("CanIncludeInClipboardHistory") is None


def test_ordinary_copy_has_no_privacy_marks(real_clipboard):
    """Control: the marks come from termvault, not from Windows."""
    import pyperclip
    pyperclip.copy("plain text")
    assert clipboard.paste() == "plain text"
    assert clipboard.read_format("ExcludeClipboardContentFromMonitorProcessing") is None
