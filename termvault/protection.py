"""Microsoft Defender integration, not an antivirus engine or a clean-PC proof.

Queries never alter Defender settings. File scans use detection-only mode and
never execute the selected file. Trust ultimately depends on the Windows OS.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATUS_TIMEOUT = 20
SCAN_TIMEOUT = 300
MAX_SIGNATURE_AGE_HOURS = 48


class ProtectionError(OSError):
    """Protection requirements failed or their status could not be verified."""


@dataclass(frozen=True)
class DefenderStatus:
    signature_age_hours: float
    known_active_threats: int


@dataclass(frozen=True)
class ScanResult:
    completed_without_detection: bool
    message: str


def _windows_paths() -> tuple[Path, Path]:
    if sys.platform != "win32":
        raise ProtectionError("Defender integration requires Windows with Microsoft Defender active.")
    # Avoid searching PATH or trusting user-modifiable SystemRoot/ProgramFiles.
    import ctypes
    from ctypes import wintypes as wt
    import winreg

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetWindowsDirectoryW.argtypes = [wt.LPWSTR, wt.UINT]
    kernel32.GetWindowsDirectoryW.restype = wt.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise ProtectionError("Could not locate Windows system tools.")
    root = Path(buffer.value)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            program_files, kind = winreg.QueryValueEx(key, "ProgramFilesDir")
        if kind != winreg.REG_SZ or not isinstance(program_files, str):
            raise ProtectionError("Could not locate Microsoft Defender.")
    except OSError as exc:
        raise ProtectionError("Could not locate Microsoft Defender.") from exc
    return root, Path(program_files)


def _powershell(script: str, *, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    root, _ = _windows_paths()
    executable = root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_file():
        raise ProtectionError("Windows PowerShell is unavailable; protection cannot be verified.")
    env = dict(os.environ)
    env.update(extra_env or {})
    env["TERMVAULT_WINDOWS_ROOT"] = str(root)
    # All script text is application-owned. Filenames are data in environment
    # variables, never interpolated into PowerShell source or a shell command.
    command = [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        result = subprocess.run(command, shell=False, capture_output=True, text=True,
                                encoding="utf-8", errors="strict", timeout=STATUS_TIMEOUT,
                                env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise ProtectionError("Defender query failed or timed out; protection is unverified.") from exc
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ProtectionError("Defender query failed; protection is unverified.")
    try:
        data = json.loads(result.stdout.lstrip("\ufeff"))
    except (ValueError, RecursionError) as exc:
        raise ProtectionError("Defender returned an unreadable status.") from exc
    if not isinstance(data, dict):
        raise ProtectionError("Defender returned an unreadable status.")
    return data


_STATUS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$module = Join-Path $env:TERMVAULT_WINDOWS_ROOT 'System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1'
Import-Module -Name $module -ErrorAction Stop
$s = Defender\Get-MpComputerStatus -ErrorAction Stop
$active = @(Defender\Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive -eq $true })
[pscustomobject]@{
    AMServiceEnabled = $s.AMServiceEnabled
    AntivirusEnabled = $s.AntivirusEnabled
    RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
    BehaviorMonitorEnabled = $s.BehaviorMonitorEnabled
    IoavProtectionEnabled = $s.IoavProtectionEnabled
    AMRunningMode = $s.AMRunningMode
    SignatureAgeHours = $(if ($null -eq $s.AntivirusSignatureLastUpdated) { $null } else {
        ([DateTime]::UtcNow - $s.AntivirusSignatureLastUpdated.ToUniversalTime()).TotalHours
    })
    KnownActiveThreatCount = $active.Count
} | ConvertTo-Json -Compress
"""


def validate_status(data: Any) -> DefenderStatus:
    if not isinstance(data, dict):
        raise ProtectionError("Defender protection status is unverified.")
    for field in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled",
                  "BehaviorMonitorEnabled", "IoavProtectionEnabled"):
        if data.get(field) is not True:
            raise ProtectionError("Defender antivirus, real-time, behavior and download protection must be enabled.")
    if data.get("AMRunningMode") != "Normal":
        raise ProtectionError("Microsoft Defender must be the active antivirus, not in passive mode.")
    age = data.get("SignatureAgeHours")
    if type(age) not in (int, float) or not 0 <= age <= MAX_SIGNATURE_AGE_HOURS or not math.isfinite(age):
        raise ProtectionError("Defender definitions must be updated within the last 48 hours.")
    active = data.get("KnownActiveThreatCount")
    if type(active) is not int or active < 0:
        raise ProtectionError("Known-threat status could not be verified.")
    if active:
        raise ProtectionError("Defender reports an active threat. Keep the vault locked and use Windows Security.")
    return DefenderStatus(float(age), active)


def require_defender() -> DefenderStatus:
    return validate_status(_powershell(_STATUS_SCRIPT))


_FOLDER_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$module = Join-Path $env:TERMVAULT_WINDOWS_ROOT 'System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1'
Import-Module -Name $module -ErrorAction Stop
$p = Defender\Get-MpPreference -ErrorAction Stop
$folder = [IO.Path]::GetFullPath($env:TERMVAULT_VAULT_FOLDER).TrimEnd('\')
$covered = $false
foreach ($item in @($p.ControlledFolderAccessProtectedFolders)) {
    if ($null -eq $item) { continue }
    $root = [IO.Path]::GetFullPath($item).TrimEnd('\')
    if ($folder.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $folder.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { $covered = $true }
}
$interpreters = @('python.exe','pythonw.exe','powershell.exe','pwsh.exe','cmd.exe',
                  'wscript.exe','cscript.exe','mshta.exe')
$broad = @($p.ControlledFolderAccessAllowedApplications | Where-Object {
    $null -ne $_ -and [IO.Path]::GetFileName($_).ToLowerInvariant() -in $interpreters
})
[pscustomobject]@{
    ControlledFolderAccessMode = [int]$p.EnableControlledFolderAccess
    FolderExplicitlyCovered = $covered
    BroadInterpreterExceptionCount = $broad.Count
} | ConvertTo-Json -Compress
"""


def require_protected_folder(folder: Path) -> None:
    """Require an explicit protected folder and actual blocking, not audit mode."""
    data = _powershell(_FOLDER_SCRIPT, extra_env={"TERMVAULT_VAULT_FOLDER": str(folder.resolve())})
    mode = data.get("ControlledFolderAccessMode")
    if type(mode) is not int or mode != 1:
        raise ProtectionError("Controlled Folder Access must be enabled in blocking mode in Windows Security.")
    if data.get("FolderExplicitlyCovered") is not True:
        raise ProtectionError("Add the vault directory to Controlled Folder Access protected folders first.")
    broad = data.get("BroadInterpreterExceptionCount")
    if type(broad) is not int or broad < 0:
        raise ProtectionError("Controlled Folder Access exceptions could not be verified.")
    if broad:
        raise ProtectionError("General-purpose interpreters are allowed through Controlled Folder Access. "
                              "Review those exceptions; protected mode refuses this broad access.")


def require_protection(folder: Path) -> None:
    require_defender()
    require_protected_folder(folder)


_SIGNATURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$s = Get-AuthenticodeSignature -LiteralPath $env:TERMVAULT_SCANNER -ErrorAction Stop
$microsoft = $null -ne $s.SignerCertificate -and
    $s.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)'
[pscustomobject]@{ TrustedMicrosoftSignature = ($s.Status -eq 'Valid' -and $microsoft) } |
    ConvertTo-Json -Compress
"""


def scan_file(path: Path) -> ScanResult:
    """Ask Defender to scan a local regular file, with no remediation by this command."""
    require_defender()
    target = Path(path).expanduser().absolute()
    if target.is_symlink() or not target.is_file():
        raise ProtectionError("Choose a local regular file to scan.")
    # UNC shares and device namespace paths are outside this command's scope.
    if str(target).startswith("\\\\"):
        raise ProtectionError("Choose a file on a local drive.")
    target = target.resolve()
    _, program_files = _windows_paths()
    executable = program_files / "Windows Defender" / "MpCmdRun.exe"
    if not executable.is_file():
        raise ProtectionError("Microsoft Defender's command-line scanner is unavailable.")
    signature = _powershell(_SIGNATURE_SCRIPT, extra_env={"TERMVAULT_SCANNER": str(executable)})
    if signature.get("TrustedMicrosoftSignature") is not True:
        raise ProtectionError("Scanner signature could not be verified as Microsoft-signed.")
    command = [str(executable), "-Scan", "-ScanType", "3", "-File", str(target), "-DisableRemediation"]
    try:
        result = subprocess.run(command, shell=False, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=SCAN_TIMEOUT,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise ProtectionError("Scan timed out; its result is unknown. Check Windows Security.") from exc
    except OSError as exc:
        raise ProtectionError("Scanner could not run; its result is unknown.") from exc
    if result.returncode == 0:
        return ScanResult(True, "Defender completed the detection-only scan without a reported detection. "
                                "This is not a guarantee that the file is safe.")
    if result.returncode == 2:
        return ScanResult(False, "Defender reported a detection, required action, or a scan error. "
                                 "Do not run the file; inspect it in Windows Security.")
    raise ProtectionError("Defender did not report a completed scan; its result is unknown. "
                          "The scan command may require administrator permissions.")
