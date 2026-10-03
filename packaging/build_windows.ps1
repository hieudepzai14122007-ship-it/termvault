# Build only. This does not change antivirus settings or application allowlists.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Build on a Windows computer.' }
Push-Location (Join-Path $PSScriptRoot '..')
try {
    python -m PyInstaller --noconfirm --clean --onefile --name TermVault --paths . `
        --collect-all textual --collect-all zxcvbn `
        --add-data 'termvault/app.tcss:termvault' `
        --add-data 'termvault/eff_short_wordlist.txt:termvault' `
        packaging/windows_launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'Executable build failed.' }
    Write-Host 'Built dist\TermVault.exe. Native Windows testing and release signing remain your responsibility.'
} finally {
    Pop-Location
}
