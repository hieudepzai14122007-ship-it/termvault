# TermVault security hardening review

Latest follow-up: 2026-10-04. Combined result: **301 passed, 9 skipped**. See the privacy upgrade below for the latest changes; native Windows enforcement remains unverified.

Date: 2026-10-02
Input archive commit marker: 38a83fca027d4a116309cf8b03be0c589332ab58

This is a source review and tested hardening patch, not an independent security audit or a guarantee of maximum security. The application remains an offline, local password manager. The encrypted version-1 format, Argon2id and AES-256-GCM are preserved.

## Changes

| Area | Problem addressed | Result |
| --- | --- | --- |
| Password rotation | Backup rewrite and deletion failures were swallowed; main replacement could leave an old-password backup | Derive first; remove and flush the managed old backup before main replacement; abort on removal failure; report new-backup failures |
| Rotation state | Derivation failures could leave mismatched salt, KDF and key | Prepare new material before state changes and restore state on pre-commit failures |
| Writes | Fixed temporary names, permissive file creation and non-atomic backup copy | Exclusive random temporary files; atomic ciphertext publication; file and POSIX directory flushing; atomic backup writes |
| File access | Symbolic links, extra hard links and unsafe directories | Reject nonregular and multiply linked vault/backup/lock files; check ownership and reject POSIX directories writable by others |
| Permissions | Legacy and new vaults could be readable by other local users | New POSIX files use 0600; owned legacy files are tightened on reading; new parent directories request 0700 |
| Multiple writers | Only the CLI had a lifetime lock | Keep CLI lock; add short-lived interprocess write locks, object thread serialization, and encrypted-envelope revision checks for direct Vault callers |
| Guard writes | Guard could write an older ciphertext snapshot; large failure counts requested giant powers | Coordinate vault-file guard writes with the write lock; bound counters and exponentiation |
| Save failures | CRUD mutated plaintext entries before persistence succeeded | Persist candidate state first; publish in-memory entries only after success |
| Uncertain commits | A directory-flush failure could be misreported as an ordinary rolled-back write | Raise CommitUncertainError and lock sessions after ambiguous main commits; require reopening |
| Opening | Partial state assignment and unvalidated entry data | Fully authenticate, parse and validate payload before marking the vault unlocked; failed unlock clears the session |
| Envelope | Wrong field types, nonstrict version checks, missing size checks | Strict version, salt and nonce lengths, Base64 types, ciphertext/tag bounds and bounded reading before JSON/KDF |
| JSON | Duplicate fields and nonfinite constants accepted | Reject duplicates, NaN and Infinity in vault documents/payloads |
| KDF | Valid but costly attacker-controlled settings | Separate compatibility bounds from default automatic execution limits; explicit API override for expensive legacy settings |
| KDF upgrade | Increasing time could reduce memory, or vice versa | Retain the greater memory and time values; preserve current parallelism |
| Entries | Live references, duplicate IDs and weak runtime types | Defensive copies; reject duplicate IDs and invalid types, timestamps and oversized values |
| Secrets in logs | Generated dataclass repr contained passwords and notes | Redacted Entry representation |
| Secrets in memory | Strength LRU cache retained plaintext password keys after locking | Remove the password-keyed cache |
| UI | Duplicate master-change submissions and ineffective weak-master warning | Submission guard; clear password inputs after processing; fix bound-method comparison; surface persistence warnings/errors |
| Clipboard | OSC 52 fallback could not clear secrets but did not prominently report it | Explicit warning when clearing/history protection are unavailable |
| Encryption contract | AESGCM also accepts shorter keys | Explicit 32-byte key contract and validated encryption inputs |

## Verification

The suite includes original tests and 48 new security regression cases, including malformed input before Argon2, invalid authenticated entries, failed writes, stale sessions after password rotation, symlink behavior, private permissions, expensive settings, and backup deletion failures.

Actual subprocess termination tests interrupt rotation before main replacement and after main replacement. They verify which password opens the surviving vault and that the managed old backup is absent.

A compatibility probe created a vault with the unmodified input code, opened and saved it with the patched code, and opened the resulting file with the original code. It passed using version 1 and cheap test KDF settings. This is not exhaustive compatibility testing for every historic or malformed file.

Tests ran on Linux, Python 3.12.14. Tested libraries: cryptography 46.0.0, argon2-cffi 25.1.0, textual 8.2.8, zxcvbn 4.5.0, pyotp 2.10.0, pyperclip 1.11.0, pytest 9.1.1 and pytest-asyncio 1.4.0. Test KDFs are intentionally cheap; this run does not benchmark production Argon2 settings or offline cracking speed. Tests were run outside the restricted executor because a minimal asyncio.to_thread program reproduced a thread-pool shutdown hang inside it.

The source inspection included the UI, clipboard, guard, generator, card, TOTP, process protection, storage and crypto code. An auxiliary AST graph was generated, but contained unresolved references and collapsed edges; security conclusions were checked against source and tests rather than relying on graph completeness.

## Compatibility and resource policy

- Automatic key derivation accepts at most 512 MiB memory, 6 passes and parallelism 8. The broader format-validation limits remain available.
- For a trusted legacy vault above the automatic limit, the Python API supports `Vault(path, allow_expensive_kdf=True)`. This override allows a potentially costly derivation; it never lowers the stored parameters. The CLI has no override flag in this patch.
- The encrypted file is limited to 24 MiB; plaintext to 16 MiB; entry count to 10,000; individual text fields to 1 MiB; IDs to 128 characters; new master passwords to 2,048 characters.
- Supported entry types remain login, note and card. Missing password_changed retains the existing migration from updated. Unknown entry fields remain ignored for compatibility.
- Malformed data previously accepted, symlink vaults, multiply linked files and unsafe POSIX parent directories now fail closed. Use a regular file in a directory you control.
- Entry callers receive copies. Call update() explicitly to persist modifications. API consumers must not depend on object identity or implicit mutation.
- The .write.lock sidecar is a coordination file, not a vault or secret. Do not remove lock files while writers are running: replacing their inode can defeat advisory locking.

## Password-change recovery

Removing and flushing the old backup precedes replacing the main vault. There is intentionally no two-file atomic-transaction claim.

1. If derivation, validation or old-backup removal fails, the main vault retains the old password.
2. If interrupted after backup removal but before main replacement, the old main vault remains and the backup may be absent.
3. If interrupted after main replacement, the new password opens the main vault. The new backup may be absent.
4. If a new backup write fails, rotation can succeed with a visible backup warning. No managed old backup is silently retained.
5. If main replacement occurred but directory flushing fails, the session locks and reports uncertainty. Reopen the canonical file; after a real power failure, recovery may require checking both passwords against the surviving file.

A failed rotation can lose the one-step undo backup while retaining the main vault. A successful ordinary save still keeps one prior encrypted state, which may include a deleted entry. Maintain a deliberate recovery copy before upgrading; that copy remains encrypted under its own old password until you separately rotate or remove it.

## Remaining boundaries

- No independent audit, formal verification, penetration test or platform certification was performed.
- Windows-specific clipboard, process-DACL and filesystem-ACL tests need execution on Windows. The privacy upgrade below supplies explicit Windows file ACLs; Python's POSIX mode bits alone do not establish Windows privacy. Python does not provide a portable Windows directory-fsync guarantee here.
- Native macOS behavior was not tested. Cloud/network filesystems may have different atomicity and durability semantics.
- Directory flushing and process-crash tests do not establish a guarantee against every hardware power-loss scenario. Use a normal local filesystem with dependable storage.
- Python strings, bytes, framework widgets, caller-held Entry copies and temporary plaintext may remain in process memory after references are dropped. Redacting repr and removing the cache reduce retention; they do not prove secure erasure. The patch does not encrypt RAM, swap or hibernation images.
- The existing process hardening is Windows-only. Administrator/root access, same-account malware, keylogging, terminal capture and a compromised interpreter remain outside the protection provided by this vault.
- The app-level wrong-password guard is unauthenticated and bypassable by anyone controlling the files or running an offline cracker. Its two locations are not a globally atomic shared counter across all vault instances. It is a keyboard deterrent.
- Write locks are advisory and coordinate this application. A program that ignores them can still alter files. Revision checks reject stale snapshots, but do not prove rollback resistance against an attacker restoring an older valid vault.
- Changing a password affects the canonical file and managed backup. It cannot revoke external copies, filesystem snapshots, cloud version history or orphaned ciphertext temporary files left by earlier crashes. Secure deletion on SSDs is not promised.
- OSC 52 cannot be read back or reliably cleared, so the privacy upgrade removes this route from TermVault copying. Clipboard privacy flags depend on OS and other clipboard managers honoring them.
- AES-GCM still relies on secure randomness and avoiding nonce reuse. The random nonce implementation was preserved; there is no deterministic uniqueness proof or altered cryptographic format.

## Use and test

Extract the archive into a separate directory and install using the existing README instructions. Review the included patch and try opening a copy of an existing vault first. Do not test an upgrade on your only recovery copy.

Run the tests in an isolated Python environment:

```sh
python -m venv .venv
# Activate .venv for your operating system.
python -m pip install -e '.[dev]'
python -m pytest -q
```

Windows 11 results are recorded in the native Windows verification section at the end of this file.

## 2026-10-03 extension

The latest archive additionally includes Defender/CFA-backed protected mode, detection-only file scanning, and a dedicated Windows build recipe. See [MALWARE_PROTECTION.md](../MALWARE_PROTECTION.md) for the Kaspersky-inspired design comparison and exact limitations. Forty-four additional policy/integration cases pass using mocked Windows calls; native Windows enforcement, scanner operation and packaging remain unverified.

## 2026-10-04 follow-up bug review

This review found and patched additional failures in the already hardened archive. The encrypted format remains version 1.

| Failure | Result after this patch |
| --- | --- |
| Ctrl+L during a background unlock was ignored; cancelling its coroutine could leave the worker unlocked | An unlock generation invalidates pending attempts. Checks run before derivation and before opening the main screen, and the background worker itself drops the key after invalidation, even if its awaiter was cancelled |
| Shutdown retained the Vault object's key and decrypted-entry references | App teardown invalidates attempts, waits for the vault mutex and locks the object. This drops references; it does not prove memory erasure |
| Locking while a password-change worker held the mutex could block the UI before hiding details | The lock screen is shown before waiting for the mutex. New unlock submissions are refused while that lock operation is finishing |
| A failed second copy stopped the previous secret's clearing timer and forgot its ownership | Ownership and the existing timer change only after a successful native copy |
| A transient clearing error discarded the comparison value and never retried | While the UI runs, three one-second retries retain the comparison value. Exhaustion or shutdown drops it and reports manual clearing; successful clearing cannot be guaranteed |
| Windows compared clipboard text and cleared it in separate clipboard sessions | The native compare-and-clear helper holds one clipboard lock across both operations. The pyperclip fallback cannot provide this atomic guarantee |
| A Windows copy containing NUL was truncated, so the full-string clearing comparison never matched | Both the app and clipboard API refuse NUL-containing text before publishing it. Native clipboard reads are bounded to 4 MiB plus a terminator |
| A temporary-file cleanup error after replacement could hide a committed write, restoring the old in-memory key during rotation | Cleanup no longer masks write outcomes. Errors after exclusive publication are reported as CommitUncertainError, which locks the vault. Best-effort cleanup can still leave encrypted temporary files |
| TOTP URI parameters were discarded, including algorithm, code length, time period and HOTP type | Only SHA1, six-digit, 30-second TOTP links are accepted by this seed-only model. Other settings, duplicated security parameters and malformed links are rejected. Previously discarded parameters cannot be recovered; re-enter the original provisioning data |
| An invalid stored TOTP seed crashed the Copy 2FA action | Invalid or unsupported seeds show an error and are not copied |
| Deep JSON in the guard store or vault crashed before the normal vault parser could reject it; non-string salts could fail during fingerprinting | Guard reads catch recursion failures and validate the encryption header before fingerprinting |
| Invalid generator settings retained an older password that the Use action could still accept | Failure clears the generated value, output and strength information, so no stale value can be accepted |
| zxcvbn 4.5.0 rejects input longer than 72 characters, but the app supplied a 100-character prefix | Strength estimation uses at most 72 characters. Full passwords remain unchanged in storage and key derivation |

The new regressions are in `tests/test_review_round2.py`. They include controlled thread interleavings, cancellation of a running unlock awaiter, simulated committed-write cleanup errors, malformed guard input, TOTP parameter ambiguity, clipboard retry exhaustion, and long-password storage round trips. Windows clipboard compare-and-clear ordering is tested with mocked APIs; it still needs native Windows execution. Existing native Windows tests remain skipped on this Linux host.

An auxiliary code-only AST map was used for navigation, but its extraction reported 130 dangling-endpoint edges, 9 self-loops and 29 collapsed directed endpoint pairs. Findings were established from source and executable regressions, not from assumptions about graph completeness.

Sources checked for the compatibility fixes:

- https://github.com/google/google-authenticator/wiki/Key-Uri-Format
- https://github.com/dwolfhub/zxcvbn-python
- https://docs.python.org/3/library/asyncio-task.html

The existing malware-protection boundaries remain: this is application hardening, not proof of a clean OS or protection against every keylogger, injected process or privileged attacker. See [MALWARE_PROTECTION.md](../MALWARE_PROTECTION.md) for Windows deployment requirements.

## 2026-10-04 privacy upgrade

This implements the approved Windows storage-permission and secret-exposure upgrades.

| Area | Change | Limit |
| --- | --- | --- |
| Windows files | Create files with a protected DACL granting full access to the current user and SYSTEM, using Win32 SECURITY_ATTRIBUTES; verify the actual handle ACL before use | Requires local storage that preserves and enforces ACLs; does not stop administrators or same-user programs |
| Legacy files | Tighten owned vault files, managed backups and lock files; verify the new ACL after applying it | Does not revoke previously opened handles or protect external copies; unreadable or foreign-owned files are refused |
| Temporary files | Supply the private ACL at CREATE_NEW, before writing any ciphertext; use random names and noninheritable handles | Existing process/power-loss durability limits remain |
| Directories | Create new directories with private ACLs under a verified private parent; inspect existing directories without rewriting them | Existing directories must be owned by the user, with no mutation rights for other ordinary accounts; administrators remain privileged |
| Storage verification | Check handle type, file attributes, hard-link count, owner, DACL and FILE_PERSISTENT_ACLS | Reparse leaf objects, alternate data streams, unverifiable ACLs and unsupported storage are refused; this is not a proof against every path race or compromised OS |
| Clipboard | Remove the OSC 52 fallback in all modes and override Textual's editor-copy route | Copy can now be unavailable on terminals without a readable backend; clearing may still fail and is reported |
| Editor clipboard cache | Read clipboard text on demand instead of storing it in Textual's indefinite App._clipboard cache | A comparison value is still held while a cleanup timer/retry is pending; Python erasure is not guaranteed |
| Cut/Paste failure | Private Input/TextArea widgets preserve text if copy/paste is refused; successful editing retains undo support | Copied plaintext remains accessible to clipboard readers until it is cleared |
| TOTP visibility | Generate and display the code only while Reveal is active; hide after 30 seconds, entry selection or locking | Direct Copy 2FA still works without displaying the code and uses the same clipboard cleanup |
| UI lock failure | Drop key/plaintext-entry references in a finally block even if the screen transition fails; propagate failures that leave a live entry screen | Does not prove erasure of widget/framework/caller-held copies |

Final verification: **301 passed, 9 skipped in 35.13 seconds**, Linux, Python 3.12.14. The new `tests/test_privacy_upgrade.py` adds 49 passing policy, failure-path and UI cases plus three native Windows filesystem cases. The existing six Windows clipboard/process tests also remain skipped. This does not establish native Win32 ABI correctness, actual cross-account denial, Defender/CFA enforcement, FAT/network behavior, or Windows packaging correctness. Run the complete suite on Windows against disposable data before using this build with an original vault.

The auto-lock test now waits for both the lock screen and completion of key locking. The previous assertion could end the app while its intentional screen-before-key sequence was still running. Controlled UI-failure cases additionally verify that a transition error cannot skip key locking.

Checked dependencies: cryptography 50.0.2, argon2-cffi 25.1.0, textual 8.2.8, zxcvbn 4.5.0, pyotp 2.10.0, pyperclip 1.11.0, pytest 9.1.1 and pytest-asyncio 1.4.0. No production KDF benchmark or malware-efficacy evaluation was performed. Encryption and the version-1 data format are unchanged; the compatibility changes are storage-permission checks, masked TOTP display, clipboard behavior and refusal of unsupported Windows storage.

Implementation sources:

- https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
- https://docs.python.org/3/library/msvcrt.html#msvcrt.open_osfhandle
- Installed Textual 8.2.8 source: App.copy_to_clipboard, Input.action_cut and TextArea.action_cut

## Native Windows verification (2026-10-04)

Run on Windows 11, Python 3.13, against disposable data:

- Full suite: 306 passed, 4 skipped (POSIX-only). This includes the native clipboard, process-protection and filesystem-ACL tests that were skipped on Linux. One test fake was missing the new `clear_if_matches` route and was fixed; auto-clear was also confirmed against the real Windows clipboard.
- A vault created by the previous version opened and saved in this version and reopened in the previous version. Its file ACL was tightened from three inherited rules to the current user and SYSTEM.
- The default `~/.termvault` folder passed the new directory checks read-only.
