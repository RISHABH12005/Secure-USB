# SecureMusic USB

A Windows desktop app that keeps music and personal files inside one password-protected
`.smusb` vault, with a dark Tkinter interface.

The vault is a single encrypted file. The app does **not** encrypt the USB drive itself,
does not hide files on the drive, and does not bypass formatting or autorun limits.

## Features

- Create, open, and lock an encrypted vault.
- Add files (including songs) and keep the originals untouched.
- List, rename, delete, and extract files.
- Play a selected song with the Windows default player or a player you choose.
- Create an extra encrypted backup at any time.
- Automatic, verified encrypted backup before every change.
- Streaming encryption, so large vaults are not loaded into memory.
- Safe filenames, case-insensitive duplicate detection, and path-traversal protection.
- Background work with progress dialogs, so the window does not freeze during scrypt or I/O.
- Clear warnings for every operation that exposes plaintext outside the vault.

## Important limits

- **Only files inside the vault are encrypted.** The rest of the USB drive is ordinary storage.
- **Formatting cannot be prevented.** Windows, another computer, a phone, or a disk tool can
  erase or reformat the drive. Keep a separate backup.
- **Autorun is not reliable.** This app does not auto-start on Windows, Android, iPhone, smart
  TVs, or car stereos. Windows blocks autorun from removable drives by default.
- **External players need a decrypted copy.** Playback writes a temporary decrypted file to
  Windows' temp folder. The app tries to delete it on lock, exit, or **Clean temp files**, but
  Windows may keep it open while the player is running.
- **Extracted files are not encrypted.** They are ordinary copies outside the vault.
- **Originals are never moved or deleted.** Adding reads a file and stores an encrypted copy.
  Deleting from the vault does not touch files outside it.
- **Password loss is permanent.** There is no recovery key or back door. Keep an offline copy
  of the password.
- **Wrong password and damage look the same.** AES-GCM reports one authentication failure for
  both. If you are certain the password is correct, restore a backup.
- **Flash erasure is not guaranteed.** Deleting vaults or backups does not physically erase
  flash memory because of wear levelling. Use full-disk encryption for that threat model.
- **Folders are not stored.** Adding a folder skips it; add its files directly. Vault names are
  flat, and original timestamps/attributes are not preserved.
- **No third-party security audit.** This is a practical personal tool, not a replacement for
  professionally reviewed full-disk encryption.

## Requirements

- Windows 10 or 11
- Python 3.10 or newer with Tcl/Tk
- [`cryptography`](https://cryptography.io/) 42 or newer

The test suite was run on Windows 11 with Python 3.13.15, Tk 8.6, and cryptography 50.0.2.

## Install

From Command Prompt or PowerShell in this folder:

```bat
py -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt
```

## Run

```bat
.venv\Scripts\python securemusic_usb.py
```

or:

```bat
.venv\Scripts\python -m securemusic
```

The launcher prints an installation hint if `cryptography` or Tkinter is missing.

To install it as a packaged local command:

```bat
.venv\Scripts\python -m pip install .
.venv\Scripts\securemusic-usb.exe
```

## First use

1. Copy your song to the computer and confirm the copy plays.
2. Plug in the USB drive. **Do not format it.**
3. Click **Create vault** and save the `.smusb` file on the USB drive.
4. Use a long, unique passphrase of at least 12 characters.
5. Click **Add files** and select the song(s). The originals stay where they are.
6. Lock and reopen the vault to confirm the password works.
7. Keep a copy of the vault somewhere else before deleting originals.
8. Playback works through external Windows players only. Other devices cannot read `.smusb`.

## Using the app

| Action | Notes |
| --- | --- |
| Create vault | Refuses to overwrite an existing file. |
| Open vault | Unlocks in a worker thread; the UI stays responsive. |
| Lock / Ctrl+L | Clears the in-memory password and removes temporary songs where possible. |
| Add files | Rejects folders, duplicates get `name (1).ext`, unsafe names are sanitised. |
| Extract selected | Never overwrites unless you explicitly choose **Yes**. **No** creates numbered copies. |
| Rename | Validates the new name and rejects case-insensitive duplicates. |
| Delete from vault | Creates a verified encrypted backup first. Originals outside the vault are untouched. |
| Play / Play with... | Writes a temporary decrypted copy, then launches a player. |
| Backup now | Extra verified encrypted copy next to the vault. |
| Safety & limits | Full warning list inside the app. |

## Security design

### Vault format (version 2)

```text
offset  size  field
0       8     magic "SMUSBv02"
8       1     format version
9       1     KDF id (1 = scrypt)
10      4     scrypt N (big-endian)
14      4     scrypt r
18      4     scrypt p
22      16    random salt
38      12    random AES-GCM nonce
50      ...   ciphertext
end-16  16    AES-GCM authentication tag
```

- **Encryption:** AES-256-GCM, streamed in 1 MiB chunks.
- **Key derivation:** scrypt with `N=2^15`, `r=8`, `p=1` by default (about 32 MiB of memory).
- **Authentication:** the magic, version, KDF parameters, and salt are authenticated as
  additional data. Header tampering fails instead of silently weakening the vault.
- **Fresh randomness:** a new salt and nonce are generated for every save.
- **Password handling:** the session keeps the password in a wipeable byte buffer. Locking
  zeroes it. The app never intentionally writes the password to disk, logs, configuration, or
  the vault (Windows may still page process memory).
- **Header sanity:** unreasonable scrypt parameters are rejected before the KDF runs.
- **Legacy support:** version 1 vaults from the original starter script can be opened; the next
  save upgrades the vault to version 2.

### Safe updates

Every add, rename, or delete follows this sequence:

1. Decrypt the current vault into a private temporary zip.
2. Verify the vault has not changed on disk since unlock.
3. Build and validate the new archive (safe names, no duplicates, size limit).
4. Check free space.
5. Copy the current encrypted vault to a backup and verify its size and SHA-256.
6. Encrypt the new archive to a temporary file, fsync it, and atomically replace the vault.
7. Refresh the on-disk signature.

If any step before the atomic replace fails, the original vault is untouched. An external change
to the vault is detected by size, modification time, and a SHA-256 hash of the first 64 bytes.

### Backups and recovery

- Automatic backups are named like
  `music.backup-20261024-214530-a1b2c3.smusb`, next to the vault.
- Backups are encrypted with the same password as the vault.
- A backup is written to a temporary file, verified, and then renamed into place, so an
  interrupted backup does not look like a valid one.
- **Backup now** creates an extra copy without changing the vault.
- To recover, open a backup with **Open vault**, extract what you need, then create a fresh
  vault and add the files again. Restoring with the same filename is a manual choice; the app
  never overwrites a vault.
- Backups accumulate until you delete them. They contain the same encrypted data and are not a
  substitute for an off-device backup.

### Filename and extraction safety

- Names are validated against Windows rules, reserved device names, control/bidi characters,
  trailing dots/spaces, and length limits.
- Vault members that contain directory components, duplicates, or unsafe names are rejected at
  unlock.
- Extraction resolves the target inside the chosen folder and refuses any escape.
- Existing files are never overwritten unless the user explicitly confirms.
- Zip entries are streamed with a size check, so a malicious archive cannot claim a small size
  and inflate without bound.

### Temporary playback copies

- Directory: `%TEMP%\SecureMusicUSB-*`.
- Each song is random-named, and the app attempts to restrict permissions where Windows allows.
- Files are deleted on lock, exit, or **Clean temp files**.
- Startup cleanup removes leftovers older than 24 hours.
- If Windows or the player still holds a file, the app reports it instead of hiding the failure.
  Close the player and retry.

The same temporary-copy rule applies to encrypting/rewriting: decrypted scratch zips are created
in the system temp folder and deleted immediately after use; older ones are cleaned at startup.

## Tests

```bat
.venv\Scripts\python -m unittest discover -s tests -t . -v
```

Result on Windows 11 with the environment above: **86 tests, all passing**. The suite covers the
vault format, authentication failures, legacy migration, filename/path safety, corrupt and
malicious archives, backup verification, atomic-replace failure, external changes, temp-copy
cleanup, and a Tkinter UI smoke test (skipped automatically when no display is available).

Lint (optional):

```bat
.venv\Scripts\python -m pip install ruff
.venv\Scripts\ruff check securemusic tests securemusic_usb.py
```

Ruff settings live in `pyproject.toml`.

## Packaging (optional, not verified here)

PyInstaller is listed in `requirements-build.txt` but the packaged executable has **not** been
built or tested in this workspace:

```bat
.venv\Scripts\python -m pip install -r requirements-build.txt
.venv\Scripts\pyinstaller --noconfirm --clean --onefile --windowed ^
  --name SecureMusicUSB securemusic_usb.py
```

The result is `dist\SecureMusicUSB.exe`. Test it with a copy of a vault before relying on it.
Unsigned PyInstaller executables are sometimes flagged by antivirus software.

## Project layout

```text
securemusic_usb.py       launcher
securemusic/
  __main__.py            python -m securemusic entry point
  crypto.py              vault header, scrypt, AES-GCM streaming, legacy format
  vault.py               sessions, add/extract/rename/delete, backups, atomic updates
  filenames.py           filename validation and safe destinations
  player.py              temporary decrypted playback copies
  ui.py                  dark Tkinter interface and dialogs
  errors.py              user-facing exception types
tests/                   unit and UI smoke tests
pyproject.toml           packaging, entry point, ruff settings
requirements.txt         runtime dependency
requirements-build.txt   optional PyInstaller dependency
```

## Troubleshooting

- **"cryptography" is missing** — activate the venv or run the `pip install` command above.
- **Tkinter is missing** — reinstall Python from python.org with the Tcl/Tk option enabled.
- **Authentication failed** — check the password and keyboard layout. If it is definitely
  correct, the vault is damaged; use a backup.
- **"Vault changed outside this application"** — another program changed the vault. The app
  locks it for safety. Reopen it.
- **Not enough free space** — the app needs room for the new vault, the old vault, and a backup.
- **A temporary song will not delete** — close the player, then use **Clean temp files**.
- **The drive disappeared** — reconnect it without formatting, then reopen the vault.

## License and risk

No license is included in this repository. This software is provided as-is, without warranty.
Keep independent backups of anything important, and do not rely on it as the only protection for
irreplaceable data.
