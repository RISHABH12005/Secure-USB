"""High-level vault operations.

A vault is one encrypted file that contains a zip archive of flat filenames.
Every change follows the same safe sequence:

1. decrypt to a private temporary zip and verify the vault did not change;
2. build and validate the new archive in a temporary file;
3. check free space for the atomic update and, for deletions, a backup;
4. before deleting, copy the current encrypted vault to a unique backup and
   verify it; adds and renames do not create automatic backups;
5. encrypt the new archive to a temporary file, fsync it, and atomically
   replace the vault.

If any step fails before the atomic replace, the original vault is untouched.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import tempfile
import threading
import time
import zipfile
import zlib
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import crypto
from .errors import (
    BackupError,
    DuplicateNameError,
    InsufficientSpaceError,
    InvalidFilenameError,
    PasswordPolicyError,
    SecureUSBError,
    UnknownFileError,
    VaultChangedError,
    VaultFormatError,
    VaultLockedError,
    VaultTooLargeError,
)
from .filenames import (
    numbered_destination,
    safe_destination,
    sanitize_filename,
    unique_filename,
    validate_filename,
)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
MIN_PASSWORD_BYTES = 1
MAX_PASSWORD_BYTES = MAX_PASSWORD_LENGTH * 4

CHUNK_SIZE = 1024 * 1024
BACKUP_PREFIX = ".backup-"

# Keep under the FAT32 single-file limit (4 GiB - 1 byte) with room for
# filesystem overhead.  Vaults on exFAT/NTFS can still be up to this limit.
MAX_VAULT_BYTES = 4 * 1024**3 - 64 * 1024**2
MAX_TOTAL_PLAINTEXT_BYTES = MAX_VAULT_BYTES
FREE_SPACE_MARGIN = 16 * 1024 * 1024

# Replaced in tests to simulate a failed atomic rename.
ATOMIC_REPLACE = os.replace

# Temporary plaintext artifacts that can survive a crash or power loss.
# They are removed on startup once they are old enough not to belong to a
# concurrent instance.
STALE_PAYLOAD_PREFIXES = (
    "secureusb-payload-",
    "secureusb-new-",
    "secureusb-empty-",
)
STALE_PAYLOAD_MAX_AGE = 24 * 60 * 60


@dataclass(frozen=True)
class VaultEntry:
    name: str
    size: int


@dataclass
class AddResult:
    added: list[str] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    total_bytes: int = 0
    backup: Path | None = None


@dataclass
class ExtractResult:
    written: list[Path] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)
    total_bytes: int = 0


@dataclass
class DeleteResult:
    removed: list[str] = field(default_factory=list)
    backup: Path | None = None


class VaultSession:
    """An unlocked vault.  Call :meth:`lock` when finished.

    The password is held as a mutable byte buffer so it can be overwritten on
    lock.  Python strings created by the GUI cannot be wiped reliably; the GUI
    therefore avoids retaining them beyond the unlock call.
    """

    def __init__(
        self,
        path: Path,
        password: bytearray,
        header: crypto.VaultHeader,
        entries: dict[str, VaultEntry],
        signature: tuple[int, int, bytes],
    ) -> None:
        self._path = path
        self._password: bytearray | None = password
        self._header: crypto.VaultHeader | None = header
        self._entries: dict[str, VaultEntry] = dict(entries)
        self._signature = signature
        self._lock = threading.RLock()
        self._params = crypto.ScryptParams(n=header.n, r=header.r, p=header.p)

    # ------------------------------------------------------------------ state

    @property
    def path(self) -> Path:
        return self._path

    @property
    def unlocked(self) -> bool:
        return self._password is not None

    @property
    def header(self) -> crypto.VaultHeader | None:
        return self._header

    @property
    def is_legacy(self) -> bool:
        return bool(self._header and self._header.is_legacy)

    @property
    def kdf_params(self) -> crypto.ScryptParams:
        return self._params

    def list_files(self) -> list[VaultEntry]:
        with self._lock:
            self._ensure_unlocked()
            return sorted(self._entries.values(), key=lambda entry: entry.name.casefold())

    def ensure_current(self) -> None:
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()

    def lock(self) -> None:
        with self._lock:
            if self._password is not None:
                _wipe(self._password)
            self._password = None
            self._entries.clear()
            self._signature = None
            self._header = None

    # ------------------------------------------------------------- lifecycle

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str],
        password: str,
        *,
        params: crypto.ScryptParams | None = None,
    ) -> VaultSession:
        """Create a new vault and return it unlocked.

        Raises:
            PasswordPolicyError: password shorter than 12 characters.
            FileExistsError: the destination already exists (never overwritten).
        """
        vault_path = Path(path)
        validate_new_password(password)
        if vault_path.exists():
            raise FileExistsError(
                f"A file already exists at {vault_path.name!r}; refusing to overwrite it."
            )
        if not vault_path.parent.is_dir():
            raise FileNotFoundError(
                f"The folder {str(vault_path.parent)!r} does not exist."
            )

        password_bytes = _password_to_bytes(password)
        zip_fd, zip_path = tempfile.mkstemp(prefix="secureusb-empty-", suffix=".zip")
        os.close(zip_fd)
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=f".{vault_path.name}.tmp-", dir=str(vault_path.parent)
        )
        os.close(tmp_fd)
        reserved = False
        try:
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED):
                pass
            chosen_params = params or crypto.DEFAULT_KDF
            with open(zip_path, "rb") as src, open(tmp_path, "wb") as dst:
                crypto.encrypt_stream(src, dst, password_bytes, params=chosen_params)
                dst.flush()
                os.fsync(dst.fileno())

            # Reserve the final name exclusively, then atomically replace the
            # empty reservation.  Another process cannot silently be overwritten.
            try:
                fd = os.open(vault_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise FileExistsError(
                    f"A file already exists at {vault_path.name!r}; refusing to overwrite it."
                ) from exc
            os.close(fd)
            reserved = True
            ATOMIC_REPLACE(tmp_path, str(vault_path))
            tmp_path = ""

            header = crypto.read_header(vault_path)
            signature = _signature(vault_path)
            # Ownership of password_bytes moves to the returned session.
            return cls(vault_path, password_bytes, header, {}, signature)
        except BaseException:
            _wipe(password_bytes)
            if reserved:
                try:
                    if vault_path.exists() and vault_path.stat().st_size == 0:
                        vault_path.unlink()
                except OSError:
                    pass
            raise
        finally:
            _remove_quietly(zip_path)
            if tmp_path:
                _remove_quietly(tmp_path)

    @classmethod
    def unlock(
        cls,
        path: str | os.PathLike[str],
        password: str | bytes | bytearray,
    ) -> VaultSession:
        vault_path = Path(path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Vault file not found: {vault_path}")
        if not vault_path.is_file():
            raise VaultFormatError("The selected path is not a file.")
        try:
            size = vault_path.stat().st_size
        except OSError as exc:
            raise VaultFormatError("The vault file could not be read.") from exc
        if size == 0:
            raise VaultFormatError(
                "The vault file is empty or incomplete (was a write interrupted?)."
            )
        if size > MAX_VAULT_BYTES:
            raise VaultFormatError(
                "The vault is larger than the supported maximum size of this app."
            )

        password_bytes = _password_to_bytes(password)
        payload_fd = None
        payload_path = ""
        try:
            header = crypto.read_header(vault_path)
            signature = _signature(vault_path)
            payload_fd, payload_path = tempfile.mkstemp(
                prefix="secureusb-payload-", suffix=".zip"
            )
            os.close(payload_fd)
            payload_fd = None
            _restrict_file(payload_path)
            with open(vault_path, "rb") as src, open(payload_path, "wb") as dst:
                crypto.decrypt_stream(src, dst, password_bytes)
            if _signature(vault_path) != signature:
                raise VaultChangedError(
                    "The vault file changed while it was being unlocked. Try again."
                )
            entries = _read_entries(payload_path)
            return cls(vault_path, password_bytes, header, entries, signature)
        except BaseException:
            _wipe(password_bytes)
            raise
        finally:
            if payload_fd is not None:
                try:
                    os.close(payload_fd)
                except OSError:
                    pass
            if payload_path:
                _remove_quietly(payload_path)

    # ------------------------------------------------------------- operations

    def add_files(self, paths: Iterable[str | os.PathLike[str]]) -> AddResult:
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()

            taken = {name.casefold() for name in self._entries}
            prepared: list[tuple[Path, str, int]] = []
            renamed: list[tuple[str, str]] = []
            skipped: list[tuple[str, str]] = []
            total_new = 0
            vault_resolved = _try_resolve(self._path)

            for raw in paths:
                source = Path(raw)
                if vault_resolved is not None and _try_resolve(source) == vault_resolved:
                    skipped.append((str(source), "That is the vault file itself."))
                    continue
                if not source.is_file():
                    skipped.append((str(source), "Not a regular file."))
                    continue
                try:
                    size = source.stat().st_size
                except OSError as exc:
                    skipped.append((str(source), f"Could not read the file: {exc}"))
                    continue
                if size > MAX_VAULT_BYTES:
                    raise VaultTooLargeError(
                        f"{source.name!r} is larger than the supported vault size."
                    )

                cleaned = sanitize_filename(source.name)
                final_name = unique_filename(cleaned, taken)
                if final_name != source.name:
                    renamed.append((source.name, final_name))
                taken.add(final_name.casefold())
                total_new += size
                prepared.append((source, final_name, size))

            if not prepared:
                return AddResult(skipped=skipped)

            existing_total = sum(entry.size for entry in self._entries.values())
            if existing_total + total_new > MAX_VAULT_BYTES:
                raise VaultTooLargeError(
                    "The new files would make the vault larger than the supported "
                    "limit (about 4 GiB, the FAT32 single-file limit)."
                )

            def build(source_zip: zipfile.ZipFile, target_zip: zipfile.ZipFile) -> None:
                for name in list(self._entries):
                    _copy_member(source_zip, target_zip, name)
                for source, final_name, _size in prepared:
                    with open(source, "rb") as src, target_zip.open(final_name, "w") as dst:
                        shutil.copyfileobj(src, dst, CHUNK_SIZE)

            backup = self._commit(build)
            return AddResult(
                added=[name for _, name, _ in prepared],
                renamed=renamed,
                skipped=skipped,
                total_bytes=total_new,
                backup=backup,
            )

    def rename_file(
        self, current_name: str, new_name: str
    ) -> Path | None:
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            actual = self._resolve(current_name)
            if not isinstance(new_name, str):
                raise InvalidFilenameError("The new filename must be text.")
            new_name = new_name.strip()
            new_name = validate_filename(new_name)
            if new_name == actual:
                return None
            if new_name.casefold() in {
                name.casefold() for name in self._entries if name != actual
            }:
                raise DuplicateNameError(
                    f"A file named {new_name!r} already exists in this vault."
                )

            def build(source_zip: zipfile.ZipFile, target_zip: zipfile.ZipFile) -> None:
                for name in list(self._entries):
                    destination = new_name if name == actual else name
                    _copy_member(source_zip, target_zip, name, destination)

            return self._commit(build)

    def delete_files(self, names: Iterable[str]) -> DeleteResult:
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            names_list = list(names)
            if not names_list:
                raise UnknownFileError("No files were selected.")
            removed = [self._resolve(name) for name in names_list]
            removed_set = set(removed)

            def build(source_zip: zipfile.ZipFile, target_zip: zipfile.ZipFile) -> None:
                for name in list(self._entries):
                    if name not in removed_set:
                        _copy_member(source_zip, target_zip, name)

            backup = self._commit(build, backup_before_change=True)
            return DeleteResult(removed=removed, backup=backup)

    def extract(
        self,
        names: Iterable[str],
        destination: str | os.PathLike[str],
        *,
        overwrite: bool = False,
    ) -> ExtractResult:
        """Extract selected entries as plain files.

        Existing files are never replaced unless ``overwrite=True``; otherwise
        a numbered filename is chosen.  The caller must warn the user that
        extracted copies are no longer protected by the vault.
        """
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            selected = [self._resolve(name) for name in names]
            if not selected:
                raise UnknownFileError("No files were selected.")
            dest = Path(destination)
            if not dest.is_dir():
                raise SecureUSBError(
                    f"The destination folder {str(dest)!r} does not exist."
                )

            result = ExtractResult()
            try:
                with self._read_payload() as payload, zipfile.ZipFile(payload, "r") as archive:
                    for name in selected:
                        target = safe_destination(dest, name)
                        final_target = target
                        if target.exists() and not overwrite:
                            final_target = numbered_destination(target)
                            result.renamed.append((name, final_target.name))
                        _extract_member(archive, name, final_target, overwrite=overwrite)
                        result.written.append(final_target)
                        result.total_bytes += self._entries[name].size
            except (
                zipfile.BadZipFile,
                zlib.error,
                RuntimeError,
                NotImplementedError,
            ) as exc:
                raise VaultFormatError(
                    "The vault payload is damaged; extraction was stopped."
                ) from exc
            return result

    def preview_extract_conflicts(
        self, names: Iterable[str], destination: str | os.PathLike[str]
    ) -> list[str]:
        with self._lock:
            self._ensure_unlocked()
            dest = Path(destination)
            conflicts: list[str] = []
            for name in names:
                actual = self._resolve(name)
                target = safe_destination(dest, actual)
                if target.exists():
                    conflicts.append(actual)
            return conflicts

    def extract_to_file(
        self, name: str, destination: str | os.PathLike[str]
    ) -> Path:
        """Stream one entry to a caller-chosen path (used for temporary playback)."""
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            actual = self._resolve(name)
            target = Path(destination)
            try:
                with self._read_payload() as payload, zipfile.ZipFile(payload, "r") as archive:
                    info = archive.getinfo(actual)
                    with archive.open(info, "r") as src, open(target, "wb") as dst:
                        _stream_member(src, dst, info.file_size)
                        dst.flush()
                        try:
                            os.fsync(dst.fileno())
                        except OSError:
                            pass
            except (
                zipfile.BadZipFile,
                zlib.error,
                RuntimeError,
                NotImplementedError,
            ) as exc:
                _remove_quietly(target)
                raise VaultFormatError(
                    "The vault payload is damaged; the file could not be read."
                ) from exc
            except BaseException:
                _remove_quietly(target)
                raise
            return target

    def backup_now(self) -> Path:
        """Create an extra encrypted backup without changing the vault."""
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            return self._create_backup()

    # --------------------------------------------------------------- internals

    def _ensure_unlocked(self) -> None:
        if self._password is None:
            raise VaultLockedError("The vault is locked. Unlock it first.")

    def _verify_unchanged(self) -> None:
        if self._signature is None:
            raise VaultLockedError("The vault is locked. Unlock it first.")
        try:
            current = _signature(self._path)
        except OSError as exc:
            raise VaultChangedError(
                "The vault file is missing or can no longer be read. "
                "Lock and unlock it again."
            ) from exc
        if current != self._signature:
            raise VaultChangedError(
                "The vault file changed outside this application. "
                "For safety, lock and unlock it again before continuing."
            )

    def _resolve(self, name: str) -> str:
        if not isinstance(name, str):
            raise UnknownFileError("Invalid file selection.")
        lookup = {existing.casefold(): existing for existing in self._entries}
        actual = lookup.get(name.casefold())
        if actual is None:
            raise UnknownFileError(
                f"{name!r} is not in the unlocked vault (it may have been removed)."
            )
        return actual

    @contextmanager
    def _read_payload(self) -> Iterator[str]:
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            fd, payload_path = tempfile.mkstemp(
                prefix="secureusb-payload-", suffix=".zip"
            )
            os.close(fd)
            try:
                _restrict_file(payload_path)
                with open(self._path, "rb") as src, open(payload_path, "wb") as dst:
                    crypto.decrypt_stream(src, dst, self._password)
                self._verify_unchanged()
                yield payload_path
            finally:
                _remove_quietly(payload_path)

    def _commit(
        self,
        build: Callable[[zipfile.ZipFile, zipfile.ZipFile], None],
        *,
        backup_before_change: bool = False,
    ) -> Path | None:
        with self._lock:
            self._ensure_unlocked()
            self._verify_unchanged()
            new_fd, new_zip_path = tempfile.mkstemp(
                prefix="secureusb-new-", suffix=".zip"
            )
            os.close(new_fd)
            try:
                with self._read_payload() as payload_path:
                    try:
                        with zipfile.ZipFile(payload_path, "r") as source_zip, zipfile.ZipFile(
                            new_zip_path,
                            "w",
                            compression=zipfile.ZIP_DEFLATED,
                            compresslevel=6,
                        ) as target_zip:
                            build(source_zip, target_zip)
                    except (
                zipfile.BadZipFile,
                zlib.error,
                RuntimeError,
                NotImplementedError,
            ) as exc:
                        raise VaultFormatError(
                            "The decrypted vault payload is damaged and cannot be rewritten."
                        ) from exc

                new_entries = _read_entries(new_zip_path)
                self._verify_unchanged()
                self._check_free_space(
                    os.path.getsize(new_zip_path), backup=backup_before_change
                )
                backup = self._create_backup() if backup_before_change else None
                new_header = self._encrypt_and_replace(new_zip_path)
                self._entries = new_entries
                self._signature = _signature(self._path)
                self._header = new_header
                return backup
            finally:
                _remove_quietly(new_zip_path)

    def _check_free_space(
        self, new_payload_size: int, *, backup: bool = False
    ) -> None:
        try:
            current_size = self._path.stat().st_size
        except OSError:
            current_size = 0
        # Atomic replacement needs space for the old vault and new temporary
        # encrypted vault. Deletion additionally needs a second old-vault copy.
        needed = new_payload_size + current_size * (2 if backup else 1) + FREE_SPACE_MARGIN
        free = shutil.disk_usage(self._path.parent).free
        if free < needed:
            detail = "including the deletion backup and temporary files" if backup else "for the temporary update files"
            raise InsufficientSpaceError(
                "Not enough free space for a safe update. "
                f"About {_fmt_bytes(needed)} is needed ({detail}) "
                f"but only {_fmt_bytes(free)} is available."
            )

    def _create_backup(self) -> Path:
        """Copy, verify, then atomically publish an encrypted vault backup."""
        try:
            source_size = self._path.stat().st_size
        except OSError as exc:
            raise BackupError("The current vault could not be read for backup.") from exc

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        last_error: Exception | None = None
        for _attempt in range(10):
            candidate = self._path.with_name(
                f"{self._path.stem}.backup-{stamp}-{secrets.token_hex(3)}.smusb"
            )
            if candidate.exists():
                continue
            temp_candidate = self._path.with_name(
                f".secureusb-backup-{secrets.token_hex(6)}.tmp"
            )
            try:
                digest = hashlib.sha256()
                with open(self._path, "rb") as src, open(temp_candidate, "xb") as dst:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        digest.update(chunk)
                        dst.write(chunk)
                    dst.flush()
                    os.fsync(dst.fileno())

                if (
                    os.path.getsize(temp_candidate) != source_size
                    or _sha256_file(temp_candidate) != digest.digest()
                ):
                    raise BackupError(
                        "The encrypted backup failed verification and was removed. "
                        "No changes were made."
                    )
                os.replace(temp_candidate, candidate)
                temp_candidate = ""
                return candidate
            except FileExistsError as exc:
                last_error = exc
                continue
            except BackupError:
                raise
            except OSError as exc:
                raise BackupError(
                    f"An encrypted backup could not be created: {exc}"
                ) from exc
            finally:
                if temp_candidate:
                    _remove_quietly(temp_candidate)

        raise BackupError("A unique backup filename could not be created.") from last_error

    def _encrypt_and_replace(self, zip_path: str) -> crypto.VaultHeader:
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=f".{self._path.name}.tmp-", dir=str(self._path.parent)
        )
        try:
            with os.fdopen(tmp_fd, "wb") as dst, open(zip_path, "rb") as src:
                header = crypto.encrypt_stream(
                    src, dst, self._password, params=self._params
                )
                dst.flush()
                os.fsync(dst.fileno())
            self._verify_unchanged()
            ATOMIC_REPLACE(tmp_path, str(self._path))
            tmp_path = ""
            return header
        finally:
            if tmp_path:
                _remove_quietly(tmp_path)


# --------------------------------------------------------------------- helpers


def validate_new_password(password: str) -> None:
    if not isinstance(password, str):
        raise PasswordPolicyError("The password must be text.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Use a password or passphrase of at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"The password is too long (maximum {MAX_PASSWORD_LENGTH} characters)."
        )
    if not password.strip():
        raise PasswordPolicyError("The password cannot consist only of whitespace.")


def _password_to_bytes(password: str | bytes | bytearray) -> bytearray:
    if isinstance(password, bytearray):
        data = bytearray(password)
    elif isinstance(password, bytes):
        data = bytearray(password)
    elif isinstance(password, str):
        if len(password) > MAX_PASSWORD_LENGTH:
            raise PasswordPolicyError("The password is too long.")
        data = bytearray(password.encode("utf-8"))
    else:
        raise TypeError("password must be str or bytes-like")
    if len(data) < MIN_PASSWORD_BYTES:
        raise PasswordPolicyError("The password cannot be empty.")
    if len(data) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError("The password is too long.")
    return data


def _wipe(buffer: bytearray | None) -> None:
    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


def _read_entries(zip_path: str) -> dict[str, VaultEntry]:
    entries: dict[str, VaultEntry] = {}
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir():
                    raise VaultFormatError(
                        "The vault contains directory entries, which this app does not create."
                    )
                try:
                    name = validate_filename(info.filename)
                except InvalidFilenameError as exc:
                    raise VaultFormatError(
                        "The vault contains an unsafe filename and was not opened."
                    ) from exc
                key = name.casefold()
                if key in seen:
                    raise VaultFormatError(
                        "The vault contains duplicate filenames and was not opened."
                    )
                if info.file_size < 0:
                    raise VaultFormatError("The vault contains an invalid file size.")
                total += info.file_size
                if total > MAX_TOTAL_PLAINTEXT_BYTES:
                    raise VaultFormatError(
                        "The vault payload is larger than this app supports."
                    )
                seen.add(key)
                entries[name] = VaultEntry(name=name, size=info.file_size)
    except zipfile.BadZipFile as exc:
        raise VaultFormatError(
            "The decrypted data is not a valid vault archive; the vault may be damaged."
        ) from exc
    return entries


def cleanup_stale_payload_files(
    temp_root: str | os.PathLike[str] | None = None,
    *,
    older_than_seconds: int = STALE_PAYLOAD_MAX_AGE,
) -> tuple[int, int]:
    """Best-effort removal of old decrypted scratch zips.

    Returns ``(removed, failed)``.  Only regular files with a known prefix and
    an age above the threshold are touched, so a concurrent operation is not
    disturbed and unrelated temp files are left alone.
    """
    root = Path(temp_root) if temp_root is not None else Path(tempfile.gettempdir())
    now = time.time()
    removed = 0
    failed = 0
    try:
        entries = list(root.iterdir())
    except OSError:
        return (0, 1)
    for entry in entries:
        try:
            if entry.is_symlink() or not entry.is_file():
                continue
            if not entry.name.startswith(STALE_PAYLOAD_PREFIXES):
                continue
            if now - entry.stat().st_mtime < older_than_seconds:
                continue
            entry.unlink()
            removed += 1
        except OSError:
            failed += 1
    return (removed, failed)


def _stream_member(src, dst, expected: int) -> None:
    """Copy exactly ``expected`` bytes, refusing deceptive zip metadata."""
    remaining = expected
    while remaining:
        chunk = src.read(min(CHUNK_SIZE, remaining + 1))
        if not chunk:
            break
        if len(chunk) > remaining:
            raise VaultFormatError(
                "A file inside the vault is larger than its recorded size. "
                "The vault may be malicious or damaged."
            )
        dst.write(chunk)
        remaining -= len(chunk)
    if remaining:
        raise VaultFormatError(
            "A file inside the vault is shorter than its recorded size. "
            "The vault may be damaged."
        )
    if src.read(1):
        raise VaultFormatError(
            "A file inside the vault contains more data than its recorded size. "
            "The vault may be malicious or damaged."
        )


def _copy_member(
    source_zip: zipfile.ZipFile,
    target_zip: zipfile.ZipFile,
    source_name: str,
    target_name: str | None = None,
) -> None:
    info = source_zip.getinfo(source_name)
    with source_zip.open(info, "r") as src, target_zip.open(
        target_name or source_name, "w"
    ) as dst:
        _stream_member(src, dst, info.file_size)


def _extract_member(
    archive: zipfile.ZipFile,
    name: str,
    target: Path,
    *,
    overwrite: bool,
) -> None:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise UnknownFileError(f"{name!r} is not in the vault archive.") from exc

    if overwrite:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".secureusb-extract-", dir=str(target.parent)
        )
        try:
            with os.fdopen(fd, "wb") as dst, archive.open(info, "r") as src:
                _stream_member(src, dst, info.file_size)
                dst.flush()
                try:
                    os.fsync(dst.fileno())
                except OSError:
                    pass
            os.replace(tmp_path, target)
            tmp_path = ""
        finally:
            if tmp_path:
                _remove_quietly(tmp_path)
    else:
        created = False
        try:
            with archive.open(info, "r") as src, open(target, "xb") as dst:
                created = True
                _stream_member(src, dst, info.file_size)
                dst.flush()
                try:
                    os.fsync(dst.fileno())
                except OSError:
                    pass
        except BaseException:
            if created:
                _remove_quietly(target)
            raise


def _signature(path: Path) -> tuple[int, int, bytes]:
    stat = path.stat()
    with open(path, "rb") as fp:
        head = fp.read(64)
    return (stat.st_size, stat.st_mtime_ns, hashlib.sha256(head).digest())


def _sha256_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.digest()


def _try_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except OSError:
        return None


def _restrict_file(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _remove_quietly(path: str | os.PathLike[str]) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _fmt_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024**2:
        return f"{value / 1024:.1f} KB"
    if value < 1024**3:
        return f"{value / 1024**2:.1f} MB"
    return f"{value / 1024**3:.2f} GB"
