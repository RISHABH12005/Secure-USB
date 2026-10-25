"""Temporary decrypted copies for external Windows media players.

An external player cannot read inside the encrypted vault.  To play a song the
app must therefore write a temporary decrypted copy.  Copies are held in a
private per-session temporary directory and deleted when the user locks the
vault, closes the app, or clicks "Clean temp files".  Deletion is best-effort:
Windows may keep a file open while a player is using it.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .errors import MediaError

AUDIO_EXTENSIONS = frozenset(
    {
        ".aac",
        ".aif",
        ".aiff",
        ".alac",
        ".flac",
        ".m4a",
        ".mp3",
        ".mp4",
        ".oga",
        ".ogg",
        ".opus",
        ".wav",
        ".wma",
    }
)

TEMP_PREFIX = "SecureMusicUSB-"


@dataclass
class CleanupReport:
    removed: int = 0
    failed: list[Path] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.failed


def is_audio(name: str) -> bool:
    return Path(name).suffix.lower() in AUDIO_EXTENSIONS


def open_default(path: str | os.PathLike[str]) -> None:
    """Ask Windows to open the file with its default associated application."""
    if os.name != "nt":
        raise MediaError(
            "Opening songs with the default player is supported on Windows only."
        )
    startfile = getattr(os, "startfile", None)
    if startfile is None:
        raise MediaError("Windows' default file opener is not available.")
    try:
        startfile(str(path))
    except OSError as exc:
        raise MediaError(
            "Windows could not open the temporary song with a media player. "
            "Use 'Play with...' to choose a player program. "
            f"({exc})"
        ) from exc


def open_with(path: str | os.PathLike[str], player: str | os.PathLike[str]) -> subprocess.Popen:
    """Launch a specific player executable with the temporary song."""
    player_path = Path(player)
    if not player_path.is_file():
        raise MediaError(f"The selected player {str(player_path)!r} was not found.")
    try:
        return subprocess.Popen(
            [str(player_path), str(path)],
            close_fds=True,
        )
    except OSError as exc:
        raise MediaError(f"The selected player could not be started: {exc}") from exc


class TempMediaManager:
    """Owns one private temporary directory of decrypted songs."""

    def __init__(self, parent_directory: str | os.PathLike[str] | None = None) -> None:
        parent = Path(parent_directory) if parent_directory is not None else None
        if parent is not None:
            parent.mkdir(parents=True, exist_ok=True)
        self._dir = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=parent))
        self._files: list[Path] = []
        _restrict(self._dir)

    @property
    def directory(self) -> Path:
        return self._dir

    @property
    def pending(self) -> list[Path]:
        return list(self._files)

    def materialize(self, session, name: str) -> Path:
        """Write a decrypted copy of one vault entry into the private directory."""
        _ensure_directory(self._dir)
        suffix = _safe_suffix(name)
        target = self._dir / f"track-{secrets.token_hex(6)}{suffix}"
        session.extract_to_file(name, target)
        _restrict(target)
        self._files.append(target)
        return target

    def cleanup(self) -> CleanupReport:
        report = CleanupReport()
        remaining: list[Path] = []
        for path in self._files:
            try:
                path.unlink()
                report.removed += 1
            except FileNotFoundError:
                report.removed += 1
            except OSError:
                report.failed.append(path)
                remaining.append(path)
        self._files = remaining
        if not self._files:
            try:
                self._dir.rmdir()
            except OSError:
                pass
        return report

    def close(self) -> CleanupReport:
        return self.cleanup()


def cleanup_stale_temp_dirs(
    temp_root: str | os.PathLike[str] | None = None,
    *,
    older_than_seconds: float = 24 * 60 * 60,
) -> tuple[int, int]:
    """Best-effort removal of decrypted leftovers from previously crashed runs.

    Only flat files directly inside directories created by this app are
    considered.  Returns ``(removed_files, failures)``.
    """
    root = Path(temp_root or tempfile.gettempdir())
    now = time.time()
    removed = 0
    failures = 0
    try:
        candidates = list(root.glob(f"{TEMP_PREFIX}*"))
    except OSError:
        return (0, 1)

    for directory in candidates:
        try:
            if not directory.is_dir() or directory.is_symlink():
                continue
            if now - directory.stat().st_mtime < older_than_seconds:
                continue
            for child in directory.iterdir():
                try:
                    if child.is_file() and not child.is_symlink():
                        if now - child.stat().st_mtime >= older_than_seconds:
                            child.unlink()
                            removed += 1
                except OSError:
                    failures += 1
            try:
                directory.rmdir()
            except OSError:
                failures += 1
        except OSError:
            failures += 1
    return (removed, failures)


def _safe_suffix(name: str) -> str:
    suffix = Path(name).suffix.lower()
    if 1 < len(suffix) <= 10 and all(ch.isascii() and (ch.isalnum() or ch == ".") for ch in suffix):
        return suffix
    return ".bin"


def _ensure_directory(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        _restrict(path)


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    except OSError:
        pass
