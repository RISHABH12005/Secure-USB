"""Filename validation and safe destination handling.

The vault stores a flat set of filenames.  Anything read from a vault is
treated as hostile until it passes :func:`validate_filename`, and anything
written to disk is confined to the chosen destination directory.
"""

from __future__ import annotations

import os
from pathlib import Path

from .errors import InvalidFilenameError

MAX_FILENAME_CHARS = 180
MAX_FILENAME_EXT_CHARS = 32

_INVALID_CHARS = set('<>:"/\\|?*')
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
_BIDI_CONTROLS = {chr(cp) for cp in range(0x202A, 0x202F)} | {
    chr(cp) for cp in range(0x2066, 0x206A)
}

_SAFE_REPLACEMENT = "_"


def _is_control(ch: str) -> bool:
    return ord(ch) < 0x20 or ord(ch) == 0x7F


def _is_reserved(name: str) -> bool:
    stem = name.split(".", 1)[0].upper().rstrip(" ")
    return stem in _RESERVED_NAMES


def validate_filename(name: str) -> str:
    """Return ``name`` if it is a safe, flat Windows-compatible filename.

    Raises:
        InvalidFilenameError: with a user-facing reason.
    """
    if not isinstance(name, str):
        raise InvalidFilenameError("A filename must be text.")
    if not name:
        raise InvalidFilenameError("A filename cannot be empty.")
    if name in (".", ".."):
        raise InvalidFilenameError("A filename cannot be '.' or '..'.")
    if name != name.strip():
        raise InvalidFilenameError(
            f"Filename {name!r} starts or ends with whitespace."
        )
    if name != name.rstrip(" ."):
        raise InvalidFilenameError(
            f"Filename {name!r} cannot end with a space or a dot on Windows."
        )
    if len(name) > MAX_FILENAME_CHARS:
        raise InvalidFilenameError(
            f"Filename {name!r} is too long (maximum {MAX_FILENAME_CHARS} characters)."
        )
    if any(ch in _INVALID_CHARS for ch in name):
        raise InvalidFilenameError(
            f"Filename {name!r} contains a character Windows does not allow "
            f'(one of < > : " / \\ | ? *).'
        )
    if any(_is_control(ch) or ch in _BIDI_CONTROLS for ch in name):
        raise InvalidFilenameError(
            f"Filename {name!r} contains invisible or control characters."
        )
    if _is_reserved(name):
        raise InvalidFilenameError(
            f"Filename {name!r} is reserved by Windows and cannot be used."
        )
    return name


def _fit_length(stem: str, suffix: str) -> str:
    """Trim ``stem`` so ``stem + suffix`` fits the filename limit."""
    allowed = MAX_FILENAME_CHARS - len(suffix)
    if allowed < 1:
        # Very unusual: keep a short extension and at least one stem character.
        suffix = suffix[-(MAX_FILENAME_CHARS - 1):]
        allowed = 1
    return stem[:allowed].rstrip(" .") or "file"


def sanitize_filename(name: str) -> str:
    """Convert a host filename into a safe vault filename.

    Directory components are discarded (only the final name is kept), invalid
    characters become underscores, reserved Windows names are prefixed with an
    underscore, and the result is length-limited while preserving the extension.
    """
    text = str(name)
    base = text.replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(
        ch
        if not (ch in _INVALID_CHARS or _is_control(ch) or ch in _BIDI_CONTROLS)
        else _SAFE_REPLACEMENT
        for ch in base
    )
    base = base.strip(" .")
    if base in ("", ".", ".."):
        base = "file"

    stem, ext = os.path.splitext(base)
    if len(ext) > MAX_FILENAME_EXT_CHARS:
        stem, ext = base, ""
    stem = _fit_length(stem, ext)
    base = stem + ext
    if _is_reserved(base):
        base = "_" + base
        base = _fit_length(base, "")
    if base in ("", ".", ".."):
        base = "file"
    return validate_filename(base)


def unique_filename(name: str, taken_casefold: set[str]) -> str:
    """Return ``name`` or ``name (n)`` that is not in ``taken_casefold``."""
    if name.casefold() not in taken_casefold:
        return name
    stem, ext = os.path.splitext(name)
    counter = 1
    while counter <= 99999:
        suffix = f" ({counter})"
        candidate = _fit_length(stem, suffix + ext) + suffix + ext
        if candidate.casefold() not in taken_casefold:
            return validate_filename(candidate)
        counter += 1
    raise InvalidFilenameError("Could not generate a unique filename.")


def numbered_destination(path: Path) -> Path:
    """Return a non-existing path near ``path`` using ``name (n).ext``."""
    stem, ext = path.stem, path.suffix
    counter = 1
    while counter <= 99999:
        suffix = f" ({counter})"
        candidate = path.with_name(_fit_length(stem, suffix + ext) + suffix + ext)
        if not candidate.exists():
            return candidate
        counter += 1
    raise InvalidFilenameError("Could not find a free filename in the destination.")


def safe_destination(directory: str | os.PathLike[str], name: str) -> Path:
    """Resolve ``name`` inside ``directory`` and refuse any escape."""
    validate_filename(name)
    directory_path = Path(directory).resolve()
    target = (directory_path / name).resolve()
    if target.parent != directory_path:
        raise InvalidFilenameError(
            f"Refusing to write {name!r} outside the chosen destination folder."
        )
    try:
        common = os.path.commonpath((str(directory_path), str(target)))
    except ValueError as exc:
        raise InvalidFilenameError(
            f"Refusing to write {name!r} outside the chosen destination folder."
        ) from exc
    if os.path.normcase(common) != os.path.normcase(str(directory_path)):
        raise InvalidFilenameError(
            f"Refusing to write {name!r} outside the chosen destination folder."
        )
    return directory_path / name
