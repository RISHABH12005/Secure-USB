from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from securemusic.errors import InvalidFilenameError
from securemusic.filenames import (
    MAX_FILENAME_CHARS,
    numbered_destination,
    safe_destination,
    sanitize_filename,
    unique_filename,
    validate_filename,
)


class ValidateFilenameTests(unittest.TestCase):
    def test_accepts_ordinary_names(self) -> None:
        for name in (
            "song.mp3",
            "My Song (1).flac",
            "Ünïcode – track.ogg",
            "a.b.c",
            "no_extension",
            "x" * MAX_FILENAME_CHARS,
        ):
            self.assertEqual(validate_filename(name), name)

    def test_rejects_path_traversal_and_separators(self) -> None:
        for name in (
            "",
            ".",
            "..",
            "../song.mp3",
            "..\\song.mp3",
            "folder/song.mp3",
            "folder\\song.mp3",
            "C:\\Windows\\evil.mp3",
            "C:evil.mp3",
        ):
            with self.subTest(name=name), self.assertRaises(InvalidFilenameError):
                validate_filename(name)

    def test_rejects_windows_invalid_characters(self) -> None:
        for name in (
            "bad?.mp3",
            "bad*.mp3",
            'bad".mp3',
            "bad<name>.mp3",
            "bad|name.mp3",
            "bad\x00name.mp3",
            "bad\x1fname.mp3",
        ):
            with self.subTest(name=name), self.assertRaises(InvalidFilenameError):
                validate_filename(name)

    def test_rejects_reserved_device_names(self) -> None:
        for name in ("CON", "con.mp3", "PRN.txt", "AUX", "NUL.mp3", "COM1", "LPT9.mp3"):
            with self.subTest(name=name), self.assertRaises(InvalidFilenameError):
                validate_filename(name)

    def test_rejects_trailing_dots_spaces_and_leading_space(self) -> None:
        for name in ("song.mp3.", "song.mp3 ", " song.mp3"):
            with self.subTest(name=name), self.assertRaises(InvalidFilenameError):
                validate_filename(name)

    def test_rejects_overlong_and_bidi_controls(self) -> None:
        with self.assertRaises(InvalidFilenameError):
            validate_filename("a" * (MAX_FILENAME_CHARS + 1))
        with self.assertRaises(InvalidFilenameError):
            validate_filename("song\u202egnp.exe")


class SanitizeFilenameTests(unittest.TestCase):
    def test_strips_directory_components(self) -> None:
        self.assertEqual(
            sanitize_filename(r"C:\Users\someone\Music\song.mp3"), "song.mp3"
        )
        self.assertEqual(sanitize_filename("/home/user/song.mp3"), "song.mp3")

    def test_replaces_invalid_characters(self) -> None:
        self.assertEqual(sanitize_filename("bad:name?.mp3"), "bad_name_.mp3")

    def test_reserved_names_are_prefixed(self) -> None:
        self.assertEqual(sanitize_filename("CON.mp3"), "_CON.mp3")
        self.assertEqual(sanitize_filename("lpt1"), "_lpt1")

    def test_emptyish_names_become_file(self) -> None:
        for name in ("", "...", "   ", "///"):
            with self.subTest(name=name):
                self.assertEqual(sanitize_filename(name), "file")

    def test_long_names_are_truncated_keeping_extension(self) -> None:
        sanitized = sanitize_filename("a" * 300 + ".mp3")
        self.assertLessEqual(len(sanitized), MAX_FILENAME_CHARS)
        self.assertTrue(sanitized.endswith(".mp3"))
        self.assertEqual(validate_filename(sanitized), sanitized)

    def test_result_always_validates(self) -> None:
        for name in (".hidden", "a" * 200 + ".flac", "CON", "x?.wav", "trail. "):
            with self.subTest(name=name):
                self.assertEqual(
                    validate_filename(sanitize_filename(name)),
                    sanitize_filename(name),
                )


class UniqueNameTests(unittest.TestCase):
    def test_unique_name_uses_counter_and_preserves_extension(self) -> None:
        taken = {"song.mp3"}
        self.assertEqual(unique_filename("song.mp3", taken), "song (1).mp3")
        taken.add("song (1).mp3")
        self.assertEqual(unique_filename("song.mp3", taken), "song (2).mp3")

    def test_comparison_is_case_insensitive(self) -> None:
        self.assertEqual(unique_filename("SONG.MP3", {"song.mp3"}), "SONG (1).MP3")

    def test_stem_truncation_keeps_name_within_limit(self) -> None:
        long_name = "a" * MAX_FILENAME_CHARS + ".mp3"
        candidate = unique_filename(long_name, {long_name.casefold()})
        self.assertLessEqual(len(candidate), MAX_FILENAME_CHARS)
        self.assertTrue(candidate.endswith(".mp3"))
        validate_filename(candidate)


class DestinationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="securemusic-names-")
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)

    def test_safe_destination_stays_inside(self) -> None:
        target = safe_destination(self.directory, "song.mp3")
        self.assertEqual(target, self.directory.resolve() / "song.mp3")

    def test_safe_destination_rejects_traversal(self) -> None:
        for name in ("../escape.mp3", "..\\escape.mp3", "/etc/passwd"):
            with self.subTest(name=name), self.assertRaises(InvalidFilenameError):
                safe_destination(self.directory, name)

    def test_numbered_destination_counts_existing_files(self) -> None:
        base = self.directory / "song.mp3"
        self.assertEqual(numbered_destination(base).name, "song (1).mp3")
        (self.directory / "song (1).mp3").write_bytes(b"x")
        self.assertEqual(numbered_destination(base).name, "song (2).mp3")
