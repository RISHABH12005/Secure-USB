from __future__ import annotations

import os
import time
import unittest
from unittest import mock

from securemusic.errors import MediaError
from securemusic.player import (
    TempMediaManager,
    cleanup_stale_temp_dirs,
    is_audio,
    open_default,
    open_with,
)
from tests.support import VaultTestBase


class AudioDetectionTests(unittest.TestCase):
    def test_recognises_common_audio_extensions(self) -> None:
        for name in ("song.mp3", "Track.FLAC", "voice.m4a", "x.ogg", "y.opus", "z.wav"):
            with self.subTest(name=name):
                self.assertTrue(is_audio(name))

    def test_rejects_non_audio_names(self) -> None:
        for name in ("notes.txt", "song.exe", "mp3", "archive.zip", "cover.jpg"):
            with self.subTest(name=name):
                self.assertFalse(is_audio(name))


class TempMediaManagerTests(VaultTestBase):
    def _manager(self) -> TempMediaManager:
        manager = TempMediaManager(parent_directory=self.tmp / "temp")
        self.addCleanup(manager.close)
        return manager

    def test_materialize_creates_private_decrypted_copy(self) -> None:
        data = b"ID3-fake-audio" * 100
        session = self.create_vault({"song.mp3": data})
        manager = self._manager()

        path = manager.materialize(session, "song.mp3")
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.parent, manager.directory)
        self.assertEqual(path.suffix, ".mp3")
        self.assertIn(path, manager.pending)
        self.assertEqual(manager.directory.parent, self.tmp / "temp")

        report = manager.cleanup()
        self.assertTrue(report.complete)
        self.assertEqual(report.removed, 1)
        self.assertFalse(path.exists())
        self.assertEqual(manager.pending, [])

    def test_unknown_extension_uses_bin_suffix(self) -> None:
        session = self.create_vault({"track.weird!": b"data"})
        manager = self._manager()
        path = manager.materialize(session, "track.weird!")
        self.assertEqual(path.suffix, ".bin")
        self.assertEqual(path.read_bytes(), b"data")

    def test_cleanup_is_best_effort_while_file_is_open(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows-specific file locking behaviour")
        session = self.create_vault({"song.mp3": b"music"})
        manager = self._manager()
        path = manager.materialize(session, "song.mp3")

        handle = open(path, "rb")
        try:
            report = manager.cleanup()
            self.assertFalse(report.complete)
            self.assertEqual(len(report.failed), 1)
            self.assertTrue(path.exists())
            self.assertIn(path, manager.pending)
        finally:
            handle.close()

        report = manager.cleanup()
        self.assertTrue(report.complete)
        self.assertFalse(path.exists())
        self.assertEqual(manager.pending, [])

    @unittest.skipUnless(os.name == "nt", "Windows default-file association")
    def test_open_default_uses_windows_association(self) -> None:
        with mock.patch(
            "securemusic.player.os.startfile", create=True
        ) as startfile:
            open_default(self.tmp / "song.mp3")
        startfile.assert_called_once()
        self.assertTrue(str(startfile.call_args.args[0]).endswith("song.mp3"))

    def test_open_with_rejects_missing_player(self) -> None:
        with self.assertRaises(MediaError):
            open_with(self.tmp / "song.mp3", self.tmp / "not-a-player.exe")

    def test_open_with_builds_expected_command(self) -> None:
        player = self.tmp / "player.exe"
        song = self.tmp / "song.mp3"
        player.write_bytes(b"")
        song.write_bytes(b"")
        with mock.patch("securemusic.player.subprocess.Popen") as popen:
            popen.return_value = object()
            open_with(song, player)
        popen.assert_called_once()
        self.assertEqual(
            popen.call_args.args[0],
            [str(player), str(song)],
        )


class StaleTempCleanupTests(VaultTestBase):
    def test_removes_only_old_prefixed_directories(self) -> None:
        temp_root = self.tmp / "temproot"
        temp_root.mkdir()

        old_directory = temp_root / "SecureMusicUSB-old"
        old_directory.mkdir()
        old_file = old_directory / "track-1.mp3"
        old_file.write_bytes(b"decrypted")
        old_time = time.time() - 3 * 24 * 60 * 60
        os.utime(old_file, (old_time, old_time))
        os.utime(old_directory, (old_time, old_time))

        fresh_directory = temp_root / "SecureMusicUSB-fresh"
        fresh_directory.mkdir()
        fresh_file = fresh_directory / "track-2.mp3"
        fresh_file.write_bytes(b"in use")

        unrelated = temp_root / "OtherApp"
        unrelated.mkdir()
        (unrelated / "file.txt").write_bytes(b"untouched")

        removed, _failures = cleanup_stale_temp_dirs(
            temp_root, older_than_seconds=24 * 60 * 60
        )
        self.assertEqual(removed, 1)
        self.assertFalse(old_directory.exists())
        self.assertTrue(fresh_directory.exists())
        self.assertTrue(fresh_file.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((unrelated / "file.txt").exists())
