from __future__ import annotations

import io
import os
import time
import zipfile
from unittest import mock

from securemusic import crypto
from securemusic.errors import (
    AuthenticationError,
    BackupError,
    DuplicateNameError,
    InvalidFilenameError,
    PasswordPolicyError,
    UnknownFileError,
    VaultChangedError,
    VaultFormatError,
    VaultLockedError,
)
from securemusic.vault import VaultSession, cleanup_stale_payload_files
from tests.support import PASSWORD, TEST_KDF, WRONG_PASSWORD, VaultTestBase


class CreateAndUnlockTests(VaultTestBase):
    def test_create_empty_vault_and_reopen(self) -> None:
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        self.assertTrue(self.vault_path.is_file())
        self.assertTrue(session.unlocked)
        self.assertEqual(session.list_files(), [])
        self.assertFalse(session.is_legacy)
        self.assertEqual(session.kdf_params, TEST_KDF)
        self.assertEqual(self.backups(), [])

        session.lock()
        self.assertFalse(session.unlocked)
        reopened = self.unlock()
        self.assertEqual(reopened.list_files(), [])
        reopened.lock()

    def test_create_refuses_to_overwrite_existing_file(self) -> None:
        self.vault_path.write_bytes(b"do not touch this file")
        with self.assertRaises(FileExistsError):
            VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        self.assertEqual(self.vault_path.read_bytes(), b"do not touch this file")

    def test_create_enforces_minimum_password_length(self) -> None:
        for password in ("short", "elevenchars", "", "            "):
            with self.subTest(password=password):
                with self.assertRaises(PasswordPolicyError):
                    VaultSession.create(self.vault_path, password, params=TEST_KDF)
        self.assertFalse(self.vault_path.exists())

    def test_wrong_password_fails_and_leaves_vault_unchanged(self) -> None:
        session = self.create_vault({"song.mp3": b"music"})
        session.lock()
        before = self.vault_path.read_bytes()
        with self.assertRaises(AuthenticationError):
            self.unlock(password=WRONG_PASSWORD)
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_non_vault_file_is_rejected(self) -> None:
        self.vault_path.write_bytes(b"this is not a vault" * 10)
        with self.assertRaises(VaultFormatError):
            self.unlock()

    def test_empty_and_truncated_vault_files_are_rejected(self) -> None:
        self.vault_path.write_bytes(b"")
        with self.assertRaises(VaultFormatError):
            self.unlock()

        self.vault_path.unlink()
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        raw = self.vault_path.read_bytes()
        session.lock()
        self.vault_path.write_bytes(raw[:30])
        with self.assertRaises(VaultFormatError):
            self.unlock()

    def test_corrupted_ciphertext_fails_authentication(self) -> None:
        session = self.create_vault({"song.mp3": b"music"})
        session.lock()
        raw = bytearray(self.vault_path.read_bytes())
        raw[-25] ^= 0xFF  # in ciphertext, not the tag
        self.vault_path.write_bytes(raw)
        with self.assertRaises(AuthenticationError):
            self.unlock()

    def test_parameter_tampering_fails_authentication(self) -> None:
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        session.lock()
        raw = bytearray(self.vault_path.read_bytes())
        raw[10:14] = (2**13).to_bytes(4, "big")
        self.vault_path.write_bytes(raw)
        with self.assertRaises(AuthenticationError):
            self.unlock()

    def test_unlock_accepts_bytes_password(self) -> None:
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        session.lock()
        reopened = VaultSession.unlock(self.vault_path, PASSWORD.encode("utf-8"))
        self.assertTrue(reopened.unlocked)
        reopened.lock()


class FileOperationTests(VaultTestBase):
    def test_add_list_extract_and_original_preserved(self) -> None:
        data = b"original song data\x00\x01" * 500
        source = self.make_source("song.mp3", data)
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)

        result = session.add_files([source])
        self.assertEqual(result.added, ["song.mp3"])
        self.assertEqual(result.renamed, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.total_bytes, len(data))
        self.assertIsNotNone(result.backup)
        assert result.backup is not None
        self.assertTrue(result.backup.exists())

        self.assertEqual(source.read_bytes(), data)
        self.assertTrue(source.exists())
        entries = session.list_files()
        self.assertEqual([(entry.name, entry.size) for entry in entries], [("song.mp3", len(data))])

        extracted = session.extract(["song.mp3"], self.dest)
        self.assertEqual((self.dest / "song.mp3").read_bytes(), data)
        self.assertEqual(len(extracted.written), 1)
        self.assertEqual(extracted.total_bytes, len(data))
        self.assertEqual(source.read_bytes(), data)

        backup_session = self.unlock(result.backup)
        self.assertEqual(backup_session.list_files(), [])
        backup_session.lock()

    def test_unicode_and_space_filenames_roundtrip(self) -> None:
        name = "My Song – ünïcode.flac"
        data = b"flacbytes"
        session = self.create_vault({name: data})
        result = session.extract([name], self.dest)
        self.assertEqual(result.written[0].name, name)
        self.assertEqual((self.dest / name).read_bytes(), data)

    def test_selection_is_case_insensitive(self) -> None:
        session = self.create_vault({"Song.MP3": b"music"})
        result = session.extract(["song.mp3"], self.dest)
        self.assertEqual(result.written[0].name, "Song.MP3")
        self.assertEqual((self.dest / "Song.MP3").read_bytes(), b"music")

    def test_adding_duplicate_names_renames_new_file(self) -> None:
        session = self.create_vault({"song.mp3": b"first"})
        second = self.make_source("Song.mp3", b"second", folder="other")
        result = session.add_files([second])
        self.assertEqual(result.added, ["Song (1).mp3"])
        self.assertEqual(result.renamed, [("Song.mp3", "Song (1).mp3")])
        names = {entry.name for entry in session.list_files()}
        self.assertEqual(names, {"song.mp3", "Song (1).mp3"})

        session.extract(["song.mp3", "Song (1).mp3"], self.dest)
        self.assertEqual((self.dest / "song.mp3").read_bytes(), b"first")
        self.assertEqual((self.dest / "Song (1).mp3").read_bytes(), b"second")

    def test_empty_file_roundtrip(self) -> None:
        source = self.make_source("empty.mp3", b"")
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        result = session.add_files([source])
        self.assertEqual(result.added, ["empty.mp3"])
        self.assertEqual(session.list_files()[0].size, 0)
        session.extract(["empty.mp3"], self.dest)
        self.assertEqual((self.dest / "empty.mp3").read_bytes(), b"")

    def test_add_skips_missing_files_and_directories(self) -> None:
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        result = session.add_files([self.tmp / "missing.mp3", self.src])
        self.assertEqual(result.added, [])
        self.assertEqual(len(result.skipped), 2)
        self.assertIsNone(result.backup)
        self.assertEqual(self.backups(), [])
        self.assertEqual(session.list_files(), [])

    def test_extract_conflict_keeps_existing_and_numbers_copy(self) -> None:
        session = self.create_vault({"song.mp3": b"vault content"})
        existing = self.dest / "song.mp3"
        existing.write_bytes(b"existing content")

        result = session.extract(["song.mp3"], self.dest)
        self.assertEqual(existing.read_bytes(), b"existing content")
        self.assertEqual((self.dest / "song (1).mp3").read_bytes(), b"vault content")
        self.assertEqual(result.renamed, [("song.mp3", "song (1).mp3")])
        self.assertEqual(result.written, [(self.dest / "song (1).mp3").resolve()])

    def test_extract_overwrite_true_replaces_existing(self) -> None:
        session = self.create_vault({"song.mp3": b"vault content"})
        existing = self.dest / "song.mp3"
        existing.write_bytes(b"existing content")

        result = session.extract(["song.mp3"], self.dest, overwrite=True)
        self.assertEqual(existing.read_bytes(), b"vault content")
        self.assertFalse((self.dest / "song (1).mp3").exists())
        self.assertEqual(result.renamed, [])
        self.assertEqual(result.written, [existing.resolve()])

    def test_extract_unknown_file_raises(self) -> None:
        session = self.create_vault({"song.mp3": b"music"})
        with self.assertRaises(UnknownFileError):
            session.extract(["missing.mp3"], self.dest)

    def test_rename_preserves_content_and_creates_backup(self) -> None:
        session = self.create_vault({"old.mp3": b"music bytes"})
        backup = session.rename_file("old.mp3", "new.mp3")
        self.assertIsNotNone(backup)
        assert backup is not None
        self.assertTrue(backup.exists())
        self.assertEqual([entry.name for entry in session.list_files()], ["new.mp3"])

        session.extract(["new.mp3"], self.dest)
        self.assertEqual((self.dest / "new.mp3").read_bytes(), b"music bytes")

        backup_session = self.unlock(backup)
        self.assertEqual([entry.name for entry in backup_session.list_files()], ["old.mp3"])
        backup_session.lock()

    def test_rename_to_existing_name_is_rejected(self) -> None:
        session = self.create_vault({"a.mp3": b"a", "b.mp3": b"b"})
        before = self.vault_path.read_bytes()
        with self.assertRaises(DuplicateNameError):
            session.rename_file("a.mp3", "B.MP3")
        self.assertEqual(self.vault_path.read_bytes(), before)
        self.assertEqual({entry.name for entry in session.list_files()}, {"a.mp3", "b.mp3"})

    def test_rename_with_unsafe_name_is_rejected(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        before = self.vault_path.read_bytes()
        for bad_name in ("../evil.mp3", "C:\\evil.mp3", "CON", "bad?.mp3"):
            with self.subTest(bad_name=bad_name), self.assertRaises(InvalidFilenameError):
                session.rename_file("a.mp3", bad_name)
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_rename_to_same_name_is_a_noop(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        before = self.vault_path.read_bytes()
        self.assertIsNone(session.rename_file("a.mp3", "a.mp3"))
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_delete_removes_only_selected_and_keeps_original(self) -> None:
        source_a = self.make_source("a.mp3", b"a")
        session = self.create_vault({"a.mp3": b"a", "b.mp3": b"b"})
        result = session.delete_files(["a.mp3"])
        self.assertEqual(result.removed, ["a.mp3"])
        self.assertIsNotNone(result.backup)
        assert result.backup is not None
        self.assertEqual([entry.name for entry in session.list_files()], ["b.mp3"])
        self.assertTrue(source_a.exists())
        self.assertEqual(source_a.read_bytes(), b"a")

        backup_session = self.unlock(result.backup)
        self.assertEqual(
            {entry.name for entry in backup_session.list_files()}, {"a.mp3", "b.mp3"}
        )
        backup_session.lock()

    def test_delete_unknown_file_is_rejected(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        with self.assertRaises(UnknownFileError):
            session.delete_files(["missing.mp3"])

    def test_delete_all_files_leaves_a_valid_empty_vault(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        session.delete_files(["a.mp3"])
        self.assertEqual(session.list_files(), [])
        session.lock()
        reopened = self.unlock()
        self.assertEqual(reopened.list_files(), [])

    def test_kdf_parameters_are_preserved_across_saves(self) -> None:
        self.create_vault({"a.mp3": b"a"})
        header = crypto.read_header(self.vault_path)
        self.assertEqual((header.n, header.r, header.p), (TEST_KDF.n, TEST_KDF.r, TEST_KDF.p))
        self.assertEqual(header.version, 2)


class SafetyTests(VaultTestBase):
    def test_backups_are_unique_encrypted_and_decryptable(self) -> None:
        session = VaultSession.create(self.vault_path, PASSWORD, params=TEST_KDF)
        session.add_files([self.make_source("one.mp3", b"UNIQUE-CONTENT-ONE")])
        session.add_files([self.make_source("two.mp3", b"UNIQUE-CONTENT-TWO")])

        backups = self.backups()
        self.assertGreaterEqual(len(backups), 2)
        self.assertEqual(len({backup.name for backup in backups}), len(backups))
        for backup in backups:
            raw = backup.read_bytes()
            self.assertNotIn(b"UNIQUE-CONTENT-ONE", raw)
            self.assertNotIn(b"UNIQUE-CONTENT-TWO", raw)
            reopened = self.unlock(backup)
            reopened.lock()

    def test_failed_atomic_replace_leaves_vault_intact(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        source = self.make_source("b.mp3", b"b")
        before = self.vault_path.read_bytes()

        with mock.patch(
            "securemusic.vault.ATOMIC_REPLACE",
            side_effect=OSError("simulated replace failure"),
        ):
            with self.assertRaises(OSError):
                session.add_files([source])

        self.assertEqual(self.vault_path.read_bytes(), before)
        leftovers = [
            path
            for path in self.tmp.iterdir()
            if path.is_file() and ".tmp-" in path.name
        ]
        self.assertEqual(leftovers, [])
        reopened = self.unlock()
        self.assertEqual([entry.name for entry in reopened.list_files()], ["a.mp3"])
        reopened.lock()

    def test_failed_backup_verification_aborts_change(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        source = self.make_source("b.mp3", b"b")
        before = self.vault_path.read_bytes()
        backups_before = set(self.backups())

        with mock.patch(
            "securemusic.vault._sha256_file", return_value=b"\x00" * 32
        ):
            with self.assertRaises(BackupError):
                session.add_files([source])

        self.assertEqual(self.vault_path.read_bytes(), before)
        self.assertEqual(set(self.backups()), backups_before)
        self.assertEqual(
            [entry.name for entry in session.list_files()], ["a.mp3"]
        )

    def test_external_vault_change_is_detected(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        with open(self.vault_path, "ab") as handle:
            handle.write(b"tamper")
        with self.assertRaises(VaultChangedError):
            session.ensure_current()
        with self.assertRaises(VaultChangedError):
            session.add_files([self.make_source("b.mp3", b"b")])
        session.lock()

    def test_locked_session_rejects_every_operation(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        session.lock()
        operations = (
            session.list_files,
            session.ensure_current,
            lambda: session.add_files([]),
            lambda: session.extract(["a.mp3"], self.dest),
            lambda: session.rename_file("a.mp3", "b.mp3"),
            lambda: session.delete_files(["a.mp3"]),
            lambda: session.extract_to_file("a.mp3", self.dest / "out.mp3"),
            session.backup_now,
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(VaultLockedError):
                operation()

    def test_backup_now_creates_verified_copy(self) -> None:
        session = self.create_vault({"a.mp3": b"a"})
        backup = session.backup_now()
        self.assertTrue(backup.exists())
        self.assertTrue(backup.name.endswith(".smusb"))
        self.assertIn(".backup-", backup.name)
        self.assertEqual(backup.read_bytes(), self.vault_path.read_bytes())
        reopened = self.unlock(backup)
        self.assertEqual([entry.name for entry in reopened.list_files()], ["a.mp3"])


class StalePayloadCleanupTests(VaultTestBase):
    def test_removes_only_old_matching_regular_files(self) -> None:
        root = self.tmp / "temp"
        root.mkdir()
        old_time = time.time() - 2 * 24 * 60 * 60
        expected = []
        for prefix in ("securemusic-payload-", "securemusic-new-", "securemusic-empty-"):
            path = root / f"{prefix}scratch.zip"
            path.write_bytes(b"plaintext")
            os.utime(path, (old_time, old_time))
            expected.append(path)
        fresh = root / "securemusic-payload-fresh.zip"
        fresh.write_bytes(b"plaintext")
        unrelated = root / "unrelated-old.zip"
        unrelated.write_bytes(b"keep")
        os.utime(unrelated, (old_time, old_time))
        directory = root / "securemusic-payload-dir"
        directory.mkdir()

        removed, failed = cleanup_stale_payload_files(
            root, older_than_seconds=24 * 60 * 60
        )

        self.assertEqual((removed, failed), (3, 0))
        for path in expected:
            self.assertFalse(path.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue(directory.exists())


class MaliciousVaultTests(VaultTestBase):
    def _encrypt_zip(
        self,
        path,
        members: list[tuple[str, bytes]],
        *,
        compression: int = zipfile.ZIP_STORED,
    ) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
            for name, data in members:
                archive.writestr(name, data)
        with open(path, "wb") as destination:
            crypto.encrypt_stream(
                io.BytesIO(buffer.getvalue()),
                destination,
                PASSWORD.encode("utf-8"),
                params=TEST_KDF,
            )

    def test_path_traversal_members_are_rejected(self) -> None:
        for index, bad_name in enumerate(
            ("../evil.mp3", "..\\evil.mp3", "C:\\evil.mp3", "folder/evil.mp3")
        ):
            with self.subTest(name=bad_name):
                path = self.tmp / f"bad-{index}.smusb"
                self._encrypt_zip(path, [(bad_name, b"x")])
                with self.assertRaises(VaultFormatError):
                    VaultSession.unlock(path, PASSWORD)

    def test_reserved_or_invalid_member_names_are_rejected(self) -> None:
        for index, bad_name in enumerate(("CON.mp3", "bad?.mp3", "trailing. ")):
            with self.subTest(name=bad_name):
                path = self.tmp / f"invalid-{index}.smusb"
                self._encrypt_zip(path, [(bad_name, b"x")])
                with self.assertRaises(VaultFormatError):
                    VaultSession.unlock(path, PASSWORD)

    def test_case_insensitive_duplicate_members_are_rejected(self) -> None:
        path = self.tmp / "duplicates.smusb"
        self._encrypt_zip(path, [("Song.mp3", b"a"), ("song.mp3", b"b")])
        with self.assertRaises(VaultFormatError):
            VaultSession.unlock(path, PASSWORD)

    def test_directory_entries_are_rejected(self) -> None:
        path = self.tmp / "directory.smusb"
        self._encrypt_zip(path, [("folder/", b"")])
        with self.assertRaises(VaultFormatError):
            VaultSession.unlock(path, PASSWORD)

    def test_authenticated_non_zip_payload_is_rejected(self) -> None:
        path = self.tmp / "notzip.smusb"
        with open(path, "wb") as destination:
            crypto.encrypt_stream(
                io.BytesIO(b"this is authenticated but not a zip archive"),
                destination,
                PASSWORD.encode("utf-8"),
                params=TEST_KDF,
            )
        with self.assertRaises(VaultFormatError):
            VaultSession.unlock(path, PASSWORD)

    def test_corrupt_zip_entry_is_detected_on_extract(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("song.mp3", b"hello world payload")
        raw = bytearray(buffer.getvalue())
        position = raw.find(b"hello world payload")
        self.assertGreater(position, 0)
        raw[position] ^= 0xFF

        path = self.tmp / "corrupt-entry.smusb"
        with open(path, "wb") as destination:
            crypto.encrypt_stream(
                io.BytesIO(bytes(raw)),
                destination,
                PASSWORD.encode("utf-8"),
                params=TEST_KDF,
            )

        session = VaultSession.unlock(path, PASSWORD)
        self.assertEqual([entry.name for entry in session.list_files()], ["song.mp3"])
        with self.assertRaises(VaultFormatError):
            session.extract(["song.mp3"], self.dest)
        self.assertFalse((self.dest / "song.mp3").exists())


class LegacyVaultTests(VaultTestBase):
    def test_legacy_vault_unlocks_and_upgrades_on_save(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("legacy.mp3", b"old song")
        self.vault_path.write_bytes(
            crypto.encrypt_bytes_legacy(buffer.getvalue(), PASSWORD)
        )

        session = self.unlock()
        self.assertTrue(session.is_legacy)
        self.assertEqual([entry.name for entry in session.list_files()], ["legacy.mp3"])

        source = self.make_source("new.mp3", b"new song")
        session.add_files([source])
        self.assertFalse(session.is_legacy)
        header = crypto.read_header(self.vault_path)
        self.assertEqual(header.version, 2)
        self.assertEqual(
            {entry.name for entry in session.list_files()}, {"legacy.mp3", "new.mp3"}
        )

        reopened = self.unlock()
        self.assertFalse(reopened.is_legacy)
        reopened.extract(["legacy.mp3"], self.dest)
        self.assertEqual((self.dest / "legacy.mp3").read_bytes(), b"old song")
