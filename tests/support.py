"""Shared fixtures for the test suite."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from securemusic import crypto
from securemusic.vault import VaultSession

PASSWORD = "Correct horse battery staple 2026"
WRONG_PASSWORD = "This is definitely not the password"

# A deliberately cheap scrypt setting so the suite runs quickly.  Vaults
# created by the app itself use crypto.DEFAULT_KDF (N=2**15, r=8, p=1).
TEST_KDF = crypto.ScryptParams(n=2**12, r=8, p=1)


class VaultTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="securemusic-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.src = self.tmp / "source"
        self.src.mkdir()
        self.dest = self.tmp / "dest"
        self.dest.mkdir()
        self.vault_path = self.tmp / "music.smusb"

    def make_source(self, name: str, data: bytes, folder: str = "") -> Path:
        path = self.src / folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def create_vault(
        self,
        files: dict[str, bytes] | None = None,
        *,
        password: str = PASSWORD,
    ) -> VaultSession:
        session = VaultSession.create(self.vault_path, password, params=TEST_KDF)
        if files:
            sources = [
                self.make_source(name, data, folder=f"f{index}")
                for index, (name, data) in enumerate(files.items())
            ]
            session.add_files(sources)
        return session

    def unlock(
        self,
        path: Path | None = None,
        password: str = PASSWORD,
    ) -> VaultSession:
        return VaultSession.unlock(path or self.vault_path, password)

    def backups(self) -> list[Path]:
        return sorted(self.tmp.glob("*.backup-*.smusb"))
