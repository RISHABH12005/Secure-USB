from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from securemusic import crypto
from securemusic.errors import AuthenticationError, VaultFormatError

PASSWORD = b"Correct horse battery staple 2026"
TEST_KDF = crypto.ScryptParams(n=2**12, r=8, p=1)


class CryptoRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="securemusic-crypto-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _write_vault(
        self,
        data: bytes,
        *,
        password: bytes = PASSWORD,
        params: crypto.ScryptParams = TEST_KDF,
    ) -> Path:
        path = self.tmp / f"vault-{os.urandom(4).hex()}.smusb"
        path.write_bytes(crypto.encrypt_bytes(data, password, params=params))
        return path

    def test_stream_roundtrip_large_payload(self) -> None:
        data = os.urandom(2 * 1024 * 1024 + 137)
        packed = crypto.encrypt_bytes(data, PASSWORD, params=TEST_KDF)
        self.assertEqual(crypto.decrypt_bytes(packed, PASSWORD), data)

    def test_empty_payload_roundtrip(self) -> None:
        packed = crypto.encrypt_bytes(b"", PASSWORD, params=TEST_KDF)
        self.assertEqual(crypto.decrypt_bytes(packed, PASSWORD), b"")

    def test_header_fields_and_kdf_params(self) -> None:
        params = crypto.ScryptParams(n=2**13, r=4, p=2)
        path = self._write_vault(b"payload", params=params)
        header = crypto.read_header(path)
        self.assertEqual(header.version, crypto.FORMAT_VERSION)
        self.assertEqual(header.kdf_id, crypto.KDF_SCRYPT)
        self.assertEqual((header.n, header.r, header.p), (2**13, 4, 2))
        self.assertEqual(len(header.salt), crypto.SALT_LEN)
        self.assertEqual(len(header.nonce), crypto.NONCE_LEN)
        self.assertEqual(header.header_length, 50)
        self.assertFalse(header.is_legacy)

    def test_plaintext_and_password_are_not_stored(self) -> None:
        secret_plaintext = b"unreleased song bytes 1234567890"
        secret_password = b"SuperSecretPassphrase-For-Tests"
        packed = crypto.encrypt_bytes(
            secret_plaintext, secret_password, params=TEST_KDF
        )
        self.assertNotIn(secret_plaintext, packed)
        self.assertNotIn(secret_password, packed)

    def test_salt_and_nonce_change_on_every_encryption(self) -> None:
        first = crypto.encrypt_bytes(b"identical", PASSWORD, params=TEST_KDF)
        second = crypto.encrypt_bytes(b"identical", PASSWORD, params=TEST_KDF)
        self.assertNotEqual(first[: crypto.SALT_LEN + 22], second[: crypto.SALT_LEN + 22])
        self.assertNotEqual(first[50:], second[50:])
        self.assertEqual(crypto.decrypt_bytes(first, PASSWORD), b"identical")
        self.assertEqual(crypto.decrypt_bytes(second, PASSWORD), b"identical")

    def test_derive_key_is_deterministic_per_salt(self) -> None:
        salt = os.urandom(crypto.SALT_LEN)
        first = crypto.derive_key(PASSWORD, salt, 2**12, 8, 1)
        second = crypto.derive_key(PASSWORD, salt, 2**12, 8, 1)
        other = crypto.derive_key(PASSWORD, os.urandom(crypto.SALT_LEN), 2**12, 8, 1)
        self.assertEqual(len(first), 32)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)


class CryptoFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="securemusic-crypto-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.packed = crypto.encrypt_bytes(
            b"some encrypted music payload", PASSWORD, params=TEST_KDF
        )

    def test_wrong_password_raises_authentication_error(self) -> None:
        with self.assertRaises(AuthenticationError):
            crypto.decrypt_bytes(self.packed, b"wrong password entirely")

    def test_tampered_ciphertext_raises_authentication_error(self) -> None:
        tampered = bytearray(self.packed)
        tampered[-20] ^= 0x01  # inside ciphertext, before the 16-byte tag
        with self.assertRaises(AuthenticationError):
            crypto.decrypt_bytes(bytes(tampered), PASSWORD)

    def test_tampered_tag_raises_authentication_error(self) -> None:
        tampered = bytearray(self.packed)
        tampered[-1] ^= 0x01
        with self.assertRaises(AuthenticationError):
            crypto.decrypt_bytes(bytes(tampered), PASSWORD)

    def test_kdf_parameters_are_authenticated(self) -> None:
        tampered = bytearray(self.packed)
        tampered[10:14] = (2**13).to_bytes(4, "big")  # valid but different N
        with self.assertRaises(AuthenticationError):
            crypto.decrypt_bytes(bytes(tampered), PASSWORD)

    def test_unsafe_kdf_parameters_rejected_before_key_derivation(self) -> None:
        tampered = bytearray(self.packed)
        tampered[10:14] = (3).to_bytes(4, "big")  # not a power of two
        with self.assertRaises(VaultFormatError):
            crypto.decrypt_bytes(bytes(tampered), PASSWORD)

        too_expensive = bytearray(self.packed)
        too_expensive[10:14] = (2**20).to_bytes(4, "big")
        with self.assertRaises(VaultFormatError):
            crypto.decrypt_bytes(bytes(too_expensive), PASSWORD)

    def test_bad_magic_raises_format_error(self) -> None:
        with self.assertRaises(VaultFormatError):
            crypto.decrypt_bytes(b"NOTAVAULT" + b"\x00" * 100, PASSWORD)

    def test_unsupported_version_raises_format_error(self) -> None:
        tampered = bytearray(self.packed)
        tampered[8] = 99
        with self.assertRaises(VaultFormatError) as raised:
            crypto.decrypt_bytes(bytes(tampered), PASSWORD)
        self.assertIn("version", str(raised.exception).lower())

    def test_truncated_header_raises_format_error(self) -> None:
        with self.assertRaises(VaultFormatError):
            crypto.decrypt_bytes(self.packed[:20], PASSWORD)

    def test_truncated_payload_raises_authentication_error(self) -> None:
        with self.assertRaises(AuthenticationError):
            crypto.decrypt_bytes(self.packed[:-1], PASSWORD)

    def test_empty_password_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            crypto.derive_key(b"", os.urandom(16), 2**12, 8, 1)


class LegacyFormatTests(unittest.TestCase):
    def test_version_one_vault_is_readable(self) -> None:
        payload = b"legacy zip payload"
        legacy = crypto.encrypt_bytes_legacy(payload, "legacy password")
        self.assertTrue(legacy.startswith(crypto.MAGIC_V1))
        self.assertEqual(crypto.decrypt_bytes(legacy, b"legacy password"), payload)
        with self.assertRaises(AuthenticationError):
            crypto.decrypt_bytes(legacy, b"wrong legacy password")

    def test_version_one_header_is_reported_as_legacy(self) -> None:
        legacy = crypto.encrypt_bytes_legacy(b"x", "legacy password")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.smusb"
            path.write_bytes(legacy)
            header = crypto.read_header(path)
        self.assertEqual(header.version, 1)
        self.assertTrue(header.is_legacy)
        self.assertEqual((header.n, header.r, header.p), (2**15, 8, 1))
