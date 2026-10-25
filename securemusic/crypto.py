"""Authenticated encryption for SecureUSB vaults.

Current vault format (version 2)::

    offset  size  field
    0       8     magic b"SMUSBv02"
    8       1     format version (2)
    9       1     KDF id (1 = scrypt)
    10      4     scrypt cost N (big-endian uint32)
    14      4     scrypt block size r
    18      4     scrypt parallelism p
    22      16    random salt
    38      12    random AES-GCM nonce
    50      ...   ciphertext
    end-16  16    AES-GCM authentication tag

Everything from the magic through the salt is supplied to AES-GCM as
additional authenticated data (AAD).  Changing the version, KDF parameters,
or salt therefore makes decryption fail instead of silently weakening the
vault.  The file is encrypted and decrypted as a stream, so large vaults are
not held in memory.

Legacy format (version 1, read-only, produced by the first starter script)::

    0       7     b"SMUSB01"
    7       16    random salt
    23      12    nonce
    35      ...   ciphertext
    end-16  16    tag

Version 1 uses the old fixed scrypt parameters and uses b"SMUSB01" as AAD.
A version 1 vault is transparently upgraded to version 2 the next time it is
saved.
"""

from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import AuthenticationError, VaultFormatError

MAGIC_V2 = b"SMUSBv02"
MAGIC_V1 = b"SMUSB01"
FORMAT_VERSION = 2
KDF_SCRYPT = 1

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
CHUNK_SIZE = 1024 * 1024

_HEADER_STRUCT = struct.Struct(">8sBBIII")
_HEADER_FIXED_LEN = _HEADER_STRUCT.size  # 22
_HEADER_LEN_V2 = _HEADER_FIXED_LEN + SALT_LEN + NONCE_LEN  # 50
_HEADER_LEN_V1 = len(MAGIC_V1) + SALT_LEN + NONCE_LEN  # 35

MIN_N = 2**12
MAX_N = 2**18
MIN_R = 1
MAX_R = 32
MIN_P = 1
MAX_P = 16
MAX_KDF_MEMORY = 512 * 1024 * 1024  # refuse headers that could exhaust RAM


def validate_kdf_params(n: int, r: int, p: int) -> None:
    """Reject expensive or nonsensical scrypt parameters before running KDF."""
    if not isinstance(n, int) or n < MIN_N or n > MAX_N or (n & (n - 1)) != 0:
        raise VaultFormatError("The vault uses unsupported scrypt cost parameters.")
    if not isinstance(r, int) or r < MIN_R or r > MAX_R:
        raise VaultFormatError("The vault uses unsupported scrypt block-size parameters.")
    if not isinstance(p, int) or p < MIN_P or p > MAX_P:
        raise VaultFormatError("The vault uses unsupported scrypt parallelism parameters.")
    if 128 * n * r > MAX_KDF_MEMORY:
        raise VaultFormatError("The vault requests more KDF memory than this app allows.")


@dataclass(frozen=True)
class ScryptParams:
    n: int = 2**15
    r: int = 8
    p: int = 1

    def __post_init__(self) -> None:
        validate_kdf_params(self.n, self.r, self.p)


DEFAULT_KDF = ScryptParams()


@dataclass(frozen=True)
class VaultHeader:
    version: int
    kdf_id: int
    n: int
    r: int
    p: int
    salt: bytes
    nonce: bytes
    aad: bytes
    header_length: int

    @property
    def is_legacy(self) -> bool:
        return self.version == 1


def derive_key(password: bytes | bytearray, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Derive a 32-byte AES key with scrypt.

    The caller is responsible for encoding the password (UTF-8).  Bytes are
    used deliberately so the vault service can wipe its copy when locking.
    """
    if not isinstance(password, (bytes, bytearray, memoryview)):
        raise TypeError("password must be bytes-like")
    if len(password) == 0:
        raise ValueError("password must not be empty")
    validate_kdf_params(n, r, p)
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(bytes(password))


def _parse_header(fp: BinaryIO) -> VaultHeader:
    try:
        fp.seek(0, os.SEEK_END)
        size = fp.tell()
        fp.seek(0)
        prefix = fp.read(8)
    except (OSError, ValueError) as exc:
        raise VaultFormatError("The vault file could not be read.") from exc

    if len(prefix) < 7:
        raise VaultFormatError("This file is too small to be a SecureUSB vault.")

    if prefix[:7] == MAGIC_V1:
        fp.seek(len(MAGIC_V1))
        salt = fp.read(SALT_LEN)
        nonce = fp.read(NONCE_LEN)
        if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
            raise VaultFormatError("The vault header is truncated.")
        if size < _HEADER_LEN_V1 + TAG_LEN:
            raise VaultFormatError("The vault is truncated and cannot be decrypted.")
        return VaultHeader(
            version=1,
            kdf_id=KDF_SCRYPT,
            n=2**15,
            r=8,
            p=1,
            salt=salt,
            nonce=nonce,
            aad=MAGIC_V1,
            header_length=_HEADER_LEN_V1,
        )

    if prefix != MAGIC_V2:
        raise VaultFormatError(
            "This is not a SecureUSB vault (unrecognised file header)."
        )

    fp.seek(0)
    fixed = fp.read(_HEADER_FIXED_LEN)
    if len(fixed) != _HEADER_FIXED_LEN:
        raise VaultFormatError("The vault header is truncated.")
    magic, version, kdf_id, n, r, p = _HEADER_STRUCT.unpack(fixed)
    if magic != MAGIC_V2:
        raise VaultFormatError("This is not a SecureUSB vault.")
    if version != FORMAT_VERSION:
        raise VaultFormatError(
            f"Vault format version {version} is not supported by this version of the app."
        )
    if kdf_id != KDF_SCRYPT:
        raise VaultFormatError("The vault uses an unsupported key-derivation function.")

    salt = fp.read(SALT_LEN)
    nonce = fp.read(NONCE_LEN)
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise VaultFormatError("The vault header is truncated.")
    if size < _HEADER_LEN_V2 + TAG_LEN:
        raise VaultFormatError("The vault is truncated and cannot be decrypted.")

    validate_kdf_params(n, r, p)
    aad = fixed + salt
    return VaultHeader(
        version=version,
        kdf_id=kdf_id,
        n=n,
        r=r,
        p=p,
        salt=salt,
        nonce=nonce,
        aad=aad,
        header_length=_HEADER_LEN_V2,
    )


def read_header(path: str | os.PathLike[str]) -> VaultHeader:
    """Parse and validate a vault header without requiring the password."""
    with open(path, "rb") as fp:
        return _parse_header(fp)


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    password: bytes | bytearray,
    *,
    params: ScryptParams = DEFAULT_KDF,
) -> VaultHeader:
    """Encrypt a readable stream into ``dst`` using AES-256-GCM.

    ``dst`` is written from its current position and is not rewound or closed.
    The caller must fsync and atomically rename the finished file.
    """
    validate_kdf_params(params.n, params.r, params.p)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    fixed = _HEADER_STRUCT.pack(
        MAGIC_V2, FORMAT_VERSION, KDF_SCRYPT, params.n, params.r, params.p
    )
    aad = fixed + salt
    key = derive_key(password, salt, params.n, params.r, params.p)

    dst.write(aad)
    dst.write(nonce)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)

    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break
        dst.write(encryptor.update(chunk))
    dst.write(encryptor.finalize())
    dst.write(encryptor.tag)

    return VaultHeader(
        version=FORMAT_VERSION,
        kdf_id=KDF_SCRYPT,
        n=params.n,
        r=params.r,
        p=params.p,
        salt=salt,
        nonce=nonce,
        aad=aad,
        header_length=_HEADER_LEN_V2,
    )


def decrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    password: bytes | bytearray,
) -> VaultHeader:
    """Authenticate and decrypt a seekable vault stream into ``dst``.

    Raises:
        VaultFormatError: bad magic/version/parameters or a truncated file.
        AuthenticationError: wrong password or modified ciphertext.

    Note: decrypted bytes are written to ``dst`` before the GCM tag is
    verified.  Callers must write to a private temporary file and delete it
    when this function raises.
    """
    header = _parse_header(src)
    key = derive_key(password, header.salt, header.n, header.r, header.p)

    src.seek(0, os.SEEK_END)
    size = src.tell()
    ciphertext_len = size - header.header_length - TAG_LEN
    if ciphertext_len < 0:
        raise VaultFormatError("The vault is truncated and cannot be decrypted.")

    src.seek(size - TAG_LEN)
    tag = src.read(TAG_LEN)
    if len(tag) != TAG_LEN:
        raise VaultFormatError("The vault is truncated and cannot be decrypted.")

    try:
        decryptor = Cipher(algorithms.AES(key), modes.GCM(header.nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header.aad)
    except ValueError as exc:
        raise VaultFormatError("The vault header is invalid.") from exc

    src.seek(header.header_length)
    remaining = ciphertext_len
    while remaining > 0:
        chunk = src.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise VaultFormatError("The vault is truncated and cannot be decrypted.")
        remaining -= len(chunk)
        dst.write(decryptor.update(chunk))

    try:
        decryptor.finalize()
    except InvalidTag as exc:
        raise AuthenticationError(
            "Authentication failed: the password is incorrect or the vault data is damaged."
        ) from exc
    return header


def encrypt_bytes(
    data: bytes,
    password: bytes | bytearray,
    *,
    params: ScryptParams = DEFAULT_KDF,
) -> bytes:
    """Convenience wrapper used by tests and small payloads."""
    src = io.BytesIO(data)
    dst = io.BytesIO()
    encrypt_stream(src, dst, password, params=params)
    return dst.getvalue()


def decrypt_bytes(data: bytes, password: bytes | bytearray) -> bytes:
    """Convenience wrapper used by tests and small payloads."""
    src = io.BytesIO(data)
    dst = io.BytesIO()
    decrypt_stream(src, dst, password)
    return dst.getvalue()


def encrypt_bytes_legacy(data: bytes, password: str) -> bytes:
    """Reproduce the original v1 format for compatibility tests only.

    Never use this for new vaults.
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1)
    key = kdf.derive(password.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC_V1)
    return MAGIC_V1 + salt + nonce + ciphertext
