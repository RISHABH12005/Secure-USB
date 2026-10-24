"""Application-specific exceptions.

Messages are written to be safe to show to the user: they never include
passwords or decrypted file contents.
"""

from __future__ import annotations


class SecureMusicError(Exception):
    """Base class for errors this application understands."""


class PasswordPolicyError(SecureMusicError):
    """The supplied password does not meet the minimum policy."""


class VaultFormatError(SecureMusicError):
    """The file is not a vault, uses an unsupported format, or is truncated."""


class AuthenticationError(SecureMusicError):
    """The password is wrong or the encrypted data failed authentication."""


class VaultLockedError(SecureMusicError):
    """An operation needs an unlocked vault."""


class VaultChangedError(SecureMusicError):
    """The vault file changed on disk after it was unlocked."""


class UnknownFileError(SecureMusicError):
    """The requested file is not present in the vault."""


class InvalidFilenameError(SecureMusicError):
    """A filename is unsafe or not valid on Windows."""


class DuplicateNameError(SecureMusicError):
    """A file with that name already exists in the vault."""


class BackupError(SecureMusicError):
    """An encrypted backup could not be created or verified."""


class InsufficientSpaceError(SecureMusicError):
    """There is not enough free disk space for a safe write."""


class VaultTooLargeError(SecureMusicError):
    """The vault would exceed the supported size limit."""


class MediaError(SecureMusicError):
    """A song could not be prepared or opened in an external player."""


class FileOperationError(SecureMusicError):
    """A filesystem operation could not be completed safely."""
