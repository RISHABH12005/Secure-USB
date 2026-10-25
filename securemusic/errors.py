"""Application-specific exceptions.

Messages are written to be safe to show to the user: they never include
passwords or decrypted file contents.
"""

from __future__ import annotations


class SecureUSBError(Exception):
    """Base class for errors this application understands."""


class PasswordPolicyError(SecureUSBError):
    """The supplied password does not meet the minimum policy."""


class VaultFormatError(SecureUSBError):
    """The file is not a vault, uses an unsupported format, or is truncated."""


class AuthenticationError(SecureUSBError):
    """The password is wrong or the encrypted data failed authentication."""


class VaultLockedError(SecureUSBError):
    """An operation needs an unlocked vault."""


class VaultChangedError(SecureUSBError):
    """The vault file changed on disk after it was unlocked."""


class UnknownFileError(SecureUSBError):
    """The requested file is not present in the vault."""


class InvalidFilenameError(SecureUSBError):
    """A filename is unsafe or not valid on Windows."""


class DuplicateNameError(SecureUSBError):
    """A file with that name already exists in the vault."""


class BackupError(SecureUSBError):
    """An encrypted backup could not be created or verified."""


class InsufficientSpaceError(SecureUSBError):
    """There is not enough free disk space for a safe write."""


class VaultTooLargeError(SecureUSBError):
    """The vault would exceed the supported size limit."""


class MediaError(SecureUSBError):
    """A song could not be prepared or opened in an external player."""


class FileOperationError(SecureUSBError):
    """A filesystem operation could not be completed safely."""
