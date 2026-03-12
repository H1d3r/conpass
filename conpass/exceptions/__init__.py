"""Custom exceptions for ConPass."""

from conpass.exceptions.errors import (
    ConpassError,
    ConfigurationError,
    LdapConnectionError,
    SmbConnectionError,
    UserLockedOutError,
)

__all__ = [
    "ConpassError",
    "ConfigurationError",
    "LdapConnectionError",
    "SmbConnectionError",
    "UserLockedOutError",
]
