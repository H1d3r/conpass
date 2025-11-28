"""Credentials model for authentication."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Credentials:
    """User credentials for authentication."""

    username: str
    domain: str
    password: str

    @property
    def user_principal(self) -> str:
        """Get user principal name for LDAP binding."""
        return f"{self.domain}\\{self.username}"
