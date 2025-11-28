"""Credentials model for authentication."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Credentials:
    """User credentials for authentication."""

    username: str
    domain: str
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None

    @property
    def user_principal(self) -> str:
        """Get user principal name for LDAP binding."""
        return f"{self.domain}\\{self.username}"

    def __post_init__(self):
        """Validate credentials."""
        if not any([self.password, self.nt_hash, self.aes_key]):
            raise ValueError("At least one authentication method must be provided")
