"""Password policy model."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordPolicy:
    """Password policy information (default domain policy or PSO)."""

    name: str
    lockout_threshold: int
    lockout_window_seconds: int

    @property
    def allows_spraying(self) -> bool:
        """Check if this policy allows password spraying (lockout threshold > 0)."""
        return self.lockout_threshold > 0

    @property
    def is_default(self) -> bool:
        """Check if this is the default domain policy."""
        return self.name == "Default Domain Policy"

    def __str__(self) -> str:
        return (
            f"{self.name}: "
            f"Lockout Threshold={self.lockout_threshold}, "
            f"Lockout Window={self.lockout_window_seconds}s"
        )
