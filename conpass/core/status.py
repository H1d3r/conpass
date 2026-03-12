"""Authentication status codes and conversion logic."""

from enum import Enum


class AuthStatus(Enum):
    """Authentication status codes from SMB login attempts."""

    SUCCESS = "success"
    PASSWORD_EXPIRED = "password_expired"
    PASSWORD_MUST_CHANGE = "password_must_change"
    ACCOUNT_EXPIRED = "account_expired"
    INVALID_PASSWORD = "invalid_password"
    SMB_CLOSED = "smb_closed"
    ACCOUNT_LOCKOUT = "account_lockout"
    ACCOUNT_RESTRICTION = "account_restriction"
    INVALID_WORKSTATION = "invalid_workstation"
    INVALID_LOGON_HOURS = "invalid_logon_hours"

    @classmethod
    def from_exception(cls, exception: Exception) -> 'AuthStatus':
        """
        Determine authentication status from SMB exception.

        Args:
            exception: Exception raised during SMB login

        Returns:
            AuthStatus corresponding to the exception
        """
        error_str = str(exception)

        # Account lockout - CRITICAL
        if 'STATUS_ACCOUNT_LOCKED_OUT' in error_str:
            return cls.ACCOUNT_LOCKOUT

        # Password issues - These are "success" variants
        if 'STATUS_PASSWORD_EXPIRED' in error_str:
            return cls.PASSWORD_EXPIRED
        if 'STATUS_PASSWORD_MUST_CHANGE' in error_str:
            return cls.PASSWORD_MUST_CHANGE

        # Account issues
        if 'STATUS_ACCOUNT_EXPIRED' in error_str:
            return cls.ACCOUNT_EXPIRED
        if 'STATUS_ACCOUNT_RESTRICTION' in error_str:
            return cls.ACCOUNT_RESTRICTION

        # Logon restrictions
        if 'STATUS_INVALID_WORKSTATION' in error_str:
            return cls.INVALID_WORKSTATION
        if 'STATUS_INVALID_LOGON_HOURS' in error_str:
            return cls.INVALID_LOGON_HOURS
        if 'STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT' in error_str:
            return cls.ACCOUNT_RESTRICTION

        # Invalid password
        if 'STATUS_LOGON_FAILURE' in error_str:
            return cls.INVALID_PASSWORD

        # Connection issues
        if any(msg in error_str for msg in ['Broken pipe', 'Connection reset by peer', 'Error occurs while reading from remote']):
            return cls.SMB_CLOSED

        # Default to invalid password for unknown errors
        return cls.INVALID_PASSWORD

    @property
    def is_success(self) -> bool:
        """Check if this status represents successful authentication."""
        return self in (AuthStatus.SUCCESS, AuthStatus.PASSWORD_EXPIRED, AuthStatus.PASSWORD_MUST_CHANGE, AuthStatus.ACCOUNT_EXPIRED)

    @property
    def is_lockout(self) -> bool:
        """Check if this status represents account lockout."""
        return self == AuthStatus.ACCOUNT_LOCKOUT

    @property
    def is_fatal(self) -> bool:
        """Check if this status should stop the spray operation."""
        return self in (AuthStatus.ACCOUNT_LOCKOUT, AuthStatus.SMB_CLOSED)
