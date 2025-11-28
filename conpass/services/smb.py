"""SMB service for authentication testing and time synchronization."""

import time
from datetime import datetime, timedelta, timezone

from impacket.smbconnection import SMBConnection
from rich.console import Console

from conpass.core.status import AuthStatus
from conpass.exceptions import SmbConnectionError, UserLockedOutError
from conpass.utils import NtlmInfo


class SmbService:
    """Service for SMB operations (authentication testing, time sync)."""

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        console: Console | None = None,
        max_retries: int = 3
    ):
        self.dc_ip = dc_ip
        self.domain = domain
        self.console = console
        self.max_retries = max_retries

        self._connection: SMBConnection | None = None
        self._retry_count = 0

    def connect(self) -> None:
        """
        Establish SMB connection to the domain controller.

        Raises:
            SmbConnectionError: If unable to establish connection
        """
        try:
            self._connection = SMBConnection(self.dc_ip, self.dc_ip)
            self._retry_count = self.max_retries
        except Exception as e:
            raise SmbConnectionError(f"Could not establish SMB connection: {e}") from e

    def test_credentials(self, username: str, password: str) -> AuthStatus:
        """
        Test credentials via SMB login.

        Creates a fresh connection for each test to avoid state issues.

        Args:
            username: Username to test
            password: Password to test

        Returns:
            AuthStatus indicating the result of the authentication attempt

        Raises:
            UserLockedOutError: If account is locked out
            SmbConnectionError: If SMB connection is broken and cannot be restored
        """
        if not self._connection:
            raise SmbConnectionError("Not connected. Call connect() first.")

        try:
            # Test login
            self._connection.login(user=username, password=password, domain=self.domain)

            # Login succeeded - logoff to clean up
            self._safe_logoff()

            # Reset retry count on successful test
            self._retry_count = self.max_retries

            return AuthStatus.SUCCESS

        except Exception as e:
            # Handle connection issues (retry)
            if self._is_connection_error(e):
                return self._handle_connection_error(username, password, e)

            # Reset retry count on successful connection (even if auth failed)
            self._retry_count = self.max_retries

            # Determine status from exception
            status = AuthStatus.from_exception(e)

            # Handle account lockout
            if status.is_lockout:
                if self.console:
                    self.console.print(
                        f"[red]DANGER: {username} LOCKED OUT - ABORTING "
                        f"(Unlock-ADAccount -Identity {username})[/red]"
                    )
                raise UserLockedOutError(username) from e

            return status

    def _safe_logoff(self) -> None:
        """Safely logoff, handling any errors gracefully."""
        if not self._connection:
            return

        try:
            self._connection.logoff()
        except Exception:
            # Logoff failed - connection might be in bad state
            # Try to reconnect for next test
            try:
                self._connection.close()
            except Exception:
                pass
            self.connect()

    def _is_connection_error(self, exception: Exception) -> bool:
        """Check if exception is a connection error that should trigger retry."""
        error_str = str(exception)
        return any(msg in error_str for msg in [
            'Broken pipe',
            'Connection reset by peer',
            'Error occurs while reading from remote'
        ])

    def _handle_connection_error(self, username: str, password: str, error: Exception) -> AuthStatus:
        """
        Handle connection errors with retry logic.

        Args:
            username: Username being tested
            password: Password being tested
            error: The connection error

        Returns:
            AuthStatus from retry, or raises SmbConnectionError

        Raises:
            SmbConnectionError: If max retries exceeded
        """
        if self._retry_count == 0:
            if self.console:
                self.console.print("[red]SMB connection broken. Aborting.[/red]")
            raise SmbConnectionError("SMB connection broken") from error

        self._retry_count -= 1
        time.sleep(0.5)
        self.connect()
        return self.test_credentials(username, password)

    @staticmethod
    def get_dc_details(domain: str) -> tuple[str, str]:
        """
        Get domain controller hostname and IP from domain name.

        Args:
            domain: Domain name (FQDN)

        Returns:
            Tuple of (hostname, ip_address)
        """
        smb_connection = SMBConnection(domain, domain)
        smb_connection.login('', '', '')
        host = smb_connection.getServerName()
        ip = smb_connection.getNMBServer().get_socket().getpeername()[0]
        smb_connection.logoff()
        return host, ip

    @staticmethod
    def get_time_delta(dc_ip: str) -> timedelta:
        """
        Get time difference between local machine and domain controller.

        Args:
            dc_ip: Domain controller IP address

        Returns:
            timedelta representing the time difference
        """
        utc_remote_time = NtlmInfo(dc_ip, dc_ip).get_server_time()
        utc_local_time = datetime.now(timezone.utc)
        return utc_local_time - utc_remote_time
