from pathlib import Path

import typer
from rich.console import Console

from conpass.config import SprayConfig
from conpass.exceptions import ConfigurationError
from conpass.models import Credentials
from conpass.services.spray import SprayOrchestrator
from conpass.utils import get_logger, read_file_blocks

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})


def complete_path():
    """Typer bug workaround: https://github.com/fastapi/typer/issues/951"""
    return []


@app.command(
    help='Spray given passwords to all Active Directory users taking password policies into account',
)
def spray(
    # Domain and authentication
    domain: str = typer.Option(..., "--domain", "-d", help="Domain name (FQDN)", rich_help_panel="Authentication"),
    username: str | None = typer.Option(None, "--username", "-u", help="Domain user", rich_help_panel="Authentication"),
    password: str | None = typer.Option(None, "--password", "-p", help="Domain password", rich_help_panel="Authentication"),
    hashes: str | None = typer.Option(None, "--hashes", "-H", help="NT hash(es) in format LM:NT, :NT or NT", rich_help_panel="Authentication"),

    # Connection settings
    dc_ip: str | None = typer.Option(None, "--dc-ip", "-D", help="Domain Controller IP address", rich_help_panel="Authentication"),
    dc_host: str | None = typer.Option(None, "--dc-host", help="Hostname of the DC (default: --dc-ip or --domain)", rich_help_panel="Authentication"),
    dns_ip: str | None = typer.Option(None, "--dns-ip", help="DNS server IP address for name resolution", rich_help_panel="Authentication"),
    use_ssl: bool = typer.Option(False, "--use-ssl", help="Use LDAP over SSL/TLS (port 636)", rich_help_panel="Authentication"),

    # Spray settings
    password_file: Path | None = typer.Option(None, "--password-file", "-P", exists=True, file_okay=True, readable=True, resolve_path=True, help="File containing passwords to test", autocompletion=complete_path, rich_help_panel="Spray"),
    user_file: Path | None = typer.Option(None, "--user-file", "-U", exists=True, file_okay=True, readable=True, resolve_path=True, help="File containing users to test", autocompletion=complete_path, rich_help_panel="Spray"),
    user_as_pass: bool = typer.Option(False, "--user-as-pass", "-a", help="Enable user-as-pass for each user", rich_help_panel="Spray"),
    security_threshold: int = typer.Option(2, "--security-threshold", "-s", help="Number of remaining attempts before lockout threshold", rich_help_panel="Spray"),
    disable_spray: bool = typer.Option(False, "--disable-spray", help="Disable password spraying (retrieve PSO details only)", rich_help_panel="Spray"),

    # Manual policy (offline mode)
    lockout_threshold: int | None = typer.Option(None, "--lockout-threshold", "-t", help="Manual lockout threshold (required with --user-file)", rich_help_panel="Spray"),
    lockout_observation_window: int | None = typer.Option(None, "--lockout-observation-window", "-o", help="Manual lockout observation window in seconds (required with --user-file)", rich_help_panel="Spray"),

    # Performance
    max_threads: int = typer.Option(10, "--max-threads", "-m", help="Maximum number of threads", rich_help_panel="Spray"),
    timeout: int = typer.Option(3, "--timeout", help="Connection timeout in seconds", rich_help_panel="Spray"),
    limit_memory: bool = typer.Option(False, "--limit-memory", "-l", help="Limit queue size (useful for 10k+ users)", rich_help_panel="Spray"),

    # Debug
    debug: bool = typer.Option(False, "--debug", help="Enable debug messages", rich_help_panel="Spray"),
):
    """Password spraying tool for Active Directory."""
    console = Console()
    logger = get_logger(console)

    # Validate inputs
    try:
        _validate_inputs(
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            user_file=user_file,
            lockout_threshold=lockout_threshold,
            lockout_observation_window=lockout_observation_window,
        )
    except ConfigurationError as e:
        logger.error(str(e))
        raise typer.Exit(code=1) from None

    # Check password file size
    if password_file:
        _check_password_file_size(password_file, console)

    # Build configuration
    try:
        config = SprayConfig(
            domain=domain,
            dc_ip=dc_ip,
            dc_host=dc_host,
            dns_ip=dns_ip,
            use_ssl=use_ssl,
            password_file=password_file,
            user_file=user_file,
            user_as_pass=user_as_pass,
            security_threshold=security_threshold,
            disable_spray=disable_spray or (not password_file and not user_as_pass),
            manual_lockout_threshold=lockout_threshold,
            manual_lockout_observation_window=lockout_observation_window,
            max_threads=max_threads,
            timeout=timeout,
            limit_memory=limit_memory,
            debug=debug,
        )
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(code=1) from None

    # Build credentials (if provided)
    credentials = None
    if username:
        try:
            credentials = _build_credentials(username, domain, password, hashes)
        except ValueError as e:
            logger.error(str(e))
            raise typer.Exit(code=1) from None

    # Run spray
    try:
        orchestrator = SprayOrchestrator(config=config, credentials=credentials, console=console)
        orchestrator.run()
    except (ConfigurationError, Exception) as e:
        # Import here to avoid circular imports
        from conpass.exceptions import SmbConnectionError, LdapConnectionError

        # For expected errors, just show the message without stack trace
        if isinstance(e, (ConfigurationError, SmbConnectionError, LdapConnectionError)):
            logger.error(str(e))
        else:
            # For unexpected errors, show full stack trace
            logger.critical(str(e))
            console.print_exception()
        raise typer.Exit(code=1) from None


def _validate_inputs(
    domain: str,
    username: str | None,
    password: str | None,
    hashes: str | None,
    user_file: Path | None,
    lockout_threshold: int | None,
    lockout_observation_window: int | None,
) -> None:
    """Validate CLI inputs."""
    # Check domain format
    if '.' not in domain:
        raise ConfigurationError("Provide fully qualified domain name (e.g., domain.local instead of DOMAIN)")

    # Check authentication requirements
    if username is None and user_file is None:
        raise ConfigurationError("Either --username or --user-file is required")

    if username is not None and password is None and hashes is None:
        raise ConfigurationError("Either --password or --hashes is required for authentication")

    if password is not None and hashes is not None:
        raise ConfigurationError("--password and --hashes are mutually exclusive")

    # Check offline mode requirements
    if username is None and user_file:
        if not lockout_threshold or not lockout_observation_window:
            raise ConfigurationError(
                "When using --user-file without --username, "
                "--lockout-threshold and --lockout-observation-window are required"
            )


def _check_password_file_size(password_file: Path, console: Console) -> None:
    """Check password file size and prompt if too large."""
    with open(password_file) as f:
        nb_passwords = sum(block.count("\n") for block in read_file_blocks(f))

    if nb_passwords > 100:
        response = console.input(
            f"[yellow]The password file has {nb_passwords} passwords. "
            f"It will take a very long time to try them all[/yellow]\n"
            f"Do you want to continue? \\[y/N] "
        )
        if not response.lower().startswith('y'):
            raise typer.Exit(code=1)


def _build_credentials(
    username: str,
    domain: str,
    password: str | None,
    hashes: str | None,
) -> Credentials:
    """Build Credentials object from CLI parameters."""
    return Credentials(
        username=username,
        domain=domain,
        password=password,
        hashes=hashes,
    )
