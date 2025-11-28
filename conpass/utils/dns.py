"""DNS resolution utilities with custom DNS server support."""

import socket


def resolve_hostname(hostname: str, dns_server: str | None = None) -> str:
    """
    Resolve a hostname to an IP address.

    Args:
        hostname: The hostname to resolve
        dns_server: Optional DNS server IP to use for resolution

    Returns:
        The resolved IP address

    Raises:
        socket.gaierror: If hostname resolution fails
    """
    if dns_server:
        # Use dnspython for custom DNS server
        try:
            import dns.resolver
        except ImportError:
            raise ImportError(
                "dnspython is required for custom DNS resolution. "
                "Install it with: pip install dnspython"
            ) from None

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        try:
            answers = resolver.resolve(hostname, 'A')
            return str(answers[0])
        except Exception as e:
            raise socket.gaierror(f"DNS resolution failed for {hostname} using DNS server {dns_server}: {e}") from e
    else:
        # Use default system DNS
        return socket.gethostbyname(hostname)
