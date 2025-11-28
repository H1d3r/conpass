"""Hash detection and manipulation utilities."""

import re


def is_nt_hash(password: str) -> bool:
    """
    Check if a password string is an NT hash.

    NT hash format: 32 hexadecimal characters

    Args:
        password: The password string to check

    Returns:
        True if the password is an NT hash, False otherwise
    """
    if not password:
        return False

    # NT hash is exactly 32 hexadecimal characters
    nt_hash_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
    return bool(nt_hash_pattern.match(password))
