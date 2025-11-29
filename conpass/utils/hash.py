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


def parse_hashes(hashes: str) -> tuple[str | None, str]:
    """
    Parse hash string in different formats (LM:NT, :NT, or NT).

    Args:
        hashes: Hash string in format LM:NT, :NT or NT

    Returns:
        Tuple of (lm_hash, nt_hash). lm_hash can be None if not provided.

    Raises:
        ValueError: If hash format is invalid
    """
    if not hashes:
        raise ValueError("Hash string cannot be empty")

    # Check if it contains a colon (LM:NT or :NT format)
    if ':' in hashes:
        parts = hashes.split(':', 1)
        lm_hash = parts[0] if parts[0] else None
        nt_hash = parts[1]

        # Validate LM hash if provided
        if lm_hash and not re.match(r'^[a-fA-F0-9]{32}$', lm_hash):
            raise ValueError(f"Invalid LM hash format: {lm_hash}")

        # Validate NT hash
        if not re.match(r'^[a-fA-F0-9]{32}$', nt_hash):
            raise ValueError(f"Invalid NT hash format: {nt_hash}")

        return (lm_hash, nt_hash)
    else:
        # Single hash provided (assumed to be NT)
        if not re.match(r'^[a-fA-F0-9]{32}$', hashes):
            raise ValueError(f"Invalid NT hash format: {hashes}")

        return (None, hashes)


def format_hash_for_ldap(lm_hash: str | None, nt_hash: str) -> str:
    """
    Format LM and NT hashes for LDAP3 authentication.

    LDAP3 requires format: LM:NT

    Args:
        lm_hash: LM hash (optional, uses empty hash if None)
        nt_hash: NT hash (required)

    Returns:
        Hash string in LM:NT format
    """
    # Use empty LM hash if not provided (common case)
    lm = lm_hash if lm_hash else "aad3b435b51404eeaad3b435b51404ee"
    return f"{lm}:{nt_hash}"
