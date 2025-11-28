"""Time-related utilities."""

from datetime import datetime, timezone


def win_timestamp_to_datetime(timestamp: int) -> datetime:
    """
    Convert Windows FILETIME timestamp to datetime.

    Windows FILETIME is a 64-bit value representing the number of 100-nanosecond
    intervals since January 1, 1601 (UTC).

    Args:
        timestamp: Windows FILETIME timestamp

    Returns:
        datetime object in UTC
    """
    # Windows epoch: January 1, 1601
    # Unix epoch: January 1, 1970
    # Difference in seconds: 11644473600
    WINDOWS_TICKS_TO_UNIX_EPOCH = 116444736000000000

    # Convert 100-nanosecond intervals to seconds
    unix_timestamp = (timestamp - WINDOWS_TICKS_TO_UNIX_EPOCH) / 10000000.0

    return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
