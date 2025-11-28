"""Logging utilities."""

import logging

from rich.console import Console
from rich.logging import RichHandler


def get_logger(console: Console | None = None) -> logging.Logger:
    """
    Get configured logger for ConPass.

    Args:
        console: Optional Rich console for pretty logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("conpass")

    if not logger.handlers:
        if console:
            handler = RichHandler(console=console, rich_tracebacks=True)
        else:
            handler = RichHandler(rich_tracebacks=True)

        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
