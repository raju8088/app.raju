import logging
import sys

logger = logging.getLogger("omnidim_ui")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(level)

    # Configure root/package logger
    root = logging.getLogger()
    root.setLevel(level)
    # Remove existing stream handlers to prevent duplicates
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    logger.setLevel(level)
