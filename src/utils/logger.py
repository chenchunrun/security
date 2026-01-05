"""Logging Configuration"""
import sys
from loguru import logger
from pathlib import Path
from .config import config


def setup_logger():
    """Setup logger configuration"""

    # Remove default handler
    logger.remove()

    # Console handler with colors
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=config.log_level,
        colorize=True
    )

    # File handler
    log_file = config.log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        log_file,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=config.log_level,
        rotation=config.get("logging.rotation", "100 MB"),
        retention=config.get("logging.retention", "30 days"),
        compression="zip"
    )

    return logger


# Initialize logger
log = setup_logger()
