# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Structured logging utilities.

Provides JSON-structured logging with loguru.
"""

import sys
from datetime import datetime
from typing import Any, Dict, Optional

from loguru import logger as _logger


def get_logger(name: str) -> Any:
    """
    Get logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    # Remove default handler
    _logger.remove()

    # Add console handler with color and format
    _logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level="INFO",
        colorize=True,
    )

    # Add file handler for JSON logs
    _logger.add(
        "logs/triage.log",
        rotation="100 MB",
        retention="30 days",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} - {message}",
        level="DEBUG",
        serialize=True,  # JSON format
    )

    return _logger


def log_structured(
    level: str,
    message: str,
    extra: Optional[Dict[str, Any]] = None,
):
    """
    Log structured message with extra fields.

    Args:
        level: Log level (info, warning, error, etc.)
        message: Log message
        extra: Additional fields for structured logging
    """
    logger = get_logger("structured")

    log_func = getattr(logger, level, logger.info)
    if extra:
        logger.bind(**extra).log(level, message)
    else:
        log_func(message)
