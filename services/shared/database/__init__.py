"""
Shared database layer for all microservices.

This package provides database connectivity, session management,
and repository base classes used across all services.
"""

from .base import DatabaseManager, get_database_manager

__version__ = "1.0.0"

__all__ = ["DatabaseManager", "get_database_manager"]
