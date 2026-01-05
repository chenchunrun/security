"""
Configuration management.

Provides application configuration from environment variables and YAML files.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings
import os
import yaml


class AppConfig(BaseSettings):
    """Application configuration from environment variables."""

    # Application
    app_name: str = "Security Alert Triage"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    database_url: str = Field(
        ...,
        description="Database connection URL (async)",
        examples=["postgresql+asyncpg://user:pass@localhost/db"],
    )
    db_pool_size: int = 20
    db_max_overflow: int = 40

    # Redis
    redis_url: str = Field(
        ...,
        description="Redis connection URL",
        examples=["redis://localhost:6379/0"],
    )
    redis_pool_size: int = 10

    # RabbitMQ
    rabbitmq_url: str = Field(
        ...,
        description="RabbitMQ connection URL",
        examples=["amqp://user:pass@localhost:5672/"],
    )

    # Private MaaS
    deepseek_base_url: Optional[str] = Field(
        default=None,
        description="DeepSeek MaaS base URL",
    )
    deepseek_api_key: Optional[str] = Field(
        default=None,
        description="DeepSeek API key",
    )
    qwen_base_url: Optional[str] = Field(
        default=None,
        description="Qwen MaaS base URL",
    )
    qwen_api_key: Optional[str] = Field(
        default=None,
        description="Qwen API key",
    )

    # Fallback LLM
    llm_api_key: Optional[str] = Field(
        default=None,
        description="Fallback LLM API key",
    )
    llm_base_url: Optional[str] = Field(
        default=None,
        description="Fallback LLM base URL",
    )
    llm_model: str = "qwen-plus"

    # Logging
    log_level: str = "INFO"
    log_file: str = "logs/triage.log"

    # JWT
    jwt_secret_key: str = Field(
        ...,
        description="JWT secret key",
    )
    jwt_algorithm: str = "HS256"

    model_config = ConfigDict(env_file=".env", case_sensitive=False)
    """Configuration manager."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Optional path to YAML config file
        """
        self.app_config = AppConfig()
        self.yaml_config: Dict[str, Any] = {}

        if config_path:
            self._load_yaml(config_path)

    def _load_yaml(self, path: str):
        """Load YAML configuration file."""
        try:
            with open(path, "r") as f:
                self.yaml_config = yaml.safe_load(f)
        except FileNotFoundError:
            pass

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.

        Checks YAML config first, then environment variables.

        Args:
            key: Configuration key (dot-separated path)
            default: Default value if not found

        Returns:
            Configuration value
        """
        # Check YAML config
        keys = key.split(".")
        value = self.yaml_config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                value = None
                break

        if value is not None:
            return value

        # Check environment variables
        return os.getenv(key.upper(), default)

    @property
    def database_url(self) -> str:
        """Get database URL."""
        return self.app_config.database_url

    @property
    def redis_url(self) -> str:
        """Get Redis URL."""
        return self.app_config.redis_url

    @property
    def rabbitmq_url(self) -> str:
        """Get RabbitMQ URL."""
        return self.app_config.rabbitmq_url

    @property
    def host(self) -> str:
        """Get server host."""
        return self.app_config.host

    @property
    def port(self) -> int:
        """Get server port."""
        return self.app_config.port


# Global config instance
config: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """Get global configuration instance."""
    global config
    if config is None:
        config = Config(config_path)
    return config
