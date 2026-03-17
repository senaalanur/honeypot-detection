from enum import StrEnum
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Environment
    environment: Environment = Environment.DEVELOPMENT
    log_level: LogLevel = LogLevel.INFO

    # Anthropic
    anthropic_api_key: str = Field(..., description="Anthropic API key")

    # Redis
    redis_url: str = "redis://localhost:6379"
    redis_event_channel: str = "honeypot:events"

    # PostgreSQL
    postgres_dsn: str = "postgresql+asyncpg://user:pass@localhost:5432/honeypot"

    # Elasticsearch
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_index: str = "honeypot-events"

    # Honeypot ports
    ssh_port: int = 2222
    http_port: int = 8080
    ftp_port: int = 2121

    # Email alerts
    email_user: str = Field(default="", description="Gmail address")
    email_password: str = Field(default="", description="Gmail app password")
    email_recipient: str = Field(default="", description="Alert recipient")

    # Slack alerts
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")

    # AI analysis
    ai_min_severity_to_alert: int = Field(
        default=7,
        ge=1,
        le=10,
        description="Minimum threat score (1-10) to trigger an alert",
    )
    ai_model: str = "claude-sonnet-4-20250514"

    # GeoIP
    geoip_db_path: str = "data/GeoLite2-City.mmdb"

    @field_validator("anthropic_api_key")
    @classmethod
    def api_key_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ANTHROPIC_API_KEY must not be empty")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()