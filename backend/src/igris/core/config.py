"""Centralized runtime configuration for the Igris backend."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
MetadataBackend = Literal["json", "memory", "postgres"]


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="IGRIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Igris"
    environment: Environment = "development"
    log_level: LogLevel = "INFO"
    enable_docs: bool = True
    database_url: SecretStr | None = None
    metadata_backend: MetadataBackend = "json"
    sample_storage_dir: str = "data/samples"
    metadata_storage_file: str = "data/metadata/samples.json"
    sample_temp_dir: str = "data/tmp"
    max_upload_bytes: int = Field(default=52_428_800, ge=1, le=1_073_741_824)
    analysis_timeout_seconds: int = Field(default=10, ge=1, le=300)
    static_min_string_length: int = Field(default=4, ge=3, le=64)
    static_max_strings: int = Field(default=5_000, ge=1, le=100_000)
    static_high_entropy_threshold: float = Field(default=7.2, ge=0.0, le=8.0)
    detection_rules_path: str = "config/rules/static_rules.json"
    detection_engine_version: str = "heuristic-detection/v1"
    request_id_header: str = "X-Request-ID"
    trusted_proxy_headers: bool = False

    @field_validator("request_id_header")
    @classmethod
    def validate_request_id_header(cls, value: str) -> str:
        if not value.strip():
            msg = "request_id_header must not be empty"
            raise ValueError(msg)
        return value


@lru_cache
def get_settings() -> Settings:
    """Return cached settings for the running process."""

    return Settings()
