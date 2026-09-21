from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "JobShield AI API"
    app_version: str = "0.1.0"
    app_env: str = "development"
    app_host: str = "127.0.0.1"
    app_port: int = 8000

    # AI provider configuration
    ai_enabled: bool = False
    ai_provider: Literal["none", "openai"] = "none"
    ai_model: str = ""
    ai_api_key: str = ""
    ai_timeout_seconds: float = Field(
        default=20.0,
        gt=0,
        le=120,
    )

    api_v1_prefix: str = "/api/v1"

    cors_origins: str = (
        "http://localhost:3000,http://127.0.0.1:3000"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("ai_provider", mode="before")
    @classmethod
    def normalize_ai_provider(cls, value: str) -> str:
        """Normalize provider names before validation."""

        if not isinstance(value, str):
            return value

        return value.strip().lower()

    @property
    def cors_origin_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()