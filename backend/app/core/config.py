from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "JobShield AI API"
    app_env: str = "development"
    app_host: str = "127.0.0.1"
    app_port: int = 8000

    api_v1_prefix: str = "/api/v1"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
