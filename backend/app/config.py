"""Application configuration using pydantic-settings."""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_name: str = "Detection-as-Code Platform"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True

    # Database
    database_url: str = "postgresql://dacuser:dacpassword@localhost:5432/dacdb"

    # Security
    secret_key: str = "dev-secret-key-change-in-production"

    # Seeding
    seed_on_startup: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
