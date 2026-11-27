"""Application configuration (environment-driven). Secrets never live in code."""
from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_NAME = "ARYAN CYBERSHIELD AI"
PROJECT_SUBTITLE = "Agentic AI-Based Cybersecurity Intelligence and Threat Investigation Platform"
PROJECT_AUTHOR = "Aryan"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    secret_key: str = "dev-only-insecure-key-change-me-0123456789abcdef"
    access_token_expire_minutes: int = 30
    database_url: str = "sqlite:///./cybershield.db"
    cors_origins: str = "http://localhost:5173,http://localhost:8080"
    demo_mode: bool = True
    virustotal_api_key: str = ""
    chroma_path: str = "./chroma_data"
    upload_max_mb: int = 10
    rate_limit_auth: str = "20/minute"

    @field_validator("secret_key")
    @classmethod
    def _min_len(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @property
    def cors_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.is_production and s.secret_key.startswith("dev-only"):
        raise RuntimeError("Refusing to start in production with the default SECRET_KEY")
    return s
