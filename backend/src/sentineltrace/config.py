"""Application configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_rules_path() -> Path:
    # backend/rules when developing; /app/rules in Docker
    here = Path(__file__).resolve().parent
    candidate = here.parent.parent.parent / "rules"
    if candidate.is_dir():
        return candidate
    docker_rules = Path("/app/rules")
    if docker_rules.is_dir():
        return docker_rules
    return here.parent.parent / "rules"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql+psycopg://sentineltrace:changeme_local_only@localhost:5432/sentineltrace",
        alias="DATABASE_URL",
    )
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000",
        alias="CORS_ORIGINS",
    )
    max_upload_bytes: int = Field(default=104_857_600, alias="MAX_UPLOAD_BYTES")
    ingest_batch_size: int = Field(default=500, alias="INGEST_BATCH_SIZE")
    rules_path: Path = Field(default_factory=_default_rules_path, alias="RULES_PATH")
    detection_default_since_hours: int = Field(default=168, alias="DETECTION_DEFAULT_SINCE_HOURS")
    default_timezone: str = Field(default="UTC", alias="DEFAULT_TIMEZONE")
    default_page_size: int = Field(default=50, alias="DEFAULT_PAGE_SIZE")
    sentineltrace_env: str = Field(default="local", alias="SENTINELTRACE_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    upload_dir: Path = Field(default=Path("/tmp/sentineltrace/uploads"), alias="UPLOAD_DIR")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
