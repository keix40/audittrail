from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AuditTrail"
    debug: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    database_url: str = "postgresql+psycopg://audittrail:audittrail@localhost:5432/audittrail"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    github_app_id: str = ""
    github_app_private_key: str = ""
    github_webhook_secret: str = ""
    github_api_base: str = "https://api.github.com"

    api_key_pepper: str = "change-me-in-production"
    bootstrap_admin_token: str = ""
    rate_limit_per_minute: int = 60

    scanner_docker_image: str = "audittrail-scanner:local"
    scanner_network_disabled: bool = True
    scanner_memory_limit: str = "512m"
    scanner_cpu_quota: int = 100_000
    scanner_timeout_seconds: int = 300

    llm_provider: str = ""  # openai, anthropic, or empty for fallback
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str = ""

    work_dir: str = "/tmp/audittrail/work"


@lru_cache
def get_settings() -> Settings:
    return Settings()
