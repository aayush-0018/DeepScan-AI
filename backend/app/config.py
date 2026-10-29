from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]

GROQ_KEY_PLACEHOLDER = "your_groq_api_key_here"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    model_dir: Path = REPO_ROOT / "artifacts" / "model"
    device: str = "auto"
    default_detector: str = "auto"
    confidence_threshold: float = 0.5
    cors_origins: str = "http://localhost:5173,http://localhost:8080"
    max_upload_mb: int = 10
    max_files: int = 200
    max_functions_per_request: int = 2000

    groq_api_key: str = GROQ_KEY_PLACEHOLDER
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_timeout_seconds: float = 30.0
    groq_max_concurrency: int = 4

    @property
    def resolved_model_dir(self) -> Path:
        return self.model_dir if self.model_dir.is_absolute() else REPO_ROOT / self.model_dir

    @property
    def groq_enabled(self) -> bool:
        key = (self.groq_api_key or "").strip()
        return bool(key) and key != GROQ_KEY_PLACEHOLDER

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
