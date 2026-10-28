import os
from pathlib import Path
from pydantic import BaseModel, Field

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BACKEND_DIR / "storage"
UPLOADS_DIR = STORAGE_DIR / "uploads"
REPORTS_DIR = STORAGE_DIR / "reports"

# Ensure directories exist
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ScoringWeights(BaseModel):
    critical: int = 10
    high: int = 7
    medium: int = 4
    low: int = 1
    informational: int = 0
    dampening_factor: float = 0.2
    max_dampening_instances: int = 5


class Settings(BaseModel):
    app_name: str = "Sentinel-X"
    app_version: str = "1.0.0"
    app_description: str = "ESP32 Embedded Device Security Assessment Platform"
    database_url: str = f"sqlite:///{STORAGE_DIR / 'sentinel_x.db'}"
    max_upload_size_bytes: int = 32 * 1024 * 1024  # 32 MB limit
    default_serial_baud: int = 115200
    serial_timeout_seconds: float = 3.0
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    scoring: ScoringWeights = Field(default_factory=ScoringWeights)


settings = Settings()
