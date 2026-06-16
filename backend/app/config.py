from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ClawGuard Web"
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 120
    database_url: str = "sqlite:///./clawguard.db"
    cfl_mode: str = "mock"
    cfl_dll_path: str = "./CFLClientLib.dll"
    sandbox_image: str = "openclaw-sandbox:latest"
    jobs_dir: Path = Path("../jobs")
    policy_path: Path = Path("../policies/security_policy.yaml")
    upload_max_bytes: int = 2 * 1024 * 1024
    nonce_ttl_seconds: int = 300

    model_config = SettingsConfigDict(env_file="../.env", env_prefix="CLAWGUARD_")


@lru_cache
def get_settings() -> Settings:
    return Settings()

