"""Central, validated application configuration.

Every setting is read from the environment exactly once, at import time, and
exposed through a single immutable ``settings`` object. Nothing else in the
codebase touches ``os.environ`` directly, which keeps configuration auditable
and makes the service trivially testable.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "APISentinel"
    environment: Literal["development", "production"] = "development"

    database_url: str = Field(
        default="postgresql+psycopg://apisentinel:apisentinel@localhost:5433/apisentinel",
        alias="DATABASE_URL",
    )

    jwt_secret: str = Field(default="change-me-in-production", alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 12 * 60

    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")

    # --- LLM reasoning layer -------------------------------------------------
    llm_provider: Literal["ollama", "hosted", "disabled"] = Field(
        default="ollama", alias="LLM_PROVIDER"
    )
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen2.5-coder:7b", alias="OLLAMA_MODEL")
    hosted_llm_base_url: str = Field(default="", alias="HOSTED_LLM_BASE_URL")
    hosted_llm_api_key: str = Field(default="", alias="HOSTED_LLM_API_KEY")
    hosted_llm_model: str = Field(default="", alias="HOSTED_LLM_MODEL")
    llm_timeout_seconds: int = Field(default=600, alias="LLM_TIMEOUT_SECONDS")
    llm_max_retries: int = Field(default=2, alias="LLM_MAX_RETRIES")

    # --- Runtime validation layer -------------------------------------------
    runtime_target_allowlist: str = Field(
        default="http://localhost,http://127.0.0.1", alias="RUNTIME_TARGET_ALLOWLIST"
    )
    zap_base_url: str = Field(default="", alias="ZAP_BASE_URL")
    zap_api_key: str = Field(default="", alias="ZAP_API_KEY")
    runtime_timeout_seconds: int = Field(default=20, alias="RUNTIME_TIMEOUT_SECONDS")
    # Operator kill switch for ZAP's intrusive Active Scan. Spidering and
    # passive scanning (read-only) are unaffected by this flag; only the
    # attack-traffic-generating active scan is gated here, in addition to the
    # per-scan opt-in (ScanCreate.run_active_scan) — both must be true.
    zap_enable_active_scan: bool = Field(default=False, alias="ZAP_ENABLE_ACTIVE_SCAN")

    # --- Static analysis layer ----------------------------------------------
    static_timeout_seconds: int = Field(default=180, alias="STATIC_TIMEOUT_SECONDS")

    # --- URL-based (black-box) web scanning ----------------------------------
    # Operator-level switch: a non-allowlisted public host can be scanned only
    # when this is true, in addition to the per-project authorization record.
    # Off by default so a fresh deployment cannot scan the open internet until
    # someone deliberately turns this on.
    allow_public_targets: bool = Field(default=False, alias="ALLOW_PUBLIC_TARGETS")
    web_max_pages: int = Field(default=60, alias="WEB_MAX_PAGES")
    web_max_crawl_depth: int = Field(default=6, alias="WEB_MAX_CRAWL_DEPTH")
    web_request_timeout_seconds: int = Field(default=10, alias="WEB_REQUEST_TIMEOUT_SECONDS")
    web_request_delay_ms: int = Field(default=150, alias="WEB_REQUEST_DELAY_MS")
    web_user_agent: str = Field(
        default="APISentinel-WebScanner/1.0 (+authorized-security-assessment)",
        alias="WEB_USER_AGENT",
    )

    # --- Bootstrap ----------------------------------------------------------
    seed_ground_truth: bool = Field(default=True, alias="SEED_GROUND_TRUTH")
    ground_truth_path: str = Field(default="/datasets/ground_truth.yml", alias="GROUND_TRUTH_PATH")
    seed_demo_user: bool = Field(default=False, alias="SEED_DEMO_USER")
    demo_user_email: str = Field(default="analyst@apisentinel.local", alias="DEMO_USER_EMAIL")
    demo_user_password: str = Field(default="apisentinel123", alias="DEMO_USER_PASSWORD")

    max_upload_bytes: int = Field(default=8 * 1024 * 1024, alias="MAX_UPLOAD_BYTES")

    @field_validator("jwt_secret")
    @classmethod
    def _warn_default_secret(cls, value: str) -> str:
        if not value:
            raise ValueError("JWT_SECRET must not be empty")
        return value

    @property
    def cors_origin_list(self) -> List[str]:
        raw = self.cors_origins.strip()
        if raw in {"", "*"}:
            return ["*"]
        return [item.strip() for item in raw.split(",") if item.strip()]

    @property
    def allowlisted_targets(self) -> List[str]:
        return [
            item.strip().rstrip("/")
            for item in self.runtime_target_allowlist.split(",")
            if item.strip()
        ]

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider != "disabled"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
