"""Typed application configuration.

Every environment variable the service reads is declared here. Nothing else in
the codebase calls ``os.getenv`` directly, so this module is the single place to
look when answering "what can be configured?".
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Runtime ---
    environment: Literal["development", "production"] = "development"
    log_level: str = "INFO"

    # Comma-separated. Kept as a string rather than list[str] because
    # pydantic-settings parses list-typed env vars as JSON, which is a
    # persistently surprising failure mode for operators.
    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    # Where a report lives, for links in text this service publishes elsewhere
    # — currently the pull request comment. Derived here rather than taken from
    # the request: the caller supplying it would mean a caller could have
    # Vantage post a link to anywhere into someone's pull request.
    app_base_url: str = "http://localhost:3000"

    # --- AI provider (optional; the service is fully functional without it) ---
    gemini_api_key: str | None = None
    # Free-tier quota is allocated per model, not per key — an exhausted model
    # returns 429 while a sibling still serves. Keep this configurable so an
    # operator can switch buckets without a code change.
    gemini_model: str = "gemini-3.6-flash"
    # Current flash models reason before answering; a real analysis prompt takes
    # far longer than a trivial one. 30s was measured to be too tight.
    ai_timeout_seconds: float = 90.0
    # After this many consecutive provider failures the circuit opens and we stop
    # issuing calls until the cooldown elapses. Prevents a rate-limited key from
    # being hammered — the failure mode that drained quota in v2.
    ai_circuit_failure_threshold: int = 3
    ai_circuit_cooldown_seconds: float = 120.0

    # --- Persistence (optional; falls back to in-memory, surfaced in /health) ---
    database_url: str | None = None

    # --- Source ingestion ---
    # Raises the GitHub API rate limit from 60/hr (anonymous) to 5000/hr.
    # Commit-history enrichment spends one request per file with findings, so an
    # anonymous server can exhaust its budget in a couple of analyses.
    github_token: str | None = None
    github_timeout_seconds: float = 60.0

    # --- Sign-in (optional; everything works signed-out) ---
    # The OAuth *app* credentials. The client secret is only ever used by the
    # frontend's server-side callback handler; this copy exists so the backend
    # can report honestly whether sign-in is available at all.
    github_client_id: str | None = None
    # Shared secret authenticating the frontend server to this API when it
    # exchanges a GitHub token for a session. Not a user credential.
    internal_api_secret: str | None = None
    # urlsafe-base64 32-byte Fernet key encrypting stored GitHub tokens.
    # Deliberately separate from any session secret so the two rotate
    # independently.
    token_encryption_key: str | None = None
    session_ttl_days: int = 30

    # --- Archive safety limits ---
    # Enforced *during* streaming extraction, not after, so a malicious archive
    # is rejected before it is fully written to disk.
    max_archive_bytes: int = Field(default=250 * 1024 * 1024)  # 250 MB uploaded
    max_extracted_bytes: int = Field(default=500 * 1024 * 1024)  # 500 MB on disk
    max_file_bytes: int = Field(default=8 * 1024 * 1024)  # 8 MB single file
    max_file_count: int = Field(default=30_000)
    max_compression_ratio: float = Field(default=20.0)
    max_path_depth: int = Field(default=24)

    # --- Analysis ---
    analysis_timeout_seconds: float = 180.0
    max_findings: int = 500
    osv_enabled: bool = True
    osv_timeout_seconds: float = 30.0

    @field_validator("cors_origins")
    @classmethod
    def _strip_origins(cls, v: str) -> str:
        return v.strip()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ai_configured(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def db_configured(self) -> bool:
        return bool(self.database_url)

    @property
    def auth_configured(self) -> bool:
        return self.auth_unavailable_reason is None

    @property
    def auth_unavailable_reason(self) -> str | None:
        """Why sign-in cannot be offered, in words fit for the UI.

        Returned verbatim to the user, so it names the missing piece rather than
        saying "unavailable". Sign-in is optional: with none of this configured
        the product still analyses public repositories.
        """
        if not self.database_url:
            return (
                "Sign-in needs a database to store accounts in, and this server "
                "is running without one."
            )
        missing = [
            name
            for name, value in (
                ("GITHUB_CLIENT_ID", self.github_client_id),
                ("INTERNAL_API_SECRET", self.internal_api_secret),
                ("TOKEN_ENCRYPTION_KEY", self.token_encryption_key),
            )
            if not value
        ]
        if missing:
            return f"Sign-in is not configured on this server ({', '.join(missing)})."
        return None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
