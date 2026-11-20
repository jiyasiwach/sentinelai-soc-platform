"""Application settings, read once from environment variables.

Secrets are never hard-coded for production: the app refuses to start with
APP_ENV=production and a weak or default JWT_SECRET.
"""

from __future__ import annotations

import os
from functools import lru_cache

DEFAULT_DEV_SECRET = "dev-only-insecure-jwt-secret-change-me"


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_database_url(url: str) -> str:
    """Accept postgres:// and postgresql:// URLs (Heroku/Render style) and use psycopg 3."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


class Settings:
    def __init__(self) -> None:
        self.app_name = "SentinelAI"
        self.env = (os.getenv("APP_ENV") or "development").lower()
        self.on_vercel = bool(os.getenv("VERCEL"))
        # Vercel functions have a read-only filesystem except /tmp. Without DATABASE_URL the demo runs on an
        # ephemeral SQLite file there (re-seeded on each cold start); set DATABASE_URL (Postgres) to keep data.
        default_db = "sqlite:////tmp/sentinel.db" if self.on_vercel else "sqlite:///./sentinel.db"
        self.database_url = normalize_database_url(os.getenv("DATABASE_URL") or default_db)
        self.jwt_secret = os.getenv("JWT_SECRET") or DEFAULT_DEV_SECRET
        self.jwt_algorithm = "HS256"
        self.jwt_expire_minutes = int(os.getenv("JWT_EXPIRE_MINUTES") or "480")

        # AI provider: offline | anthropic | openai
        self.ai_provider = (os.getenv("AI_PROVIDER") or "offline").strip().lower()
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL") or "claude-opus-5-5"
        self.anthropic_base_url = (os.getenv("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
        self.anthropic_fallbacks = _bool("ANTHROPIC_FALLBACKS", True)
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.openai_base_url = (os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.openai_model = os.getenv("OPENAI_MODEL") or "gpt-4o-mini"
        self.ai_timeout_seconds = float(os.getenv("AI_TIMEOUT_SECONDS") or "90")

        # Login throttling (see app/ratelimit.py)
        self.login_max_failures = int(os.getenv("LOGIN_MAX_FAILURES") or "5")
        self.login_ip_max_failures = int(os.getenv("LOGIN_IP_MAX_FAILURES") or "20")
        self.login_lockout_minutes = int(os.getenv("LOGIN_LOCKOUT_MINUTES") or "15")

        self.correlation_window_minutes = int(os.getenv("CORRELATION_WINDOW_MINUTES") or "60")
        self.seed_demo_data = _bool("SEED_DEMO_DATA", True)
        self.admin_password = os.getenv("ADMIN_PASSWORD") or "Admin@12345"
        self.analyst_password = os.getenv("ANALYST_PASSWORD") or "Analyst@12345"
        self.viewer_password = os.getenv("VIEWER_PASSWORD") or "Viewer@12345"

        self.cors_origins = [
            o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()
        ]
        self.static_dir = os.getenv("STATIC_DIR", "")

        # Upload limits
        self.max_alert_upload_bytes = 20 * 1024 * 1024
        self.max_alerts_per_request = 1000
        self.max_xml_bytes = 10 * 1024 * 1024
        self.max_findings_per_request = 5000

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def validate(self) -> None:
        """Refuse to run in production with insecure configuration."""
        if self.is_production:
            weak = (
                self.jwt_secret == DEFAULT_DEV_SECRET
                or len(self.jwt_secret) < 32
                or self.jwt_secret.lower() in {"secret", "changeme", "change-me", "password"}
            )
            if weak:
                raise RuntimeError(
                    "Refusing to start: APP_ENV=production requires JWT_SECRET of at least 32 random characters. "
                    'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
                )
        if self.is_production and self.seed_demo_data and self.admin_password == "Admin@12345":
            import logging

            logging.getLogger("sentinel").warning(
                "Production is seeding demo users with DEFAULT passwords. Set ADMIN_PASSWORD/ANALYST_PASSWORD/"
                "VIEWER_PASSWORD or SEED_DEMO_DATA=false."
            )
        if self.ai_provider not in {"offline", "anthropic", "openai"}:
            raise RuntimeError(f"AI_PROVIDER must be offline, anthropic or openai (got {self.ai_provider!r})")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
