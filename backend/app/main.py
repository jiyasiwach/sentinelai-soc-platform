"""SentinelAI FastAPI application: API under /api, built React UI served from the same port."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import __version__
from .api import alerts, auth, cases, dashboard, vulns
from .config import settings
from .database import SessionLocal, init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate()
    init_db()
    if settings.seed_demo_data:
        from .seed import seed_if_empty

        with SessionLocal() as db:
            seed_if_empty(db)
    log.info("SentinelAI started (env=%s, ai_provider=%s)", settings.env, settings.ai_provider)
    yield


app = FastAPI(
    title="SentinelAI - AI-Powered SOC Investigation Platform",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

if not settings.is_production and settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/docs"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


for module in (auth, alerts, cases, vulns, dashboard):
    app.include_router(module.router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok", "version": __version__, "ai_provider": settings.ai_provider}


# ----------------------------------------------------------------- serve the built UI (single port)
def _static_dir() -> Path | None:
    """Resolved per request, so a UI built after the server started is picked up without a restart."""
    candidates = [settings.static_dir, Path(__file__).resolve().parents[2] / "frontend" / "dist"]
    for c in candidates:
        if c and Path(c, "index.html").is_file():
            return Path(c).resolve()
    return None


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str):
    static = _static_dir()
    if full_path.startswith("api/") or static is None:
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    candidate = (static / full_path).resolve()
    if full_path and candidate.is_file() and static in candidate.parents:
        response = FileResponse(candidate)
        if full_path.startswith("assets/"):  # Vite fingerprints these file names
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response
    return FileResponse(static / "index.html")
