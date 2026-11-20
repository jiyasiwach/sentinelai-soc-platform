"""Vercel entry point: runs the FastAPI backend as a Python serverless function.

Vercel serves the built React UI (frontend/dist) from its CDN and routes /api/* here (see vercel.json).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.config import settings  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402,F401  (Vercel looks for the ASGI `app`)

# Serverless platforms do not reliably run ASGI lifespan events, so prepare the database at import
# time (once per cold start). Both steps are idempotent.
settings.validate()
init_db()
if settings.seed_demo_data:
    from app.seed import seed_if_empty

    with SessionLocal() as db:
        seed_if_empty(db)
