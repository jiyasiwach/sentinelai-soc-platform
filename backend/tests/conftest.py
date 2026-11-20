"""Test fixtures: offline AI, temporary SQLite database seeded with the demo data."""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_tmp, 'test.db')}"
os.environ["AI_PROVIDER"] = "offline"
os.environ["APP_ENV"] = "test"
os.environ["SEED_DEMO_DATA"] = "true"
os.environ.setdefault("JWT_SECRET", "test-secret-test-secret-test-secret-1234")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:  # runs lifespan: init_db + seed
        yield c


def _token(client, username, password):
    r = client.post("/api/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return _token(client, "admin", "Admin@12345")


@pytest.fixture(scope="session")
def analyst(client):
    return _token(client, "analyst", "Analyst@12345")


@pytest.fixture(scope="session")
def viewer(client):
    return _token(client, "viewer", "Viewer@12345")


@pytest.fixture
def db(client):
    from app.database import SessionLocal

    session = SessionLocal()
    yield session
    session.close()
