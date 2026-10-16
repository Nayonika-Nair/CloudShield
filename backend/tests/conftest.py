"""Shared fixtures.

The suite runs against SQLite by default. Set TEST_DATABASE_URL to a PostgreSQL
URL to run the very same tests against PostgreSQL.
"""

import os
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="cloudshield-tests-")
os.environ["DATABASE_URL"] = os.getenv("TEST_DATABASE_URL") or f"sqlite:///{Path(_TMP, 'test.db').as_posix()}"
os.environ["JWT_SECRET_KEY"] = "test-secret-not-for-production"
os.environ["SEED_DEMO_ENVIRONMENT"] = "false"
os.environ["SERVE_FRONTEND"] = "false"
os.environ["ADMIN_EMAIL"] = "admin@example.com"
os.environ["ADMIN_PASSWORD"] = "Admin-pass-1"
os.environ["ANALYST_EMAIL"] = "analyst@example.com"
os.environ["ANALYST_PASSWORD"] = "Analyst-pass-1"
os.environ["VIEWER_EMAIL"] = "viewer@example.com"
os.environ["VIEWER_PASSWORD"] = "Viewer-pass-1"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app import auth as _auth  # noqa: E402
from app.main import app, seed_users  # noqa: E402

_auth.pwd_context.update(bcrypt__default_rounds=4)  # keep the suite fast; production uses the library default
from app.simulator.config import SimConfig, preset_config  # noqa: E402
from app.simulator.generator import generate_environment  # noqa: E402


@pytest.fixture(scope="session")
def base_env():
    """Default seeded environment. Treat as read-only; use ``env`` for mutations."""
    return generate_environment(SimConfig())


@pytest.fixture()
def env(base_env):
    return base_env.copy()


@pytest.fixture(scope="session")
def clean_base():
    return generate_environment(preset_config("clean"))


@pytest.fixture()
def clean_env(clean_base):
    return clean_base.copy()


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    seed_users()
    with SessionLocal() as session:
        yield session


@pytest.fixture()
def client(db):
    return TestClient(app)


def _login(client, email, password):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def admin(client):
    return _login(client, "admin@example.com", "Admin-pass-1")


@pytest.fixture()
def analyst(client):
    return _login(client, "analyst@example.com", "Analyst-pass-1")


@pytest.fixture()
def viewer(client):
    return _login(client, "viewer@example.com", "Viewer-pass-1")


@pytest.fixture()
def sim(client, admin):
    """Client with a generated default environment; returns (client, admin headers)."""
    r = client.post("/api/sim/environments", headers=admin, json={"preset": "typical"})
    assert r.status_code == 201, r.text
    return client, admin
