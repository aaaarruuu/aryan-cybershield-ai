import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="cybershield_test_")
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{_tmp}/test.db"
os.environ["CHROMA_PATH"] = f"{_tmp}/chroma"
os.environ["DEMO_MODE"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-0123456789-abcdefghijklmnop"
os.environ["RATE_LIMIT_AUTH"] = "1000/minute"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database.session import Base, SessionLocal, engine  # noqa: E402
import app.models  # noqa: E402,F401


@pytest.fixture(autouse=True)
def fresh_db():
    from sqlalchemy.orm import close_all_sessions
    close_all_sessions()          # sessions left open by a test would hold locks and block drop_all on PostgreSQL
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture()
def client():
    from app.main import app
    return TestClient(app)


def _register(client, email, name="Test User"):
    r = client.post("/api/auth/register", json={"email": email, "full_name": name, "password": "StrongPass123"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def admin_headers(client):
    return _register(client, "admin@example.com", "Admin User")  # first user => admin


@pytest.fixture()
def analyst_headers(client, admin_headers):
    return _register(client, "analyst@example.com", "Analyst User")
