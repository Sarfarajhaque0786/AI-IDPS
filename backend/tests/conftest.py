import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture(scope="session")
def test_client():
    return client


@pytest.fixture(scope="session")
def admin_credentials():
    unique_email = f"test_admin_{uuid.uuid4().hex[:8]}@aiidps.com"
    return {"name": "Test Admin", "email": unique_email, "password": "testpass123", "role": "ADMIN"}


@pytest.fixture(scope="session")
def admin_token(test_client, admin_credentials):
    test_client.post("/api/auth/register", json=admin_credentials)
    res = test_client.post("/api/auth/login", json={
        "email": admin_credentials["email"],
        "password": admin_credentials["password"],
    })
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}