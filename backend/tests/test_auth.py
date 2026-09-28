import uuid


def test_register_new_user(test_client):
    email = f"user_{uuid.uuid4().hex[:8]}@aiidps.com"
    res = test_client.post("/api/auth/register", json={
        "name": "Test User", "email": email, "password": "pass1234", "role": "VIEWER"
    })
    assert res.status_code == 201
    assert res.json()["email"] == email


def test_login_success(admin_token):
    assert admin_token is not None


def test_login_invalid_credentials(test_client, admin_credentials):
    res = test_client.post("/api/auth/login", json={
        "email": admin_credentials["email"], "password": "wrongpassword"
    })
    assert res.status_code == 401


def test_protected_route_without_token(test_client):
    res = test_client.get("/api/auth/me")
    assert res.status_code in (401, 403)


def test_protected_route_with_token(test_client, auth_headers):
    res = test_client.get("/api/auth/me", headers=auth_headers)
    assert res.status_code == 200
    assert "email" in res.json()