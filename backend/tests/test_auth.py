def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["author"] == "Aryan"


def test_register_login_me(client, admin_headers):
    r = client.get("/api/auth/me", headers=admin_headers)
    assert r.status_code == 200 and r.json()["role"] == "admin"
    r = client.post("/api/auth/login", json={"email": "admin@example.com", "password": "StrongPass123"})
    assert r.status_code == 200 and "access_token" in r.json()
    assert "password" not in r.text


def test_second_user_is_analyst(client, analyst_headers):
    assert client.get("/api/auth/me", headers=analyst_headers).json()["role"] == "analyst"


def test_weak_password_rejected(client):
    r = client.post("/api/auth/register", json={"email": "a@b.com", "full_name": "Abc", "password": "short"})
    assert r.status_code == 422
    r = client.post("/api/auth/register", json={"email": "a@b.com", "full_name": "Abc", "password": "onlyletterspassword"})
    assert r.status_code == 422


def test_duplicate_email(client, admin_headers):
    r = client.post("/api/auth/register", json={"email": "ADMIN@example.com", "full_name": "Dup", "password": "StrongPass123"})
    assert r.status_code == 409


def test_bad_login_and_unauthenticated(client, admin_headers):
    assert client.post("/api/auth/login", json={"email": "admin@example.com", "password": "wrong"}).status_code == 401
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_logout_revokes_token(client, admin_headers):
    assert client.post("/api/auth/logout", headers=admin_headers).status_code == 204
    assert client.get("/api/auth/me", headers=admin_headers).status_code == 401


def test_rbac_admin_only(client, admin_headers, analyst_headers):
    assert client.get("/api/auth/users", headers=analyst_headers).status_code == 403
    assert client.get("/api/auth/users", headers=admin_headers).status_code == 200


def test_admin_cannot_self_demote(client, admin_headers):
    me = client.get("/api/auth/me", headers=admin_headers).json()
    r = client.patch(f"/api/auth/users/{me['id']}", json={"role": "analyst"}, headers=admin_headers)
    assert r.status_code == 400
