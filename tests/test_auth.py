import io

from app import models
from app.auth import hash_password

PASSWORD = "un-mot-de-passe-solide-123"


def _create_user(db_session, username: str, role: str, is_active: bool = True) -> None:
    user = models.User(
        username=username,
        hashed_password=hash_password(PASSWORD),
        role=role,
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()


def test_login_success_returns_token(client, db_session):
    _create_user(db_session, "bob", "viewer")

    response = client.post("/auth/login", data={"username": "bob", "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_wrong_password_returns_401(client, db_session):
    _create_user(db_session, "bob", "viewer")

    response = client.post("/auth/login", data={"username": "bob", "password": "wrong"})
    assert response.status_code == 401


def test_login_unknown_user_returns_401(client):
    response = client.post("/auth/login", data={"username": "ghost", "password": "whatever12345"})
    assert response.status_code == 401


def test_login_inactive_user_returns_401(client, db_session):
    _create_user(db_session, "disabled", "viewer", is_active=False)

    response = client.post("/auth/login", data={"username": "disabled", "password": PASSWORD})
    assert response.status_code == 401


def test_create_user_requires_admin(client, viewer_headers):
    response = client.post(
        "/users",
        json={"username": "newbie", "password": PASSWORD, "role": "viewer"},
        headers=viewer_headers,
    )
    assert response.status_code == 403


def test_admin_can_create_user(client, admin_headers):
    response = client.post(
        "/users",
        json={"username": "newbie", "password": PASSWORD, "role": "analyst"},
        headers=admin_headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "analyst"
    assert "password" not in body
    assert "hashed_password" not in body


def test_create_duplicate_user_returns_409(client, admin_headers):
    payload = {"username": "dup-user", "password": PASSWORD, "role": "viewer"}
    assert client.post("/users", json=payload, headers=admin_headers).status_code == 201
    assert client.post("/users", json=payload, headers=admin_headers).status_code == 409


def test_list_users_requires_admin(client, analyst_headers):
    response = client.get("/users", headers=analyst_headers)
    assert response.status_code == 403


def test_admin_can_list_users(client, admin_headers):
    response = client.get("/users", headers=admin_headers)
    assert response.status_code == 200
    assert any(u["username"] == "admin-test" for u in response.json())


def test_ingest_endpoint_ignores_jwt_and_still_requires_api_key(client, admin_headers):
    """/scans/ingest reste reserve a la cle d'API (machine-a-machine) : un
    jeton JWT valide ne doit pas suffire, meme pour un admin."""
    response = client.post(
        "/scans/ingest",
        data={"asset_name": "x", "asset_type": "image", "scanner": "trivy"},
        files={"report": ("r.json", io.BytesIO(b"{}"), "application/json")},
        headers=admin_headers,
    )
    assert response.status_code == 401
