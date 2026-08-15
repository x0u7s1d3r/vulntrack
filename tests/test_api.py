def test_health_no_auth_required(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers


def test_list_assets_without_key_returns_401(client):
    response = client.get("/assets")
    assert response.status_code == 401


def test_list_assets_with_bad_key_returns_401(client):
    response = client.get("/assets", headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_list_assets_empty(client, auth_headers):
    response = client.get("/assets", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == []


def test_create_asset(client, auth_headers):
    response = client.post(
        "/assets",
        json={"name": "nginx:1.25", "type": "image"},
        headers=auth_headers,
    )
    assert response.status_code == 201
    assert response.json()["name"] == "nginx:1.25"


def test_create_asset_invalid_type_returns_422(client, auth_headers):
    response = client.post(
        "/assets",
        json={"name": "x", "type": "not-a-valid-type"},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_create_asset_extra_field_rejected(client, auth_headers):
    response = client.post(
        "/assets",
        json={"name": "x", "type": "image", "is_admin": True},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_create_duplicate_asset_returns_409(client, auth_headers):
    payload = {"name": "dup:latest", "type": "image"}
    assert client.post("/assets", json=payload, headers=auth_headers).status_code == 201
    assert client.post("/assets", json=payload, headers=auth_headers).status_code == 409


def test_findings_unknown_asset_returns_404(client, auth_headers):
    response = client.get("/assets/999999/findings", headers=auth_headers)
    assert response.status_code == 404
