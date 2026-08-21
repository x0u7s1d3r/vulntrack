def test_health_no_auth_required(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers


def test_list_assets_without_token_returns_401(client):
    response = client.get("/assets")
    assert response.status_code == 401


def test_list_assets_with_bad_token_returns_401(client):
    response = client.get("/assets", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_list_assets_empty(client, viewer_headers):
    response = client.get("/assets", headers=viewer_headers)
    assert response.status_code == 200
    assert response.json() == []


def test_create_asset(client, analyst_headers):
    response = client.post(
        "/assets",
        json={"name": "nginx:1.25", "type": "image"},
        headers=analyst_headers,
    )
    assert response.status_code == 201
    assert response.json()["name"] == "nginx:1.25"


def test_create_asset_forbidden_for_viewer(client, viewer_headers):
    """Un viewer peut consulter mais pas creer : c'est le point du RBAC."""
    response = client.post(
        "/assets",
        json={"name": "nginx:1.25", "type": "image"},
        headers=viewer_headers,
    )
    assert response.status_code == 403


def test_create_asset_invalid_type_returns_422(client, analyst_headers):
    response = client.post(
        "/assets",
        json={"name": "x", "type": "not-a-valid-type"},
        headers=analyst_headers,
    )
    assert response.status_code == 422


def test_create_asset_extra_field_rejected(client, analyst_headers):
    response = client.post(
        "/assets",
        json={"name": "x", "type": "image", "is_admin": True},
        headers=analyst_headers,
    )
    assert response.status_code == 422


def test_create_duplicate_asset_returns_409(client, analyst_headers):
    payload = {"name": "dup:latest", "type": "image"}
    assert client.post("/assets", json=payload, headers=analyst_headers).status_code == 201
    assert client.post("/assets", json=payload, headers=analyst_headers).status_code == 409


def test_findings_unknown_asset_returns_404(client, viewer_headers):
    response = client.get("/assets/999999/findings", headers=viewer_headers)
    assert response.status_code == 404
