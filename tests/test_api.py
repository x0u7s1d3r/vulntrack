def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_assets_empty(client):
    response = client.get("/assets")
    assert response.status_code == 200
    assert response.json() == []


def test_create_asset(client):
    response = client.post("/assets", json={"name": "nginx:1.25", "type": "image"})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "nginx:1.25"
    assert "id" in body


def test_create_duplicate_asset_returns_409(client):
    payload = {"name": "dup:latest", "type": "image"}
    assert client.post("/assets", json=payload).status_code == 201
    assert client.post("/assets", json=payload).status_code == 409


def test_findings_unknown_asset_returns_404(client):
    response = client.get("/assets/999999/findings")
    assert response.status_code == 404
