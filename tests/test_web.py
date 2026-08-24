from app import models
from app.auth import hash_password

PASSWORD = "un-mot-de-passe-solide-123"


def _create_user(db_session, username="webuser", role="viewer", is_active=True):
    user = models.User(
        username=username,
        hashed_password=hash_password(PASSWORD),
        role=role,
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()
    return user


def _login(client, username="webuser"):
    return client.post(
        "/ui/login",
        data={"username": username, "password": PASSWORD},
        follow_redirects=False,
    )


def _asset_with_findings(db_session):
    asset = models.Asset(name="repo-x", type="repository")
    db_session.add(asset)
    db_session.flush()
    db_session.add_all([
        models.Finding(asset_id=asset.id, scanner="trivy", fingerprint="fp-1",
                       title="Buffer overflow", severity="critical", cve="CVE-2024-0001",
                       component="openssl", epss_score=0.87, status="open"),
        models.Finding(asset_id=asset.id, scanner="trivy", fingerprint="fp-2",
                       title="Info leak", severity="high", cve="CVE-2024-0002", status="open"),
        models.Finding(asset_id=asset.id, scanner="trivy", fingerprint="fp-3",
                       title="Vieux bug", severity="medium", cve="CVE-2023-9999", status="fixed"),
    ])
    db_session.commit()
    return asset


# ------------------------------------------------------------- pages (coquilles)

def test_login_page_renders(client):
    response = client.get("/ui/login")
    assert response.status_code == 200
    assert "Connexion" in response.text
    assert 'name="username"' in response.text


def test_protected_page_without_cookie_redirects(client):
    response = client.get("/ui", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login"


def test_dashboard_shell_renders_after_login(client, db_session):
    _create_user(db_session)
    _login(client)
    response = client.get("/ui")
    assert response.status_code == 200
    assert "Tableau de bord" in response.text
    # Coquille : charge le JS qui ira chercher les donnees.
    assert "/ui/static/app.js" in response.text


def test_asset_page_shell_renders(client, db_session):
    _create_user(db_session)
    asset = _asset_with_findings(db_session)
    _login(client)
    response = client.get(f"/ui/assets/{asset.id}")
    assert response.status_code == 200
    assert "repo-x" in response.text
    assert f'data-asset-id="{asset.id}"' in response.text


def test_asset_page_unknown_returns_404(client, db_session):
    _create_user(db_session)
    _login(client)
    assert client.get("/ui/assets/999999").status_code == 404


# ------------------------------------------------------------- auth

def test_login_bad_credentials_returns_401(client, db_session):
    _create_user(db_session)
    response = client.post("/ui/login", data={"username": "webuser", "password": "faux"}, follow_redirects=False)
    assert response.status_code == 401
    assert "Identifiants invalides" in response.text


def test_login_sets_httponly_cookie(client, db_session):
    _create_user(db_session)
    response = _login(client)
    assert response.status_code == 303
    set_cookie = response.headers.get("set-cookie", "")
    assert "vulntrack_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Path=/ui" in set_cookie


def test_logout_clears_cookie(client, db_session):
    _create_user(db_session)
    _login(client)
    response = client.get("/ui/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login"


def test_inactive_user_cannot_login(client, db_session):
    _create_user(db_session, username="disabled", is_active=False)
    response = client.post("/ui/login", data={"username": "disabled", "password": PASSWORD}, follow_redirects=False)
    assert response.status_code == 401


# ------------------------------------------------------------- endpoints JSON

def test_api_overview_requires_session_returns_401(client):
    """Un endpoint JSON renvoie 401 (pas une redirection HTML) sans session."""
    response = client.get("/ui/api/overview")
    assert response.status_code == 401


def test_api_overview_returns_totals_and_assets(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)

    data = client.get("/ui/api/overview").json()
    assert data["totals"]["assets"] == 1
    assert data["totals"]["findings"] == 3
    assert data["totals"]["open"] == 2  # 2 open, 1 fixed
    assert data["totals"]["critical_open"] == 1
    assert data["open_by_severity"]["critical"] == 1
    assert data["open_by_severity"]["high"] == 1
    # medium est fixed, donc absent des "ouverts"
    assert data["open_by_severity"]["medium"] == 0

    asset = data["assets"][0]
    assert asset["name"] == "repo-x"
    assert asset["open"] == 2
    assert asset["total"] == 3
    assert asset["worst"] == "critical"


def test_api_overview_includes_rich_widgets(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)

    d = client.get("/ui/api/overview").json()
    # Exploitable = EPSS >= 0.5 sur findings ouverts (le critical a 0.87).
    assert d["totals"]["exploitable_open"] == 1
    assert d["totals"]["fixed"] == 1
    # Scanner breakdown (findings ouverts, tous trivy ici).
    assert d["by_scanner"].get("trivy") == 2
    # A prioriser : critical/high ouverts, le plus exploitable d'abord.
    assert d["prioritize"][0]["severity"] == "critical"
    assert d["prioritize"][0]["epss_score"] == 0.87
    assert all(f["severity"] in ("critical", "high") for f in d["prioritize"])
    # Top CVE et timeline presents.
    assert any(c["cve"] == "CVE-2024-0001" for c in d["top_cves"])
    assert isinstance(d["timeline"], list)
    # Top assets a risque (repo-x a des criticals).
    assert d["top_assets"][0]["name"] == "repo-x"


def test_api_asset_returns_sorted_findings(client, db_session):
    _create_user(db_session)
    asset = _asset_with_findings(db_session)
    _login(client)

    data = client.get(f"/ui/api/assets/{asset.id}").json()
    assert data["asset"]["name"] == "repo-x"
    assert data["stats"]["total"] == 3
    # Tri par gravite : critical d'abord.
    severities = [f["severity"] for f in data["findings"]]
    assert severities == ["critical", "high", "medium"]
    # Les donnees sont renvoyees brutes (le rendu cote client echappe via
    # textContent) : le titre est present tel quel dans le JSON.
    assert data["findings"][0]["title"] == "Buffer overflow"
    assert data["findings"][0]["epss_score"] == 0.87


def test_api_asset_requires_session(client, db_session):
    _create_user(db_session)
    asset = _asset_with_findings(db_session)
    # Pas de login : 401.
    assert client.get(f"/ui/api/assets/{asset.id}").status_code == 401


def test_api_asset_unknown_returns_404(client, db_session):
    _create_user(db_session)
    _login(client)
    assert client.get("/ui/api/assets/999999").status_code == 404


# ------------------------------------------- modules Wazuh-style (pages + API)

MODULE_PAGES = ["/ui/vulnerabilities", "/ui/sca", "/ui/secrets", "/ui/attack", "/ui/inventory"]
MODULE_APIS = ["/ui/api/vulnerabilities", "/ui/api/sca", "/ui/api/secrets",
               "/ui/api/attack", "/ui/api/inventory"]


def test_module_pages_render_after_login(client, db_session):
    _create_user(db_session)
    _login(client)
    for path in MODULE_PAGES:
        r = client.get(path)
        assert r.status_code == 200, path
        assert "/ui/static/app.js" in r.text


def test_module_apis_require_session(client):
    for path in MODULE_APIS:
        assert client.get(path).status_code == 401, path


def test_module_apis_return_json_after_login(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)
    for path in MODULE_APIS:
        r = client.get(path)
        assert r.status_code == 200, path
        assert "totals" in r.json(), path


def test_attack_api_lists_seven_tactics(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)
    d = client.get("/ui/api/attack").json()
    assert len(d["tactics"]) == 7
    assert d["totals"]["mapped"] >= 1


def test_posture_page_and_api(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)
    assert client.get("/ui/posture").status_code == 200
    d = client.get("/ui/api/posture").json()
    assert "totals" in d and "sla" in d and "mttr" in d and "risk" in d


def test_posture_api_requires_session(client):
    assert client.get("/ui/api/posture").status_code == 401


def test_report_pdf_endpoint(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)
    r = client.get("/ui/api/report.pdf")
    assert r.status_code == 200
    assert "application/pdf" in r.headers["content-type"]
    assert r.content[:5] == b"%PDF-"


def test_set_criticality_requires_write_role(client, db_session):
    # viewer : lecture seule -> 403 (RBAC), meme avec CSRF.
    _create_user(db_session, role="viewer")
    asset = _asset_with_findings(db_session)
    _login(client)
    csrf = client.cookies.get("vulntrack_csrf")
    r = client.patch(f"/ui/api/assets/{asset.id}/criticality",
                     json={"criticality": "crown"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403


def test_set_criticality_admin_ok(client, db_session):
    _create_user(db_session, role="admin")
    asset = _asset_with_findings(db_session)
    _login(client)
    csrf = client.cookies.get("vulntrack_csrf")
    r = client.patch(f"/ui/api/assets/{asset.id}/criticality",
                     json={"criticality": "crown"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json()["criticality"] == "crown"
    db_session.expire_all()
    assert db_session.get(models.Asset, asset.id).criticality == "crown"


def test_findings_kev_filter_and_risk_sort(client, db_session):
    _create_user(db_session)
    _asset_with_findings(db_session)
    _login(client)
    # tri par risque accepté + chaque item porte un score de risque.
    d = client.get("/ui/api/findings?sort=risk&order=desc").json()
    assert d["items"], "au moins un finding"
    assert "risk" in d["items"][0] and "kev" in d["items"][0] and "overdue" in d["items"][0]
    risks = [i["risk"] for i in d["items"]]
    assert risks == sorted(risks, reverse=True)
