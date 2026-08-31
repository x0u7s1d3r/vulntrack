from app import models
from app.auth import hash_password

PASSWORD = "un-mot-de-passe-solide-123"


def _user(db_session, username, role):
    u = models.User(username=username, hashed_password=hash_password(PASSWORD), role=role)
    db_session.add(u)
    db_session.commit()
    return u


def _login(client, username):
    client.get("/ui/login")  # pose le cookie + jeton anti-CSRF de login
    csrf = client.cookies.get("vulntrack_login_csrf")
    client.post(
        "/ui/login",
        data={"username": username, "password": PASSWORD, "csrf_token": csrf},
        follow_redirects=False,
    )


def _csrf(client):
    return client.cookies.get("vulntrack_csrf")


def _seed(db_session):
    asset = models.Asset(name="repo-x", type="repository")
    db_session.add(asset)
    db_session.flush()
    db_session.add_all([
        models.Finding(asset_id=asset.id, scanner="trivy", fingerprint="f1", title="Buffer overflow",
                       severity="critical", cve="CVE-2024-0001", epss_score=0.9, status="open"),
        models.Finding(asset_id=asset.id, scanner="trivy", fingerprint="f2", title="Info leak",
                       severity="high", cve="CVE-2024-0002", epss_score=0.05, status="open"),
        models.Finding(asset_id=asset.id, scanner="semgrep", fingerprint="f3", title="SQL injection",
                       severity="high", rule_id="python.sqli", file_path="app/db.py", line_number=10, status="open"),
        models.Finding(asset_id=asset.id, scanner="trivy", fingerprint="f4", title="Vieux bug",
                       severity="low", cve="CVE-2023-1", status="fixed"),
    ])
    db_session.commit()
    return asset


# ------------------------------------------------------------- recherche / filtres

def test_findings_search_pagination_and_facets(client, db_session):
    _user(db_session, "amiir", "admin")
    _seed(db_session)
    _login(client, "amiir")

    d = client.get("/ui/api/findings?page_size=2").json()
    assert d["total"] == 4
    assert d["pages"] == 2
    assert len(d["items"]) == 2
    assert d["facets"]["severity"]["high"] == 2
    assert d["can_write"] is True


def test_findings_filter_by_severity_and_scanner(client, db_session):
    _user(db_session, "amiir", "admin")
    _seed(db_session)
    _login(client, "amiir")

    d = client.get("/ui/api/findings?severity=high&scanner=semgrep").json()
    assert d["total"] == 1
    assert d["items"][0]["title"] == "SQL injection"


def test_findings_filter_by_min_epss_and_text(client, db_session):
    _user(db_session, "amiir", "admin")
    _seed(db_session)
    _login(client, "amiir")

    assert client.get("/ui/api/findings?min_epss=0.5").json()["total"] == 1
    assert client.get("/ui/api/findings?q=injection").json()["total"] == 1
    assert client.get("/ui/api/findings?has_cve=true").json()["total"] == 3


def test_findings_requires_session(client):
    assert client.get("/ui/api/findings").status_code == 401


# ------------------------------------------------------------- triage / CSRF / RBAC

def test_patch_status_without_csrf_header_is_forbidden(client, db_session):
    _user(db_session, "amiir", "admin")
    _seed(db_session)
    _login(client, "amiir")
    fid = db_session.query(models.Finding).filter_by(fingerprint="f1").one().id
    # Pas d'en-tete X-CSRF-Token : refuse.
    r = client.patch(f"/ui/api/findings/{fid}", json={"status": "accepted"})
    assert r.status_code == 403


def test_analyst_can_change_status_and_it_is_audited(client, db_session):
    _user(db_session, "ana", "analyst")
    _seed(db_session)
    _login(client, "ana")
    fid = db_session.query(models.Finding).filter_by(fingerprint="f1").one().id

    r = client.patch(f"/ui/api/findings/{fid}", json={"status": "accepted", "note": "risque accepté"},
                     headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"

    detail = client.get(f"/ui/api/findings/{fid}").json()
    assert detail["finding"]["status"] == "accepted"
    # Une note de type status_change a été journalisée avec la justification.
    note = detail["notes"][0]
    assert note["kind"] == "status_change"
    assert note["old_status"] == "open"
    assert note["new_status"] == "accepted"
    assert note["author"] == "ana"
    assert note["body"] == "risque accepté"


def test_viewer_cannot_triage(client, db_session):
    _user(db_session, "obs", "viewer")
    _seed(db_session)
    _login(client, "obs")
    fid = db_session.query(models.Finding).filter_by(fingerprint="f1").one().id

    r = client.patch(f"/ui/api/findings/{fid}", json={"status": "accepted"},
                     headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 403
    # can_write reflète le rôle en lecture seule.
    assert client.get("/ui/api/findings").json()["can_write"] is False


def test_add_comment_note(client, db_session):
    _user(db_session, "ana", "analyst")
    _seed(db_session)
    _login(client, "ana")
    fid = db_session.query(models.Finding).filter_by(fingerprint="f2").one().id

    r = client.post(f"/ui/api/findings/{fid}/notes", json={"body": "à investiguer"},
                    headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 201
    notes = client.get(f"/ui/api/findings/{fid}").json()["notes"]
    assert notes[0]["kind"] == "comment"
    assert notes[0]["body"] == "à investiguer"


def test_bulk_status_change(client, db_session):
    _user(db_session, "adm", "admin")
    _seed(db_session)
    _login(client, "adm")
    ids = [f.id for f in db_session.query(models.Finding).filter(models.Finding.severity == "high").all()]

    r = client.post("/ui/api/findings/bulk", json={"ids": ids, "status": "in_progress", "note": "sprint sécu"},
                    headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 200
    assert r.json()["changed"] == 2
    d = client.get("/ui/api/findings?status=in_progress").json()
    assert d["total"] == 2


def test_export_csv(client, db_session):
    _user(db_session, "adm", "admin")
    _seed(db_session)
    _login(client, "adm")

    r = client.get("/ui/api/export.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "attachment" in r.headers["content-disposition"]
    body = r.text
    assert "CVE-2024-0001" in body
    assert body.splitlines()[0].startswith("id,asset,criticality,scanner,severity")
    # Respecte les filtres.
    filtered = client.get("/ui/api/export.csv?severity=critical").text
    assert "CVE-2024-0001" in filtered
    assert "CVE-2024-0002" not in filtered


def test_finding_detail_unknown_404(client, db_session):
    _user(db_session, "adm", "admin")
    _login(client, "adm")
    assert client.get("/ui/api/findings/999999").status_code == 404


def test_findings_page_shell_renders(client, db_session):
    _user(db_session, "adm", "admin")
    _login(client, "adm")
    r = client.get("/ui/findings")
    assert r.status_code == 200
    assert "Findings" in r.text
    assert 'data-page="findings"' in r.text
    assert 'data-can-write="true"' in r.text
