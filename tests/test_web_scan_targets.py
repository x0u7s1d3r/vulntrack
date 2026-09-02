"""Tests des endpoints de gestion des cibles d'auto-scan (/ui/api/scan-targets).

Deux axes : validation metier (schema Pydantic : scanners coherents avec le
type, cron valide) et matrice d'acces (RBAC + CSRF + 401 sur lecture JSON).
L'enqueue RQ est mocke (pas de Redis en test) : on verifie le cablage.
"""
from unittest.mock import patch

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


def _image_payload(**kw):
    p = {
        "name": "img-cible", "target_type": "image", "reference": "alpine:3.19",
        "scanners": ["trivy"], "schedule": None,
    }
    p.update(kw)
    return p


# ------------------------------------------------------------- validation metier

def test_create_rejette_scanner_incompatible_avec_type(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    # image + semgrep : semgrep n'analyse que du code, pas une image -> 422
    r = client.post(
        "/ui/api/scan-targets",
        json=_image_payload(scanners=["semgrep"]),
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 422


def test_create_rejette_cron_invalide(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    r = client.post(
        "/ui/api/scan-targets",
        json=_image_payload(schedule="pas un cron"),
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 422


def test_create_accepte_cron_valide(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    r = client.post(
        "/ui/api/scan-targets",
        json=_image_payload(schedule="0 3 * * *"),
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 201
    assert r.json()["schedule"] == "0 3 * * *"


# ------------------------------------------------------------- matrice d'acces

def test_liste_non_authentifiee_renvoie_401(client, db_session):
    # Lecture JSON : current_api_user -> 401, PAS une redirection 303.
    r = client.get("/ui/api/scan-targets")
    assert r.status_code == 401


def test_viewer_ne_peut_pas_creer(client, db_session):
    _user(db_session, "obs", "viewer")
    _login(client, "obs")
    r = client.post(
        "/ui/api/scan-targets",
        json=_image_payload(),
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 403


def test_creation_sans_csrf_refusee(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    # Jeton de session valide mais PAS d'en-tete X-CSRF-Token -> 403.
    r = client.post("/ui/api/scan-targets", json=_image_payload())
    assert r.status_code == 403


# ------------------------------------------------------------- cycle de vie complet

def test_admin_cree_liste_lance_supprime(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    h = {"X-CSRF-Token": _csrf(client)}

    # creation
    r = client.post(
        "/ui/api/scan-targets",
        json=_image_payload(name="prod-api", reference="ghcr.io/x/y:1"),
        headers=h,
    )
    assert r.status_code == 201
    tid = r.json()["id"]
    assert r.json()["scanners"] == ["trivy"]  # stocke en CSV, rendu en liste

    # listing
    d = client.get("/ui/api/scan-targets").json()
    assert d["can_write"] is True
    assert any(t["name"] == "prod-api" for t in d["targets"])

    # lancement a la demande : enqueue mocke (pas de Redis en test)
    with patch("app.queue.ingest_queue.enqueue") as enq:
        r = client.post(f"/ui/api/scan-targets/{tid}/scan", headers=h)
    assert r.status_code == 200
    assert r.json()["status"] == "queued"
    enq.assert_called_once_with("app.scanning.scan_target", tid)

    # suppression
    r = client.delete(f"/ui/api/scan-targets/{tid}", headers=h)
    assert r.status_code == 200
    assert client.get("/ui/api/scan-targets").json()["targets"] == []


def test_nom_duplique_renvoie_409(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    h = {"X-CSRF-Token": _csrf(client)}
    client.post("/ui/api/scan-targets", json=_image_payload(name="dup"), headers=h)
    r = client.post("/ui/api/scan-targets", json=_image_payload(name="dup"), headers=h)
    assert r.status_code == 409


def test_repository_accepte_gitleaks(client, db_session):
    _user(db_session, "amiir", "admin")
    _login(client, "amiir")
    r = client.post(
        "/ui/api/scan-targets",
        json={
            "name": "repo-x", "target_type": "repository",
            "reference": "https://github.com/x/y",
            "scanners": ["trivy", "gitleaks"], "schedule": None,
        },
        headers={"X-CSRF-Token": _csrf(client)},
    )
    assert r.status_code == 201
    assert set(r.json()["scanners"]) == {"trivy", "gitleaks"}
