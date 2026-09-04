"""Tests du webhook GitHub (/ui/webhooks/github).

Authentification par signature HMAC (X-Hub-Signature-256). On envoie le corps
brut (content=) pour que la signature calculee corresponde exactement a ce que
le serveur relit.
"""
import hashlib
import hmac
import json
import os
from unittest.mock import patch

from app import models
from app.config import get_settings

SECRET = "testsecret-webhook"


def _enable_secret():
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    get_settings.cache_clear()


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


def _push_body(clone_url="https://github.com/x/y.git") -> bytes:
    return json.dumps({
        "repository": {"clone_url": clone_url, "html_url": clone_url.removesuffix(".git")}
    }).encode()


def test_webhook_signature_invalide_401(client, db_session):
    _enable_secret()
    body = _push_body()
    r = client.post("/ui/webhooks/github", content=body,
                    headers={"X-Hub-Signature-256": "sha256=deadbeef",
                             "X-GitHub-Event": "push"})
    assert r.status_code == 401


def test_webhook_evenement_non_push_ignore(client, db_session):
    _enable_secret()
    body = _push_body()
    r = client.post("/ui/webhooks/github", content=body,
                    headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "ping"})
    assert r.status_code == 200
    assert r.json()["status"] == "ignore"


def test_webhook_push_sans_cible_ignore(client, db_session):
    _enable_secret()
    body = _push_body("https://github.com/aucune/correspondance.git")
    r = client.post("/ui/webhooks/github", content=body,
                    headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "push"})
    assert r.status_code == 200
    assert r.json()["status"] == "ignore"


def test_webhook_push_avec_cible_enfile(client, db_session):
    _enable_secret()
    target = models.ScanTarget(name="repo-y", target_type="repository",
                               reference="https://github.com/x/y.git",
                               scanners="trivy,gitleaks", enabled=True)
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    body = _push_body("https://github.com/x/y.git")
    with patch("app.queue.ingest_queue.enqueue") as enq:
        r = client.post("/ui/webhooks/github", content=body,
                        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "push"})

    assert r.status_code == 200
    assert r.json()["status"] == "queued"
    assert "repo-y" in r.json()["targets"]
    enq.assert_called_once_with("app.scanning.scan_target", target.id)
    db_session.expire_all()
    assert db_session.get(models.ScanTarget, target.id).last_status == "queued"
