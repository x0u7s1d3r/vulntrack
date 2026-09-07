"""Tests du module IA (app/ai.py). Aucun appel reseau reel : urlopen est mocke."""
import json
import os
from unittest.mock import patch

import pytest

from app import ai, models
from app.config import get_settings


def _finding():
    return models.Finding(
        asset_id=1, scanner="trivy", fingerprint="f1", title="Log4Shell RCE",
        severity="critical", cve="CVE-2021-44228", component="log4j-core", status="open",
    )


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_ai_enabled_reflete_la_config():
    os.environ.pop("OLLAMA_URL", None)
    get_settings.cache_clear()
    assert ai.ai_enabled() is False
    os.environ["OLLAMA_URL"] = "http://ollama:11434"
    get_settings.cache_clear()
    try:
        assert ai.ai_enabled() is True
    finally:
        os.environ.pop("OLLAMA_URL", None)
        get_settings.cache_clear()


def test_build_prompt_ancre_sur_le_finding():
    p = ai.build_prompt(_finding())
    assert "CVE-2021-44228" in p
    assert "log4j-core" in p
    assert "n'invente" in p.lower()   # garde-fou anti-hallucination present


def test_explain_finding_desactive_leve():
    os.environ.pop("OLLAMA_URL", None)
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="non configuree"):
        ai.explain_finding(_finding())


def test_explain_finding_succes():
    os.environ["OLLAMA_URL"] = "http://ollama:11434"
    get_settings.cache_clear()
    fake = _FakeResp(json.dumps({"response": "Explication claire de la vuln."}).encode())
    try:
        with patch("app.ai.urllib.request.urlopen", return_value=fake):
            out = ai.explain_finding(_finding())
    finally:
        os.environ.pop("OLLAMA_URL", None)
        get_settings.cache_clear()
    assert "Explication claire" in out


def test_explain_finding_erreur_reseau_leve():
    os.environ["OLLAMA_URL"] = "http://ollama:11434"
    get_settings.cache_clear()
    import urllib.error

    def _boom(*a, **k):
        raise urllib.error.URLError("connexion refusee")

    try:
        with patch("app.ai.urllib.request.urlopen", side_effect=_boom):
            with pytest.raises(RuntimeError, match="indisponible"):
                ai.explain_finding(_finding())
    finally:
        os.environ.pop("OLLAMA_URL", None)
        get_settings.cache_clear()
