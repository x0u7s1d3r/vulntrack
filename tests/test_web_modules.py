"""Tests des modules du tableau de bord (Wazuh-style, adaptes a VulnTrack)."""
from app import models
from app.web_modules import (
    attack_matrix,
    classify_attack,
    inventory_stats,
    sca_stats,
    secrets_stats,
    vuln_detection_stats,
)


def _finding(asset_id, **kw):
    base = dict(
        asset_id=asset_id, scanner="trivy", fingerprint=f"fp-{kw.get('_n', 0)}",
        title="x", severity="high", status="open",
    )
    base.update({k: v for k, v in kw.items() if not k.startswith("_")})
    return models.Finding(**base)


# ----------------------------------------------------------- classify_attack

def test_classify_attack_secret_to_credential_access():
    m = classify_attack("Hardcoded AWS access key committed", "generic.secrets.aws-access-key", "gitleaks")
    assert m["tactic"] == "TA0006"
    assert m["technique"] == "T1552"


def test_classify_attack_sqli_to_initial_access():
    m = classify_attack("SQL injection via unsanitized input", "python.django.sqli", "semgrep")
    assert m["tactic"] == "TA0001"
    assert m["technique"] == "T1190"


def test_classify_attack_memory_corruption_to_priv_esc():
    m = classify_attack("Heap buffer overflow in openssl", None, "trivy")
    assert m["tactic"] == "TA0004"
    assert m["technique"] == "T1068"


def test_classify_attack_fallback_by_scanner():
    # Aucun mot-cle : repli sur le scanner.
    assert classify_attack("mystere", None, "gitleaks")["tactic"] == "TA0006"
    assert classify_attack("mystere", None, "trivy")["tactic"] == "TA0001"


# ----------------------------------------------------------- vuln detection

def test_vuln_detection_counts_and_epss_buckets(db_session):
    a = models.Asset(name="img", type="image")
    db_session.add(a)
    db_session.flush()
    db_session.add_all([
        _finding(a.id, _n=1, cve="CVE-2024-1", component="openssl", severity="critical",
                 status="open", epss_score=0.9),
        _finding(a.id, _n=2, cve="CVE-2024-2", component="openssl", severity="high",
                 status="open", epss_score=0.3),
        _finding(a.id, _n=3, cve="CVE-2024-3", component="zlib", severity="high",
                 status="open", epss_score=None),
        # Sans CVE : ignore par ce module.
        _finding(a.id, _n=4, scanner="semgrep", cve=None, severity="high", status="open"),
        # CVE corrigee : compte dans with_cve mais pas dans open.
        _finding(a.id, _n=5, cve="CVE-2024-4", severity="low", status="fixed", epss_score=0.1),
    ])
    db_session.commit()

    d = vuln_detection_stats(db_session)
    assert d["totals"]["with_cve"] == 4
    assert d["totals"]["open"] == 3
    assert d["totals"]["unique_cves"] == 4
    assert d["totals"]["exploitable"] == 1  # seul 0.9 >= 0.5
    assert d["totals"]["critical_open"] == 1
    # Distribution EPSS : une valeur "sans score".
    dist = {b["key"]: b["count"] for b in d["epss_dist"]}
    assert dist["inconnu"] == 1
    # openssl est le composant le plus present (2).
    assert d["top_components"][0] == {"name": "openssl", "count": 2}
    # Prioritaire trie par EPSS decroissant.
    assert d["priority"][0]["cve"] == "CVE-2024-1"


# ----------------------------------------------------------- SCA

def test_sca_stats_only_semgrep(db_session):
    a = models.Asset(name="repo", type="repository")
    db_session.add(a)
    db_session.flush()
    db_session.add_all([
        _finding(a.id, _n=1, scanner="semgrep", rule_id="python.django.sqli",
                 file_path="src/api/db.py", severity="critical", status="open"),
        _finding(a.id, _n=2, scanner="semgrep", rule_id="python.django.sqli",
                 file_path="src/api/views.py", severity="high", status="open"),
        _finding(a.id, _n=3, scanner="semgrep", rule_id="javascript.express.xss",
                 file_path="src/api/db.py", severity="medium", status="open"),
        # Trivy : hors module SCA.
        _finding(a.id, _n=4, scanner="trivy", cve="CVE-2024-9", status="open"),
    ])
    db_session.commit()

    d = sca_stats(db_session)
    assert d["totals"]["total"] == 3
    assert d["totals"]["rules"] == 2
    assert d["totals"]["files"] == 2
    assert d["totals"]["high_open"] == 2  # critical + high
    assert d["top_rules"][0]["rule_id"] == "python.django.sqli"
    assert d["top_rules"][0]["count"] == 2
    cats = {c["category"]: c["count"] for c in d["by_category"]}
    assert cats["python"] == 2
    assert cats["javascript"] == 1


# ----------------------------------------------------------- secrets

def test_secrets_stats_only_gitleaks(db_session):
    a1 = models.Asset(name="repo1", type="repository")
    a2 = models.Asset(name="repo2", type="repository")
    db_session.add_all([a1, a2])
    db_session.flush()
    db_session.add_all([
        _finding(a1.id, _n=1, scanner="gitleaks", rule_id="generic.secrets.aws-access-key",
                 title="AWS key", file_path="config.py", line_number=3,
                 severity="critical", status="open"),
        _finding(a1.id, _n=2, scanner="gitleaks", title="API key", severity="high", status="fixed"),
        _finding(a2.id, _n=3, scanner="gitleaks", title="DB pwd", severity="high", status="open"),
        _finding(a2.id, _n=4, scanner="trivy", cve="CVE-2024-1", status="open"),
    ])
    db_session.commit()

    d = secrets_stats(db_session)
    assert d["totals"]["total"] == 3
    assert d["totals"]["open"] == 2
    assert d["totals"]["remediated"] == 1
    assert d["totals"]["repos"] == 2
    # Detail : jamais de valeur de secret, seulement l'emplacement.
    first = d["items"][0]
    assert "file_path" in first and "line_number" in first
    assert not any("value" in it or "secret" in it for it in d["items"])


# ----------------------------------------------------------- ATT&CK matrix

def test_attack_matrix_maps_open_findings(db_session):
    a = models.Asset(name="x", type="image")
    db_session.add(a)
    db_session.flush()
    db_session.add_all([
        _finding(a.id, _n=1, scanner="gitleaks", title="Hardcoded AWS access key committed",
                 severity="critical", status="open"),
        _finding(a.id, _n=2, scanner="semgrep", title="SQL injection via unsanitized input",
                 rule_id="python.django.sqli", severity="high", status="open"),
        # Corrige : hors matrice.
        _finding(a.id, _n=3, scanner="trivy", title="Heap buffer overflow", status="fixed"),
    ])
    db_session.commit()

    d = attack_matrix(db_session)
    assert d["totals"]["mapped"] == 2
    tactics = {t["id"]: t for t in d["tactics"]}
    assert tactics["TA0006"]["count"] == 1  # secret -> Credential Access
    assert tactics["TA0001"]["count"] == 1  # sqli -> Initial Access
    # La matrice liste toujours les 7 tactiques (meme a zero).
    assert len(d["tactics"]) == 7


# ----------------------------------------------------------- inventaire

def test_inventory_coverage_and_hygiene(db_session):
    img = models.Asset(name="img", type="image")
    repo = models.Asset(name="repo", type="repository")
    db_session.add_all([img, repo])
    db_session.flush()
    # img : trivy + gitleaks seulement (couverture incomplete, pas de semgrep).
    db_session.add_all([
        _finding(img.id, _n=1, scanner="trivy", cve="CVE-1", severity="critical", status="open"),
        _finding(img.id, _n=2, scanner="gitleaks", title="secret", severity="high", status="open"),
        # repo : les 3 scanners.
        _finding(repo.id, _n=3, scanner="trivy", cve="CVE-2", severity="low", status="open"),
        _finding(repo.id, _n=4, scanner="semgrep", rule_id="r", severity="low", status="open"),
        _finding(repo.id, _n=5, scanner="gitleaks", title="s", severity="low", status="fixed"),
    ])
    db_session.commit()

    d = inventory_stats(db_session)
    assert d["totals"]["assets"] == 2
    assert d["totals"]["with_critical"] == 1  # img a une critique
    assert d["totals"]["incomplete_coverage"] == 1  # img manque semgrep
    by_name = {it["name"]: it for it in d["items"]}
    assert by_name["img"]["coverage_count"] == 2
    assert by_name["repo"]["coverage_count"] == 3
    # L'asset avec critique est classe en tete.
    assert d["items"][0]["name"] == "img"
    # Hygiene bornee 0..100.
    for it in d["items"]:
        assert 0 <= it["hygiene"] <= 100
