import json

import app.jobs as jobs_module
from app import models
from app.jobs import process_scan


def _install_session(monkeypatch, db_session):
    # process_scan() appelle db.close() dans son bloc finally : sur une
    # session partagee avec le test, on neutralise close() pour garder la
    # session utilisable dans les assertions qui suivent l'appel.
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr(jobs_module, "SessionLocal", lambda: db_session)


def _install_reports(monkeypatch, reports: dict):
    def fake_load_report(path):
        return json.dumps(reports[path]).encode()

    monkeypatch.setattr(jobs_module, "load_report", fake_load_report)


def _install_no_epss(monkeypatch):
    monkeypatch.setattr(jobs_module, "fetch_epss_scores", lambda cves: {})


def _make_scan(db_session, asset_name, scanner, path, asset_type="repository"):
    asset = db_session.query(models.Asset).filter_by(name=asset_name).first()
    if not asset:
        asset = models.Asset(name=asset_name, type=asset_type)
        db_session.add(asset)
        db_session.flush()
    scan = models.Scan(
        asset_id=asset.id, scanner=scanner, status="pending", raw_report_path=path
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


TRIVY_REPORT = {
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "Severity": "CRITICAL",
                    "Title": "Buffer overflow",
                    "Description": "desc",
                }
            ]
        }
    ]
}

SEMGREP_REPORT = {
    "results": [
        {
            "check_id": "rule-1",
            "path": "a.py",
            "start": {"line": 1},
            "extra": {"message": "probleme", "severity": "ERROR"},
        }
    ]
}

EMPTY_SEMGREP_REPORT = {"results": []}

# Meme regle en jeu (rule-2), differente de SEMGREP_REPORT (rule-1) : sert a
# simuler "rule-1 corrigee, rule-2 nouvellement detectee" sans que le lot de
# fingerprints vus soit vide (voir la note ci-dessous sur seen_fingerprints).
SEMGREP_REPORT_DIFFERENT_RULE = {
    "results": [
        {
            "check_id": "rule-2",
            "path": "b.py",
            "start": {"line": 5},
            "extra": {"message": "autre probleme", "severity": "WARNING"},
        }
    ]
}


def test_process_scan_trivy_creates_then_updates_on_rescan(db_session, monkeypatch):
    _install_session(monkeypatch, db_session)
    _install_no_epss(monkeypatch)
    _install_reports(monkeypatch, {"/fake/trivy1.json": TRIVY_REPORT, "/fake/trivy2.json": TRIVY_REPORT})

    scan1 = _make_scan(db_session, "nginx:1.25", "trivy", "/fake/trivy1.json")
    result1 = process_scan(scan1.id)
    assert result1 == {"status": "completed", "created": 1, "updated": 0, "fixed": 0}

    finding = db_session.query(models.Finding).filter_by(cve="CVE-2024-0001").one()
    assert finding.scanner == "trivy"
    assert finding.status == "open"

    scan2 = _make_scan(db_session, "nginx:1.25", "trivy", "/fake/trivy2.json")
    result2 = process_scan(scan2.id)
    assert result2 == {"status": "completed", "created": 0, "updated": 1, "fixed": 0}


def test_multi_scanner_stale_detection_does_not_cross_scanners(db_session, monkeypatch):
    """Regression : avant le fix, un scan Semgrep sans resultats marquait a
    tort les findings Trivy du meme asset comme corriges, faute de scoper
    la detection des findings "disparus" par scanner."""
    _install_session(monkeypatch, db_session)
    _install_no_epss(monkeypatch)
    _install_reports(
        monkeypatch,
        {
            "/fake/trivy.json": TRIVY_REPORT,
            "/fake/semgrep1.json": SEMGREP_REPORT,
            "/fake/semgrep2.json": SEMGREP_REPORT_DIFFERENT_RULE,
        },
    )

    trivy_scan = _make_scan(db_session, "repo-x", "trivy", "/fake/trivy.json")
    process_scan(trivy_scan.id)
    trivy_finding = db_session.query(models.Finding).filter_by(scanner="trivy").one()
    assert trivy_finding.status == "open"

    semgrep_scan1 = _make_scan(db_session, "repo-x", "semgrep", "/fake/semgrep1.json")
    process_scan(semgrep_scan1.id)
    semgrep_finding = db_session.query(models.Finding).filter_by(
        scanner="semgrep", rule_id="rule-1"
    ).one()
    assert semgrep_finding.status == "open"

    # rule-1 a ete corrigee (le rapport ne la remonte plus), rule-2 est
    # nouvellement detectee : seen_fingerprints est non vide, la detection
    # des findings disparus s'execute normalement.
    semgrep_scan2 = _make_scan(db_session, "repo-x", "semgrep", "/fake/semgrep2.json")
    result = process_scan(semgrep_scan2.id)
    assert result["fixed"] == 1

    db_session.refresh(trivy_finding)
    db_session.refresh(semgrep_finding)
    assert semgrep_finding.status == "fixed"
    assert trivy_finding.status == "open", (
        "un scan semgrep ne doit jamais affecter les findings trivy du meme asset"
    )


def test_epss_score_applied_only_to_cve_findings(db_session, monkeypatch):
    _install_session(monkeypatch, db_session)
    monkeypatch.setattr(
        jobs_module, "fetch_epss_scores", lambda cves: {"CVE-2024-0001": 0.734}
    )
    _install_reports(
        monkeypatch,
        {"/fake/trivy.json": TRIVY_REPORT, "/fake/semgrep.json": SEMGREP_REPORT},
    )

    trivy_scan = _make_scan(db_session, "repo-y", "trivy", "/fake/trivy.json")
    process_scan(trivy_scan.id)
    trivy_finding = db_session.query(models.Finding).filter_by(scanner="trivy").one()
    assert trivy_finding.epss_score == 0.734

    semgrep_scan = _make_scan(db_session, "repo-y", "semgrep", "/fake/semgrep.json")
    process_scan(semgrep_scan.id)
    semgrep_finding = db_session.query(models.Finding).filter_by(scanner="semgrep").one()
    assert semgrep_finding.epss_score is None


def test_epss_failure_does_not_fail_the_scan(db_session, monkeypatch):
    _install_session(monkeypatch, db_session)
    _install_reports(monkeypatch, {"/fake/trivy.json": TRIVY_REPORT})

    def boom(cves):
        raise RuntimeError("panne reseau")

    monkeypatch.setattr(jobs_module, "fetch_epss_scores", boom)

    scan = _make_scan(db_session, "repo-z", "trivy", "/fake/trivy.json")
    result = process_scan(scan.id)
    assert result["status"] == "completed"

    finding = db_session.query(models.Finding).filter_by(cve="CVE-2024-0001").one()
    assert finding.epss_score is None
