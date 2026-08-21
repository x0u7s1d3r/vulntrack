from app.models import Finding
from app.parsers import parse_gitleaks, parse_semgrep, parse_trivy


def test_parse_trivy_maps_severity_and_fields():
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "openssl",
                        "Severity": "CRITICAL",
                        "Title": "Buffer overflow",
                        "Description": "x" * 6000,
                    }
                ]
            }
        ]
    }
    findings = list(parse_trivy(report))
    assert len(findings) == 1
    f = findings[0]
    assert f["cve"] == "CVE-2024-0001"
    assert f["component"] == "openssl"
    assert f["severity"] == "critical"
    assert len(f["description"]) == 5000
    assert f["rule_id"] is None
    assert f["file_path"] is None


def test_parse_trivy_unknown_severity_falls_back_to_info():
    report = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-x", "Severity": "WEIRD"}]}]}
    findings = list(parse_trivy(report))
    assert findings[0]["severity"] == "info"


def test_parse_trivy_handles_missing_results():
    assert list(parse_trivy({})) == []


def test_parse_semgrep_maps_severity_and_location():
    report = {
        "results": [
            {
                "check_id": "python.django.security.injection.sql",
                "path": "app/views.py",
                "start": {"line": 42},
                "extra": {"message": "Injection SQL potentielle", "severity": "ERROR"},
            }
        ]
    }
    findings = list(parse_semgrep(report))
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "python.django.security.injection.sql"
    assert f["file_path"] == "app/views.py"
    assert f["line_number"] == 42
    assert f["severity"] == "high"
    assert f["cve"] is None
    assert f["component"] is None


def test_parse_semgrep_severity_mapping():
    for semgrep_sev, expected in [("ERROR", "high"), ("WARNING", "medium"), ("INFO", "low")]:
        report = {
            "results": [
                {"check_id": "r", "path": "f.py", "start": {"line": 1}, "extra": {"severity": semgrep_sev}}
            ]
        }
        assert list(parse_semgrep(report))[0]["severity"] == expected


def test_parse_semgrep_handles_missing_results():
    assert list(parse_semgrep({})) == []


def test_parse_gitleaks_is_always_critical_and_never_leaks_secret():
    report = [
        {
            "RuleID": "aws-access-key",
            "File": "config/settings.py",
            "StartLine": 12,
            "Description": "AWS Access Key",
            "Secret": "AKIAABCDEFGHIJKLMNOP",
            "Match": "AKIAABCDEFGHIJKLMNOP",
        }
    ]
    findings = list(parse_gitleaks(report))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["rule_id"] == "aws-access-key"
    assert f["file_path"] == "config/settings.py"
    assert f["line_number"] == 12
    assert "AKIAABCDEFGHIJKLMNOP" not in f["title"]
    assert "AKIAABCDEFGHIJKLMNOP" not in f["description"]


def test_parse_gitleaks_handles_empty_report():
    assert list(parse_gitleaks([])) == []


def test_fingerprint_trivy_formula_unchanged():
    """Regression : la formule Trivy ne doit jamais changer, sous peine
    d'invalider toutes les empreintes deja stockees en production."""
    import hashlib

    expected = hashlib.sha256(b"nginx:1.25|CVE-2024-0001|openssl").hexdigest()
    assert Finding.make_fingerprint("nginx:1.25", "trivy", cve="CVE-2024-0001", component="openssl") == expected


def test_fingerprint_differs_by_scanner_for_same_asset():
    """Deux scanners differents sur le meme asset ne doivent jamais produire
    la meme empreinte, meme avec des identifiants vides par ailleurs."""
    trivy_fp = Finding.make_fingerprint("repo-x", "trivy", cve="CVE-1", component="lib")
    semgrep_fp = Finding.make_fingerprint(
        "repo-x", "semgrep", rule_id="rule-1", file_path="a.py", line_number=1
    )
    assert trivy_fp != semgrep_fp


def test_fingerprint_semgrep_stable_and_location_sensitive():
    fp1 = Finding.make_fingerprint("repo-x", "semgrep", rule_id="r", file_path="a.py", line_number=10)
    fp2 = Finding.make_fingerprint("repo-x", "semgrep", rule_id="r", file_path="a.py", line_number=10)
    fp3 = Finding.make_fingerprint("repo-x", "semgrep", rule_id="r", file_path="a.py", line_number=11)
    assert fp1 == fp2
    assert fp1 != fp3
