"""Tests du runner d'auto-scan (app/scanning.py).

Principe : on ne lance JAMAIS de vrai scanner. build_command est pure
(testee directement) ; run_scanner touche subprocess (mocke). Les vrais
scanners sont lents, non-deterministes (les CVE d'alpine changent chaque
semaine) et exigeraient trivy/semgrep/gitleaks installes en CI.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from app import scanning

# ------------------------------------------------------------- build_command

def test_build_command_trivy_image():
    cmd = scanning.build_command("trivy", "image", "alpine:3.19", "/tmp/r.json")
    assert cmd == [
        "trivy", "image", "--quiet", "--format", "json",
        "--output", "/tmp/r.json", "alpine:3.19",
    ]


def test_build_command_trivy_repository_utilise_fs():
    # Sur un depot clone, trivy scanne le systeme de fichiers (fs), pas une image.
    cmd = scanning.build_command("trivy", "repository", "/src", "/tmp/r.json")
    assert cmd[:2] == ["trivy", "fs"]
    assert cmd[-1] == "/src"
    assert cmd[cmd.index("--output") + 1] == "/tmp/r.json"


def test_build_command_semgrep_config_auto():
    cmd = scanning.build_command("semgrep", "repository", "/src", "/tmp/r.json")
    assert cmd[:2] == ["semgrep", "scan"]
    assert cmd[cmd.index("--config") + 1] == "auto"
    assert cmd[cmd.index("--output") + 1] == "/tmp/r.json"


def test_build_command_gitleaks_report_path():
    cmd = scanning.build_command("gitleaks", "repository", "/src", "/tmp/r.json")
    assert cmd[:2] == ["gitleaks", "detect"]
    assert cmd[cmd.index("--source") + 1] == "/src"
    assert cmd[cmd.index("--report-path") + 1] == "/tmp/r.json"


def test_build_command_scanner_inconnu_leve():
    with pytest.raises(ValueError):
        scanning.build_command("nessus", "image", "alpine", "/tmp/r.json")


def test_build_command_trivy_type_inconnu_leve():
    with pytest.raises(ValueError):
        scanning.build_command("trivy", "url", "http://x", "/tmp/r.json")


# ------------------------------------------------------------- run_scanner (subprocess mocke)

class _FakeProc:
    """Imite le CompletedProcess de subprocess.run."""

    def __init__(self, returncode: int, stderr: bytes = b""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = b""


def _out_file_from_cmd(cmd: list[str]) -> str:
    """Retrouve le fichier de sortie demande dans la commande."""
    for flag in ("--output", "--report-path"):
        if flag in cmd:
            return cmd[cmd.index(flag) + 1]
    raise AssertionError(f"aucun fichier de sortie dans {cmd}")


def _fake_run(returncode: int, content: bytes = b'{"ok": true}', stderr: bytes = b""):
    """Fabrique un faux subprocess.run qui ecrit le rapport et rend un code."""
    def _run(cmd, **kwargs):
        # N'ecrit le fichier que si le code est "normal" : sinon run_scanner
        # leve avant de relire, comme avec un vrai scanner en panne.
        if returncode in scanning.OK_EXIT_CODES.get(cmd[0], {0}):
            Path(_out_file_from_cmd(cmd)).write_bytes(content)
        return _FakeProc(returncode, stderr)
    return _run


def test_run_scanner_renvoie_le_rapport():
    with patch("app.scanning.subprocess.run", side_effect=_fake_run(0, b'{"vulns": []}')):
        data = scanning.run_scanner("trivy", "image", "alpine:3.19")
    assert data == b'{"vulns": []}'


def test_run_scanner_gitleaks_code_1_est_normal():
    # Gitleaks sort en 1 quand il TROUVE des secrets : ce n'est pas une erreur.
    with patch("app.scanning.subprocess.run", side_effect=_fake_run(1, b'[{"secret": "x"}]')):
        data = scanning.run_scanner("gitleaks", "repository", "/src")
    assert data == b'[{"secret": "x"}]'


def test_run_scanner_trivy_code_1_echoue():
    # Pour trivy, en revanche, 1 n'est PAS dans les codes normaux -> RuntimeError.
    with patch("app.scanning.subprocess.run", side_effect=_fake_run(1, stderr=b"boom")):
        with pytest.raises(RuntimeError, match="trivy"):
            scanning.run_scanner("trivy", "image", "alpine:3.19")


def test_run_scanner_gitleaks_code_2_echoue():
    # 2 sort de {0, 1} : vraie panne de gitleaks.
    with patch("app.scanning.subprocess.run", side_effect=_fake_run(2, stderr=b"crash")):
        with pytest.raises(RuntimeError, match="gitleaks"):
            scanning.run_scanner("gitleaks", "repository", "/src")


# ---------------------------------------------------- scan_target (orchestration)
#
# Piege : scan_target ouvre ses PROPRES sessions via SessionLocal (il tourne
# dans le worker, sans get_db injecte). En test cette SessionLocal viserait une
# base en memoire DIFFERENTE de celle des fixtures. On la remplace donc par la
# fabrique de session des tests (meme moteur StaticPool partage) et on mocke les
# frontieres externes : run_scanner, save_report (disque), process_scan.

from app.models import Asset, Scan, ScanTarget  # noqa: E402
from tests.conftest import TestingSessionLocal  # noqa: E402


def _make_target(db, **kw):
    defaults = dict(
        name="cible-test", target_type="image", reference="alpine:3.19",
        scanners="trivy", schedule=None, enabled=True,
    )
    defaults.update(kw)
    target = ScanTarget(**defaults)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def test_scan_target_succes(db_session):
    target = _make_target(db_session, scanners="trivy")
    with patch("app.scanning.SessionLocal", TestingSessionLocal), \
         patch("app.scanning.run_scanner", return_value=b'{"vulns": []}') as run, \
         patch("app.scanning.save_report", return_value="/fake/report.json"), \
         patch("app.scanning.process_scan", return_value={"created": 3}) as proc:
        result = scanning.scan_target(target.id)

    assert result["status"] == "success"
    # image trivy : pas de clone, la source est la reference telle quelle
    run.assert_called_once_with("trivy", "image", "alpine:3.19")
    proc.assert_called_once()

    db_session.expire_all()
    refreshed = db_session.get(ScanTarget, target.id)
    assert refreshed.last_status == "success"
    assert refreshed.last_scan_at is not None
    assert db_session.query(Asset).filter_by(name="cible-test").count() == 1
    assert db_session.query(Scan).count() == 1


def test_scan_target_filtre_scanners_incompatibles(db_session):
    # semgrep ne s'applique pas a une image (SCANNERS_BY_TYPE) -> ignore.
    target = _make_target(db_session, scanners="trivy,semgrep")
    with patch("app.scanning.SessionLocal", TestingSessionLocal), \
         patch("app.scanning.run_scanner", return_value=b"{}") as run, \
         patch("app.scanning.save_report", return_value="/fake/r.json"), \
         patch("app.scanning.process_scan", return_value={}):
        result = scanning.scan_target(target.id)

    assert result["status"] == "success"
    run.assert_called_once_with("trivy", "image", "alpine:3.19")  # semgrep saute


def test_scan_target_erreur_scanner_marque_error(db_session):
    target = _make_target(db_session, scanners="trivy")
    with patch("app.scanning.SessionLocal", TestingSessionLocal), \
         patch("app.scanning.run_scanner", side_effect=RuntimeError("trivy explose")), \
         patch("app.scanning.save_report", return_value="/fake/r.json"), \
         patch("app.scanning.process_scan", return_value={}):
        result = scanning.scan_target(target.id)

    assert result["status"] == "error"
    assert any("trivy" in e for e in result["errors"])
    db_session.expire_all()
    assert db_session.get(ScanTarget, target.id).last_status == "error"


def test_scan_target_introuvable(db_session):
    with patch("app.scanning.SessionLocal", TestingSessionLocal):
        result = scanning.scan_target(999999)
    assert result["status"] == "not_found"


def test_scan_target_repository_scanne_le_clone_pas_lurl(db_session):
    target = _make_target(
        db_session, target_type="repository",
        reference="https://github.com/x/y", scanners="gitleaks",
    )
    captured: dict = {}

    def _fake_clone(url, dest):
        captured["url"] = url
        captured["dest"] = dest

    def _fake_run(scanner, ttype, source):
        captured["source"] = source
        return b"[]"

    with patch("app.scanning.SessionLocal", TestingSessionLocal), \
         patch("app.scanning._git_clone", side_effect=_fake_clone), \
         patch("app.scanning.run_scanner", side_effect=_fake_run), \
         patch("app.scanning.save_report", return_value="/fake/r.json"), \
         patch("app.scanning.process_scan", return_value={}):
        result = scanning.scan_target(target.id)

    assert result["status"] == "success"
    assert captured["url"] == "https://github.com/x/y"
    # le scanner tourne sur le repertoire clone, jamais sur l'URL brute
    assert captured["source"] == captured["dest"]
