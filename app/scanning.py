"""Auto-scan : VulnTrack execute lui-meme les scanners et reinjecte leurs
rapports dans le pipeline d'ingestion existant (app.jobs.process_scan).

Ce module NE reimplemente AUCUNE detection : il pilote trivy/semgrep/gitleaks
en sous-processus, puis reutilise exactement le meme chemin que l'ingestion
poussee via /scans/ingest -> save_report -> Scan -> process_scan.
"""
import json
import logging
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.database import SessionLocal
from app.jobs import process_scan
from app.models import Asset, Scan, ScanTarget
from app.storage import save_report

logger = logging.getLogger(__name__)

# Delai max d'un scanner (s) : au-dela, le sous-processus est tue.
SCANNER_TIMEOUT = 600

# Scanners applicables par type de cible (garde-fou v1).
SCANNERS_BY_TYPE = {
    "image": {"trivy"},
    "repository": {"trivy", "semgrep", "gitleaks"},
    "url": {"nuclei"},
}

# Codes de sortie "normaux" (rapport quand meme produit) par scanner.
# Gitleaks sort en 1 quand il TROUVE des secrets : ce n'est pas une erreur.
OK_EXIT_CODES = {
    "trivy": {0},
    "semgrep": {0},
    "gitleaks": {0, 1},
    "nuclei": {0},
}


def build_command(scanner: str, target_type: str, source: str, out_file: str) -> list[str]:
    """Construit la commande d'un scanner. `source` = reference d'image
    (target_type=image) ou chemin du depot clone (repository). Le rapport JSON
    est ecrit dans out_file (lecture uniforme ensuite)."""
    if scanner == "trivy" and target_type == "image":
        return ["trivy", "image", "--quiet", "--format", "json", "--output", out_file, source]
    if scanner == "trivy" and target_type == "repository":
        return ["trivy", "fs", "--quiet", "--format", "json", "--output", out_file, source]
    if scanner == "semgrep":
        return ["semgrep", "scan", "--quiet", "--json", "--output", out_file, "--config", "auto", source]
    if scanner == "gitleaks":
        return ["gitleaks", "detect", "--source", source, "--no-git", "--no-banner",
                "--report-format", "json", "--report-path", out_file]
    if scanner == "nuclei" and target_type == "url":
        # DAST : scanne une URL avec les templates bakes dans l'image worker.
        # -duc : pas de check de MAJ (aucun appel reseau parasite).
        return ["nuclei", "-u", source, "-jsonl", "-o", out_file, "-silent",
                "-nc", "-duc", "-t", "/opt/nuclei-templates"]
    raise ValueError(f"combinaison non supportee: {scanner}/{target_type}")


def run_scanner(scanner: str, target_type: str, source: str) -> bytes:
    """Execute un scanner et renvoie le JSON produit (bytes)."""
    with tempfile.TemporaryDirectory() as tmp:
        out_file = str(Path(tmp) / "report.json")
        cmd = build_command(scanner, target_type, source, out_file)
        logger.info("Auto-scan %s: %s", scanner, " ".join(cmd))
        proc = subprocess.run(
            cmd, capture_output=True, timeout=SCANNER_TIMEOUT, check=False,
        )
        if proc.returncode not in OK_EXIT_CODES.get(scanner, {0}):
            raise RuntimeError(
                f"{scanner} a echoue (code {proc.returncode}): "
                f"{proc.stderr.decode(errors='replace')[:500]}"
            )
        if scanner == "nuclei":
            # Nuclei sort du JSONL ; on le normalise en tableau JSON pour rester
            # compatible avec process_scan (json.loads unique).
            return _nuclei_jsonl_to_array(Path(out_file))
        return Path(out_file).read_bytes()


def _nuclei_jsonl_to_array(out_file: Path) -> bytes:
    """Nuclei ecrit une ligne JSON par finding (JSONL), et rien si 0 finding.
    On agrege en un tableau JSON (b"[]" si vide) pour uniformiser l'ingestion."""
    if not out_file.exists():
        return b"[]"
    items = []
    for line in out_file.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except ValueError:
            continue
    return json.dumps(items).encode()


def _ingest(db, asset_name: str, asset_type: str, scanner: str, content: bytes) -> int:
    """Reproduit le 'front' de /scans/ingest : get-or-create de l'asset,
    sauvegarde du rapport, creation du Scan. Renvoie l'id du Scan."""
    asset = db.query(Asset).filter_by(name=asset_name).first()
    if not asset:
        asset = Asset(name=asset_name, type=asset_type)
        db.add(asset)
        db.flush()
    path = save_report(content, scanner)
    scan = Scan(asset_id=asset.id, scanner=scanner, status="pending", raw_report_path=path)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan.id


def _git_clone(url: str, dest: str) -> None:
    token = get_settings().git_token
    clone_url = url
    if token and url.startswith("https://") and "@" not in url:
        # Depot prive : injecte le token (GitHub utilise l'utilisateur
        # x-access-token). Le token ne quitte jamais la config.
        clone_url = "https://x-access-token:" + token + "@" + url[len("https://"):]
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, dest],
        capture_output=True, timeout=SCANNER_TIMEOUT, check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        if token:
            stderr = stderr.replace(token, "***")  # ne JAMAIS divulguer le token
        raise RuntimeError(
            f"git clone a echoue (code {proc.returncode}): {stderr[:400]}"
        )


def _finish_target(target_id: int, status: str) -> None:
    db = SessionLocal()
    try:
        target = db.get(ScanTarget, target_id)
        if target:
            target.last_status = status
            target.last_scan_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def scan_target(target_id: int) -> dict:
    """Job worker : execute tous les scanners d'une cible et ingere leurs
    rapports. Une cible = un asset (par nom). Point d'entree enfile dans la
    file (app.scanning.scan_target)."""
    db = SessionLocal()
    try:
        target = db.get(ScanTarget, target_id)
        if not target:
            logger.error("Cible de scan %s introuvable", target_id)
            return {"status": "not_found"}
        target.last_status = "running"
        db.commit()
        scanners = [s.strip() for s in target.scanners.split(",") if s.strip()]
        name, ttype, ref = target.name, target.target_type, target.reference
    finally:
        db.close()

    if ttype == "url" and not get_settings().dast_enabled:
        # Garde-fou legal : le DAST attaque une cible vivante. Desactive par
        # defaut ; l'operateur doit l'activer en confirmant qu'il est autorise.
        _finish_target(target_id, "error")
        logger.warning("DAST desactive (dast_enabled=false) : URL %s ignoree", name)
        return {"status": "error", "error": "DAST desactive (dast_enabled=false)"}

    results: dict = {}
    errors: list = []
    with tempfile.TemporaryDirectory() as workdir:
        source = ref
        if ttype == "repository":
            try:
                _git_clone(ref, workdir)
                source = workdir
            except Exception as exc:
                _finish_target(target_id, "error")
                logger.exception("Clone du depot %s echoue", ref)
                return {"status": "error", "error": f"git clone: {exc}"}

        for scanner in scanners:
            if scanner not in SCANNERS_BY_TYPE.get(ttype, set()):
                continue
            try:
                content = run_scanner(scanner, ttype, source)
                db = SessionLocal()
                try:
                    scan_id = _ingest(db, name, ttype, scanner, content)
                finally:
                    db.close()
                results[scanner] = process_scan(scan_id)
            except Exception as exc:
                errors.append(f"{scanner}: {exc}")
                logger.exception("Scanner %s en echec sur %s", scanner, name)

    _finish_target(target_id, "error" if errors else "success")
    return {"status": "error" if errors else "success", "results": results, "errors": errors}
