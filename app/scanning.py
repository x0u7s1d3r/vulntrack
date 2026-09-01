"""Auto-scan : VulnTrack execute lui-meme les scanners et reinjecte leurs
rapports dans le pipeline d'ingestion existant (app.jobs.process_scan).

Ce module NE reimplemente AUCUNE detection : il pilote trivy/semgrep/gitleaks
en sous-processus, puis reutilise exactement le meme chemin que l'ingestion
poussee via /scans/ingest -> save_report -> Scan -> process_scan.
"""
import logging
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

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
}

# Codes de sortie "normaux" (rapport quand meme produit) par scanner.
# Gitleaks sort en 1 quand il TROUVE des secrets : ce n'est pas une erreur.
OK_EXIT_CODES = {
    "trivy": {0},
    "semgrep": {0},
    "gitleaks": {0, 1},
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
        return Path(out_file).read_bytes()


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
    subprocess.run(
        ["git", "clone", "--depth", "1", url, dest],
        capture_output=True, timeout=SCANNER_TIMEOUT, check=True,
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
