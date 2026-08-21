import json
import logging
from datetime import datetime, timezone

from app.database import SessionLocal
from app.epss import fetch_epss_scores
from app.models import Asset, Finding, Scan
from app.parsers import get_parser
from app.storage import load_report

logger = logging.getLogger(__name__)


def utcnow():
    return datetime.now(timezone.utc)


def process_scan(scan_id: int) -> dict:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            logger.error("Scan %s introuvable", scan_id)
            return {"status": "not_found"}

        scan.status = "processing"
        db.commit()

        try:
            raw = load_report(scan.raw_report_path)
            report = json.loads(raw)
            parser = get_parser(scan.scanner)
            asset = db.get(Asset, scan.asset_id)

            created = 0
            updated = 0
            seen_fingerprints = []
            # Findings avec CVE, cree(e)s ou mis a jour dans ce scan : cible
            # de l'enrichissement EPSS une fois la boucle terminee.
            findings_with_cve = []

            for parsed in parser(report):
                fingerprint = Finding.make_fingerprint(
                    asset.name,
                    scan.scanner,
                    cve=parsed["cve"],
                    component=parsed["component"],
                    rule_id=parsed["rule_id"],
                    file_path=parsed["file_path"],
                    line_number=parsed["line_number"],
                )
                seen_fingerprints.append(fingerprint)

                existing = (
                    db.query(Finding).filter_by(fingerprint=fingerprint).first()
                )

                if existing:
                    existing.last_seen = utcnow()
                    existing.scan_id = scan.id
                    if existing.status == "fixed":
                        existing.status = "open"
                    updated += 1
                    if parsed["cve"]:
                        findings_with_cve.append(existing)
                else:
                    finding = Finding(
                        asset_id=asset.id,
                        scan_id=scan.id,
                        scanner=scan.scanner,
                        fingerprint=fingerprint,
                        title=parsed["title"][:500],
                        description=parsed["description"],
                        severity=parsed["severity"],
                        cve=parsed["cve"],
                        component=parsed["component"],
                        rule_id=parsed["rule_id"],
                        file_path=parsed["file_path"],
                        line_number=parsed["line_number"],
                        status="open",
                    )
                    db.add(finding)
                    created += 1
                    if parsed["cve"]:
                        findings_with_cve.append(finding)

            db.flush()

            # Enrichissement EPSS : best-effort, ne doit jamais faire echouer
            # l'ingestion. Un appel reseau qui echoue laisse simplement
            # epss_score a None sur les findings concernes.
            if findings_with_cve:
                try:
                    scores = fetch_epss_scores(
                        [f.cve for f in findings_with_cve if f.cve]
                    )
                    for finding in findings_with_cve:
                        if finding.cve in scores:
                            finding.epss_score = scores[finding.cve]
                except Exception:
                    logger.warning(
                        "Enrichissement EPSS indisponible pour le scan %s",
                        scan_id,
                        exc_info=True,
                    )

            fixed = 0
            if seen_fingerprints:
                # Scope par scanner : un scan Semgrep ne doit jamais marquer
                # comme "corrigees" des findings Trivy (ou inversement) du
                # meme asset, puisqu'il ne les a simplement pas regardees.
                stale = (
                    db.query(Finding)
                    .filter(
                        Finding.asset_id == asset.id,
                        Finding.scanner == scan.scanner,
                        Finding.status.in_(["open", "in_progress"]),
                        ~Finding.fingerprint.in_(seen_fingerprints),
                    )
                    .all()
                )
                for finding in stale:
                    finding.status = "fixed"
                    fixed += 1

            scan.status = "completed"
            scan.finished_at = utcnow()
            scan.findings_count = created + updated
            db.commit()

            logger.info(
                "Scan %s termine: %s nouveaux, %s mis a jour, %s corriges",
                scan_id, created, updated, fixed,
            )
            return {
                "status": "completed",
                "created": created,
                "updated": updated,
                "fixed": fixed,
            }

        except Exception as exc:
            db.rollback()
            scan = db.get(Scan, scan_id)
            scan.status = "failed"
            scan.error_message = str(exc)[:1000]
            scan.finished_at = utcnow()
            db.commit()
            logger.exception("Echec du scan %s", scan_id)
            raise

    finally:
        db.close()
