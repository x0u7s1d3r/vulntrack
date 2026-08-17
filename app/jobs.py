import json
import logging
from datetime import datetime, timezone

from app.database import SessionLocal
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

            for parsed in parser(report):
                fingerprint = Finding.make_fingerprint(
                    asset.name, parsed["cve"], parsed["component"]
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
                else:
                    db.add(
                        Finding(
                            asset_id=asset.id,
                            scan_id=scan.id,
                            fingerprint=fingerprint,
                            title=parsed["title"][:500],
                            description=parsed["description"],
                            severity=parsed["severity"],
                            cve=parsed["cve"],
                            component=parsed["component"],
                            status="open",
                        )
                    )
                    created += 1

            db.flush()

            fixed = 0
            if seen_fingerprints:
                stale = (
                    db.query(Finding)
                    .filter(
                        Finding.asset_id == asset.id,
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
