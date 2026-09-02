"""Planificateur d'auto-scan : se reveille chaque minute et enfile les scans
des cibles dont la cadence cron est echue. Reutilise la file existante ; les
scans sont executes par le worker. Process dedie (service compose 'scheduler').
"""
import logging
import time
from datetime import datetime, timedelta, timezone

from croniter import croniter

from app.database import SessionLocal
from app.models import ScanTarget
from app.queue import ingest_queue

logger = logging.getLogger(__name__)
TICK_SECONDS = 60
# Statuts pour lesquels on n'enfile PAS (un scan est deja en vol).
BUSY = {"queued", "running"}


def due_targets(db, now):
    """Cibles activees, planifiees, echues et pas deja en cours."""
    targets = (
        db.query(ScanTarget)
        .filter(ScanTarget.enabled.is_(True), ScanTarget.schedule.isnot(None))
        .all()
    )
    due = []
    for t in targets:
        if t.last_status in BUSY:
            continue
        base = t.last_scan_at or t.created_at or (now - timedelta(days=1))
        try:
            nxt = croniter(t.schedule, base).get_next(datetime)
        except Exception:
            logger.warning("Cron invalide pour la cible %s: %r", t.name, t.schedule)
            continue
        if nxt <= now:
            due.append(t)
    return due


def tick():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        for t in due_targets(db, now):
            ingest_queue.enqueue("app.scanning.scan_target", t.id)
            t.last_status = "queued"
            logger.info("Cible '%s' echue -> scan enfile", t.name)
        db.commit()
    finally:
        db.close()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger.info("Planificateur d'auto-scan demarre (tick=%ss)", TICK_SECONDS)
    while True:
        try:
            tick()
        except Exception:
            logger.exception("Erreur dans le tick du planificateur")
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    main()
