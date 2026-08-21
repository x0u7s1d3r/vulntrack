"""Metriques d'etat metier, exposees depuis le worker.

Contrairement aux metriques RED de l'API (compteurs incrementes a chaque
requete, repartis sur plusieurs processus), ces metriques decrivent l'etat
courant du systeme : profondeur de la file, nombre de findings par severite
et par statut. Ce sont des jauges, calculees a la volee au moment du scrape.

Le worker RQ est un processus unique : pas de complexite multi-process ici,
un simple collecteur custom qui interroge Redis et la base a chaque scrape.
Un echec de lecture (base ou Redis momentanement indisponible) n'emet
simplement pas la metrique concernee plutot que de faire echouer tout le
scrape.
"""

import logging

from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import func

from app.database import SessionLocal
from app.models import Finding
from app.queue import ingest_queue

logger = logging.getLogger(__name__)


class VulnTrackStateCollector:
    def collect(self):
        yield from self._queue_depth()
        yield from self._findings_by_severity_status()

    def _queue_depth(self):
        try:
            depth = len(ingest_queue)
        except Exception:
            logger.warning("Metrique file : Redis injoignable", exc_info=True)
            return

        gauge = GaugeMetricFamily(
            "vulntrack_ingest_queue_depth",
            "Nombre de scans en attente de traitement dans la file d'ingestion",
        )
        gauge.add_metric([], depth)
        yield gauge

    def _findings_by_severity_status(self):
        db = None
        try:
            db = SessionLocal()
            rows = (
                db.query(
                    Finding.severity,
                    Finding.status,
                    func.count(Finding.id),
                )
                .group_by(Finding.severity, Finding.status)
                .all()
            )
        except Exception:
            logger.warning("Metrique findings : base injoignable", exc_info=True)
            return
        finally:
            if db is not None:
                db.close()

        gauge = GaugeMetricFamily(
            "vulntrack_findings",
            "Nombre de findings par severite et par statut",
            labels=["severity", "status"],
        )
        for severity, status, count in rows:
            gauge.add_metric([severity or "unknown", status or "unknown"], count)
        yield gauge
