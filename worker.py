import logging
import os

from prometheus_client import REGISTRY, start_http_server
from rq import Worker

from app.metrics_state import VulnTrackStateCollector
from app.queue import ingest_queue, redis_conn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger(__name__)

# Port du serveur de metriques du worker (jauges d'etat metier). Scrape par
# Prometheus. Le worker est mono-process : pas de mode multi-process ici.
METRICS_PORT = int(os.getenv("WORKER_METRICS_PORT", "9100"))


if __name__ == "__main__":
    REGISTRY.register(VulnTrackStateCollector())
    start_http_server(METRICS_PORT)
    logger.info("Serveur de metriques du worker demarre sur le port %s", METRICS_PORT)

    worker = Worker([ingest_queue], connection=redis_conn)
    worker.work()
