"""Instrumentation Prometheus des metriques RED de l'API (Rate, Errors,
Duration).

Subtilite multi-process : chaque conteneur api fait tourner plusieurs
workers uvicorn (processus distincts). Sans precaution, un scrape Prometheus
tomberait sur un seul worker au hasard et ne verrait que ses compteurs. En
mode multi-process (variable d'environnement PROMETHEUS_MULTIPROC_DIR
positionnee), chaque worker ecrit ses metriques dans un repertoire partage,
et l'endpoint /metrics les agrege a la lecture. Hors de ce mode (tests,
dev mono-process), on retombe sur le registre par defaut.
"""

import os
import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    multiprocess,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

REQUEST_COUNT = Counter(
    "vulntrack_http_requests_total",
    "Nombre total de requetes HTTP traitees",
    ["method", "route", "status"],
)

REQUEST_DURATION = Histogram(
    "vulntrack_http_request_duration_seconds",
    "Duree de traitement des requetes HTTP",
    ["method", "route"],
    # Bornes adaptees a une API web : de 5 ms a 5 s. Permet de calculer des
    # quantiles (p50/p95/p99) cote Prometheus via histogram_quantile.
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Mesure chaque requete : incremente le compteur et observe la duree.

    Le label `route` utilise le gabarit de route (ex: /assets/{asset_id}/
    findings) et non le chemin brut : sinon chaque id genererait une serie
    temporelle distincte et ferait exploser la cardinalite. Les chemins non
    routes (404) sont regroupes sous "__unmatched__" pour la meme raison.
    """

    async def dispatch(self, request: Request, call_next):
        # L'endpoint /metrics ne se mesure pas lui-meme.
        if request.url.path == "/metrics":
            return await call_next(request)

        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start

        route = request.scope.get("route")
        route_path = getattr(route, "path", None) or "__unmatched__"

        REQUEST_COUNT.labels(request.method, route_path, str(response.status_code)).inc()
        REQUEST_DURATION.labels(request.method, route_path).observe(elapsed)

        return response


def render_metrics() -> tuple[bytes, str]:
    """Serialise les metriques au format texte Prometheus.

    En mode multi-process, agrege les fichiers de tous les workers du
    conteneur dans un registre neuf ; sinon, expose le registre par defaut.
    """
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
    else:
        registry = REGISTRY

    return generate_latest(registry), CONTENT_TYPE_LATEST
