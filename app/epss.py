"""Enrichissement des findings avec le score EPSS (Exploit Prediction Scoring
System, FIRST.org).

Le CVSS mesure la gravite theorique d'une vulnerabilite ; l'EPSS estime la
probabilite qu'elle soit reellement exploitee dans les 30 jours a venir.
Combiner les deux est ce qui permet de prioriser une CVE "high" activement
exploitee avant une CVE "critical" jamais vue en conditions reelles.

L'appel a l'API FIRST.org est fait cote worker (hors du chemin de requete
HTTP), en best-effort : un echec reseau ne doit jamais faire echouer
l'ingestion d'un scan, seulement priver les findings concernes de score.
"""

import logging

import httpx

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
TIMEOUT_SECONDS = 10


def fetch_epss_scores(cves: list[str]) -> dict[str, float]:
    """Recupere le score EPSS (0-1) pour chaque CVE fournie.

    Renvoie un dict partiel en cas d'echec sur un lot : les CVE non
    resolues sont simplement absentes plutot que de faire lever une
    exception a l'appelant.
    """
    scores: dict[str, float] = {}
    unique_cves = sorted({c for c in cves if c})

    for i in range(0, len(unique_cves), BATCH_SIZE):
        batch = unique_cves[i : i + BATCH_SIZE]
        try:
            response = httpx.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                timeout=TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(
                "Echec de la recuperation EPSS pour un lot de %s CVE: %s",
                len(batch),
                exc,
            )
            continue

        for entry in payload.get("data") or []:
            cve = entry.get("cve")
            epss = entry.get("epss")
            if not cve or epss is None:
                continue
            try:
                scores[cve] = float(epss)
            except (TypeError, ValueError):
                continue

    return scores
