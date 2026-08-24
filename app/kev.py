"""Enrichissement des findings avec le catalogue CISA KEV (Known Exploited
Vulnerabilities).

Le KEV recense les CVE dont l'exploitation active dans la nature est confirmee
par la CISA. La la ou l'EPSS estime une *probabilite* d'exploitation, le KEV
est un *fait* : la vulnerabilite EST exploitee, maintenant. C'est le signal le
plus fort pour prioriser une remediation, et il est requis par la directive
BOD 22-01 pour les agences federales americaines.

Comme pour l'EPSS, l'appel reseau est fait cote worker, en best-effort : un
echec ne fait jamais echouer l'ingestion, il prive seulement les findings du
drapeau KEV jusqu'au prochain enrichissement.
"""

import logging

import httpx

logger = logging.getLogger(__name__)

# Flux JSON public de la CISA (catalogue complet, ~1200 CVE).
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
TIMEOUT_SECONDS = 15


def fetch_kev_set(url: str = KEV_FEED_URL, timeout: int = TIMEOUT_SECONDS) -> set[str]:
    """Renvoie l'ensemble des identifiants CVE presents dans le catalogue KEV.

    En cas d'echec reseau/format, renvoie un ensemble vide : l'appelant
    considere alors qu'aucun finding n'est KEV pour ce cycle, sans planter.
    """
    try:
        response = httpx.get(url, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Echec de la recuperation du catalogue CISA KEV: %s", exc)
        return set()

    cves: set[str] = set()
    for entry in payload.get("vulnerabilities") or []:
        cve = entry.get("cveID")
        if cve:
            cves.add(cve.strip().upper())
    logger.info("Catalogue KEV charge: %s CVE activement exploitees", len(cves))
    return cves
