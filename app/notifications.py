"""Notifications de findings (etape 12).

Quand un scan produit de nouveaux findings de severite suffisante, le worker
alerte via deux canaux independants et optionnels : Slack (webhook entrant)
et un webhook generique (POST JSON, pour brancher n'importe quel outil).

Principes :
- Best-effort : un echec d'envoi (reseau, URL invalide) est journalise mais
  ne fait jamais echouer le traitement du scan. Une notification perdue est
  moins grave qu'un scan perdu.
- Silencieux par defaut : sans URL configuree, aucun appel reseau.
- Seuil de severite : on n'alerte que sur les findings vraiment importants
  (par defaut high et au-dessus), pour ne pas noyer sous le bruit.
"""

import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

# Ordre de gravite, du plus grave au moins grave. Sert a comparer une
# severite au seuil configure.
SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def meets_threshold(severity: str, threshold: str) -> bool:
    """Vrai si `severity` est au moins aussi grave que `threshold`."""
    sev_rank = SEVERITY_RANK.get(severity, -1)
    threshold_rank = SEVERITY_RANK.get(threshold, SEVERITY_RANK["high"])
    return sev_rank >= threshold_rank


def _slack_payload(summary: dict) -> dict:
    counts = summary["new_by_severity"]
    lines = [f"*Nouvelles vulnérabilités détectées* — {summary['asset_name']}"]
    lines.append(f"Scanner : `{summary['scanner']}` · scan #{summary['scan_id']}")
    detail = ", ".join(
        f"{count} {sev}" for sev, count in counts.items() if count
    )
    lines.append(f"Au seuil `{summary['threshold']}`+ : {detail}")
    return {"text": "\n".join(lines)}


def _post(url: str, payload: dict, timeout: int) -> None:
    response = httpx.post(url, json=payload, timeout=timeout)
    response.raise_for_status()


def send_scan_notification(summary: dict) -> None:
    """Envoie la notification sur les canaux configures. Best-effort.

    `summary` attend : scan_id, asset_name, scanner, threshold,
    new_by_severity (dict severite -> nombre de nouveaux findings au seuil).
    """
    settings = get_settings()
    timeout = settings.notify_timeout_seconds

    if settings.slack_webhook_url:
        try:
            _post(settings.slack_webhook_url, _slack_payload(summary), timeout)
        except Exception:
            logger.warning(
                "Notification Slack echouee pour le scan %s",
                summary.get("scan_id"),
                exc_info=True,
            )

    if settings.notify_webhook_url:
        try:
            # Webhook generique : on transmet le resume brut, a charge de
            # l'outil recepteur de le mettre en forme.
            _post(settings.notify_webhook_url, summary, timeout)
        except Exception:
            logger.warning(
                "Notification webhook echouee pour le scan %s",
                summary.get("scan_id"),
                exc_info=True,
            )
