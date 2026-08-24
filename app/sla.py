"""Politique SLA de remediation (delais cibles par severite).

Module neutre (ne depend que de datetime) pour etre importe aussi bien par les
agregations de posture que par le rendu des lignes de findings, sans cycle
d'import.
"""

from datetime import datetime, timedelta, timezone

# Delai de remediation cible par severite (jours).
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}


def due_date(first_seen: datetime | None, severity: str) -> datetime | None:
    if first_seen is None:
        return None
    first = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=timezone.utc)
    return first + timedelta(days=SLA_DAYS.get(severity, 180))


def is_overdue(first_seen: datetime | None, severity: str, status: str,
               now: datetime | None = None) -> bool:
    """Vrai si un finding ouvert a depasse son echeance SLA."""
    if status not in ("open", "in_progress"):
        return False
    due = due_date(first_seen, severity)
    if due is None:
        return False
    return (now or datetime.now(timezone.utc)) > due
