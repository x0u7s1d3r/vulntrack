"""Pilotage de la posture : SLA, MTTR, flux de remediation et risque.

Ce module repond aux questions qu'un responsable securite pose reellement :
sommes-nous dans les temps (SLA) ? a quelle vitesse corrigeons-nous (MTTR) ?
la dette de vulnerabilites se resorbe-t-elle (flux decouvertes/corrigees) ?
ou se concentre le risque (bandes de risque, top findings) ?

Le MTTR et la conformite SLA sont calcules a partir de l'audit trail deja
present (FindingNote de type "status_change" vers "fixed") : aucune donnee
supplementaire n'est requise, la tracabilite du triage suffit.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Asset, Finding, FindingNote
from app.risk import CRITICALITY_LABEL, risk_band, risk_score
from app.sla import SLA_DAYS, due_date
from app.web_stats import OPEN_STATUSES, SEVERITIES


def _aware(dt: datetime | None) -> datetime | None:
    """Normalise en UTC-aware : SQLite peut renvoyer des datetimes naifs."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fix_dates(db: Session) -> dict[int, datetime]:
    """Date de correction par finding : la derniere transition vers "fixed"
    dans l'audit trail."""
    rows = (
        db.query(FindingNote.finding_id, func.max(FindingNote.created_at))
        .filter(FindingNote.kind == "status_change", FindingNote.new_status == "fixed")
        .group_by(FindingNote.finding_id)
        .all()
    )
    return {fid: _aware(ts) for fid, ts in rows if ts}


def sla_status(db: Session) -> dict:
    """Etat SLA sur les findings ouverts : en retard vs dans les temps."""
    now = _now()
    open_rows = (
        db.query(Finding.id, Finding.severity, Finding.first_seen)
        .filter(Finding.status.in_(OPEN_STATUSES))
        .all()
    )
    overdue = 0
    overdue_by_sev = dict.fromkeys(SEVERITIES, 0)
    soon = 0  # echeance dans moins de 3 jours
    for _id, sev, first in open_rows:
        due = due_date(_aware(first), sev)
        if due is None:
            continue
        if now > due:
            overdue += 1
            overdue_by_sev[sev if sev in overdue_by_sev else "info"] += 1
        elif (due - now) <= timedelta(days=3):
            soon += 1
    return {
        "open_total": len(open_rows),
        "overdue": overdue,
        "overdue_by_severity": overdue_by_sev,
        "due_soon": soon,
        "on_track": len(open_rows) - overdue,
        "policy": SLA_DAYS,
    }


def mttr_stats(db: Session) -> dict:
    """MTTR (temps moyen de remediation) global et par severite, en jours,
    calcule sur les findings effectivement corriges."""
    fixes = _fix_dates(db)
    if not fixes:
        return {"overall": None, "by_severity": {}, "resolved": 0, "compliance_pct": None}

    fixed = (
        db.query(Finding.id, Finding.severity, Finding.first_seen)
        .filter(Finding.id.in_(list(fixes.keys())))
        .all()
    )
    per_sev: dict[str, list[float]] = defaultdict(list)
    all_days: list[float] = []
    within_sla = 0
    counted = 0
    for fid, sev, first in fixed:
        first = _aware(first)
        fix = fixes.get(fid)
        if first is None or fix is None:
            continue
        days = max(0.0, (fix - first).total_seconds() / 86400)
        per_sev[sev].append(days)
        all_days.append(days)
        counted += 1
        if days <= SLA_DAYS.get(sev, 180):
            within_sla += 1

    def avg(xs):
        return round(sum(xs) / len(xs), 1) if xs else None

    return {
        "overall": avg(all_days),
        "by_severity": {s: avg(per_sev[s]) for s in SEVERITIES if per_sev.get(s)},
        "resolved": counted,
        "compliance_pct": round(within_sla / counted * 100) if counted else None,
    }


def remediation_flow(db: Session, days: int = 30) -> list[dict]:
    """Flux quotidien : nombre de findings decouverts vs corriges, sur la
    fenetre. Bucketise en Python pour rester portable SQLite/PostgreSQL."""
    now = _now()
    start = now - timedelta(days=days)

    opened = defaultdict(int)
    for (first,) in db.query(Finding.first_seen).all():
        first = _aware(first)
        if first and first >= start:
            opened[first.strftime("%Y-%m-%d")] += 1

    closed = defaultdict(int)
    for ts in _fix_dates(db).values():
        if ts and ts >= start:
            closed[ts.strftime("%Y-%m-%d")] += 1

    series = []
    for i in range(days + 1):
        d = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        series.append({"date": d, "opened": opened.get(d, 0), "closed": closed.get(d, 0)})
    return series


def risk_overview(db: Session, top: int = 12) -> dict:
    """Distribution du risque (findings ouverts) et top findings par score."""
    rows = (
        db.query(Finding, Asset.name, Asset.criticality)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Finding.status.in_(OPEN_STATUSES))
        .all()
    )
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scored = []
    kev_open = 0
    for f, asset_name, crit in rows:
        s = risk_score(f.severity, f.epss_score, bool(f.kev), crit or "medium")
        bands[risk_band(s)] += 1
        if f.kev:
            kev_open += 1
        scored.append({
            "id": f.id, "asset_id": f.asset_id, "asset_name": asset_name,
            "title": f.title, "severity": f.severity, "cve": f.cve,
            "epss_score": f.epss_score, "kev": bool(f.kev),
            "criticality": crit or "medium",
            "criticality_label": CRITICALITY_LABEL.get(crit or "medium", "Moyenne"),
            "risk": s, "risk_band": risk_band(s),
        })
    scored.sort(key=lambda x: x["risk"], reverse=True)
    return {
        "bands": bands,
        "kev_open": kev_open,
        "top": scored[:top],
        "open_total": len(rows),
    }


def posture_stats(db: Session) -> dict:
    """Agrege l'ensemble pour la page Pilotage."""
    sla = sla_status(db)
    mttr = mttr_stats(db)
    risk = risk_overview(db)
    flow = remediation_flow(db)
    return {
        "totals": {
            "overdue": sla["overdue"],
            "due_soon": sla["due_soon"],
            "mttr": mttr["overall"],
            "sla_compliance": mttr["compliance_pct"],
            "kev_open": risk["kev_open"],
            "open_total": sla["open_total"],
        },
        "sla": sla,
        "mttr": mttr,
        "risk": risk,
        "flow": flow,
    }
