"""Agregations pour le tableau de bord web (etape 13).

Calcule les indicateurs affiches par le frontend : compteurs globaux,
repartition par severite et par statut, et statistiques par asset. Les
segments de barre de severite sont pre-calcules ici (largeurs en pourcentage)
pour que le gabarit n'ait qu'a poser des <rect> SVG - CSP stricte oblige,
aucune largeur en style inline.
"""

from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from app.models import Asset, Finding, Scan
from app.risk import risk_band, risk_score, risk_score_sql
from app.sla import is_overdue

# Du plus grave au moins grave. Ordre d'affichage et de tri partout.
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {sev: i for i, sev in enumerate(SEVERITIES)}

# Statuts consideres comme "actifs" (a traiter), par opposition a fixed /
# accepted / false_positive.
OPEN_STATUSES = ["open", "in_progress"]

# Seuil EPSS a partir duquel une vulnerabilite est jugee "exploitable" :
# probabilite d'exploitation reelle >= 50 % dans les 30 jours (FIRST.org).
EPSS_EXPLOITABLE = 0.5


def _severity_segments(counts: dict) -> list[dict]:
    """Transforme un dict {severite: nombre} en segments de barre empilee.

    Chaque segment porte sa largeur en pourcentage du total et son decalage
    cumule, prets a devenir des <rect x=.. width=..> dans un viewBox 0..100.
    """
    total = sum(counts.values())
    segments = []
    if total == 0:
        return segments

    offset = 0.0
    for sev in SEVERITIES:
        n = counts.get(sev, 0)
        if not n:
            continue
        width = round(n / total * 100, 3)
        segments.append(
            {"severity": sev, "count": n, "width": width, "offset": round(offset, 3)}
        )
        offset += width
    return segments


def dashboard_stats(db: Session) -> dict:
    """Indicateurs de la page d'accueil du tableau de bord."""
    total_assets = db.query(func.count(Asset.id)).scalar() or 0

    # Une seule requete groupee : (asset_id, severite, statut) -> nombre.
    rows = (
        db.query(
            Finding.asset_id,
            Finding.severity,
            Finding.status,
            func.count(Finding.id),
        )
        .group_by(Finding.asset_id, Finding.severity, Finding.status)
        .all()
    )

    by_severity = dict.fromkeys(SEVERITIES, 0)
    by_status: dict = {}
    open_by_severity = dict.fromkeys(SEVERITIES, 0)
    per_asset: dict = {}
    total_findings = 0
    total_open = 0

    for asset_id, severity, statusv, count in rows:
        severity = severity if severity in by_severity else "info"
        by_severity[severity] += count
        by_status[statusv] = by_status.get(statusv, 0) + count
        total_findings += count

        a = per_asset.setdefault(
            asset_id, {"total": 0, "open": 0, "by_severity": dict.fromkeys(SEVERITIES, 0)}
        )
        a["total"] += count
        a["by_severity"][severity] += count

        if statusv in OPEN_STATUSES:
            total_open += count
            open_by_severity[severity] += count
            a["open"] += count

    return {
        "total_assets": total_assets,
        "total_findings": total_findings,
        "total_open": total_open,
        "critical_open": open_by_severity["critical"],
        "high_open": open_by_severity["high"],
        "by_severity": by_severity,
        "open_by_severity": open_by_severity,
        "by_status": by_status,
        "severity_segments": _severity_segments(open_by_severity),
        "per_asset": per_asset,
    }


def asset_stats(findings: list) -> dict:
    """Repartition par severite pour un asset, a partir de ses findings."""
    counts = dict.fromkeys(SEVERITIES, 0)
    open_counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        sev = f.severity if f.severity in counts else "info"
        counts[sev] += 1
        if f.status in OPEN_STATUSES:
            open_counts[sev] += 1
    return {
        "by_severity": counts,
        "open_by_severity": open_counts,
        "severity_segments": _severity_segments(counts),
        "total": len(findings),
        "open": sum(open_counts.values()),
    }


def worst_severity(by_severity: dict) -> str | None:
    """Severite la plus grave presente (pour le badge d'un asset)."""
    for sev in SEVERITIES:
        if by_severity.get(sev):
            return sev
    return None


def extra_totals(db: Session) -> dict:
    """Compteurs qui necessitent l'EPSS ou le statut, hors requete groupee."""
    exploitable = (
        db.query(func.count(Finding.id))
        .filter(
            Finding.status.in_(OPEN_STATUSES),
            Finding.epss_score.isnot(None),
            Finding.epss_score >= EPSS_EXPLOITABLE,
        )
        .scalar()
        or 0
    )
    fixed = (
        db.query(func.count(Finding.id)).filter(Finding.status == "fixed").scalar() or 0
    )
    kev_open = (
        db.query(func.count(Finding.id))
        .filter(Finding.status.in_(OPEN_STATUSES), Finding.kev.is_(True))
        .scalar()
        or 0
    )
    # En retard (SLA depasse) : calcul en Python sur les findings ouverts.
    open_rows = (
        db.query(Finding.severity, Finding.first_seen, Finding.status)
        .filter(Finding.status.in_(OPEN_STATUSES))
        .all()
    )
    overdue = sum(1 for sev, first, st in open_rows if is_overdue(first, sev, st))
    return {
        "exploitable_open": exploitable,
        "fixed": fixed,
        "kev_open": kev_open,
        "overdue_open": overdue,
    }


def scanner_breakdown(db: Session) -> dict:
    """Nombre de findings ouverts par scanner (Trivy / Semgrep / Gitleaks)."""
    rows = (
        db.query(Finding.scanner, func.count(Finding.id))
        .filter(Finding.status.in_(OPEN_STATUSES))
        .group_by(Finding.scanner)
        .all()
    )
    return {scanner: count for scanner, count in rows}


def timeline(db: Session, limit: int = 30) -> list[dict]:
    """Nombre de findings decouverts par jour (d'apres first_seen).

    func.date() est portable SQLite/PostgreSQL ; la valeur retournee est
    normalisee en chaine YYYY-MM-DD cote Python.
    """
    rows = (
        db.query(func.date(Finding.first_seen), func.count(Finding.id))
        .group_by(func.date(Finding.first_seen))
        .order_by(func.date(Finding.first_seen))
        .all()
    )
    series = [{"date": str(day)[:10], "count": count} for day, count in rows if day]
    return series[-limit:]


def timeline_by_severity(db: Session, limit: int = 24) -> list[dict]:
    """Decouvertes par jour, ventilees par severite (histogramme empile)."""
    rows = (
        db.query(func.date(Finding.first_seen), Finding.severity, func.count(Finding.id))
        .group_by(func.date(Finding.first_seen), Finding.severity)
        .all()
    )
    days: dict = {}
    for day, sev, n in rows:
        if not day:
            continue
        key = str(day)[:10]
        e = days.setdefault(key, {"date": key, **dict.fromkeys(SEVERITIES, 0)})
        e[sev if sev in SEVERITIES else "info"] += n
    return [days[k] for k in sorted(days)][-limit:]


def top_assets_ranked(per_asset: dict, assets_by_id: dict, limit: int = 6) -> list[dict]:
    """Assets classes par risque : les critiques pesent plus que les hautes,
    etc. (score ponderee, sur les findings ouverts)."""
    weights = {"critical": 1000, "high": 100, "medium": 10, "low": 1, "info": 0}
    ranked = []
    for asset_id, a in per_asset.items():
        asset = assets_by_id.get(asset_id)
        if not asset:
            continue
        score = sum(weights[s] * a["by_severity"].get(s, 0) for s in SEVERITIES)
        if score == 0:
            continue
        ranked.append(
            {
                "id": asset_id,
                "name": asset.name,
                "open": a["open"],
                "total": a["total"],
                "critical": a["by_severity"].get("critical", 0),
                "high": a["by_severity"].get("high", 0),
                "worst": worst_severity(a["by_severity"]),
                "_score": score,
            }
        )
    ranked.sort(key=lambda x: x["_score"], reverse=True)
    for r in ranked:
        del r["_score"]
    return ranked[:limit]


def prioritized_findings(db: Session, limit: int = 8) -> list[dict]:
    """Le panneau clef d'un analyste : les vulnerabilites ouvertes les plus
    graves ET les plus exploitables (severite critical/high, triees par EPSS
    decroissant). coalesce pour un tri portable des EPSS absents."""
    rows = (
        db.query(Finding, Asset.name)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Finding.status.in_(OPEN_STATUSES),
            Finding.severity.in_(["critical", "high"]),
        )
        .order_by(func.coalesce(Finding.epss_score, -1).desc(), Finding.id)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": f.id,
            "asset_id": f.asset_id,
            "asset_name": asset_name,
            "title": f.title,
            "severity": f.severity,
            "cve": f.cve,
            "epss_score": f.epss_score,
            "status": f.status,
        }
        for f, asset_name in rows
    ]


def top_cves(db: Session, limit: int = 8) -> list[dict]:
    """CVE les plus frequentes (tous assets confondus), avec leur pire
    severite observee."""
    rows = (
        db.query(Finding.cve, Finding.severity, func.count(Finding.id))
        .filter(Finding.cve.isnot(None))
        .group_by(Finding.cve, Finding.severity)
        .all()
    )
    agg: dict = {}
    for cve, severity, count in rows:
        e = agg.setdefault(cve, {"cve": cve, "count": 0, "worst": "info"})
        e["count"] += count
        if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(e["worst"], 9):
            e["worst"] = severity
    ordered = sorted(agg.values(), key=lambda x: x["count"], reverse=True)
    return ordered[:limit]


def recent_scans(db: Session, limit: int = 6) -> list[dict]:
    """Derniers scans ingeres, pour un fil d'activite."""
    rows = (
        db.query(Scan, Asset.name)
        .join(Asset, Scan.asset_id == Asset.id)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": scan.id,
            "asset_id": scan.asset_id,
            "asset_name": asset_name,
            "scanner": scan.scanner,
            "status": scan.status,
            "findings_count": scan.findings_count,
            "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else None,
        }
        for scan, asset_name in rows
    ]


# ------------------------------------------------------------- explorateur global

SORT_COLUMNS = {"severity", "epss", "risk", "last_seen", "title", "status"}


def _severity_sort_expr():
    """Expression SQL pour trier par gravite (critical d'abord)."""
    return case(
        *[(Finding.severity == s, i) for i, s in enumerate(SEVERITIES)],
        else_=len(SEVERITIES),
    )


def build_findings_query(db: Session, f: dict):
    """Requete de base sur les findings, filtres appliques (sans tri ni
    pagination). Reutilisee pour le comptage, la page et l'export."""
    q = db.query(Finding)
    if f.get("severity"):
        q = q.filter(Finding.severity.in_(f["severity"]))
    if f.get("status"):
        q = q.filter(Finding.status.in_(f["status"]))
    if f.get("scanner"):
        q = q.filter(Finding.scanner.in_(f["scanner"]))
    if f.get("asset_id"):
        q = q.filter(Finding.asset_id == f["asset_id"])
    if f.get("has_cve"):
        q = q.filter(Finding.cve.isnot(None))
    if f.get("kev"):
        q = q.filter(Finding.kev.is_(True))
    if f.get("min_epss") is not None:
        q = q.filter(Finding.epss_score.isnot(None), Finding.epss_score >= f["min_epss"])
    if f.get("q"):
        like = f"%{f['q']}%"
        q = q.filter(
            or_(
                Finding.title.ilike(like),
                Finding.cve.ilike(like),
                Finding.rule_id.ilike(like),
                Finding.file_path.ilike(like),
                Finding.component.ilike(like),
            )
        )
    return q


def _sorted(query, sort: str, order: str):
    direction = (lambda c: c.desc()) if order == "desc" else (lambda c: c.asc())
    if sort == "severity":
        col = _severity_sort_expr()
    elif sort == "epss":
        col = func.coalesce(Finding.epss_score, -1)
    elif sort == "risk":
        # Le score de risque depend de la criticite de l'asset : jointure.
        query = query.join(Asset, Finding.asset_id == Asset.id)
        col = risk_score_sql()
    elif sort == "last_seen":
        col = Finding.last_seen
    elif sort == "status":
        col = Finding.status
    else:
        col = Finding.title
    return query.order_by(direction(col), Finding.id.desc())


def finding_row(f: Finding, asset_name: str | None = None,
                criticality: str = "medium") -> dict:
    kev = bool(getattr(f, "kev", False))
    score = risk_score(f.severity, f.epss_score, kev, criticality)
    return {
        "id": f.id,
        "asset_id": f.asset_id,
        "asset_name": asset_name,
        "scanner": f.scanner,
        "severity": f.severity,
        "title": f.title,
        "cve": f.cve,
        "component": f.component,
        "rule_id": f.rule_id,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "epss_score": f.epss_score,
        "kev": kev,
        "risk": score,
        "risk_band": risk_band(score),
        "overdue": is_overdue(f.first_seen, f.severity, f.status),
        "status": f.status,
        "first_seen": f.first_seen.strftime("%Y-%m-%d") if f.first_seen else None,
        "last_seen": f.last_seen.strftime("%Y-%m-%d") if f.last_seen else None,
        "updated_at": f.updated_at.strftime("%Y-%m-%d %H:%M") if f.updated_at else None,
    }


def search_findings(db: Session, f: dict, sort: str, order: str, page: int, page_size: int) -> dict:
    """Recherche paginee + facettes (comptes par severite et statut sur
    l'ensemble filtre, pour alimenter les compteurs des filtres)."""
    base = build_findings_query(db, f)
    total = base.order_by(None).count()

    by_severity = dict(
        base.order_by(None)
        .with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )
    by_status = dict(
        base.order_by(None)
        .with_entities(Finding.status, func.count(Finding.id))
        .group_by(Finding.status)
        .all()
    )

    rows = _sorted(base, sort, order).offset((page - 1) * page_size).limit(page_size).all()
    assets = {a.id: a for a in db.query(Asset).all()}
    items = [
        finding_row(
            r,
            assets[r.asset_id].name if r.asset_id in assets else None,
            assets[r.asset_id].criticality if r.asset_id in assets else "medium",
        )
        for r in rows
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "facets": {"severity": by_severity, "status": by_status},
    }
