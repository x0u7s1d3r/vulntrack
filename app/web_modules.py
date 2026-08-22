"""Modules du tableau de bord (etape 13+), inspires de Wazuh mais adaptes a
la realite de VulnTrack.

VulnTrack ingere des rapports de scanners (Trivy, Semgrep, Gitleaks) : il n'a
ni agent, ni telemetrie temps reel, ni surveillance d'integrite de fichiers.
Les grands modules de Wazuh sont donc reinterpretes a partir des donnees dont
on dispose reellement (findings, CVE, EPSS, regles SAST, secrets, assets) :

- "Vulnerability Detection"  -> Detection de vulnerabilites (CVE + EPSS, Trivy)
- "Security Config. Assessment (SCA)" -> Analyse de code / SAST (Semgrep)
- "Malware Detection"        -> Secrets & fuites (Gitleaks : les secrets
                                 exposes sont l'equivalent d'IoC dans le code)
- "MITRE ATT&CK"             -> Cartographie des findings vers les tactiques
                                 et techniques ATT&CK (heuristique par mots-cles)
- "System Inventory / IT Hygiene" -> Inventaire des assets, couverture de scan
                                 et score d'hygiene

Toutes les agregations sont pensees pour rester portables SQLite/PostgreSQL et
pour ne renvoyer que du JSON serialisable (le rendu se fait cote client).
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Asset, Finding, Scan
from app.web_stats import (
    EPSS_EXPLOITABLE,
    OPEN_STATUSES,
    SEVERITIES,
    SEVERITY_ORDER,
    worst_severity,
)

# --------------------------------------------------------------------------
# Cartographie MITRE ATT&CK (heuristique)
# --------------------------------------------------------------------------
# VulnTrack n'a pas de donnee ATT&CK native. On classe chaque finding vers une
# tactique et une technique par mots-cles sur son titre / sa regle, avec un
# repli par scanner. C'est une approximation assumee (pas une detection), mais
# elle donne une lecture "offensive" utile : quelles etapes d'une attaque nos
# vulnerabilites ouvrent-elles ?

# Tactiques retenues (celles qu'un scanner de vulnerabilites peut raisonnablement
# eclairer), dans l'ordre de la kill chain ATT&CK Enterprise.
ATTACK_TACTICS = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0040", "name": "Impact"},
]
TACTIC_NAME = {t["id"]: t["name"] for t in ATTACK_TACTICS}

# Regles ordonnees : premier motif trouve (dans titre + rule_id, en minuscules)
# gagne. (mots-cles, tactique, technique_id, technique_name).
_ATTACK_RULES = [
    (("secret", "aws-key", "hardcoded", "credential", "jwt", "password", "api key", "api-key", "token"),
     "TA0006", "T1552", "Unsecured Credentials"),
    (("sql injection", "sqli", "sql-injection"),
     "TA0001", "T1190", "Exploit Public-Facing Application"),
    (("xss", "cross-site scripting", "cross site scripting"),
     "TA0002", "T1059", "Command and Scripting Interpreter"),
    (("ssrf", "server-side request forgery", "request forgery"),
     "TA0007", "T1046", "Network Service Scanning"),
    (("deserialization", "insecure deserialization", "remote code", "arbitrary code", "rce"),
     "TA0002", "T1203", "Exploitation for Client Execution"),
    (("use-after-free", "buffer overflow", "integer overflow", "heap", "out-of-bounds"),
     "TA0004", "T1068", "Exploitation for Privilege Escalation"),
    (("path traversal", "directory traversal", "file handler", "lfi"),
     "TA0007", "T1083", "File and Directory Discovery"),
    (("denial of service", "dos", "resource exhaustion"),
     "TA0040", "T1499", "Endpoint Denial of Service"),
    (("certificate", "improper certificate", "tls", "ssl", "trust"),
     "TA0005", "T1553", "Subvert Trust Controls"),
    (("open-redirect", "open redirect", "redirect"),
     "TA0001", "T1190", "Exploit Public-Facing Application"),
]

# Repli par scanner quand aucun mot-cle ne correspond.
_ATTACK_FALLBACK = {
    "gitleaks": ("TA0006", "T1552", "Unsecured Credentials"),
    "semgrep": ("TA0001", "T1190", "Exploit Public-Facing Application"),
    "trivy": ("TA0001", "T1190", "Exploit Public-Facing Application"),
}
_DEFAULT_ATTACK = ("TA0001", "T1190", "Exploit Public-Facing Application")


def classify_attack(title: str | None, rule_id: str | None, scanner: str | None) -> dict:
    """Associe un finding a (tactique, technique) ATT&CK. Heuristique : jamais
    une detection certifiee, mais une lecture defendable et deterministe."""
    hay = f"{title or ''} {rule_id or ''}".lower()
    for keywords, tactic, tech_id, tech_name in _ATTACK_RULES:
        if any(k in hay for k in keywords):
            return {"tactic": tactic, "tactic_name": TACTIC_NAME[tactic],
                    "technique": tech_id, "technique_name": tech_name}
    tactic, tech_id, tech_name = _ATTACK_FALLBACK.get(scanner or "", _DEFAULT_ATTACK)
    return {"tactic": tactic, "tactic_name": TACTIC_NAME[tactic],
            "technique": tech_id, "technique_name": tech_name}


# --------------------------------------------------------------------------
# Helpers communs
# --------------------------------------------------------------------------

def _sev_counts(rows) -> dict:
    """rows = iterable de (severity, count) -> dict complete par severite."""
    counts = dict.fromkeys(SEVERITIES, 0)
    for sev, n in rows:
        counts[sev if sev in counts else "info"] += n
    return counts


def _open_filter(q):
    return q.filter(Finding.status.in_(OPEN_STATUSES))


# --------------------------------------------------------------------------
# Module 1 : Detection de vulnerabilites (Trivy / CVE / EPSS)
# --------------------------------------------------------------------------

# Tranches de probabilite d'exploitation EPSS (bornes hautes exclusives).
EPSS_BUCKETS = [
    {"key": "critique", "label": "≥ 75 %", "min": 0.75, "max": 1.01},
    {"key": "eleve", "label": "50–75 %", "min": 0.50, "max": 0.75},
    {"key": "moyen", "label": "25–50 %", "min": 0.25, "max": 0.50},
    {"key": "faible", "label": "10–25 %", "min": 0.10, "max": 0.25},
    {"key": "minime", "label": "< 10 %", "min": 0.0, "max": 0.10},
]


def vuln_detection_stats(db: Session) -> dict:
    """Vue centree CVE : findings issus d'un scan de dependances (avec CVE)."""
    base = db.query(Finding).filter(Finding.cve.isnot(None))

    total = base.count()
    open_total = _open_filter(base).count()
    unique_cves = db.query(func.count(func.distinct(Finding.cve))).filter(
        Finding.cve.isnot(None)
    ).scalar() or 0
    exploitable = _open_filter(base).filter(
        Finding.epss_score.isnot(None), Finding.epss_score >= EPSS_EXPLOITABLE
    ).count()
    critical_open = _open_filter(base).filter(Finding.severity == "critical").count()

    by_severity = _sev_counts(
        _open_filter(base)
        .with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )

    # Distribution EPSS (findings ouverts avec CVE).
    epss_rows = _open_filter(base).with_entities(Finding.epss_score).all()
    dist = {b["key"]: 0 for b in EPSS_BUCKETS}
    dist["inconnu"] = 0
    for (score,) in epss_rows:
        if score is None:
            dist["inconnu"] += 1
            continue
        for b in EPSS_BUCKETS:
            if b["min"] <= score < b["max"]:
                dist[b["key"]] += 1
                break
    epss_dist = [
        {"key": b["key"], "label": b["label"], "count": dist[b["key"]]}
        for b in EPSS_BUCKETS
    ] + [{"key": "inconnu", "label": "sans score", "count": dist["inconnu"]}]

    # Composants (paquets) les plus vulnerables, ouverts.
    comp_rows = (
        _open_filter(base)
        .filter(Finding.component.isnot(None))
        .with_entities(Finding.component, func.count(Finding.id))
        .group_by(Finding.component)
        .order_by(func.count(Finding.id).desc())
        .limit(8)
        .all()
    )
    top_components = [{"name": c, "count": n} for c, n in comp_rows]

    # CVE prioritaires : ouvertes, critical/high, triees par EPSS.
    prio_rows = (
        db.query(Finding, Asset.name)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Finding.cve.isnot(None),
            Finding.status.in_(OPEN_STATUSES),
            Finding.severity.in_(["critical", "high"]),
        )
        .order_by(func.coalesce(Finding.epss_score, -1).desc(), Finding.id)
        .limit(12)
        .all()
    )
    priority = [
        {
            "id": f.id, "cve": f.cve, "asset_id": f.asset_id, "asset_name": name,
            "component": f.component, "severity": f.severity,
            "epss_score": f.epss_score, "title": f.title,
        }
        for f, name in prio_rows
    ]

    return {
        "totals": {
            "with_cve": total, "open": open_total, "unique_cves": unique_cves,
            "exploitable": exploitable, "critical_open": critical_open,
        },
        "by_severity": by_severity,
        "epss_dist": epss_dist,
        "top_components": top_components,
        "priority": priority,
    }


# --------------------------------------------------------------------------
# Module 2 : Analyse de code / SCA (Semgrep, SAST)
# --------------------------------------------------------------------------

def _rule_category(rule_id: str | None) -> str:
    """Categorie lisible depuis un identifiant de regle Semgrep
    (ex. python.django.sqli -> python)."""
    if not rule_id:
        return "autre"
    head = rule_id.split(".")[0]
    return head if head else "autre"


def sca_stats(db: Session) -> dict:
    """Vue SAST : findings Semgrep (regles de securite du code)."""
    base = db.query(Finding).filter(Finding.scanner == "semgrep")

    total = base.count()
    open_total = _open_filter(base).count()
    rules_triggered = (
        db.query(func.count(func.distinct(Finding.rule_id)))
        .filter(Finding.scanner == "semgrep", Finding.rule_id.isnot(None))
        .scalar() or 0
    )
    files_affected = (
        db.query(func.count(func.distinct(Finding.file_path)))
        .filter(Finding.scanner == "semgrep", Finding.file_path.isnot(None))
        .scalar() or 0
    )
    high_open = _open_filter(base).filter(
        Finding.severity.in_(["critical", "high"])
    ).count()

    by_severity = _sev_counts(
        _open_filter(base)
        .with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )

    # Regles les plus declenchees.
    rule_rows = (
        _open_filter(base)
        .filter(Finding.rule_id.isnot(None))
        .with_entities(Finding.rule_id, func.count(Finding.id))
        .group_by(Finding.rule_id)
        .order_by(func.count(Finding.id).desc())
        .limit(8)
        .all()
    )
    top_rules = [
        {"rule_id": r, "count": n, "category": _rule_category(r)} for r, n in rule_rows
    ]

    # Fichiers les plus touches.
    file_rows = (
        _open_filter(base)
        .filter(Finding.file_path.isnot(None))
        .with_entities(Finding.file_path, func.count(Finding.id))
        .group_by(Finding.file_path)
        .order_by(func.count(Finding.id).desc())
        .limit(8)
        .all()
    )
    top_files = [{"file_path": fp, "count": n} for fp, n in file_rows]

    # Repartition par categorie de regle (langage / famille).
    cat: dict = {}
    for r, n in (
        _open_filter(base)
        .filter(Finding.rule_id.isnot(None))
        .with_entities(Finding.rule_id, func.count(Finding.id))
        .group_by(Finding.rule_id)
        .all()
    ):
        cat[_rule_category(r)] = cat.get(_rule_category(r), 0) + n
    by_category = [
        {"category": k, "count": v}
        for k, v in sorted(cat.items(), key=lambda x: x[1], reverse=True)
    ]

    return {
        "totals": {
            "total": total, "open": open_total, "rules": rules_triggered,
            "files": files_affected, "high_open": high_open,
        },
        "by_severity": by_severity,
        "top_rules": top_rules,
        "top_files": top_files,
        "by_category": by_category,
    }


# --------------------------------------------------------------------------
# Module 3 : Secrets & fuites (Gitleaks)  [reinterpretation de Malware Detection]
# --------------------------------------------------------------------------

def secrets_stats(db: Session) -> dict:
    """Vue secrets : findings Gitleaks. On ne stocke jamais le secret lui-meme
    (cf. parser) ; on suit son exposition, son asset et sa remediation."""
    base = db.query(Finding).filter(Finding.scanner == "gitleaks")

    total = base.count()
    open_total = _open_filter(base).count()
    remediated = base.filter(Finding.status == "fixed").count()
    repos_affected = (
        _open_filter(base)
        .with_entities(func.count(func.distinct(Finding.asset_id)))
        .scalar() or 0
    )

    by_status = dict(
        base.with_entities(Finding.status, func.count(Finding.id))
        .group_by(Finding.status)
        .all()
    )

    # Secrets ouverts par asset (repository).
    asset_rows = (
        db.query(Asset.id, Asset.name, func.count(Finding.id))
        .join(Finding, Finding.asset_id == Asset.id)
        .filter(Finding.scanner == "gitleaks", Finding.status.in_(OPEN_STATUSES))
        .group_by(Asset.id, Asset.name)
        .order_by(func.count(Finding.id).desc())
        .all()
    )
    by_asset = [{"id": i, "name": nm, "count": n} for i, nm, n in asset_rows]

    # Detail des secrets ouverts (emplacement, jamais la valeur).
    detail_rows = (
        db.query(Finding, Asset.name)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Finding.scanner == "gitleaks", Finding.status.in_(OPEN_STATUSES))
        .order_by(Finding.last_seen.desc())
        .limit(20)
        .all()
    )
    items = [
        {
            "id": f.id, "asset_id": f.asset_id, "asset_name": name,
            "title": f.title, "rule_id": f.rule_id,
            "file_path": f.file_path, "line_number": f.line_number,
            "status": f.status,
            "last_seen": f.last_seen.strftime("%Y-%m-%d") if f.last_seen else None,
        }
        for f, name in detail_rows
    ]

    return {
        "totals": {
            "total": total, "open": open_total, "remediated": remediated,
            "repos": repos_affected,
        },
        "by_status": by_status,
        "by_asset": by_asset,
        "items": items,
    }


# --------------------------------------------------------------------------
# Module 4 : MITRE ATT&CK
# --------------------------------------------------------------------------

def attack_matrix(db: Session) -> dict:
    """Cartographie des findings ouverts vers les tactiques/techniques ATT&CK."""
    rows = (
        _open_filter(db.query(Finding))
        .with_entities(
            Finding.title, Finding.rule_id, Finding.scanner, Finding.severity
        )
        .all()
    )

    # Agrege par tactique puis par technique.
    tactics: dict = {
        t["id"]: {
            "id": t["id"], "name": t["name"], "count": 0,
            "worst": None, "techniques": {},
        }
        for t in ATTACK_TACTICS
    }
    total_mapped = 0
    for title, rule_id, scanner, severity in rows:
        m = classify_attack(title, rule_id, scanner)
        t = tactics[m["tactic"]]
        t["count"] += 1
        total_mapped += 1
        if t["worst"] is None or SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(t["worst"], 9):
            t["worst"] = severity
        tk = t["techniques"].setdefault(
            m["technique"], {"id": m["technique"], "name": m["technique_name"],
                             "count": 0, "worst": None}
        )
        tk["count"] += 1
        if tk["worst"] is None or SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(tk["worst"], 9):
            tk["worst"] = severity

    # Serialise (techniques triees par nombre), tactiques dans l'ordre canonique.
    out_tactics = []
    for t in ATTACK_TACTICS:
        node = tactics[t["id"]]
        techs = sorted(node["techniques"].values(), key=lambda x: x["count"], reverse=True)
        out_tactics.append({
            "id": node["id"], "name": node["name"], "count": node["count"],
            "worst": node["worst"], "techniques": techs,
        })

    covered = sum(1 for t in out_tactics if t["count"] > 0)
    all_techs = {tk["id"] for t in out_tactics for tk in t["techniques"]}
    top = max(out_tactics, key=lambda x: x["count"])
    top_tactic = top["name"] if top["count"] else "—"

    return {
        "totals": {
            "mapped": total_mapped, "tactics_covered": covered,
            "techniques": len(all_techs), "top_tactic": top_tactic,
        },
        "tactics": out_tactics,
    }


# --------------------------------------------------------------------------
# Module 5 : Inventaire systeme / hygiene IT
# --------------------------------------------------------------------------

ALL_SCANNERS = ["trivy", "semgrep", "gitleaks"]


def inventory_stats(db: Session) -> dict:
    """Inventaire des assets : couverture de scan, findings ouverts, hygiene."""
    assets = db.query(Asset).order_by(Asset.name).all()

    # Findings ouverts groupes par (asset, severite).
    open_rows = (
        _open_filter(db.query(Finding))
        .with_entities(Finding.asset_id, Finding.severity, func.count(Finding.id))
        .group_by(Finding.asset_id, Finding.severity)
        .all()
    )
    per_asset_sev: dict = {}
    for aid, sev, n in open_rows:
        per_asset_sev.setdefault(aid, dict.fromkeys(SEVERITIES, 0))
        per_asset_sev[aid][sev if sev in SEVERITIES else "info"] += n

    # Scanners ayant produit au moins un finding par asset (couverture).
    cov_rows = (
        db.query(Finding.asset_id, Finding.scanner)
        .distinct()
        .all()
    )
    coverage: dict = {}
    for aid, sc in cov_rows:
        coverage.setdefault(aid, set()).add(sc)

    # Dernier scan par asset.
    last_scan_rows = (
        db.query(Scan.asset_id, func.max(Scan.started_at))
        .group_by(Scan.asset_id)
        .all()
    )
    last_scan = {aid: ts for aid, ts in last_scan_rows}

    items = []
    types: dict = {}
    stale = 0
    with_critical = 0
    for a in assets:
        sev = per_asset_sev.get(a.id, dict.fromkeys(SEVERITIES, 0))
        open_total = sum(sev.values())
        cov = coverage.get(a.id, set())
        cov_list = [{"scanner": s, "present": s in cov} for s in ALL_SCANNERS]
        cov_count = sum(1 for s in ALL_SCANNERS if s in cov)
        ls = last_scan.get(a.id)
        types[a.type] = types.get(a.type, 0) + 1
        if sev["critical"] > 0:
            with_critical += 1

        # Score d'hygiene (0-100) : part de couverture de scan, penalisee par
        # les vulnerabilites ouvertes ponderees par gravite. Purement indicatif.
        weight = sev["critical"] * 12 + sev["high"] * 5 + sev["medium"] * 2 + sev["low"] * 1
        coverage_score = cov_count / len(ALL_SCANNERS) * 100
        hygiene = max(0, round(coverage_score - min(coverage_score, weight)))
        if cov_count < len(ALL_SCANNERS):
            stale += 1  # couverture incomplete = angle mort

        items.append({
            "id": a.id, "name": a.name, "type": a.type,
            "open": open_total,
            "critical": sev["critical"], "high": sev["high"],
            "worst": worst_severity(sev),
            "coverage": cov_list, "coverage_count": cov_count,
            "hygiene": hygiene,
            "last_scan": ls.strftime("%Y-%m-%d %H:%M") if ls else None,
        })

    # Classe par risque (critiques puis hautes puis total ouvert).
    items.sort(key=lambda x: (x["critical"], x["high"], x["open"]), reverse=True)

    return {
        "totals": {
            "assets": len(assets),
            "with_critical": with_critical,
            "incomplete_coverage": stale,
            "types": types,
        },
        "items": items,
        "scanners": ALL_SCANNERS,
    }
