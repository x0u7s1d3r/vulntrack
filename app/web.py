"""Frontend web (etape 13) : tableau de bord de consultation.

Interface en lecture seule, dynamique cote client : les pages sont des
coquilles HTML qui recuperent leurs donnees en JSON (endpoints /ui/api/*) et
se mettent a jour sans rechargement. Aucune action de mutation, ce qui reduit
la surface CSRF au strict minimum (seul POST : la connexion).

Choix de conception et de securite :
- Authentification par cookie de session HttpOnly contenant le JWT : le
  JavaScript ne peut pas lire le jeton (anti-vol XSS). Cookie limite au
  chemin /ui, jamais envoye aux endpoints d'API metier.
- Les pages (coquilles) redirigent vers /ui/login si la session manque ; les
  endpoints JSON renvoient 401 (le JS redirige alors lui-meme), pour ne pas
  servir du HTML de login la ou du JSON est attendu.
- Les donnees renvoyees en JSON sont serialisees cote serveur ; le rendu
  cote client construit le DOM via textContent (jamais innerHTML avec des
  donnees), donc pas d'injection possible depuis un titre de finding.
- CSP stricte inchangee (default-src 'self') : CSS et JS servis en fichiers
  statiques same-origin, aucun inline. Les graphiques sont du SVG construit
  par attributs.
"""

import csv
import hmac
import io
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import create_access_token, decode_access_token, verify_password
from app.cache import invalidate
from app.config import get_settings
from app.database import get_db
from app.risk import CRITICALITIES, risk_score
from app.web_modules import (
    attack_matrix,
    inventory_stats,
    sca_stats,
    secrets_stats,
    vuln_detection_stats,
)
from app.web_posture import posture_stats
from app.web_stats import (
    SEVERITY_ORDER,
    SORT_COLUMNS,
    asset_stats,
    build_findings_query,
    dashboard_stats,
    extra_totals,
    finding_row,
    prioritized_findings,
    recent_scans,
    scanner_breakdown,
    search_findings,
    timeline,
    timeline_by_severity,
    top_assets_ranked,
    top_cves,
    worst_severity,
)

VALID_STATUSES = [s.value for s in schemas.FindingStatus]

logger = logging.getLogger(__name__)

SESSION_COOKIE = "vulntrack_session"
CSRF_COOKIE = "vulntrack_csrf"
CSRF_HEADER = "X-CSRF-Token"
# Roles autorises a modifier (triage) : le viewer reste en lecture seule.
WRITE_ROLES = {"admin", "analyst"}

_BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))

router = APIRouter(prefix="/ui", tags=["web"], include_in_schema=False)


class RedirectToLogin(Exception):
    """Levee quand une PAGE protegee est demandee sans session valide.
    Interceptee par un handler qui renvoie une redirection vers /ui/login."""


def _cookie_secure() -> bool:
    # En developpement l'UI tourne en HTTP : un cookie Secure ne serait jamais
    # renvoye et casserait la session. En production (HTTPS), on l'active.
    return get_settings().environment != "development"


def _user_from_cookie(request: Request, db: Session) -> models.User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
    except Exception:
        return None
    user = db.query(models.User).filter_by(username=payload.get("sub")).first()
    if not user or not user.is_active:
        return None
    return user


def current_web_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    """Pour les PAGES : redirige vers /ui/login si pas de session valide."""
    user = _user_from_cookie(request, db)
    if user is None:
        raise RedirectToLogin()
    return user


def current_api_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    """Pour les endpoints JSON : renvoie 401 si pas de session valide, pour
    que le fetch cote client sache rediriger plutot que de parser du HTML."""
    user = _user_from_cookie(request, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session requise")
    return user


def require_action_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    """Pour les endpoints de MUTATION (triage). Verifie, dans l'ordre :
    session valide (401), jeton CSRF valide (403), role suffisant (403)."""
    user = _user_from_cookie(request, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session requise")

    header = request.headers.get(CSRF_HEADER, "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not header or not cookie or not hmac.compare_digest(header, cookie):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Jeton CSRF invalide")

    if user.role not in WRITE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Votre rôle ne permet pas cette action",
        )
    return user


# ------------------------------------------------------------- authentification


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    # Deja connecte : filer directement au tableau de bord.
    if _user_from_cookie(request, db) is not None:
        return RedirectResponse(url="/ui", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter_by(username=username).first()
    if not user or not user.is_active or not verify_password(password, user.hashed_password):
        # Message volontairement generique : ne pas reveler si le compte existe.
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Identifiants invalides."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    token = create_access_token(subject=user.username, role=user.role)
    max_age = get_settings().jwt_expire_minutes * 60
    response = RedirectResponse(url="/ui", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE, value=token, httponly=True, secure=_cookie_secure(),
        samesite="lax", max_age=max_age, path="/ui",
    )
    # Jeton CSRF (double-submit) : lisible par le JS (httponly=False) pour
    # etre renvoye en en-tete X-CSRF-Token. Un site tiers ne peut ni lire ce
    # cookie ni forger l'en-tete ; combine a SameSite=Lax, cela bloque le CSRF.
    response.set_cookie(
        key=CSRF_COOKIE, value=secrets.token_urlsafe(32), httponly=False,
        secure=_cookie_secure(), samesite="lax", max_age=max_age, path="/ui",
    )
    logger.info("Connexion web reussie: %s", user.username)
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE, path="/ui")
    response.delete_cookie(CSRF_COOKIE, path="/ui")
    return response


# ------------------------------------------------------------- pages (coquilles)


def _page_ctx(user: models.User, **extra) -> dict:
    # can_write : expose au front si l'utilisateur peut trier (agir) ou non,
    # pour n'afficher les boutons d'action qu'aux roles autorises.
    ctx = {"user": user, "can_write": user.role in WRITE_ROLES, "active": None}
    ctx.update(extra)
    return ctx


@router.get("", response_class=HTMLResponse)
def dashboard_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(request, "dashboard.html", _page_ctx(user, active="dashboard"))


@router.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(request, "findings.html", _page_ctx(user, active="findings"))


@router.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(
        request, "vulnerabilities.html", _page_ctx(user, active="vulnerabilities")
    )


@router.get("/sca", response_class=HTMLResponse)
def sca_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(request, "sca.html", _page_ctx(user, active="sca"))


@router.get("/secrets", response_class=HTMLResponse)
def secrets_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(request, "secrets.html", _page_ctx(user, active="secrets"))


@router.get("/attack", response_class=HTMLResponse)
def attack_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(request, "attack.html", _page_ctx(user, active="attack"))


@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(
        request, "inventory.html", _page_ctx(user, active="inventory")
    )


@router.get("/posture", response_class=HTMLResponse)
def posture_page(request: Request, user: models.User = Depends(current_web_user)):
    return templates.TemplateResponse(
        request, "posture.html", _page_ctx(user, active="posture")
    )


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_page(
    request: Request,
    asset_id: int,
    user: models.User = Depends(current_web_user),
    db: Session = Depends(get_db),
):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        return templates.TemplateResponse(
            request, "not_found.html", _page_ctx(user), status_code=status.HTTP_404_NOT_FOUND
        )
    return templates.TemplateResponse(
        request, "asset.html", _page_ctx(user, active="assets", asset=asset)
    )


# ------------------------------------------------------------- donnees (JSON)


@router.get("/api/overview")
def api_overview(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    stats = dashboard_stats(db)
    assets = db.query(models.Asset).order_by(models.Asset.name).all()
    assets_by_id = {a.id: a for a in assets}
    extras = extra_totals(db)

    assets_out = []
    for asset in assets:
        a = stats["per_asset"].get(
            asset.id, {"total": 0, "open": 0, "by_severity": {}}
        )
        assets_out.append(
            {
                "id": asset.id,
                "name": asset.name,
                "type": asset.type,
                "created_at": asset.created_at.strftime("%Y-%m-%d") if asset.created_at else None,
                "total": a["total"],
                "open": a["open"],
                "worst": worst_severity(a["by_severity"]),
            }
        )

    return {
        "totals": {
            "assets": stats["total_assets"],
            "findings": stats["total_findings"],
            "open": stats["total_open"],
            "critical_open": stats["critical_open"],
            "high_open": stats["high_open"],
            "exploitable_open": extras["exploitable_open"],
            "fixed": extras["fixed"],
            "kev_open": extras["kev_open"],
            "overdue_open": extras["overdue_open"],
        },
        "open_by_severity": stats["open_by_severity"],
        "by_status": stats["by_status"],
        "severity_segments": stats["severity_segments"],
        "by_scanner": scanner_breakdown(db),
        "timeline": timeline(db),
        "timeline_sev": timeline_by_severity(db),
        "top_assets": top_assets_ranked(stats["per_asset"], assets_by_id),
        "prioritize": prioritized_findings(db),
        "top_cves": top_cves(db),
        "recent_scans": recent_scans(db),
        "assets": assets_out,
    }


@router.get("/api/vulnerabilities")
def api_vulnerabilities(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    return vuln_detection_stats(db)


@router.get("/api/sca")
def api_sca(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    return sca_stats(db)


@router.get("/api/secrets")
def api_secrets(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    return secrets_stats(db)


@router.get("/api/attack")
def api_attack(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    return attack_matrix(db)


@router.get("/api/inventory")
def api_inventory(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    return inventory_stats(db)


@router.get("/api/posture")
def api_posture(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    return posture_stats(db)


@router.get("/api/report.pdf")
def api_report_pdf(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    """Rapport executif de posture au format PDF (synthese pour comite)."""
    from app.reporting import build_report_pdf

    pdf = build_report_pdf(db)
    headers = {"Content-Disposition": 'attachment; filename="vulntrack-rapport-posture.pdf"'}
    return StreamingResponse(iter([pdf]), media_type="application/pdf", headers=headers)


@router.patch("/api/assets/{asset_id}/criticality")
def api_set_criticality(
    asset_id: int,
    payload: schemas.CriticalityChange,
    user: models.User = Depends(require_action_user),
    db: Session = Depends(get_db),
):
    """Definit la criticite metier d'un asset (contexte RBVM). Reserve aux
    roles d'ecriture ; le score de risque de ses findings s'ajuste."""
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    crit = payload.criticality.value
    if crit not in CRITICALITIES:
        raise HTTPException(status_code=422, detail="Criticité invalide")
    asset.criticality = crit
    db.commit()
    logger.info("Criticite de l'asset %s definie a '%s' par %s",
                asset_id, crit, user.username)
    return {"ok": True, "criticality": asset.criticality}


@router.get("/api/assets/{asset_id}")
def api_asset(
    asset_id: int,
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")

    findings = db.query(models.Finding).filter_by(asset_id=asset_id).all()
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id))
    stats = asset_stats(findings)

    return {
        "asset": {
            "id": asset.id,
            "name": asset.name,
            "type": asset.type,
            "criticality": asset.criticality,
            "created_at": asset.created_at.strftime("%Y-%m-%d") if asset.created_at else None,
        },
        "stats": {
            "total": stats["total"],
            "open": stats["open"],
            "by_severity": stats["by_severity"],
            "severity_segments": stats["severity_segments"],
        },
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "cve": f.cve,
                "component": f.component,
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "epss_score": f.epss_score,
                "status": f.status,
                "last_seen": f.last_seen.strftime("%Y-%m-%d") if f.last_seen else None,
            }
            for f in findings
        ],
    }


# ------------------------------------------------------------- explorateur & triage


def _finding_filters(severity, status_, scanner, asset_id, q, has_cve, min_epss, kev=False) -> dict:
    return {
        "severity": severity or None,
        "status": status_ or None,
        "scanner": scanner or None,
        "asset_id": asset_id,
        "q": q.strip() if q else None,
        "has_cve": has_cve,
        "min_epss": min_epss,
        "kev": kev,
    }


@router.get("/api/assets")
def api_assets_list(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    """Liste legere des assets, pour alimenter le filtre de l'explorateur."""
    assets = db.query(models.Asset).order_by(models.Asset.name).all()
    scanners = [
        r[0]
        for r in db.query(models.Finding.scanner).distinct().order_by(models.Finding.scanner)
    ]
    return {
        "assets": [{"id": a.id, "name": a.name} for a in assets],
        "scanners": scanners,
        "statuses": VALID_STATUSES,
    }


@router.get("/api/findings")
def api_findings(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
    severity: list[str] | None = Query(None),
    status_: list[str] | None = Query(None, alias="status"),
    scanner: list[str] | None = Query(None),
    asset_id: int | None = Query(None),
    q: str | None = Query(None),
    has_cve: bool = Query(False),
    kev: bool = Query(False),
    min_epss: float | None = Query(None, ge=0, le=1),
    sort: str = Query("severity"),
    order: str = Query("asc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    if sort not in SORT_COLUMNS:
        sort = "severity"
    if order not in ("asc", "desc"):
        order = "asc"
    f = _finding_filters(severity, status_, scanner, asset_id, q, has_cve, min_epss, kev)
    result = search_findings(db, f, sort, order, page, page_size)
    result["can_write"] = user.role in WRITE_ROLES
    return result


@router.get("/api/findings/{finding_id}")
def api_finding_detail(
    finding_id: int,
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
):
    f = db.get(models.Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding introuvable")
    asset = db.get(models.Asset, f.asset_id)
    notes = (
        db.query(models.FindingNote)
        .filter_by(finding_id=finding_id)
        .order_by(models.FindingNote.created_at.desc())
        .all()
    )
    row = finding_row(
        f, asset.name if asset else None,
        asset.criticality if asset else "medium",
    )
    row["description"] = f.description
    row["criticality"] = asset.criticality if asset else "medium"
    return {
        "finding": row,
        "statuses": VALID_STATUSES,
        "can_write": user.role in WRITE_ROLES,
        "notes": [
            {
                "author": n.author,
                "kind": n.kind,
                "body": n.body,
                "old_status": n.old_status,
                "new_status": n.new_status,
                "created_at": n.created_at.strftime("%Y-%m-%d %H:%M") if n.created_at else None,
            }
            for n in notes
        ],
    }


def _apply_status_change(db, finding, new_status, author, note_text):
    """Change le statut (si different) et journalise la transition. Si le
    statut ne change pas mais qu'une note est fournie, l'enregistre en
    commentaire."""
    old = finding.status
    now = datetime.now(timezone.utc)
    if new_status != old:
        finding.status = new_status
        finding.updated_at = now
        db.add(
            models.FindingNote(
                finding_id=finding.id, author=author, kind="status_change",
                old_status=old, new_status=new_status, body=(note_text or None),
            )
        )
    elif note_text:
        finding.updated_at = now
        db.add(
            models.FindingNote(
                finding_id=finding.id, author=author, kind="comment", body=note_text
            )
        )


@router.patch("/api/findings/{finding_id}")
def api_change_status(
    finding_id: int,
    payload: schemas.StatusChange,
    user: models.User = Depends(require_action_user),
    db: Session = Depends(get_db),
):
    f = db.get(models.Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding introuvable")
    _apply_status_change(db, f, payload.status.value, user.username, payload.note)
    db.commit()
    invalidate(f"findings:asset:{f.asset_id}")
    logger.info("Triage: %s a mis le finding %s a '%s'", user.username, finding_id, payload.status.value)
    return {"ok": True, "status": f.status}


@router.post("/api/findings/{finding_id}/notes", status_code=201)
def api_add_note(
    finding_id: int,
    payload: schemas.NoteCreate,
    user: models.User = Depends(require_action_user),
    db: Session = Depends(get_db),
):
    f = db.get(models.Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding introuvable")
    f.updated_at = datetime.now(timezone.utc)
    db.add(
        models.FindingNote(
            finding_id=finding_id, author=user.username, kind="comment", body=payload.body
        )
    )
    db.commit()
    return {"ok": True}


@router.post("/api/findings/bulk")
def api_bulk_status(
    payload: schemas.BulkStatusChange,
    user: models.User = Depends(require_action_user),
    db: Session = Depends(get_db),
):
    findings = db.query(models.Finding).filter(models.Finding.id.in_(payload.ids)).all()
    for f in findings:
        _apply_status_change(db, f, payload.status.value, user.username, payload.note)
    db.commit()
    for aid in {f.asset_id for f in findings}:
        invalidate(f"findings:asset:{aid}")
    logger.info("Triage en masse: %s a mis %s findings a '%s'", user.username, len(findings), payload.status.value)
    return {"ok": True, "changed": len(findings)}


@router.get("/api/export.csv")
def api_export_csv(
    user: models.User = Depends(current_api_user),
    db: Session = Depends(get_db),
    severity: list[str] | None = Query(None),
    status_: list[str] | None = Query(None, alias="status"),
    scanner: list[str] | None = Query(None),
    asset_id: int | None = Query(None),
    q: str | None = Query(None),
    has_cve: bool = Query(False),
    kev: bool = Query(False),
    min_epss: float | None = Query(None, ge=0, le=1),
):
    f = _finding_filters(severity, status_, scanner, asset_id, q, has_cve, min_epss, kev)
    rows = build_findings_query(db, f).order_by(models.Finding.id).all()
    assets = {a.id: a for a in db.query(models.Asset).all()}

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "asset", "criticality", "scanner", "severity", "status", "cve",
        "component", "rule_id", "file_path", "line_number", "epss_score", "kev",
        "risk_score", "title", "first_seen", "last_seen",
    ])
    for r in rows:
        asset = assets.get(r.asset_id)
        crit = asset.criticality if asset else "medium"
        score = risk_score(r.severity, r.epss_score, bool(r.kev), crit)
        writer.writerow([
            r.id, asset.name if asset else "", crit, r.scanner, r.severity, r.status,
            r.cve or "", r.component or "", r.rule_id or "", r.file_path or "",
            r.line_number if r.line_number is not None else "",
            f"{r.epss_score:.5f}" if r.epss_score is not None else "",
            "yes" if r.kev else "no", score,
            r.title,
            r.first_seen.strftime("%Y-%m-%d") if r.first_seen else "",
            r.last_seen.strftime("%Y-%m-%d") if r.last_seen else "",
        ])
    buf.seek(0)
    headers = {"Content-Disposition": 'attachment; filename="vulntrack-findings.csv"'}
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers=headers)
