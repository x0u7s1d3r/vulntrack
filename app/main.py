import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from app.cache import cached_json, invalidate
from app.config import get_settings
from app.database import get_db
from app.metrics import MetricsMiddleware, render_metrics
from app.middleware import SecurityHeadersMiddleware
from app.queue import ingest_queue
from app.security import get_client_ip, require_api_key
from app.storage import save_report
from app.web import RedirectToLogin
from app.web import router as web_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger(__name__)
settings = get_settings()

CACHE_TTL_ASSETS = 30
CACHE_TTL_FINDINGS = 15
MAX_REPORT_SIZE = 20 * 1024 * 1024

limiter = Limiter(key_func=get_client_ip)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Demarrage de l'application")
    yield
    logger.info("Arret en cours, fermeture des connexions")
    from app.database import engine

    engine.dispose()


app = FastAPI(
    title="VulnTrack",
    version="0.5.0",
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)

if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Authorization", "Content-Type"],
    )

# Frontend web (etape 13) : CSS statique en same-origin (CSP inchangee) et
# routeur de consultation en lecture seule sous /ui.
_WEB_STATIC = Path(__file__).resolve().parent / "static"
app.mount("/ui/static", StaticFiles(directory=str(_WEB_STATIC)), name="web-static")
app.include_router(web_router)


@app.exception_handler(RedirectToLogin)
async def redirect_to_login_handler(request: Request, exc: RedirectToLogin):
    """Une page /ui protegee demandee sans session valide renvoie vers la
    page de connexion plutot qu'une erreur JSON."""
    return RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Erreur non geree sur %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Erreur interne"},
    )


# ---------------------------------------------------------------- sante


@app.get("/health")
@limiter.limit("600/minute")
def health(request: Request):
    """Sonde de vivacite. Ne touche aucune dependance : repond tant que le
    processus applicatif est vivant."""
    return {"status": "ok"}


@app.get("/ready")
@limiter.limit("600/minute")
def ready(request: Request, db: Session = Depends(get_db)):
    """Sonde de disponibilite. Verifie que les dependances critiques repondent,
    afin que l'orchestrateur ne route pas de trafic vers une instance
    incapable de le traiter."""
    from sqlalchemy import text

    checks = {"database": False, "cache": False}

    try:
        db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        logger.warning("Sonde de disponibilite : base injoignable")

    try:
        from app.cache import cache_client

        cache_client.ping()
        checks["cache"] = True
    except Exception:
        logger.warning("Sonde de disponibilite : cache injoignable")

    # Le cache est facultatif : son indisponibilite degrade les performances
    # mais n'empeche pas de servir les requetes.
    if not checks["database"]:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unavailable", "checks": checks},
        )

    return {"status": "ready", "checks": checks}


@app.get("/metrics", include_in_schema=False)
def metrics(request: Request):
    """Metriques RED au format Prometheus.

    Volontairement non authentifie : scrape par Prometheus sur le reseau
    interne (jamais expose publiquement via Traefik en production ; voir la
    section Observabilite du README pour le durcissement). Exclu du schema
    OpenAPI et non compte dans ses propres metriques.
    """
    data, content_type = render_metrics()
    return Response(content=data, media_type=content_type)


# ---------------------------------------------------------------- authentification


@app.post("/auth/login", response_model=schemas.Token)
@limiter.limit(settings.rate_limit_auth)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Connexion utilisateur : identifiants -> jeton JWT.

    Distinct de la cle d'API (X-API-Key), qui reste reservee a l'ingestion
    machine-a-machine sur /scans/ingest.
    """
    user = db.query(models.User).filter_by(username=form_data.username).first()

    if not user or not user.is_active or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(subject=user.username, role=user.role)
    logger.info("Connexion reussie: %s", user.username)
    return schemas.Token(access_token=token)


@app.post(
    "/users",
    response_model=schemas.UserOut,
    status_code=201,
    dependencies=[Depends(require_role("admin"))],
)
@limiter.limit(settings.rate_limit_write)
def create_user(
    request: Request,
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    """Creation d'un compte utilisateur. Reserve aux admins : pas d'auto-
    inscription sur un outil de suivi de vulnerabilites."""
    existing = db.query(models.User).filter_by(username=payload.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="Utilisateur deja existant")

    user = models.User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=payload.role.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("Utilisateur cree: %s (role=%s)", user.username, user.role)
    return user


@app.get(
    "/users",
    response_model=list[schemas.UserOut],
    dependencies=[Depends(require_role("admin"))],
)
@limiter.limit(settings.rate_limit_default)
def list_users(request: Request, db: Session = Depends(get_db)):
    return db.query(models.User).all()


# ---------------------------------------------------------------- assets


@app.post(
    "/assets",
    response_model=schemas.AssetOut,
    status_code=201,
    dependencies=[Depends(require_role("admin", "analyst"))],
)
@limiter.limit(settings.rate_limit_write)
def create_asset(
    request: Request,
    payload: schemas.AssetCreate,
    db: Session = Depends(get_db),
):
    existing = db.query(models.Asset).filter_by(name=payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset deja existant")

    asset = models.Asset(name=payload.name, type=payload.type.value)
    db.add(asset)
    db.commit()
    db.refresh(asset)

    invalidate("assets:*")
    logger.info("Asset cree: %s", asset.name)
    return asset


@app.get(
    "/assets",
    response_model=list[schemas.AssetOut],
    dependencies=[Depends(get_current_user)],
)
@limiter.limit(settings.rate_limit_default)
def list_assets(request: Request, db: Session = Depends(get_db)):
    def produce():
        assets = db.query(models.Asset).all()
        return [schemas.AssetOut.model_validate(a).model_dump() for a in assets]

    return cached_json("assets:list", CACHE_TTL_ASSETS, produce)


@app.get(
    "/assets/{asset_id}/findings",
    response_model=list[schemas.FindingOut],
    dependencies=[Depends(get_current_user)],
)
@limiter.limit(settings.rate_limit_default)
def list_findings(request: Request, asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")

    def produce():
        findings = (
            db.query(models.Finding)
            .filter_by(asset_id=asset_id)
            .order_by(models.Finding.severity, models.Finding.id)
            .all()
        )
        return [schemas.FindingOut.model_validate(f).model_dump() for f in findings]

    return cached_json(f"findings:asset:{asset_id}", CACHE_TTL_FINDINGS, produce)


# ---------------------------------------------------------------- scans


@app.post(
    "/scans/ingest",
    response_model=schemas.IngestAccepted,
    status_code=202,
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(settings.rate_limit_write)
async def ingest_scan(
    request: Request,
    asset_name: str = Form(min_length=1, max_length=255),
    asset_type: schemas.AssetType = Form(),
    scanner: schemas.ScannerType = Form(),
    report: UploadFile = File(),
    db: Session = Depends(get_db),
):
    content = await report.read()

    if len(content) > MAX_REPORT_SIZE:
        raise HTTPException(status_code=413, detail="Rapport trop volumineux")

    if not content:
        raise HTTPException(status_code=400, detail="Rapport vide")

    try:
        json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Rapport JSON invalide") from None

    asset = db.query(models.Asset).filter_by(name=asset_name).first()
    asset_created = False
    if not asset:
        asset = models.Asset(name=asset_name, type=asset_type.value)
        db.add(asset)
        db.flush()
        asset_created = True

    path = save_report(content, scanner.value)

    scan = models.Scan(
        asset_id=asset.id,
        scanner=scanner.value,
        status="pending",
        raw_report_path=path,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # L'invalidation intervient apres le commit : tant que la transaction n'est
    # pas validee, une autre instance repeuplerait le cache avec l'ancien etat.
    if asset_created:
        invalidate("assets:*")
    invalidate(f"findings:asset:{scan.asset_id}")

    ingest_queue.enqueue("app.jobs.process_scan", scan.id)

    logger.info("Scan %s mis en file pour %s", scan.id, asset.name)

    return schemas.IngestAccepted(
        scan_id=scan.id,
        status="pending",
        message="Rapport accepte, traitement en cours",
    )


@app.get(
    "/scans/{scan_id}",
    response_model=schemas.ScanOut,
    dependencies=[Depends(get_current_user)],
)
@limiter.limit(settings.rate_limit_default)
def get_scan(request: Request, scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan
