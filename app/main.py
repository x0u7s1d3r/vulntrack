import logging

import json

from fastapi import File, Form, UploadFile

from app.queue import ingest_queue
from app.storage import save_report

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.middleware import SecurityHeadersMiddleware
from app.security import require_api_key
from app import models, schemas

logger = logging.getLogger(__name__)
settings = get_settings()

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="VulnTrack",
    version="0.3.0",
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(SecurityHeadersMiddleware)

if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Erreur non geree sur %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Erreur interne"},
    )


@app.get("/health")
@limiter.limit("300/minute")
def health(request: Request):
    return {"status": "ok"}


@app.post(
    "/assets",
    response_model=schemas.AssetOut,
    status_code=201,
    dependencies=[Depends(require_api_key)],
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
    logger.info("Asset cree: %s", asset.name)
    return asset


@app.get(
    "/assets",
    response_model=list[schemas.AssetOut],
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(settings.rate_limit_default)
def list_assets(request: Request, db: Session = Depends(get_db)):
    return db.query(models.Asset).all()


@app.get(
    "/assets/{asset_id}/findings",
    response_model=list[schemas.FindingOut],
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(settings.rate_limit_default)
def list_findings(request: Request, asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    return db.query(models.Finding).filter_by(asset_id=asset_id).all()


MAX_REPORT_SIZE = 20 * 1024 * 1024


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
        raise HTTPException(status_code=400, detail="Rapport JSON invalide")

    asset = db.query(models.Asset).filter_by(name=asset_name).first()
    if not asset:
        asset = models.Asset(name=asset_name, type=asset_type.value)
        db.add(asset)
        db.flush()

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
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(settings.rate_limit_default)
def get_scan(request: Request, scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan
