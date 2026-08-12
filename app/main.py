from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas



app = FastAPI(title="VulnTrack", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/assets", response_model=schemas.AssetOut, status_code=201)
def create_asset(payload: schemas.AssetCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Asset).filter_by(name=payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset déjà existant")
    asset = models.Asset(name=payload.name, type=payload.type)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@app.get("/assets", response_model=list[schemas.AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.query(models.Asset).all()


@app.get("/assets/{asset_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    return db.query(models.Finding).filter_by(asset_id=asset_id).all()
