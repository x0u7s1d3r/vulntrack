import hashlib
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    type = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    findings = relationship("Finding", back_populates="asset")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scanner = Column(String(50), nullable=False)
    status = Column(String(20), default="pending")
    started_at = Column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    cve = Column(String(50), nullable=True, index=True)
    component = Column(String(255), nullable=True)
    status = Column(String(30), default="open")
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", back_populates="findings")

    @staticmethod
    def make_fingerprint(asset_name: str, cve: str, component: str) -> str:
        raw = f"{asset_name}|{cve or ''}|{component or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()
