import hashlib
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    # "admin" | "analyst" | "viewer", valide en amont par schemas.UserRole
    role = Column(String(20), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


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
   
    raw_report_path = Column(String(500), nullable=True)
    error_message = Column(Text, nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    findings_count = Column(Integer, default=0)

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    # Denormalise depuis scans.scanner : indispensable pour ne comparer les
    # findings "toujours vus" qu'au sein du meme scanner (voir make_fingerprint
    # et jobs.process_scan). Sans ca, un scan Semgrep marquerait a tort les
    # findings Trivy du meme asset comme corriges.
    scanner = Column(String(50), nullable=False, server_default="trivy", index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    cve = Column(String(50), nullable=True, index=True)
    component = Column(String(255), nullable=True)
    # Renseignes uniquement pour les scanners SAST/secrets (Semgrep, Gitleaks) :
    # une regle declenchee a un endroit du code, pas une CVE sur un composant.
    rule_id = Column(String(255), nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    # Probabilite d'exploitation reelle (FIRST.org EPSS), 0-1. Renseigne
    # uniquement pour les findings avec CVE ; None si l'enrichissement a
    # echoue ou n'a pas encore eu lieu.
    epss_score = Column(Float, nullable=True)
    status = Column(String(30), default="open")
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", back_populates="findings")

    @staticmethod
    def make_fingerprint(
        asset_name: str,
        scanner: str,
        cve: str | None = None,
        component: str | None = None,
        rule_id: str | None = None,
        file_path: str | None = None,
        line_number: int | None = None,
    ) -> str:
        if scanner == "trivy":
            # Formule historique, volontairement inchangee : la modifier
            # invaliderait toutes les empreintes Trivy deja stockees en
            # production (le prochain scan verrait tout comme "nouveau" et
            # marquerait les findings existants comme "corriges" a tort).
            raw = f"{asset_name}|{cve or ''}|{component or ''}"
        else:
            raw = f"{asset_name}|{scanner}|{rule_id or ''}|{file_path or ''}|{line_number or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()
