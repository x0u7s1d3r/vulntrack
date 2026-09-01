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
    # Criticite metier de l'asset (contexte RBVM) : pondere le score de risque
    # de ses findings. "low" | "medium" | "high" | "crown" (joyau : actif vital).
    criticality = Column(String(20), nullable=False, server_default="medium", default="medium")
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
    # Presence dans le catalogue CISA KEV (Known Exploited Vulnerabilities) :
    # la CVE est activement exploitee dans la nature. Signal de menace le plus
    # fort, complementaire de l'EPSS (probabilite). Enrichi par le worker.
    kev = Column(Boolean, nullable=False, server_default="0", default=False, index=True)
    status = Column(String(30), default="open")
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)
    # Derniere action de triage (changement de statut / note). Distinct de
    # last_seen, qui suit les scans, pas l'activite humaine.
    updated_at = Column(DateTime(timezone=True), nullable=True)

    asset = relationship("Asset", back_populates="findings")
    notes = relationship(
        "FindingNote", back_populates="finding", cascade="all, delete-orphan"
    )

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


class FindingNote(Base):
    """Journal d'un finding : commentaires libres et changements de statut.

    Un seul modele pour les deux, distingues par `kind` : ainsi le detail
    d'un finding affiche un fil chronologique unique (triage + discussions),
    a la maniere des "overrides" et notes d'OpenVAS/Greenbone.
    """

    __tablename__ = "finding_notes"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    # "comment" | "status_change"
    kind = Column(String(20), nullable=False, default="comment")
    body = Column(Text, nullable=True)
    # Renseignes pour kind="status_change" : tracabilite de la transition.
    old_status = Column(String(30), nullable=True)
    new_status = Column(String(30), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="notes")


class ScanTarget(Base):
    """Cible que VulnTrack scanne LUI-MEME : il declenche le scanner et
    reinjecte le rapport dans le pipeline d'ingestion existant. Une cible
    correspond a un asset (par son nom) : ses scans alimentent les findings
    de cet asset, exactement comme une ingestion poussee via /scans/ingest."""

    __tablename__ = "scan_targets"

    id = Column(Integer, primary_key=True, index=True)
    # = nom de l'asset produit (get-or-create par le runner, comme l'ingestion).
    name = Column(String(255), nullable=False, unique=True)
    # "image" (reference d'image OCI) | "repository" (URL git). Valide par schemas.
    target_type = Column(String(20), nullable=False)
    # Ce qu'on scanne : "nginx:1.25-alpine" ou "https://github.com/x/y.git".
    reference = Column(String(500), nullable=False)
    # Scanners a executer, separes par des virgules. image -> "trivy" ;
    # repository -> "trivy,semgrep,gitleaks".
    scanners = Column(String(200), nullable=False)
    # Cadence de scan, expression cron (croniter). NULL = a la demande uniquement.
    schedule = Column(String(100), nullable=True)
    enabled = Column(Boolean, nullable=False, server_default="1", default=True)
    # Suivi de la derniere execution (affichage + decisions du planificateur).
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(20), nullable=True)  # "success" | "error" | "running"
    created_at = Column(DateTime(timezone=True), default=utcnow)
