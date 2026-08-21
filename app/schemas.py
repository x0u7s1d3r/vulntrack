from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetType(str, Enum):
    IMAGE = "image"
    REPOSITORY = "repository"
    URL = "url"
    HOST = "host"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    type: AssetType

    @field_validator("name")
    @classmethod
    def name_must_be_clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("le nom ne peut pas etre vide")
        if any(c in v for c in ["\n", "\r", "\x00"]):
            raise ValueError("caracteres de controle interdits")
        return v


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    scanner: str
    title: str
    severity: str
    cve: str | None = None
    component: str | None = None
    rule_id: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    epss_score: float | None = None
    status: str
    first_seen: datetime
    last_seen: datetime


class ScannerType(str, Enum):
    TRIVY = "trivy"
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    scanner: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    findings_count: int | None = None
    error_message: str | None = None


class IngestAccepted(BaseModel):
    scan_id: int
    status: str
    message: str


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    role: UserRole = UserRole.VIEWER

    @field_validator("username")
    @classmethod
    def username_must_be_clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("le nom d'utilisateur ne peut pas etre vide")
        if any(c in v for c in ["\n", "\r", "\x00", " "]):
            raise ValueError("caracteres interdits dans le nom d'utilisateur")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
