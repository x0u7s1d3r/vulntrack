from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AssetCreate(BaseModel):
    name: str
    type: str


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
    title: str
    severity: str
    cve: Optional[str] = None
    component: Optional[str] = None
    status: str
    first_seen: datetime
    last_seen: datetime
