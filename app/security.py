import hmac
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

from app.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str = Security(api_key_header)) -> str:
    settings = get_settings()

    if not settings.api_key_list:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentification non configuree",
        )

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cle d'API manquante",
        )

    for valid_key in settings.api_key_list:
        if hmac.compare_digest(api_key, valid_key):
            return api_key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Cle d'API invalide",
    )
