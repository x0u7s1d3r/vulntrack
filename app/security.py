import hmac

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_client_ip(request: Request) -> str:
    """Adresse IP du client, utilisee comme cle de limitation de debit.

    Derriere Traefik (voir docker-compose.yml, etape 10 - haute disponibilite),
    request.client.host est l'IP du conteneur Traefik, pas celle du client :
    sans ca, tous les clients partageraient le meme quota de rate limiting.

    Note : slowapi.util.get_ipaddr existe deja pour ce cas, mais cherche
    l'en-tete "X_FORWARDED_FOR" (underscore) qui ne correspond jamais a
    l'en-tete HTTP reel "X-Forwarded-For" (tiret) - verifie empiriquement,
    get_ipaddr retombe donc toujours sur request.client.host et ne resout
    rien. D'ou cette implementation maison.

    Le premier hop de la liste (le client d'origine) est fiable ici parce que
    Traefik est le seul point d'entree du reseau : il ecrit lui-meme cet
    en-tete a partir de la connexion TCP reelle, un client ne peut pas
    l'usurper en amont. Ce ne serait plus vrai si un autre proxy non maitrise
    etait ajoute devant Traefik.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    if not request.client or not request.client.host:
        return "127.0.0.1"

    return request.client.host


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
