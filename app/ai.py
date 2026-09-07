"""Assistant IA (etape 19) : explication et remediation des findings en
langage simple, via un modele local Ollama (auto-heberge, aucune donnee ne
sort du perimetre).

Anti-hallucination : le prompt est ANCRE sur les donnees reelles du finding,
et interdit au modele d'inventer des versions ou des commandes. Le module
DEGRADE PROPREMENT : si ollama_url n'est pas configure, la fonctionnalite est
simplement absente et VulnTrack fonctionne sans elle.
"""
import json
import logging
import urllib.error
import urllib.request

from app.config import get_settings
from app.models import Finding

logger = logging.getLogger(__name__)


def ai_enabled() -> bool:
    """Vrai si un serveur Ollama est configure."""
    return bool(get_settings().ollama_url)


def build_prompt(finding: Finding) -> str:
    """Construit un prompt ANCRE sur les donnees du finding, interdisant au
    modele d'inventer des versions ou des commandes precises."""
    return (
        "Tu es un assistant securite pour developpeurs. Explique en francais "
        "simple, pour un non-expert, la vulnerabilite ci-dessous, puis donne "
        "des etapes de correction generales. IMPORTANT : n'invente AUCUN "
        "numero de version precis ni commande exacte ; si une mise a jour est "
        "necessaire, invite a consulter l'avis officiel (NVD ou l'editeur). "
        "Sois clair et concis (150 mots maximum).\n\n"
        "Donnees du finding (ne sors pas de ces faits) :\n"
        f"- Scanner : {finding.scanner}\n"
        f"- Titre : {finding.title}\n"
        f"- CVE : {finding.cve or 'n/a'}\n"
        f"- Composant : {finding.component or 'n/a'}\n"
        f"- Severite : {finding.severity}\n"
    )


def explain_finding(finding: Finding) -> str:
    """Genere une explication via Ollama. Leve RuntimeError si l'IA n'est pas
    configuree ou en cas d'echec : l'appelant gere la degradation."""
    settings = get_settings()
    if not settings.ollama_url:
        raise RuntimeError("IA non configuree")

    url = settings.ollama_url.rstrip("/") + "/api/generate"
    if not url.startswith(("http://", "https://")):
        raise RuntimeError("ollama_url doit utiliser le schema http(s)")
    data = json.dumps({
        "model": settings.ollama_model,
        "prompt": build_prompt(finding),
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        # URL = config operateur (jamais une entree utilisateur), et le schema
        # http(s) est valide ci-dessus : le vecteur file:// de la regle est ferme.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=settings.ollama_timeout) as resp:
            body = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.warning("Appel Ollama echoue: %s", exc)
        raise RuntimeError(f"IA indisponible: {exc}") from exc

    text = (body.get("response") or "").strip()
    if not text:
        raise RuntimeError("Reponse IA vide")
    return text
