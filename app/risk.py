"""Score de risque composite (Risk-Based Vulnerability Management).

Une plateforme moderne ne trie pas les vulnerabilites par la seule gravite
theorique (CVSS/severite). Elle combine quatre dimensions pour repondre a la
vraie question : "que dois-je corriger en premier ?"

  1. Severite   : la gravite intrinseque (impact potentiel).
  2. EPSS       : la probabilite d'exploitation reelle (FIRST.org, 0-1).
  3. KEV        : l'exploitation *active* confirmee (CISA) - un fait, pas une
                  probabilite : ponderation forte.
  4. Criticite  : le contexte metier de l'asset (un joyau vaut plus qu'un bac
     de l'asset    a sable).

Le tout est ramene sur une echelle 0-100, decoupee en bandes lisibles. Le
calcul est deterministe et volontairement transparent (pas de boite noire) :
un analyste doit pouvoir expliquer pourquoi un finding est prioritaire.
"""

from sqlalchemy import Boolean, case, cast, func

from app.models import Asset, Finding

# Contribution de base par severite (sur ~45 points).
SEVERITY_BASE = {"critical": 45, "high": 30, "medium": 15, "low": 6, "info": 2}

# Bonus/malus selon la criticite metier de l'asset.
CRITICALITY_BONUS = {"crown": 15, "high": 8, "medium": 0, "low": -8}
CRITICALITY_LABEL = {
    "crown": "Joyau", "high": "Haute", "medium": "Moyenne", "low": "Faible",
}
CRITICALITIES = ["crown", "high", "medium", "low"]

EPSS_WEIGHT = 25   # EPSS 1.0 ajoute 25 points.
KEV_BONUS = 25     # exploitation active confirmee.

# Bandes de risque (bornes basses inclusives).
RISK_BANDS = [
    ("critical", 75), ("high", 50), ("medium", 25), ("low", 0),
]


def risk_score(severity: str, epss: float | None, kev: bool, criticality: str) -> int:
    """Score de risque 0-100 pour un finding. Deterministe et borne."""
    score = SEVERITY_BASE.get(severity, 2)
    score += (epss or 0.0) * EPSS_WEIGHT
    if kev:
        score += KEV_BONUS
    score += CRITICALITY_BONUS.get(criticality, 0)
    return max(0, min(100, round(score)))


def risk_band(score: int) -> str:
    """Bande de risque ("critical" / "high" / "medium" / "low") depuis un score."""
    for band, low in RISK_BANDS:
        if score >= low:
            return band
    return "low"


def risk_score_sql():
    """Expression SQL equivalente a risk_score(), pour trier/filtrer en base.

    Necessite que la requete ait joint Finding a Asset (pour la criticite).
    Non bornee a 100 : sans importance pour l'ordre de tri.
    """
    sev = case(
        *[(Finding.severity == s, v) for s, v in SEVERITY_BASE.items()],
        else_=2,
    )
    crit = case(
        *[(Asset.criticality == c, v) for c, v in CRITICALITY_BONUS.items()],
        else_=0,
    )
    kev = case((cast(Finding.kev, Boolean), KEV_BONUS), else_=0)
    epss = func.coalesce(Finding.epss_score, 0.0) * EPSS_WEIGHT
    return sev + epss + kev + crit
