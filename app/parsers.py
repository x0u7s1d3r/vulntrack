from collections.abc import Iterator
from typing import TypedDict


class ParsedFinding(TypedDict):
    title: str
    description: str
    severity: str
    cve: str | None
    component: str | None
    rule_id: str | None
    file_path: str | None
    line_number: int | None


SEVERITY_MAP_TRIVY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

# Semgrep n'a pas de notion de CVE : ses trois niveaux (ERROR/WARNING/INFO)
# refletent la confiance de la regle plutot qu'une gravite CVSS. On les
# fait correspondre a nos niveaux internes de facon conservatrice.
SEVERITY_MAP_SEMGREP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def parse_trivy(report: dict) -> Iterator[ParsedFinding]:
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = SEVERITY_MAP_TRIVY.get(vuln.get("Severity", "UNKNOWN"), "info")

            yield ParsedFinding(
                title=vuln.get("Title") or vuln.get("VulnerabilityID", "Sans titre"),
                description=(vuln.get("Description") or "")[:5000],
                severity=severity,
                cve=vuln.get("VulnerabilityID"),
                component=vuln.get("PkgName"),
                rule_id=None,
                file_path=None,
                line_number=None,
            )


def parse_semgrep(report: dict) -> Iterator[ParsedFinding]:
    """Parse une sortie `semgrep --json`.

    Une trouvaille Semgrep n'a ni CVE ni composant : elle designe une regle
    (`check_id`) declenchee a un endroit precis du code (`path` + ligne).
    C'est cette localisation qui sert d'identite pour la deduplication.
    """
    for res in report.get("results") or []:
        extra = res.get("extra") or {}
        rule_id = res.get("check_id", "regle-inconnue")
        severity = SEVERITY_MAP_SEMGREP.get(extra.get("severity", "INFO"), "info")

        yield ParsedFinding(
            title=extra.get("message", rule_id)[:500] or rule_id,
            description=(extra.get("message") or "")[:5000],
            severity=severity,
            cve=None,
            component=None,
            rule_id=rule_id,
            file_path=res.get("path"),
            line_number=(res.get("start") or {}).get("line"),
        )


def parse_gitleaks(report: list) -> Iterator[ParsedFinding]:
    """Parse une sortie `gitleaks detect --report-format json`.

    Le rapport gitleaks est un tableau JSON a la racine (pas un objet). Une
    fuite de secret est par nature toujours critique : il n'y a pas de champ
    de gravite a mapper. Le secret lui-meme (`Secret`, `Match`) n'est
    volontairement jamais recopie dans les champs stockes : un finding
    consultable par des roles `viewer`/`analyst` ne doit jamais exposer un
    credential en clair, meme deja compromis.
    """
    for leak in report or []:
        rule_id = leak.get("RuleID", "secret-inconnu")

        yield ParsedFinding(
            title=f"Secret detecte : {rule_id}",
            description=(leak.get("Description") or "").strip()[:5000],
            severity="critical",
            cve=None,
            component=None,
            rule_id=rule_id,
            file_path=leak.get("File"),
            line_number=leak.get("StartLine"),
        )


PARSERS = {
    "trivy": parse_trivy,
    "semgrep": parse_semgrep,
    "gitleaks": parse_gitleaks,
}


def get_parser(scanner: str):
    parser = PARSERS.get(scanner)
    if not parser:
        raise ValueError(f"Scanner non supporte: {scanner}")
    return parser
