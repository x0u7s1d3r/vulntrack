from typing import Iterator, TypedDict


class ParsedFinding(TypedDict):
    title: str
    description: str
    severity: str
    cve: str | None
    component: str | None


SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def parse_trivy(report: dict) -> Iterator[ParsedFinding]:
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info")

            yield ParsedFinding(
                title=vuln.get("Title") or vuln.get("VulnerabilityID", "Sans titre"),
                description=(vuln.get("Description") or "")[:5000],
                severity=severity,
                cve=vuln.get("VulnerabilityID"),
                component=vuln.get("PkgName"),
            )


PARSERS = {
    "trivy": parse_trivy,
}


def get_parser(scanner: str):
    parser = PARSERS.get(scanner)
    if not parser:
        raise ValueError(f"Scanner non supporte: {scanner}")
    return parser
