from app import models
from app.web_stats import (
    _severity_segments,
    asset_stats,
    dashboard_stats,
    worst_severity,
)


def test_severity_segments_widths_sum_to_100():
    segs = _severity_segments({"critical": 1, "high": 3})
    assert [s["severity"] for s in segs] == ["critical", "high"]
    assert round(sum(s["width"] for s in segs)) == 100
    # Offsets cumulatifs, dans l'ordre de gravite.
    assert segs[0]["offset"] == 0
    assert segs[1]["offset"] == segs[0]["width"]


def test_severity_segments_empty():
    assert _severity_segments({}) == []
    assert _severity_segments({"critical": 0}) == []


def test_worst_severity_picks_most_severe_present():
    assert worst_severity({"critical": 0, "high": 2, "low": 5}) == "high"
    assert worst_severity({"low": 3}) == "low"
    assert worst_severity({"critical": 0}) is None


def test_asset_stats_counts_open_vs_total():
    class F:
        def __init__(self, severity, status):
            self.severity = severity
            self.status = status

    findings = [F("critical", "open"), F("high", "fixed"), F("high", "in_progress")]
    stats = asset_stats(findings)
    assert stats["total"] == 3
    assert stats["by_severity"]["high"] == 2
    # open + in_progress comptent comme "ouverts", pas fixed.
    assert stats["open"] == 2
    assert stats["open_by_severity"]["high"] == 1
    assert stats["open_by_severity"]["critical"] == 1


def test_dashboard_stats_aggregates_across_assets(db_session):
    a1 = models.Asset(name="a1", type="image")
    a2 = models.Asset(name="a2", type="repository")
    db_session.add_all([a1, a2])
    db_session.flush()
    db_session.add_all([
        models.Finding(asset_id=a1.id, scanner="trivy", fingerprint="f1",
                       title="x", severity="critical", status="open"),
        models.Finding(asset_id=a1.id, scanner="trivy", fingerprint="f2",
                       title="x", severity="high", status="fixed"),
        models.Finding(asset_id=a2.id, scanner="semgrep", fingerprint="f3",
                       title="x", severity="high", status="open"),
    ])
    db_session.commit()

    stats = dashboard_stats(db_session)
    assert stats["total_assets"] == 2
    assert stats["total_findings"] == 3
    assert stats["total_open"] == 2
    assert stats["open_by_severity"]["critical"] == 1
    assert stats["open_by_severity"]["high"] == 1
    assert stats["by_status"]["fixed"] == 1
    # Detail par asset.
    assert stats["per_asset"][a1.id]["total"] == 2
    assert stats["per_asset"][a1.id]["open"] == 1
    assert stats["per_asset"][a2.id]["open"] == 1
