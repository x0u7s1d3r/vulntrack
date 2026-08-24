"""Tests RBVM : score de risque, SLA/MTTR, posture, rapport PDF."""
from datetime import datetime, timedelta, timezone

from app import models
from app.risk import risk_band, risk_score
from app.sla import SLA_DAYS, due_date, is_overdue
from app.web_posture import mttr_stats, posture_stats, sla_status


def _finding(asset_id, **kw):
    base = dict(
        asset_id=asset_id, scanner="trivy", fingerprint=f"fp-{kw.pop('_n', 0)}",
        title="x", severity="high", status="open",
    )
    base.update(kw)
    return models.Finding(**base)


# ----------------------------------------------------------- risk score

def test_risk_score_ordering():
    # KEV + crown + critical + EPSS élevé => proche du max.
    top = risk_score("critical", 0.9, True, "crown")
    mid = risk_score("high", 0.3, False, "medium")
    low = risk_score("low", None, False, "low")
    assert top > mid > low
    assert 0 <= low <= 100 and 0 <= top <= 100
    assert top >= 90


def test_risk_score_kev_and_criticality_move_the_needle():
    base = risk_score("high", 0.2, False, "medium")
    with_kev = risk_score("high", 0.2, True, "medium")
    with_crown = risk_score("high", 0.2, False, "crown")
    assert with_kev > base
    assert with_crown > base


def test_risk_band_thresholds():
    assert risk_band(80) == "critical"
    assert risk_band(60) == "high"
    assert risk_band(30) == "medium"
    assert risk_band(10) == "low"


# ----------------------------------------------------------- SLA helpers

def test_due_date_and_overdue():
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    due = due_date(first, "critical")
    assert due == first + timedelta(days=SLA_DAYS["critical"])
    now = first + timedelta(days=10)
    assert is_overdue(first, "critical", "open", now) is True   # 10 > 7
    assert is_overdue(first, "high", "open", now) is False       # 10 < 30
    # Un finding corrige n'est jamais "en retard".
    assert is_overdue(first, "critical", "fixed", now) is False


# ----------------------------------------------------------- posture (DB)

def _seed_posture(db):
    a = models.Asset(name="svc", type="repository", criticality="crown")
    db.add(a)
    db.flush()
    old = datetime.now(timezone.utc) - timedelta(days=20)
    # Critique ouverte depuis 20j => en retard (SLA 7j).
    db.add(_finding(a.id, _n=1, severity="critical", status="open",
                    first_seen=old, cve="CVE-1", epss_score=0.9, kev=True))
    # Élevée ouverte depuis 20j => dans les temps (SLA 30j).
    db.add(_finding(a.id, _n=2, severity="high", status="open", first_seen=old))
    # Une corrigée avec audit de remédiation (pour MTTR).
    f = _finding(a.id, _n=3, severity="high", status="fixed", first_seen=old)
    db.add(f)
    db.flush()
    db.add(models.FindingNote(
        finding_id=f.id, author="a", kind="status_change",
        old_status="open", new_status="fixed",
        created_at=old + timedelta(days=5),
    ))
    db.commit()
    return a


def test_sla_status_counts_overdue(db_session):
    _seed_posture(db_session)
    s = sla_status(db_session)
    assert s["overdue"] == 1                       # la critique
    assert s["overdue_by_severity"]["critical"] == 1
    assert s["on_track"] == s["open_total"] - s["overdue"]


def test_mttr_from_audit_trail(db_session):
    _seed_posture(db_session)
    m = mttr_stats(db_session)
    assert m["resolved"] == 1
    assert m["overall"] == 5.0                      # corrigée en 5 jours
    assert m["by_severity"]["high"] == 5.0
    assert m["compliance_pct"] == 100               # 5j <= SLA high (30j)


def test_posture_stats_shape(db_session):
    _seed_posture(db_session)
    d = posture_stats(db_session)
    assert d["totals"]["overdue"] == 1
    assert d["totals"]["kev_open"] == 1
    assert set(d["risk"]["bands"]) == {"critical", "high", "medium", "low"}
    assert d["risk"]["top"][0]["risk"] >= d["risk"]["top"][-1]["risk"]
    # Le flux couvre une fenêtre de 31 jours (0..30).
    assert len(d["flow"]) == 31


# ----------------------------------------------------------- rapport PDF

def test_report_pdf_bytes(db_session):
    from app.reporting import build_report_pdf

    _seed_posture(db_session)
    pdf = build_report_pdf(db_session)
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 1000
