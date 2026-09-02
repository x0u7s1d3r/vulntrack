"""Tests du planificateur (app/scheduler.py).

due_targets prend db + now en parametres -> testable sans mocker le temps.
Tout est en UTC timezone-aware : croniter renvoie une echeance dans le fuseau
de la base, et la comparaison nxt <= now exige des datetimes homogenes.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app import scheduler
from app.models import ScanTarget
from tests.conftest import TestingSessionLocal


def _target(db, **kw):
    defaults = dict(
        name="c", target_type="image", reference="alpine:3.19", scanners="trivy",
        schedule="* * * * *", enabled=True, last_status=None, last_scan_at=None,
    )
    defaults.update(kw)
    t = ScanTarget(**defaults)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def test_cible_echue_remonte(db_session):
    now = datetime.now(timezone.utc)
    # cron chaque minute, dernier scan il y a 2 min -> prochaine echeance passee
    _target(db_session, name="echue", last_scan_at=now - timedelta(minutes=2))
    due = scheduler.due_targets(db_session, now)
    assert [t.name for t in due] == ["echue"]


def test_cible_pas_encore_echue_ne_remonte_pas(db_session):
    now = datetime.now(timezone.utc)
    # cron quotidien 3h, dernier scan a l'instant -> prochaine echeance demain
    _target(db_session, name="future", schedule="0 3 * * *", last_scan_at=now)
    assert scheduler.due_targets(db_session, now) == []


def test_cible_occupee_ignoree(db_session):
    now = datetime.now(timezone.utc)
    # echue mais un scan est deja en vol -> on n'enfile pas de doublon
    _target(db_session, name="occupee", last_scan_at=now - timedelta(minutes=2),
            last_status="running")
    assert scheduler.due_targets(db_session, now) == []


def test_cible_desactivee_exclue(db_session):
    now = datetime.now(timezone.utc)
    _target(db_session, name="off", last_scan_at=now - timedelta(minutes=2),
            enabled=False)
    assert scheduler.due_targets(db_session, now) == []


def test_cible_sans_cron_exclue(db_session):
    now = datetime.now(timezone.utc)
    # schedule None = cible purement manuelle, jamais planifiee
    _target(db_session, name="manuel", schedule=None,
            last_scan_at=now - timedelta(minutes=2))
    assert scheduler.due_targets(db_session, now) == []


def test_cron_invalide_ne_plante_pas(db_session):
    now = datetime.now(timezone.utc)
    # croniter leve -> capture, cible ignoree, la boucle ne casse pas
    _target(db_session, name="casse", schedule="pas un cron",
            last_scan_at=now - timedelta(minutes=2))
    assert scheduler.due_targets(db_session, now) == []


def test_tick_enfile_et_marque_queued(db_session):
    t = _target(db_session, name="tickable",
                last_scan_at=datetime.now(timezone.utc) - timedelta(minutes=2))
    with patch("app.scheduler.SessionLocal", TestingSessionLocal), \
         patch("app.scheduler.ingest_queue.enqueue") as enq:
        scheduler.tick()

    enq.assert_called_once_with("app.scanning.scan_target", t.id)
    db_session.expire_all()
    assert db_session.get(ScanTarget, t.id).last_status == "queued"
