def test_metrics_endpoint_exposes_prometheus_format(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]


def test_metrics_count_requests_by_route_template(client, viewer_headers):
    # Genere du trafic sur une route parametree.
    client.get("/assets/999999/findings", headers=viewer_headers)

    body = client.get("/metrics").text
    # Le label route doit etre le gabarit, jamais le chemin brut avec l'id :
    # sinon chaque id creerait une serie temporelle distincte (cardinalite).
    assert "/assets/{asset_id}/findings" in body
    assert "/assets/999999/findings" not in body


def test_metrics_track_status_code(client):
    client.get("/assets")  # 401 sans token
    body = client.get("/metrics").text
    assert "vulntrack_http_requests_total" in body
    assert 'status="401"' in body


def test_metrics_endpoint_not_counted_in_its_own_metrics(client):
    client.get("/metrics")
    body = client.get("/metrics").text
    # L'endpoint /metrics est explicitement exclu de la mesure.
    assert 'route="/metrics"' not in body


def test_duration_histogram_present(client):
    client.get("/health")
    body = client.get("/metrics").text
    assert "vulntrack_http_request_duration_seconds_bucket" in body


def test_state_collector_reports_queue_and_findings(db_session, monkeypatch):
    from prometheus_client.core import CounterMetricFamily

    from app import metrics_state
    from app.models import Asset, Finding

    asset = Asset(name="repo-metrics", type="repository")
    db_session.add(asset)
    db_session.flush()
    db_session.add_all(
        [
            Finding(
                asset_id=asset.id,
                scanner="trivy",
                fingerprint=f"fp-{i}",
                title="x",
                severity=sev,
                status="open",
            )
            for i, sev in enumerate(["critical", "high", "high"])
        ]
    )
    db_session.commit()

    # Le collecteur ouvre sa propre session : on la pointe vers la base de test.
    monkeypatch.setattr(metrics_state, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    # File simulee (evite de dependre d'un vrai Redis dans les tests).
    monkeypatch.setattr(metrics_state, "ingest_queue", [None, None, None, None])

    collector = metrics_state.VulnTrackStateCollector()
    families = {m.name: m for m in collector.collect()}

    assert "vulntrack_ingest_queue_depth" in families
    depth = families["vulntrack_ingest_queue_depth"].samples[0].value
    assert depth == 4

    findings = families["vulntrack_findings"]
    high_open = [
        s.value
        for s in findings.samples
        if s.labels == {"severity": "high", "status": "open"}
    ]
    assert high_open == [2]
    assert not isinstance(findings, CounterMetricFamily)  # jauge, pas compteur


def test_state_collector_survives_db_error(monkeypatch):
    from app import metrics_state

    def boom():
        raise RuntimeError("base injoignable")

    monkeypatch.setattr(metrics_state, "SessionLocal", boom)
    monkeypatch.setattr(metrics_state, "ingest_queue", [])

    # Ne doit pas lever : un echec de lecture n'emet pas la metrique, mais ne
    # casse pas tout le scrape.
    families = list(metrics_state.VulnTrackStateCollector().collect())
    names = {m.name for m in families}
    assert "vulntrack_findings" not in names
    assert "vulntrack_ingest_queue_depth" in names
