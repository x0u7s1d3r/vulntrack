import httpx

from app.epss import fetch_epss_scores


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("erreur", request=None, response=self)

    def json(self):
        return self._payload


def test_fetch_epss_scores_maps_cve_to_float(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        return _FakeResponse(
            {"data": [{"cve": "CVE-2024-0001", "epss": "0.87321"}, {"cve": "CVE-2024-0002", "epss": "0.001"}]}
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    scores = fetch_epss_scores(["CVE-2024-0001", "CVE-2024-0002"])
    assert scores == {"CVE-2024-0001": 0.87321, "CVE-2024-0002": 0.001}


def test_fetch_epss_scores_empty_input_returns_empty_without_network_call(monkeypatch):
    def fake_get(*args, **kwargs):
        raise AssertionError("ne doit pas etre appele sans CVE")

    monkeypatch.setattr(httpx, "get", fake_get)
    assert fetch_epss_scores([]) == {}
    assert fetch_epss_scores([None, ""]) == {}


def test_fetch_epss_scores_network_failure_returns_partial_dict_not_exception(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        raise httpx.ConnectError("pas de reseau")

    monkeypatch.setattr(httpx, "get", fake_get)
    # Ne doit jamais lever : l'appelant (jobs.process_scan) compte sur un
    # echec silencieux plutot que sur une exception qui ferait echouer le scan.
    assert fetch_epss_scores(["CVE-2024-0001"]) == {}


def test_fetch_epss_scores_deduplicates_cves(monkeypatch):
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cve"])
        return _FakeResponse({"data": [{"cve": "CVE-2024-0001", "epss": "0.5"}]})

    monkeypatch.setattr(httpx, "get", fake_get)
    fetch_epss_scores(["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0001"])
    assert len(calls) == 1
    assert calls[0] == "CVE-2024-0001"
