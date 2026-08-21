from starlette.requests import Request

from app.security import get_client_ip


def _make_request(headers: dict, client_host: str | None = "10.0.0.5") -> Request:
    raw_headers = [
        (k.lower().encode(), v.encode()) for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "headers": raw_headers,
        "client": (client_host, 12345) if client_host else None,
    }
    return Request(scope)


def test_get_client_ip_uses_x_forwarded_for_when_present():
    request = _make_request({"X-Forwarded-For": "203.0.113.7"})
    assert get_client_ip(request) == "203.0.113.7"


def test_get_client_ip_takes_first_ip_of_a_forwarded_chain():
    """Derriere plusieurs proxies, le premier hop est le client d'origine."""
    request = _make_request({"X-Forwarded-For": "203.0.113.7, 10.0.0.1, 10.0.0.2"})
    assert get_client_ip(request) == "203.0.113.7"


def test_get_client_ip_falls_back_to_client_host_without_header():
    request = _make_request({})
    assert get_client_ip(request) == "10.0.0.5"


def test_get_client_ip_falls_back_to_localhost_without_client_or_header():
    request = _make_request({}, client_host=None)
    assert get_client_ip(request) == "127.0.0.1"


def test_get_client_ip_header_lookup_is_case_insensitive():
    """Regression : verifie qu'on ne reproduit pas le bug de
    slowapi.util.get_ipaddr, qui cherche l'en-tete "X_FORWARDED_FOR"
    (underscore) et ne matche donc jamais le vrai en-tete HTTP
    "X-Forwarded-For" (tiret)."""
    request = _make_request({"x-forwarded-for": "198.51.100.1"})
    assert get_client_ip(request) == "198.51.100.1"
