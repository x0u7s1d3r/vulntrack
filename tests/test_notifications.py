import httpx

import app.notifications as notif
from app.config import get_settings
from app.notifications import meets_threshold, send_scan_notification


def test_meets_threshold_ranking():
    assert meets_threshold("critical", "high")
    assert meets_threshold("high", "high")
    assert not meets_threshold("medium", "high")
    assert not meets_threshold("low", "high")
    # Seuil plus bas : on remonte davantage de choses.
    assert meets_threshold("medium", "low")
    # Severite inconnue : jamais notifiee.
    assert not meets_threshold("bogus", "high")


def _summary():
    return {
        "scan_id": 7,
        "asset_name": "nginx:1.25",
        "scanner": "trivy",
        "threshold": "high",
        "new_by_severity": {"critical": 2, "high": 3},
    }


def test_no_urls_configured_sends_nothing(monkeypatch):
    called = []
    monkeypatch.setattr(notif, "_post", lambda *a, **k: called.append(a))
    # Config par defaut : URLs vides.
    get_settings.cache_clear()
    send_scan_notification(_summary())
    assert called == []


def test_slack_notification_posts_formatted_text(monkeypatch):
    posts = []
    monkeypatch.setattr(notif, "_post", lambda url, payload, timeout: posts.append((url, payload)))

    settings = get_settings()
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.slack.test/xxx")
    monkeypatch.setattr(settings, "notify_webhook_url", "")

    send_scan_notification(_summary())

    assert len(posts) == 1
    url, payload = posts[0]
    assert url == "https://hooks.slack.test/xxx"
    assert "text" in payload
    assert "nginx:1.25" in payload["text"]
    assert "2 critical" in payload["text"]


def test_generic_webhook_posts_raw_summary(monkeypatch):
    posts = []
    monkeypatch.setattr(notif, "_post", lambda url, payload, timeout: posts.append((url, payload)))

    settings = get_settings()
    monkeypatch.setattr(settings, "slack_webhook_url", "")
    monkeypatch.setattr(settings, "notify_webhook_url", "https://webhook.test/in")

    send_scan_notification(_summary())

    assert len(posts) == 1
    url, payload = posts[0]
    assert url == "https://webhook.test/in"
    # Webhook generique : resume brut transmis tel quel.
    assert payload["scan_id"] == 7
    assert payload["new_by_severity"] == {"critical": 2, "high": 3}


def test_notification_failure_is_swallowed(monkeypatch):
    def boom(url, payload, timeout):
        raise httpx.ConnectError("injoignable")

    monkeypatch.setattr(notif, "_post", boom)
    settings = get_settings()
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.slack.test/xxx")

    # Ne doit jamais lever : une notification perdue ne casse rien.
    send_scan_notification(_summary())


def test_both_channels_independent(monkeypatch):
    """Slack echoue mais le webhook generique doit quand meme etre tente."""
    posts = []

    def selective(url, payload, timeout):
        if "slack" in url:
            raise httpx.ConnectError("slack down")
        posts.append(url)

    monkeypatch.setattr(notif, "_post", selective)
    settings = get_settings()
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.slack.test/xxx")
    monkeypatch.setattr(settings, "notify_webhook_url", "https://webhook.test/in")

    send_scan_notification(_summary())
    assert posts == ["https://webhook.test/in"]


def test_maybe_notify_fires_only_above_threshold(monkeypatch):
    from collections import Counter

    import app.jobs as jobs

    sent = []
    monkeypatch.setattr(jobs, "send_scan_notification", lambda s: sent.append(s))

    settings = get_settings()
    monkeypatch.setattr(settings, "notify_min_severity", "high")

    # Que du medium/low : sous le seuil, aucune notification.
    jobs._maybe_notify(1, "asset", "trivy", Counter({"medium": 4, "low": 2}))
    assert sent == []

    # Un critical + un high franchissent le seuil : notification envoyee, et
    # ne contenant QUE les severites au seuil (pas les medium/low).
    jobs._maybe_notify(2, "asset", "trivy", Counter({"critical": 1, "high": 2, "low": 9}))
    assert len(sent) == 1
    assert sent[0]["new_by_severity"] == {"critical": 1, "high": 2}
    assert sent[0]["scan_id"] == 2


def test_maybe_notify_never_raises(monkeypatch):
    from collections import Counter

    import app.jobs as jobs

    def boom(summary):
        raise RuntimeError("panne")

    monkeypatch.setattr(jobs, "send_scan_notification", boom)
    settings = get_settings()
    monkeypatch.setattr(settings, "notify_min_severity", "high")

    # Best-effort : une erreur d'envoi ne remonte jamais jusqu'au scan.
    jobs._maybe_notify(3, "asset", "trivy", Counter({"critical": 1}))
