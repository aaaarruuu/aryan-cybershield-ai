import httpx
import pytest

from app.core.config import get_settings
from app.database.session import SessionLocal
from app.services import threat_intel as ti


def test_detect_type():
    assert ti.detect_type("8.8.8.8") == "ip"
    assert ti.detect_type("example.com") == "domain"
    assert ti.detect_type("http://evil.example/x") == "url"
    assert ti.detect_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert ti.detect_type("not a thing!!") is None
    assert ti.detect_type("999.1.1.1") is None


def test_demo_known_malicious_and_unknown_not_clean():
    db = SessionLocal()
    r = ti.lookup(db, "203.0.113.45")
    assert r["verdict"] == "malicious" and r["demo"] is True and r["source"] == "demo-sample-data"
    u = ti.lookup(db, "198.51.100.200")
    assert u["verdict"] == "unknown"          # absent from dataset must never be reported clean
    assert "NOT a clean verdict" in u["details"]["note"]


def test_caching():
    db = SessionLocal()
    assert ti.lookup(db, "203.0.113.45")["cached"] is False
    assert ti.lookup(db, "203.0.113.45")["cached"] is True


def test_invalid_indicator_rejected():
    with pytest.raises(ValueError):
        ti.lookup(SessionLocal(), "!!!")


def _live(monkeypatch, handler, key="k"):
    monkeypatch.setattr(get_settings(), "demo_mode", False)
    monkeypatch.setattr(get_settings(), "virustotal_api_key", key)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_live_parses_virustotal(monkeypatch):
    seen = {}

    def handler(req):
        seen["key"] = req.headers.get("x-apikey")
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 50, "undetected": 5}, "reputation": -20}}})
    r = ti.lookup(SessionLocal(), "evil.example.org", client=_live(monkeypatch, handler))
    assert r["verdict"] == "malicious" and r["source"] == "virustotal" and r["demo"] is False
    assert seen["key"] == "k"
    assert "k" != r["details"].get("api_key")


@pytest.mark.parametrize("status,expect", [(429, "rate limit"), (403, "rejected"), (500, "Lookup failed")])
def test_live_failures_are_unavailable_not_invented(monkeypatch, status, expect):
    r = ti.lookup(SessionLocal(), "evil.example.org", client=_live(monkeypatch, lambda req: httpx.Response(status)))
    assert r["verdict"] == "unavailable" and expect in r["details"]["error"]


def test_live_without_key_is_unavailable(monkeypatch):
    r = ti.lookup(SessionLocal(), "evil.example.org", client=_live(monkeypatch, lambda req: httpx.Response(200), key=""))
    assert r["verdict"] == "unavailable"


def test_unavailable_is_not_cached(monkeypatch):
    db = SessionLocal()
    ti.lookup(db, "evil.example.org", client=_live(monkeypatch, lambda req: httpx.Response(500)))
    ok = httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}}})
    r = ti.lookup(db, "evil.example.org", client=_live(monkeypatch, lambda req: ok))
    assert r["verdict"] == "clean" and r["cached"] is False
