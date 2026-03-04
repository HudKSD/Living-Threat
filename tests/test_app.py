from datetime import timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module
from app import _parse_iso_dt, _normalize_severity, app


def test_parse_iso_dt_accepts_lowercase_z_suffix():
    dt = _parse_iso_dt("2026-02-18T00:31:10z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2026
    assert dt.minute == 31


def test_parse_iso_dt_rejects_invalid_text():
    assert _parse_iso_dt("not-a-date") is None


def test_severity_normalization_variants():
    assert _normalize_severity("crit") == "Critical"
    assert _normalize_severity("medium") == "Moderate"
    assert _normalize_severity("") == "Low"


def test_healthz_endpoint_ok():
    client = app.test_client()
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True}


def test_heartbeat_supports_since_seq(monkeypatch):
    def fake_search_safe(**kwargs):
        return {"hits": {"hits": [{"_source": {"Timestamp": "2026-01-01T00:00:00Z", "sequence": 42}}]}}

    monkeypatch.setattr(app_module, "es_search_safe", fake_search_safe)
    monkeypatch.setattr(app_module, "es_count_safe", lambda **kwargs: 3)

    client = app.test_client()
    r = client.get("/api/heartbeat?since_seq=40")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["latest_seq"] == 42
    assert payload["new_count"] == 3


def test_heartbeat_supports_since_ts_alias(monkeypatch):
    def fake_search_safe(**kwargs):
        return {"hits": {"hits": [{"_source": {"Timestamp": "2026-01-01T00:00:00z", "sequence": None}}]}}

    monkeypatch.setattr(app_module, "es_search_safe", fake_search_safe)
    monkeypatch.setattr(app_module, "es_count_safe", lambda **kwargs: 2)

    client = app.test_client()
    r = client.get("/api/heartbeat?since=2025-12-31T00:00:00Z")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["latest_ts"] == "2026-01-01T00:00:00Z"
    assert payload["new_count"] == 2
