from datetime import timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
