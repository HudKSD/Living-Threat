import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from elasticsearch import Elasticsearch
try:
    from elasticsearch import NotFoundError
except Exception:  # pragma: no cover
    from elasticsearch.exceptions import NotFoundError  # type: ignore
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_INDEX = os.getenv("ES_INDEX", "data_cached_*")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")

ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "true").lower() in ("1", "true", "yes")
ES_CA_CERTS = os.getenv("ES_CA_CERTS") or None

BOOTSTRAP_SIZE = int(os.getenv("BOOTSTRAP_SIZE", "2000"))

# UI time anchor behavior:
# - UI_NOW_FIXED (optional): fixed ISO datetime string; wins when set
# - UI_NOW_MODE=latest: UI "now" = latest doc Timestamp (+ optional offset days)
# - UI_NOW_MODE=utc: UI "now" = server UTC now
UI_NOW_MODE = os.getenv("UI_NOW_MODE", "latest").strip().lower()
UI_NOW_FIXED = os.getenv("UI_NOW_FIXED", "").strip()
UI_NOW_LATEST_OFFSET_DAYS = int(os.getenv("UI_NOW_LATEST_OFFSET_DAYS", "0"))
UI_NOW_FUTURE_CLAMP_DAYS = int(os.getenv("UI_NOW_FUTURE_CLAMP_DAYS", "2"))

# MITRE ATT&CK STIX to map technique_id -> tactics
ATTACK_STIX_URL = os.getenv(
    "ATTACK_STIX_URL",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
)
ATTACK_CACHE_PATH = os.getenv("ATTACK_CACHE_PATH", "/app/data/attack_enterprise.json")
ATTACK_CACHE_TTL_DAYS = int(os.getenv("ATTACK_CACHE_TTL_DAYS", "14"))

# Small server cache (keeps refresh snappy without hammering ES)
BOOTSTRAP_CACHE_SECONDS = int(os.getenv("BOOTSTRAP_CACHE_SECONDS", "8"))
UA = os.getenv("HTTP_USER_AGENT", "living-mitre-repo/1.0")


# ------------------------------------------------------------
# Elasticsearch client (v7/v8 compatible auth)
# ------------------------------------------------------------
def make_es_client() -> Elasticsearch:
    base_kwargs: Dict[str, Any] = {
        "verify_certs": ES_VERIFY_CERTS,
        "ca_certs": ES_CA_CERTS,
    }
    if ES_USER and ES_PASS:
        try:
            return Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), **base_kwargs)
        except TypeError:
            return Elasticsearch(ES_URL, http_auth=(ES_USER, ES_PASS), **base_kwargs)  # type: ignore[arg-type]
    return Elasticsearch(ES_URL, **base_kwargs)


es = make_es_client()


# ------------------------------------------------------------
# ATT&CK tactic mapping helpers
# ------------------------------------------------------------
PHASE_TO_TACTIC: Dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TACTIC_ORDER_DEFAULT: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Other",
]


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm(x: Any) -> str:
    return ("" if x is None else str(x)).strip()


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _parse_iso_dt(s: Any) -> Optional[datetime]:
    s = _norm(s)
    if not s:
        return None
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_str_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        out: List[str] = []
        for i in x:
            s = _norm(i)
            if s and s != "[]":
                out.append(s)
        return out

    if isinstance(x, str):
        s = _norm(x)
        if not s or s == "[]":
            return []
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                v = json.loads(s)
                return _clean_str_list(v)
            except Exception:
                return [s]
        return [s]

    s = _norm(x)
    return [s] if s and s != "[]" else []


def _normalize_severity(sev: Any) -> str:
    s = _norm(sev).lower()
    if not s:
        return "Low"
    if s in ("critical", "crit", "severe"):
        return "Critical"
    if s in ("high", "h"):
        return "High"
    if s in ("moderate", "medium", "med", "m"):
        return "Moderate"
    if s in ("low", "l", "info", "informational"):
        return "Low"
    return s[:1].upper() + s[1:]


def _normalize_analysis_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, list):
        items = [_norm(i) for i in x if _norm(i) and _norm(i) != "[]"]
        return " • ".join(items)
    s = _norm(x)
    if s == "[]":
        return ""
    return s


# ------------------------------------------------------------
# ES compatibility wrapper (v7/v8 safe)
# ------------------------------------------------------------
def es_search_safe(
    *,
    index: str,
    size: int,
    query: Dict[str, Any],
    sort: Optional[List[Any]] = None,
    source: Any = True,
    source_includes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    try:
        kwargs: Dict[str, Any] = {
            "index": index,
            "size": size,
            "query": query,
            "_source": source,
        }
        if sort is not None:
            kwargs["sort"] = sort
        if source_includes is not None:
            kwargs["_source_includes"] = source_includes
        return es.search(**kwargs)  # type: ignore
    except TypeError:
        body: Dict[str, Any] = {"query": query}
        if sort is not None:
            body["sort"] = sort
        if source_includes is not None:
            body["_source"] = source_includes
        else:
            body["_source"] = source
        return es.search(index=index, body=body, size=size)  # type: ignore


def es_count_safe(*, index: str, query: Dict[str, Any]) -> int:
    try:
        r = es.count(index=index, query=query)  # type: ignore
        return int(r.get("count") or 0)
    except TypeError:
        r = es.count(index=index, body={"query": query})  # type: ignore
        return int(r.get("count") or 0)
    except Exception:
        return 0


# ------------------------------------------------------------
# UI "now" calculation
# ------------------------------------------------------------
def latest_plausible_timestamp(docs: List[Dict[str, Any]]) -> Optional[str]:
    if not docs:
        return None
    ceiling = utcnow() + timedelta(days=UI_NOW_FUTURE_CLAMP_DAYS)
    for d in docs:
        dt = _parse_iso_dt(d.get("Timestamp"))
        if dt and dt <= ceiling:
            return _iso(dt)
    return _iso(utcnow())


def compute_ui_now(latest_ts: Optional[str]) -> str:
    fixed = _norm(UI_NOW_FIXED)
    mode = _norm(UI_NOW_MODE).lower()
    offset = timedelta(days=max(0, UI_NOW_LATEST_OFFSET_DAYS))

    if fixed:
        fixed_l = fixed.lower()
        if fixed_l in ("now", "utc", "utcnow"):
            return _iso(utcnow())
        dt = _parse_iso_dt(UI_NOW_FIXED)
        return _iso(dt) if dt else _iso(utcnow())

    if mode in ("utc", "now", "utcnow"):
        return _iso(utcnow())

    dt_latest = _parse_iso_dt(latest_ts or "")
    if dt_latest:
        return _iso(dt_latest + offset)
    return _iso(utcnow())


# ------------------------------------------------------------
# MITRE ATT&CK catalog loader (cached)
# ------------------------------------------------------------
_attack_lock = threading.Lock()
_attack_map: Optional[Dict[str, Dict[str, Any]]] = None


def _attack_cache_fresh(path: str) -> bool:
    try:
        st = os.stat(path)
        age = time.time() - st.st_mtime
        return age < (ATTACK_CACHE_TTL_DAYS * 24 * 3600)
    except Exception:
        return False


def _download_attack_stix(url: str, path: str) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, timeout=35, headers={"User-Agent": UA})
        r.raise_for_status()
        data = r.json()
        _ensure_dir(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return data
    except Exception:
        return None


def _load_attack_stix_from_disk(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _build_attack_map(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    objs = bundle.get("objects") or []
    if not isinstance(objs, list):
        return out

    for o in objs:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") is True or o.get("x_mitre_deprecated") is True:
            continue

        tid = ""
        for ref in (o.get("external_references") or []):
            if not isinstance(ref, dict):
                continue
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid = _norm(ref.get("external_id"))
                break
        if not tid:
            continue

        name = _norm(o.get("name")) or tid

        tactics: List[str] = []
        for ph in (o.get("kill_chain_phases") or []):
            if not isinstance(ph, dict):
                continue
            if ph.get("kill_chain_name") != "mitre-attack":
                continue
            phase = _norm(ph.get("phase_name"))
            if phase:
                tactics.append(PHASE_TO_TACTIC.get(phase, phase.replace("-", " ").title()))

        seen = set()
        tactics_clean: List[str] = []
        for t in tactics:
            if t in seen:
                continue
            seen.add(t)
            tactics_clean.append(t)

        out[tid] = {"name": name, "tactics": tactics_clean}

    return out


def get_attack_map() -> Dict[str, Dict[str, Any]]:
    global _attack_map
    with _attack_lock:
        if _attack_map is not None:
            return _attack_map

        bundle: Optional[Dict[str, Any]] = None
        if _attack_cache_fresh(ATTACK_CACHE_PATH):
            bundle = _load_attack_stix_from_disk(ATTACK_CACHE_PATH)
        if bundle is None:
            bundle = _download_attack_stix(ATTACK_STIX_URL, ATTACK_CACHE_PATH)
        if bundle is None:
            bundle = _load_attack_stix_from_disk(ATTACK_CACHE_PATH)

        _attack_map = _build_attack_map(bundle) if bundle else {}
        return _attack_map


# ------------------------------------------------------------
# Bootstrap payload cache
# ------------------------------------------------------------
_bootstrap_lock = threading.Lock()
_bootstrap_cache: Optional[Dict[str, Any]] = None
_bootstrap_cache_at: float = 0.0
_bootstrap_cache_size: int = 0


# ------------------------------------------------------------
# Document normalization
# ------------------------------------------------------------
def normalize_doc(hit: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    src = hit.get("_source") or {}
    doc_id = hit.get("_id")
    idx = hit.get("_index")

    ts_raw = src.get("Timestamp")
    ts_dt = _parse_iso_dt(ts_raw)
    ts_norm = _iso(ts_dt) if ts_dt else (_norm(ts_raw) or None)

    tech_name_hints: Dict[str, str] = {}

    analyses_in = src.get("Analyses") or []
    analyses_out: List[Dict[str, Any]] = []

    if isinstance(analyses_in, list):
        for a in analyses_in:
            if not isinstance(a, dict):
                continue
            stage = _norm(a.get("Stage")) or "Unknown"
            desc = _normalize_analysis_text(a.get("Description"))
            det = _normalize_analysis_text(a.get("Detection"))
            rem = _normalize_analysis_text(a.get("Remediation"))

            techs_raw = a.get("Techniques") or []
            techs: List[str] = []
            if isinstance(techs_raw, list):
                for t in techs_raw:
                    if isinstance(t, str):
                        tid = _norm(t)
                        if tid:
                            techs.append(tid)
                    elif isinstance(t, dict):
                        tid = _norm(t.get("technique_id") or t.get("id") or t.get("technique"))
                        tnm = _norm(t.get("technique_name") or t.get("name"))
                        if tid:
                            techs.append(tid)
                            if tnm and tid not in tech_name_hints:
                                tech_name_hints[tid] = tnm

            analyses_out.append(
                {
                    "Stage": stage,
                    "Description": desc,
                    "Detection": det,
                    "Remediation": rem,
                    "Techniques": list(dict.fromkeys(techs)),
                }
            )

    sequence = src.get("sequence")
    try:
        sequence = int(sequence) if sequence is not None else None
    except Exception:
        sequence = None

    doc = {
        "id": doc_id,
        "index": idx,
        "Timestamp": ts_norm,
        "Title": src.get("Title") or "(no title)",
        "Severity": _normalize_severity(src.get("Severity")),
        "Threat_Actors": _clean_str_list(src.get("Threat_Actors")),
        "Tools": _clean_str_list(src.get("Tools")),
        "CVEs": _clean_str_list(src.get("cveID") or src.get("CVEs")),
        "source": src.get("source") or None,
        "enrichment": src.get("enrichment") or None,
        "sequence": sequence,
        "doc_summary": src.get("doc_summary") or "",
        "diamond_model_summary": src.get("diamond_model_summary") or "",
        "kill_chain_summary": src.get("kill_chain_summary") or "",
        "pyramid_of_pain_summary": src.get("pyramid_of_pain_summary") or "",
        "Adversary": src.get("Adversary") or {},
        "Capability": src.get("Capability") or {},
        "Infrastructure": src.get("Infrastructure") or {},
        "Victim": src.get("Victim") or {},
        "Pyramid_Of_Pain": src.get("Pyramid_Of_Pain") or {},
        "Recommended_Tools_And_Techniques_For_Analysis": _clean_str_list(
            src.get("Recommended_Tools_And_Techniques_For_Analysis")
        ),
        "Detection_Rules_And_Indicators": _clean_str_list(src.get("Detection_Rules_And_Indicators")),
        "Detection_Hints": _clean_str_list(src.get("Detection_Hints")),
        "Data_Exfiltration_Indicators": _clean_str_list(src.get("Data_Exfiltration_Indicators")),
        "Post_Incident_Recommendations": _clean_str_list(src.get("Post_Incident_Recommendations")),
        "Behavioral_Indicators_of_Attackers": _clean_str_list(src.get("Behavioral_Indicators_of_Attackers")),
        "Extracted_Entities": src.get("Extracted_Entities") or {},
        "Analyses": analyses_out,
    }

    return doc, tech_name_hints


def build_catalog_for_docs(docs: List[Dict[str, Any]], name_hints: Dict[str, str]) -> Dict[str, Any]:
    attack = get_attack_map()

    used: List[str] = []
    seen = set()

    for d in docs:
        for a in (d.get("Analyses") or []):
            for tid in (a.get("Techniques") or []):
                tid = _norm(tid)
                if not tid or tid in seen:
                    continue
                seen.add(tid)
                used.append(tid)

    techniques: Dict[str, Any] = {}
    for tid in used:
        info = attack.get(tid) or {}
        nm = _norm(info.get("name")) or name_hints.get(tid) or tid
        tactics = info.get("tactics") or []
        if not isinstance(tactics, list):
            tactics = []

        primary = "Other"
        for t in TACTIC_ORDER_DEFAULT:
            if t in tactics:
                primary = t
                break
        if primary == "Other" and tactics:
            primary = _norm(tactics[0]) or "Other"

        techniques[tid] = {"name": nm, "tactic": primary, "tactics": tactics}

    order = [t for t in TACTIC_ORDER_DEFAULT]
    if "Other" not in order:
        order.append("Other")

    return {"tactic_order": order, "techniques": techniques}


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/")
def home():
    return render_template("index.html")


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.get("/api/bootstrap")
def api_bootstrap():
    global _bootstrap_cache, _bootstrap_cache_at, _bootstrap_cache_size

    try:
        size_q = int(request.args.get("size", str(BOOTSTRAP_SIZE)))
    except Exception:
        size_q = BOOTSTRAP_SIZE
    size = max(50, min(size_q, 5000))

    now_s = time.time()
    with _bootstrap_lock:
        if (
            _bootstrap_cache is not None
            and _bootstrap_cache_size == size
            and (now_s - _bootstrap_cache_at) < max(1, BOOTSTRAP_CACHE_SECONDS)
        ):
            return jsonify(_bootstrap_cache)

    sort = [
        {"sequence": {"order": "desc", "unmapped_type": "long"}},
        {"enrichment.processed_at": {"order": "desc", "unmapped_type": "date"}},
        {"Timestamp": {"order": "desc", "unmapped_type": "date"}},
    ]

    try:
        resp = es_search_safe(
            index=ES_INDEX,
            size=size,
            sort=sort,
            query={"match_all": {}},
            source=True,
        )
    except Exception as e:
        return jsonify({"error": "es_search_failed", "details": str(e)}), 502

    hits = (resp.get("hits") or {}).get("hits") or []
    docs: List[Dict[str, Any]] = []
    name_hints: Dict[str, str] = {}

    for h in hits:
        d, hints = normalize_doc(h)
        docs.append(d)
        for k, v in hints.items():
            if k not in name_hints and v:
                name_hints[k] = v

    latest_ts = docs[0].get("Timestamp") if docs else None
    seqs = [d.get("sequence") for d in docs if isinstance(d.get("sequence"), int)]
    latest_seq = max(seqs) if seqs else None
    anchor_ts = latest_plausible_timestamp(docs)
    ui_now = compute_ui_now(anchor_ts)

    catalog = build_catalog_for_docs(docs, name_hints)

    payload = {
        "meta": {
            "index": ES_INDEX,
            "size": size,
            "latest_ts": latest_ts,
            "latest_seq": latest_seq,
            "anchor_ts": anchor_ts,
            "ui_now": ui_now,
            "fetched_at": _iso(utcnow()),
        },
        "count": len(docs),
        "docs": docs,
        "catalog": catalog,
    }

    with _bootstrap_lock:
        _bootstrap_cache = payload
        _bootstrap_cache_at = time.time()
        _bootstrap_cache_size = size

    return jsonify(payload)


@app.get("/api/heartbeat")
def api_heartbeat():
    # frontend currently sends since_seq/since_ts; keep since fallback for compatibility
    since_seq = _norm(request.args.get("since_seq"))
    since_ts = _norm(request.args.get("since_ts")) or _norm(request.args.get("since"))

    try:
        resp = es_search_safe(
            index=ES_INDEX,
            size=1,
            sort=[
                {"sequence": {"order": "desc", "unmapped_type": "long"}},
                {"Timestamp": {"order": "desc", "unmapped_type": "date"}},
            ],
            query={"match_all": {}},
            source_includes=["Timestamp", "sequence"],
        )
        hits = (resp.get("hits") or {}).get("hits") or []
        src = (hits[0].get("_source") or {}) if hits else {}
        latest_ts_raw = src.get("Timestamp")
        latest_ts_dt = _parse_iso_dt(latest_ts_raw)
        latest_ts = _iso(latest_ts_dt) if latest_ts_dt else (_norm(latest_ts_raw) or None)
        try:
            latest_seq = int(src.get("sequence")) if src.get("sequence") is not None else None
        except Exception:
            latest_seq = None
    except Exception as e:
        return jsonify({"ok": False, "error": "es_failed", "details": str(e)}), 502

    new_count = 0
    if since_seq:
        try:
            new_count = es_count_safe(index=ES_INDEX, query={"range": {"sequence": {"gt": int(since_seq)}}})
        except Exception:
            new_count = 0
    elif since_ts:
        new_count = es_count_safe(index=ES_INDEX, query={"range": {"Timestamp": {"gt": since_ts}}})

    return jsonify({"ok": True, "latest_ts": latest_ts, "latest_seq": latest_seq, "new_count": new_count})


@app.get("/api/doc/<doc_id>")
def api_doc(doc_id: str):
    preferred_index = _norm(request.args.get("index"))

    if preferred_index:
        try:
            r = es.get(index=preferred_index, id=doc_id)
            src = r.get("_source") or {}
            doc, _ = normalize_doc({"_id": doc_id, "_index": preferred_index, "_source": src})
            return jsonify({"ok": True, "doc": doc})
        except NotFoundError:
            pass
        except Exception as e:
            return jsonify({"ok": False, "error": "es_get_failed", "details": str(e)}), 502

    try:
        r = es.get(index=ES_INDEX, id=doc_id)
        src = r.get("_source") or {}
        doc, _ = normalize_doc({"_id": doc_id, "_index": r.get("_index") or ES_INDEX, "_source": src})
        return jsonify({"ok": True, "doc": doc})
    except NotFoundError:
        return jsonify({"ok": False, "error": "not_found"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": "es_get_failed", "details": str(e)}), 502


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8970"))
    app.run(host="0.0.0.0", port=port, debug=True)
