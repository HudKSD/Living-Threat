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

UI_NOW_MODE = os.getenv("UI_NOW_MODE", "latest").strip().lower()
UI_NOW_FIXED = os.getenv("UI_NOW_FIXED", "").strip()
UI_NOW_LATEST_OFFSET_DAYS = int(os.getenv("UI_NOW_LATEST_OFFSET_DAYS", "0"))
UI_NOW_FUTURE_CLAMP_DAYS = int(os.getenv("UI_NOW_FUTURE_CLAMP_DAYS", "2"))
DATA_STALE_SECONDS = int(os.getenv("DATA_STALE_SECONDS", "21600"))

ATTACK_STIX_URL = os.getenv(
    "ATTACK_STIX_URL",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
)
ATTACK_CACHE_PATH = os.getenv("ATTACK_CACHE_PATH", "/app/data/attack_enterprise.json")
ATTACK_CACHE_TTL_DAYS = int(os.getenv("ATTACK_CACHE_TTL_DAYS", "14"))

BOOTSTRAP_CACHE_SECONDS = int(os.getenv("BOOTSTRAP_CACHE_SECONDS", "8"))
UA = os.getenv("HTTP_USER_AGENT", "living-threat-workbench/2.0")

SEVERITY_RANK = {"Low": 1, "Moderate": 2, "High": 3, "Critical": 4}

RELATED_WEIGHTS: Dict[str, int] = {
    "techniques": 6,
    "tactics": 3,
    "domains": 5,
    "ips": 5,
    "tools": 4,
    "malware": 4,
    "sectors": 3,
    "countries": 3,
    "breach_types": 2,
    "access_vectors": 2,
    "actors": 4,
}

# ------------------------------------------------------------
# Elasticsearch client
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

KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm(x: Any) -> str:
    return ("" if x is None else str(x)).strip()


def safe_get(data: Any, *path: str, default: Any = None) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


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
        return [_norm(i) for i in x if _norm(i) and _norm(i) != "[]"]
    if isinstance(x, str):
        s = _norm(x)
        if not s or s == "[]":
            return []
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                return _clean_str_list(json.loads(s))
            except Exception:
                return [s]
        return [s]
    s = _norm(x)
    return [s] if s and s != "[]" else []


def _uniq_keep(seq: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in seq:
        v = _norm(x)
        if not v:
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def _normalize_severity(sev: Any) -> str:
    s = _norm(sev).lower()
    if s in ("critical", "crit"):
        return "Critical"
    if s in ("high",):
        return "High"
    if s in ("moderate", "medium", "med"):
        return "Moderate"
    if s in ("low", "info", "informational", ""):
        return "Low"
    return s[:1].upper() + s[1:]


def _normalize_analysis_text(x: Any) -> str:
    if isinstance(x, list):
        return " • ".join(_clean_str_list(x))
    s = _norm(x)
    return "" if s == "[]" else s


def _list_from_paths(src: Dict[str, Any], paths: List[Tuple[str, ...]]) -> List[str]:
    values: List[str] = []
    for p in paths:
        values.extend(_clean_str_list(safe_get(src, *p)))
    return _uniq_keep(values)


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
        kwargs: Dict[str, Any] = {"index": index, "size": size, "query": query, "_source": source}
        if sort is not None:
            kwargs["sort"] = sort
        if source_includes is not None:
            kwargs["_source_includes"] = source_includes
        return es.search(**kwargs)  # type: ignore
    except TypeError:
        body: Dict[str, Any] = {"query": query, "_source": source_includes if source_includes is not None else source}
        if sort is not None:
            body["sort"] = sort
        return es.search(index=index, body=body, size=size)  # type: ignore


def es_count_safe(*, index: str, query: Dict[str, Any]) -> int:
    try:
        return int((es.count(index=index, query=query) or {}).get("count") or 0)  # type: ignore
    except TypeError:
        return int((es.count(index=index, body={"query": query}) or {}).get("count") or 0)  # type: ignore
    except Exception:
        return 0


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
        if fixed.lower() in ("now", "utc", "utcnow"):
            return _iso(utcnow())
        dt = _parse_iso_dt(fixed)
        return _iso(dt) if dt else _iso(utcnow())

    if mode in ("utc", "now", "utcnow"):
        return _iso(utcnow())

    dt_latest = _parse_iso_dt(latest_ts or "")
    return _iso(dt_latest + offset) if dt_latest else _iso(utcnow())


_attack_lock = threading.Lock()
_attack_map: Optional[Dict[str, Dict[str, Any]]] = None


def _attack_cache_fresh(path: str) -> bool:
    try:
        st = os.stat(path)
        return (time.time() - st.st_mtime) < (ATTACK_CACHE_TTL_DAYS * 24 * 3600)
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
    for o in (bundle.get("objects") or []):
        if not isinstance(o, dict) or o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") is True or o.get("x_mitre_deprecated") is True:
            continue
        tid = ""
        for ref in (o.get("external_references") or []):
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid = _norm(ref.get("external_id"))
                break
        if not tid:
            continue
        tactics: List[str] = []
        for phase in (o.get("kill_chain_phases") or []):
            if not isinstance(phase, dict) or phase.get("kill_chain_name") != "mitre-attack":
                continue
            phase_name = _norm(phase.get("phase_name"))
            if phase_name:
                tactics.append(PHASE_TO_TACTIC.get(phase_name, phase_name.replace("-", " ").title()))
        out[tid] = {
            "name": _norm(o.get("name")) or tid,
            "tactics": _uniq_keep(tactics),
        }
    return out


def get_attack_map() -> Dict[str, Dict[str, Any]]:
    global _attack_map
    if _attack_map is not None:
        return _attack_map

    with _attack_lock:
        if _attack_map is not None:
            return _attack_map

        bundle: Optional[Dict[str, Any]] = None
        if _attack_cache_fresh(ATTACK_CACHE_PATH):
            bundle = _load_attack_stix_from_disk(ATTACK_CACHE_PATH)
        if bundle is None:
            bundle = _download_attack_stix(ATTACK_STIX_URL, ATTACK_CACHE_PATH)
        if bundle is None:
            bundle = _load_attack_stix_from_disk(ATTACK_CACHE_PATH) or {"objects": []}

        _attack_map = _build_attack_map(bundle)
        return _attack_map


def _freshness_meta(latest_ts: Optional[str]) -> Dict[str, Any]:
    dt_latest = _parse_iso_dt(latest_ts or "")
    if not dt_latest:
        return {"has_latest": False, "latest_age_seconds": None, "is_stale": True}
    age_seconds = max(0, int((utcnow() - dt_latest).total_seconds()))
    return {
        "has_latest": True,
        "latest_age_seconds": age_seconds,
        "is_stale": age_seconds > DATA_STALE_SECONDS,
    }


def _build_attack_from_analyses(analyses_out: List[Dict[str, Any]], attack_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    tactic_set: List[str] = []
    techniques: Dict[str, Dict[str, Any]] = {}
    for stage in analyses_out:
        for t in (stage.get("Tactics") or []):
            name = _norm(t.get("tactic_name")) or _norm(t.get("tactic_id"))
            if name:
                tactic_set.append(name)
        for td in (stage.get("Technique_Details") or []):
            tid = _norm(td.get("technique_id"))
            if not tid:
                continue
            info = attack_map.get(tid) or {}
            existing = techniques.get(tid)
            desc = _norm(td.get("technique_description"))
            name = _norm(td.get("technique_name")) or _norm(info.get("name")) or tid
            tactic_candidates = info.get("tactics") or []
            if existing is None:
                techniques[tid] = {
                    "technique_id": tid,
                    "name": name,
                    "description": desc,
                    "tactics": tactic_candidates,
                    "stages": [_norm(stage.get("Stage"))],
                }
            else:
                if desc and len(desc) > len(_norm(existing.get("description"))):
                    existing["description"] = desc
                if _norm(stage.get("Stage")) and _norm(stage.get("Stage")) not in (existing.get("stages") or []):
                    (existing.get("stages") or []).append(_norm(stage.get("Stage")))

    return {
        "tactics": _uniq_keep(tactic_set),
        "techniques": list(techniques.values()),
    }


def _build_quadrants(src: Dict[str, Any], attack: Dict[str, Any], actors: List[str], tools: List[str]) -> Dict[str, Any]:
    adv = safe_get(src, "Adversary", default={}) or {}
    cap = safe_get(src, "Capability", default={}) or {}
    infra = safe_get(src, "Infrastructure", default={}) or {}
    victim = safe_get(src, "Victim", default={}) or {}
    entities = safe_get(src, "Extracted_Entities", default={}) or {}

    return {
        "adversary": {
            "description": _norm(adv.get("Description")),
            "aliases": _uniq_keep(_clean_str_list(adv.get("Aliases")) + actors),
            "threat_actors": actors,
            "motivation": _norm(adv.get("Motivation")),
            "sophistication": _norm(adv.get("Sophistication")),
            "known_campaigns": _clean_str_list(adv.get("Known_Campaigns")),
            "associated_groups": _clean_str_list(adv.get("Associated_Groups")),
            "strategic_objectives": _clean_str_list(adv.get("Strategic_Objectives")),
            "ttps": _clean_str_list(adv.get("TTPs_Employed")),
        },
        "capability": {
            "tools": _uniq_keep(tools + _clean_str_list(cap.get("Tools"))),
            "malware": _list_from_paths(src, [("Capability", "Malware"), ("Extracted_Entities", "Malware")]),
            "exploits": _clean_str_list(cap.get("Exploits")),
            "zero_days": _clean_str_list(cap.get("Zero_Days")),
            "persistence_mechanisms": _clean_str_list(cap.get("Persistence_Mechanisms")),
            "lateral_movement_tools": _clean_str_list(cap.get("Lateral_Movement_Tools")),
            "defensive_evasion": _clean_str_list(cap.get("Defensive_Evasion_Tactics")),
            "attack_techniques": [t.get("technique_id") for t in attack.get("techniques") or [] if t.get("technique_id")],
        },
        "infrastructure": {
            "domains": _list_from_paths(src, [("Infrastructure", "Domains"), ("Extracted_Entities", "Domains")]),
            "ips": _list_from_paths(src, [("Infrastructure", "IP_Addresses"), ("Extracted_Entities", "IP_Addresses")]),
            "hosting_providers": _clean_str_list(infra.get("Hosting_Providers")),
            "c2_servers": _clean_str_list(infra.get("C2_Servers")),
            "protocols": _clean_str_list(infra.get("Communication_Protocols")),
            "botnets": _clean_str_list(infra.get("Botnets")),
            "ssl_certs": _clean_str_list(infra.get("SSL_Certificates")),
            "related_tech": _clean_str_list(entities.get("Technologies")),
        },
        "victim": {
            "industry": _list_from_paths(src, [("Victim", "Industry"), ("Extracted_Entities", "Sectors")]),
            "geography": _list_from_paths(src, [("Victim", "Geography"), ("Extracted_Entities", "Countries")]),
            "targeted_assets": _clean_str_list(victim.get("Targeted_Assets")),
            "data_at_risk": _clean_str_list(victim.get("Data_At_Risk")),
            "access_vectors": _list_from_paths(src, [("Victim", "Access_Vectors"), ("Extracted_Entities", "Access_Vectors")]),
            "security_posture": _norm(victim.get("Security_Posture")),
            "impact_severity": _norm(victim.get("Impact_Severity")) or _normalize_severity(src.get("Severity")),
        },
    }


def _build_action_pack(src: Dict[str, Any], analyses_out: List[Dict[str, Any]], diamond: Dict[str, Any]) -> Dict[str, Any]:
    det_stage = [_normalize_analysis_text(s.get("Detection")) for s in analyses_out if _norm(s.get("Detection"))]
    rem_stage = [_normalize_analysis_text(s.get("Remediation")) for s in analyses_out if _norm(s.get("Remediation"))]

    indicators = _uniq_keep(
        _clean_str_list(src.get("Detection_Rules_And_Indicators"))
        + _clean_str_list(src.get("Data_Exfiltration_Indicators"))
        + _clean_str_list(src.get("Behavioral_Indicators_of_Attackers"))
    )

    telemetry_focus = _uniq_keep(
        _clean_str_list(src.get("Detection_Hints"))
        + det_stage
        + _clean_str_list(src.get("Recommended_Tools_And_Techniques_For_Analysis"))
    )

    related_entities = {
        "domains": diamond.get("infrastructure", {}).get("domains") or [],
        "ips": diamond.get("infrastructure", {}).get("ips") or [],
        "tools": diamond.get("capability", {}).get("tools") or [],
        "malware": diamond.get("capability", {}).get("malware") or [],
    }

    return {
        "incident_summary": _norm(src.get("doc_summary")) or "No evidence captured.",
        "threat_pattern": _norm(src.get("diamond_model_summary")) or "Knowledge gap in source data.",
        "review_next": _uniq_keep(rem_stage + _clean_str_list(src.get("Post_Incident_Recommendations"))),
        "telemetry_focus": telemetry_focus,
        "hunt_areas": _uniq_keep(_clean_str_list(src.get("search_topics")) + indicators),
        "related_entities": related_entities,
        "key_indicators": indicators,
        "behavioral_indicators": _clean_str_list(src.get("Behavioral_Indicators_of_Attackers")),
        "ready_made_rule_status": "No ready-made rule available in source data" if not _clean_str_list(src.get("Detection_Rules_And_Indicators")) else "Rule or indicator statements available in source data",
    }


def _build_pyramid(src: Dict[str, Any], attack: Dict[str, Any], diamond: Dict[str, Any]) -> Dict[str, Any]:
    pop = safe_get(src, "Pyramid_Of_Pain", default={}) or {}
    score = safe_get(src, "Pyramid_Of_Pain_Scoring", default={}) or {}
    return {
        "domains": _uniq_keep(_clean_str_list(pop.get("Domains")) + (diamond.get("infrastructure", {}).get("domains") or [])),
        "ips": _uniq_keep(_clean_str_list(pop.get("IP_Addresses")) + (diamond.get("infrastructure", {}).get("ips") or [])),
        "tools": _uniq_keep(_clean_str_list(pop.get("Tools")) + (diamond.get("capability", {}).get("tools") or [])),
        "ttps": [t.get("technique_id") for t in attack.get("techniques") if t.get("technique_id")],
        "hashes": _clean_str_list(pop.get("Hashes")),
        "host_artifacts": _clean_str_list(pop.get("Host_Artifacts")),
        "network_artifacts": _clean_str_list(pop.get("Network_Artifacts")),
        "score": score,
    }


def _sort_attack_path(stages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order_map = {name.lower(): idx for idx, name in enumerate(KILL_CHAIN_ORDER)}

    def key_fn(item: Dict[str, Any]) -> Tuple[int, str]:
        stage = _norm(item.get("Stage"))
        return (order_map.get(stage.lower(), 999), stage)

    return sorted(stages, key=key_fn)


def _build_similarity_index(doc: Dict[str, Any]) -> Dict[str, set]:
    diamond = doc.get("diamond") or {}
    attack = doc.get("attack") or {}
    entities = doc.get("entities") or {}

    return {
        "techniques": {t.get("technique_id") for t in (attack.get("techniques") or []) if t.get("technique_id")},
        "tactics": {_norm(t).lower() for t in (attack.get("tactics") or []) if _norm(t)},
        "domains": {_norm(x).lower() for x in (diamond.get("infrastructure", {}).get("domains") or []) if _norm(x)},
        "ips": {_norm(x).lower() for x in (diamond.get("infrastructure", {}).get("ips") or []) if _norm(x)},
        "tools": {_norm(x).lower() for x in (diamond.get("capability", {}).get("tools") or []) if _norm(x)},
        "malware": {_norm(x).lower() for x in (diamond.get("capability", {}).get("malware") or []) if _norm(x)},
        "sectors": {_norm(x).lower() for x in entities.get("sectors", []) if _norm(x)},
        "countries": {_norm(x).lower() for x in entities.get("countries", []) if _norm(x)},
        "breach_types": {_norm(x).lower() for x in entities.get("breach_types", []) if _norm(x)},
        "access_vectors": {_norm(x).lower() for x in entities.get("access_vectors", []) if _norm(x)},
        "actors": {_norm(x).lower() for x in entities.get("actors", []) if _norm(x)},
    }


def normalize_doc(hit: Dict[str, Any], attack_map: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    src = hit.get("_source") or {}
    doc_id = hit.get("_id")
    idx = hit.get("_index")

    ts_raw = src.get("Timestamp")
    ts_dt = _parse_iso_dt(ts_raw)
    ts_norm = _iso(ts_dt) if ts_dt else (_norm(ts_raw) or None)

    analyses_out: List[Dict[str, Any]] = []
    tech_name_hints: Dict[str, str] = {}

    for analysis in (src.get("Analyses") or []):
        if not isinstance(analysis, dict):
            continue
        tactics_out: List[Dict[str, str]] = []
        for t in (analysis.get("Tactics") or []):
            if not isinstance(t, dict):
                continue
            tactics_out.append(
                {
                    "tactic_id": _norm(t.get("tactic_id") or t.get("id") or t.get("tactic")),
                    "tactic_name": _norm(t.get("tactic_name") or t.get("name")),
                    "tactic_description": _normalize_analysis_text(t.get("tactic_description") or t.get("description")),
                }
            )

        tech_ids: List[str] = []
        details: List[Dict[str, str]] = []
        for t in (analysis.get("Techniques") or []):
            if isinstance(t, str):
                tid = _norm(t)
                if tid:
                    tech_ids.append(tid)
                    details.append({"technique_id": tid, "technique_name": "", "technique_description": ""})
            elif isinstance(t, dict):
                tid = _norm(t.get("technique_id") or t.get("id") or t.get("technique"))
                if not tid:
                    continue
                name = _norm(t.get("technique_name") or t.get("name"))
                desc = _normalize_analysis_text(t.get("technique_description") or t.get("description"))
                if name and tid not in tech_name_hints:
                    tech_name_hints[tid] = name
                tech_ids.append(tid)
                details.append({"technique_id": tid, "technique_name": name, "technique_description": desc})

        unique_details: List[Dict[str, str]] = []
        seen = set()
        for item in details:
            tid = _norm(item.get("technique_id"))
            if not tid or tid in seen:
                continue
            seen.add(tid)
            attack_info = attack_map.get(tid) or {}
            unique_details.append(
                {
                    "technique_id": tid,
                    "technique_name": _norm(item.get("technique_name")) or _norm(attack_info.get("name")) or tech_name_hints.get(tid, ""),
                    "technique_description": _norm(item.get("technique_description")),
                }
            )

        analyses_out.append(
            {
                "Stage": _norm(analysis.get("Stage")) or "Unknown",
                "Description": _normalize_analysis_text(analysis.get("Description")),
                "Detection": _normalize_analysis_text(analysis.get("Detection")),
                "Remediation": _normalize_analysis_text(analysis.get("Remediation")),
                "Tactics": tactics_out,
                "Techniques": _uniq_keep(tech_ids),
                "Technique_Details": unique_details,
            }
        )

    entities = {
        "sectors": _list_from_paths(src, [("Victim", "Industry"), ("Extracted_Entities", "Sectors")]),
        "countries": _list_from_paths(src, [("Victim", "Geography"), ("Extracted_Entities", "Countries")]),
        "software": _clean_str_list(safe_get(src, "Extracted_Entities", "Software")),
        "actors": _uniq_keep(
            _clean_str_list(src.get("Threat_Actors"))
            + _clean_str_list(safe_get(src, "entities", "threat_actors"))
            + _clean_str_list(safe_get(src, "threat", "group", "name"))
        ),
        "access_vectors": _list_from_paths(src, [("Victim", "Access_Vectors"), ("Extracted_Entities", "Access_Vectors")]),
        "breach_types": _clean_str_list(safe_get(src, "Extracted_Entities", "Breach_Types")),
        "domains": _list_from_paths(src, [("Infrastructure", "Domains"), ("Extracted_Entities", "Domains")]),
        "malware": _list_from_paths(src, [("Capability", "Malware"), ("Extracted_Entities", "Malware")]),
        "tools": _uniq_keep(
            _clean_str_list(src.get("Tools"))
            + _clean_str_list(safe_get(src, "Capability", "Tools"))
            + _clean_str_list(safe_get(src, "Pyramid_Of_Pain", "Tools"))
        ),
    }

    attack = _build_attack_from_analyses(analyses_out, attack_map)
    diamond = _build_quadrants(src, attack, entities["actors"], entities["tools"])
    action_pack = _build_action_pack(src, analyses_out, diamond)
    pyramid = _build_pyramid(src, attack, diamond)

    sequence = src.get("sequence")
    try:
        sequence = int(sequence) if sequence is not None else None
    except Exception:
        sequence = None

    severity = _normalize_severity(src.get("Severity"))
    priority = min(100, max(1, SEVERITY_RANK.get(severity, 1) * 20 + len(attack.get("techniques") or []) * 4 + len(action_pack.get("key_indicators") or []) * 2))

    doc = {
        "id": doc_id,
        "index": idx,
        "Title": src.get("Title") or src.get("title") or "(no title)",
        "Timestamp": ts_norm,
        "Severity": severity,
        "source": src.get("source") or None,
        "sequence": sequence,
        "doc_summary": _norm(src.get("doc_summary")),
        "diamond_model_summary": _norm(src.get("diamond_model_summary")),
        "kill_chain_summary": _norm(src.get("kill_chain_summary")),
        "pyramid_of_pain_summary": _norm(src.get("pyramid_of_pain_summary")),
        "Analyses": _sort_attack_path(analyses_out),
        "diamond": diamond,
        "attack": attack,
        "attack_path": _sort_attack_path(analyses_out),
        "action_pack": action_pack,
        "pyramid_of_pain": pyramid,
        "entities": entities,
        "priority_score": priority,
    }
    doc["similarity_index"] = _build_similarity_index(doc)
    return doc, tech_name_hints


def build_catalog_for_docs(docs: List[Dict[str, Any]], name_hints: Dict[str, str]) -> Dict[str, Any]:
    attack = get_attack_map()
    techniques: Dict[str, Any] = {}
    for d in docs:
        for t in (d.get("attack") or {}).get("techniques") or []:
            tid = _norm(t.get("technique_id"))
            if not tid:
                continue
            info = attack.get(tid) or {}
            tactics = info.get("tactics") or t.get("tactics") or []
            primary = "Other"
            for candidate in TACTIC_ORDER_DEFAULT:
                if candidate in tactics:
                    primary = candidate
                    break
            techniques[tid] = {
                "name": _norm(t.get("name")) or _norm(info.get("name")) or name_hints.get(tid) or tid,
                "tactics": tactics,
                "tactic": primary,
            }
    return {"tactic_order": TACTIC_ORDER_DEFAULT, "techniques": techniques}


def score_related(base: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    b = base.get("similarity_index") or {}
    c = candidate.get("similarity_index") or {}
    score = 0
    overlaps: List[str] = []

    for key, weight in RELATED_WEIGHTS.items():
        shared = sorted((b.get(key) or set()) & (c.get(key) or set()))
        if not shared:
            continue
        score += weight * min(4, len(shared))
        sample = ", ".join(shared[:3])
        overlaps.append(f"{key}: {sample}")

    return {
        "score": score,
        "explanation": "Related because both incidents share " + "; ".join(overlaps[:3]) + "." if overlaps else "No meaningful overlap.",
    }


def find_related_docs(base_doc: Dict[str, Any], docs: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    scored: List[Dict[str, Any]] = []
    for d in docs:
        if d.get("id") == base_doc.get("id"):
            continue
        rel = score_related(base_doc, d)
        if rel["score"] <= 0:
            continue
        scored.append(
            {
                "id": d.get("id"),
                "index": d.get("index"),
                "title": d.get("Title"),
                "timestamp": d.get("Timestamp"),
                "severity": d.get("Severity"),
                "score": rel["score"],
                "explanation": rel["explanation"],
            }
        )

    scored.sort(key=lambda x: (x["score"], SEVERITY_RANK.get(x.get("severity") or "Low", 1)), reverse=True)
    return scored[:limit]


_bootstrap_lock = threading.Lock()
_bootstrap_cache: Optional[Dict[str, Any]] = None
_bootstrap_cache_at: float = 0.0
_bootstrap_cache_size: int = 0


def _fetch_docs(size: int) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    sort = [
        {"sequence": {"order": "desc", "unmapped_type": "long"}},
        {"enrichment.processed_at": {"order": "desc", "unmapped_type": "date"}},
        {"Timestamp": {"order": "desc", "unmapped_type": "date"}},
    ]
    resp = es_search_safe(index=ES_INDEX, size=size, sort=sort, query={"match_all": {}}, source=True)
    hits = (resp.get("hits") or {}).get("hits") or []
    attack_map = get_attack_map()
    docs: List[Dict[str, Any]] = []
    hints: Dict[str, str] = {}
    for h in hits:
        doc, name_hints = normalize_doc(h, attack_map)
        docs.append(doc)
        for k, v in name_hints.items():
            if k not in hints and v:
                hints[k] = v
    return docs, hints


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.get("/healthz/deps")
def healthz_deps():
    started = time.time()
    ping_ok = False
    count = 0
    error: Optional[str] = None
    try:
        ping_ok = bool(es.ping())
        count = es_count_safe(index=ES_INDEX, query={"match_all": {}})
    except Exception as e:
        error = str(e)
    latency_ms = int((time.time() - started) * 1000)
    ok = ping_ok and error is None
    return jsonify({"ok": ok, "es": {"ping": ping_ok, "sample_count": count, "index": ES_INDEX, "latency_ms": latency_ms, "error": error}}), (200 if ok else 503)


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
        if _bootstrap_cache is not None and _bootstrap_cache_size == size and (now_s - _bootstrap_cache_at) < max(1, BOOTSTRAP_CACHE_SECONDS):
            return jsonify(_bootstrap_cache)

    try:
        docs, hints = _fetch_docs(size)
    except Exception as e:
        return jsonify({"error": "es_search_failed", "details": str(e)}), 502

    latest_ts = docs[0].get("Timestamp") if docs else None
    seqs = [d.get("sequence") for d in docs if isinstance(d.get("sequence"), int)]
    latest_seq = max(seqs) if seqs else None
    anchor_ts = latest_plausible_timestamp(docs)

    payload = {
        "meta": {
            "index": ES_INDEX,
            "size": size,
            "latest_ts": latest_ts,
            "latest_seq": latest_seq,
            "anchor_ts": anchor_ts,
            "ui_now": compute_ui_now(anchor_ts),
            "ui_now_mode": UI_NOW_MODE or "latest",
            "data_freshness": _freshness_meta(latest_ts),
            "fetched_at": _iso(utcnow()),
        },
        "count": len(docs),
        "docs": docs,
        "catalog": build_catalog_for_docs(docs, hints),
    }

    with _bootstrap_lock:
        _bootstrap_cache = payload
        _bootstrap_cache_at = time.time()
        _bootstrap_cache_size = size

    return jsonify(payload)


@app.get("/api/related/<doc_id>")
def api_related(doc_id: str):
    size = max(100, min(int(request.args.get("size", "500")), 3000))
    try:
        docs, _ = _fetch_docs(size)
    except Exception as e:
        return jsonify({"ok": False, "error": "es_search_failed", "details": str(e)}), 502

    base_doc = next((d for d in docs if d.get("id") == doc_id), None)
    if not base_doc:
        return jsonify({"ok": False, "error": "not_found"}), 404

    related = find_related_docs(base_doc, docs, limit=max(3, min(int(request.args.get("limit", "10")), 25)))
    return jsonify({"ok": True, "doc_id": doc_id, "related": related})


@app.get("/api/heartbeat")
def api_heartbeat():
    since_seq = _norm(request.args.get("since_seq"))
    since_ts = _norm(request.args.get("since_ts")) or _norm(request.args.get("since"))
    try:
        resp = es_search_safe(
            index=ES_INDEX,
            size=1,
            sort=[{"sequence": {"order": "desc", "unmapped_type": "long"}}, {"Timestamp": {"order": "desc", "unmapped_type": "date"}}],
            query={"match_all": {}},
            source_includes=["Timestamp", "sequence"],
        )
        src = ((resp.get("hits") or {}).get("hits") or [{}])[0].get("_source") or {}
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
        if new_count == 0 and since_ts:
            new_count = es_count_safe(index=ES_INDEX, query={"range": {"Timestamp": {"gt": since_ts}}})
    elif since_ts:
        new_count = es_count_safe(index=ES_INDEX, query={"range": {"Timestamp": {"gt": since_ts}}})

    return jsonify({"ok": True, "latest_ts": latest_ts, "latest_seq": latest_seq, "new_count": new_count})


@app.get("/api/doc/<doc_id>")
def api_doc(doc_id: str):
    preferred_index = _norm(request.args.get("index"))
    attack_map = get_attack_map()

    if preferred_index:
        try:
            r = es.get(index=preferred_index, id=doc_id)
            doc, _ = normalize_doc({"_id": doc_id, "_index": preferred_index, "_source": r.get("_source") or {}}, attack_map)
            return jsonify({"ok": True, "doc": doc})
        except NotFoundError:
            pass
        except Exception as e:
            return jsonify({"ok": False, "error": "es_get_failed", "details": str(e)}), 502

    try:
        r = es.get(index=ES_INDEX, id=doc_id)
        doc, _ = normalize_doc({"_id": doc_id, "_index": r.get("_index") or ES_INDEX, "_source": r.get("_source") or {}}, attack_map)
        return jsonify({"ok": True, "doc": doc})
    except NotFoundError:
        return jsonify({"ok": False, "error": "not_found"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": "es_get_failed", "details": str(e)}), 502


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8970"))
    app.run(host="0.0.0.0", port=port, debug=True)
