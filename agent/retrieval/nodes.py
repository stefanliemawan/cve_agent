"""Nodes for the adaptive retrieval sub-graph."""
import os
import json
import requests
from datetime import datetime, timezone
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agent.db import atlas
from agent.retrieval.source_weights import get_source_order, log_retrieval

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BASE = "https://api.osv.dev/v1"
CVE_ORG_BASE = "https://cveawg.mitre.org/api"

QUALITY_THRESHOLD = 0.6
MAX_RETRIES = 2

EVAL_PROMPT = """Rate the quality of this CVE record for fixing a vulnerability in an npm package.
Score from 0.0 (useless) to 1.0 (perfect):
- 1.0: has description, CVSS score, affected package name, fixed version
- 0.7: has description and CVSS but missing fixed version
- 0.4: has description only
- 0.1: empty or irrelevant

Respond with ONLY a JSON: {"score": 0.85, "reason": "one sentence"}"""


class RetrievalState:
    pass


def retrieve_node(state: dict) -> dict:
    cve_id = state["cve_id"]
    package = state.get("package", "")
    cwes = state.get("cwes", [])
    sources_tried = state.get("sources_tried", [])

    source_order = get_source_order(cwes[0] if cwes else None)
    remaining = [s for s in source_order if s not in sources_tried]

    if not remaining:
        # all sources exhausted — fall back to Atlas semantic search
        result = _search_atlas(package, cve_id)
        return {**state, "result": result, "sources_tried": sources_tried + ["atlas"]}

    source = remaining[0]
    result = _fetch_from_source(source, cve_id, package)
    return {**state, "result": result, "sources_tried": sources_tried + [source], "last_source": source}


def evaluate_node(state: dict) -> dict:
    result = state.get("result") or {}
    cve_id = state["cve_id"]

    if not result:
        return {**state, "quality_score": 0.0}

    llm = ChatGroq(
        model=os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile"),
        temperature=0, max_tokens=128,
    )
    try:
        resp = llm.invoke([
            SystemMessage(content=EVAL_PROMPT),
            HumanMessage(content=json.dumps(result, default=str)[:2000]),
        ])
        data = json.loads(resp.content.strip())
        score = float(data.get("score", 0.5))
    except Exception:
        score = 0.5 if result.get("description") else 0.1

    # log for future weight updates
    log_retrieval(
        cve_id=cve_id,
        source=state.get("last_source", "unknown"),
        quality=score,
        cwes=state.get("cwes", []),
    )

    return {**state, "quality_score": score}


def rerank_node(state: dict) -> dict:
    result = state.get("result") or {}
    cvss = result.get("cvss_score", 5.0)
    quality = state.get("quality_score", 0.5)
    source_confidence = {"osv": 0.95, "nvd": 0.9, "cve.org": 0.8, "atlas": 0.7}.get(
        state.get("last_source", "atlas"), 0.7
    )
    # composite score: weighted average
    composite = (cvss / 10) * 0.4 + quality * 0.4 + source_confidence * 0.2
    return {**state, "composite_score": composite}


def store_node(state: dict) -> dict:
    result = state.get("result") or {}
    if not result:
        return state

    doc = {
        **result,
        "source": state.get("last_source", "unknown"),
        "source_confidence": state.get("composite_score", 0.5),
        "date_updated": datetime.now(timezone.utc).isoformat(),
    }
    atlas.upsert_cve(doc)
    return {**state, "stored": True}


def should_retry(state: dict) -> str:
    quality = state.get("quality_score", 0.0)
    retries = state.get("retry_count", 0)
    sources_tried = state.get("sources_tried", [])
    all_sources = {"osv", "nvd", "cve.org", "atlas"}

    if quality >= QUALITY_THRESHOLD:
        return "rerank"
    if retries >= MAX_RETRIES or all_sources.issubset(set(sources_tried)):
        return "rerank"  # best we can do
    return "retrieve"


# ── Source fetchers ──────────────────────────────────────────────────────────

def _fetch_from_source(source: str, cve_id: str, package: str) -> dict | None:
    try:
        if source == "osv":
            return _fetch_osv(cve_id, package)
        if source == "nvd":
            return _fetch_nvd(cve_id)
        if source == "cve.org":
            return _fetch_cve_org(cve_id)
    except Exception as e:
        print(f"  [retrieval] {source} failed for {cve_id}: {e}")
    return None


def _fetch_osv(cve_id: str, package: str) -> dict | None:
    resp = requests.get(f"{OSV_BASE}/vulns/{cve_id}", timeout=10)
    if resp.status_code != 200:
        return None
    osv = resp.json()
    description = osv.get("summary") or osv.get("details", "")
    fixed_version = None
    pkg_name = package
    for aff in osv.get("affected", []):
        if aff.get("package", {}).get("ecosystem", "").lower() == "npm":
            pkg_name = aff["package"].get("name", package)
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fixed_version = ev["fixed"]
    cvss = _parse_cvss(osv)
    return {"cve_id": cve_id, "description": description, "cvss_score": cvss,
            "package": pkg_name, "fixed_version": fixed_version,
            "cwes": [], "source": "osv"}


def _fetch_nvd(cve_id: str) -> dict | None:
    params = {"cveId": cve_id}
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=15)
    if resp.status_code != 200:
        return None
    items = resp.json().get("vulnerabilities", [])
    if not items:
        return None
    cve = items[0]["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    metrics = cve.get("metrics", {})
    cvss = 5.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            cvss = metrics[key][0].get("cvssData", {}).get("baseScore", 5.0)
            break
    cwes = [w.get("description", [{}])[0].get("value", "") for w in cve.get("weaknesses", [])]
    return {"cve_id": cve_id, "description": desc, "cvss_score": cvss,
            "cwes": cwes, "source": "nvd"}


def _fetch_cve_org(cve_id: str) -> dict | None:
    resp = requests.get(f"{CVE_ORG_BASE}/cve/{cve_id}", timeout=10)
    if resp.status_code != 200:
        return None
    data = resp.json()
    cna = data.get("containers", {}).get("cna", {})
    desc = next((d["value"] for d in cna.get("descriptions", []) if d["lang"] == "en"), "")
    cvss = 5.0
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                cvss = metric[key].get("baseScore", 5.0)
    cwes = [p.get("cweId", "") for p in cna.get("problemTypes", [{}])[0].get("descriptions", [])]
    return {"cve_id": cve_id, "description": desc, "cvss_score": cvss,
            "cwes": cwes, "source": "cve.org"}


def _search_atlas(package: str, cve_id: str) -> dict | None:
    doc = atlas.cve_records().find_one({"cve_id": cve_id}, {"_id": 0})
    return doc


def _parse_cvss(osv: dict) -> float:
    sev_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.0}
    db_sev = osv.get("database_specific", {}).get("severity", "")
    return sev_map.get(db_sev.upper(), 5.0)
