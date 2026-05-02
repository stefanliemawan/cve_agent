"""Enrich vulnerabilities with CVE details via adaptive retrieval sub-graph."""
from agent.state import AgentState, CVEDetail
from agent.db import atlas
from agent.retrieval.graph import run_retrieval


def cve_lookup_node(state: AgentState) -> dict:
    vulnerabilities = state.get("vulnerabilities", [])
    cve_details: list[CVEDetail] = []

    for vuln in vulnerabilities:
        pkg = vuln["package"]

        # check Atlas cache first (skip if it's only a benchmark stub)
        cached = atlas.cve_records().find_one(
            {"package": pkg, "source": {"$ne": "ossf-benchmark-only"}},
            {"_id": 0},
        )
        if cached and cached.get("description"):
            detail = _from_cache(cached, vuln)
            if detail:
                print(f"[cve_lookup] {pkg} — cache hit ({cached.get('cve_id')})")
                cve_details.append(detail)
                continue

        # adaptive retrieval: OSV → NVD → CVE.org → Atlas semantic
        for cve_id in (vuln.get("cve_ids") or []):
            result = run_retrieval(cve_id=cve_id, package=pkg, cwes=[])
            if result:
                detail = _from_retrieval(result, vuln)
                if detail:
                    cve_details.append(detail)
                    break
        else:
            # no CVE IDs known — query OSV by package+version
            from agent.retrieval.nodes import _fetch_osv
            result = _fetch_osv(f"pkg:{pkg}", pkg) or {}
            if result:
                cve_details.append(_from_retrieval(result, vuln))

    print(f"[cve_lookup] Enriched {len(cve_details)} CVE detail(s)")
    return {"cve_details": cve_details}


def _from_cache(doc: dict, vuln: dict) -> CVEDetail | None:
    return CVEDetail(
        cve_id=doc.get("cve_id", ""),
        package=doc.get("package", vuln["package"]),
        description=doc.get("description", ""),
        cvss_score=doc.get("cvss_score", 0.0),
        cwes=doc.get("cwes", []),
        affected_versions=[],
        fixed_version=doc.get("fixed_version"),
        similar_fixes=[],
    )


def _from_retrieval(result: dict, vuln: dict) -> CVEDetail:
    return CVEDetail(
        cve_id=result.get("cve_id", f"UNKNOWN-{vuln['package']}"),
        package=result.get("package") or vuln["package"],
        description=result.get("description", ""),
        cvss_score=result.get("cvss_score", 5.0),
        cwes=result.get("cwes", []),
        affected_versions=[],
        fixed_version=result.get("fixed_version") or vuln.get("fix_available"),
        similar_fixes=[],
    )
