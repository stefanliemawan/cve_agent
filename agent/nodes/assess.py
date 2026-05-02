"""Filter CVEs by CVSS severity and attach similar past fixes from Atlas."""
from agent.state import AgentState, CVEDetail
from agent.nodes.embed import embed_text
from agent.db import atlas

CVSS_THRESHOLD = 7.0


def assess_node(state: AgentState) -> dict:
    cve_details: list[CVEDetail] = state.get("cve_details", [])
    actionable: list[CVEDetail] = []

    for detail in cve_details:
        if detail["cvss_score"] < CVSS_THRESHOLD:
            print(f"[assess] Skipping {detail['cve_id']} — CVSS {detail['cvss_score']:.1f} below threshold")
            continue

        print(f"[assess] {detail['cve_id']} — CVSS {detail['cvss_score']:.1f} → actionable")

        # fetch similar past fixes via vector search
        try:
            text = f"{detail['description']} package:{detail['package']}"
            embedding = embed_text(text)
            similar = atlas.vector_search(embedding, limit=3)
            detail = dict(detail)
            detail["similar_fixes"] = similar
        except Exception as e:
            print(f"  [assess] Vector search failed: {e}")
            detail = dict(detail)
            detail["similar_fixes"] = []

        actionable.append(detail)

    print(f"[assess] {len(actionable)} CVE(s) above threshold, {len(cve_details) - len(actionable)} skipped")
    return {"cve_details": actionable}


def should_fix(state: AgentState) -> str:
    """Routing function: proceed to fix or end the graph."""
    return "fix" if state.get("cve_details") else "end"
