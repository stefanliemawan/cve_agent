"""Adaptive retrieval sub-graph — nested LangGraph for multi-source CVE fetching."""
from langgraph.graph import StateGraph, END
from agent.retrieval.nodes import retrieve_node, evaluate_node, rerank_node, store_node, should_retry


def build_retrieval_graph():
    g = StateGraph(dict)

    g.add_node("retrieve", retrieve_node)
    g.add_node("evaluate", evaluate_node)
    g.add_node("rerank", rerank_node)
    g.add_node("store", store_node)

    g.set_entry_point("retrieve")
    g.add_edge("retrieve", "evaluate")
    g.add_conditional_edges("evaluate", should_retry, {"retrieve": "retrieve", "rerank": "rerank"})
    g.add_edge("rerank", "store")
    g.add_edge("store", END)

    return g.compile()


_retrieval_graph = None


def run_retrieval(cve_id: str, package: str = "", cwes: list[str] | None = None) -> dict:
    """Run the adaptive retrieval sub-graph for a single CVE. Returns the enriched CVE dict."""
    global _retrieval_graph
    if _retrieval_graph is None:
        _retrieval_graph = build_retrieval_graph()

    initial = {
        "cve_id": cve_id,
        "package": package,
        "cwes": cwes or [],
        "result": None,
        "quality_score": 0.0,
        "composite_score": 0.0,
        "sources_tried": [],
        "retry_count": 0,
        "last_source": None,
        "stored": False,
    }
    final = _retrieval_graph.invoke(initial)
    return final.get("result") or {}
