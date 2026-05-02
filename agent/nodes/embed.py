"""Embed CVE descriptions using Voyage AI and upsert into Atlas."""
from langchain_voyageai import VoyageAIEmbeddings
from agent.state import AgentState, CVEDetail
from agent.db import atlas

_embeddings: VoyageAIEmbeddings | None = None


def _get_embeddings() -> VoyageAIEmbeddings:
    global _embeddings
    if _embeddings is None:
        _embeddings = VoyageAIEmbeddings(model="voyage-3")
    return _embeddings


def embed_text(text: str) -> list[float]:
    return _get_embeddings().embed_query(text)


def embed_node(state: AgentState) -> dict:
    cve_details: list[CVEDetail] = state.get("cve_details", [])

    for detail in cve_details:
        text = _build_embed_text(detail)
        try:
            embedding = embed_text(text)
            atlas.upsert_cve({
                "cve_id": detail["cve_id"],
                "package": detail["package"],
                "description": detail["description"],
                "cvss_score": detail["cvss_score"],
                "cwes": detail["cwes"],
                "fixed_version": detail.get("fixed_version"),
                "embedding": embedding,
                "source": "osv-live",
            })
            print(f"[embed] Stored embedding for {detail['cve_id']}")
        except Exception as e:
            print(f"[embed] Failed to embed {detail['cve_id']}: {e}")

    return {}


def _build_embed_text(detail: CVEDetail) -> str:
    parts = [
        f"CVE: {detail['cve_id']}",
        f"Package: {detail['package']}",
        f"Description: {detail['description']}",
    ]
    if detail.get("cwes"):
        parts.append(f"CWEs: {', '.join(detail['cwes'])}")
    if detail.get("fixed_version"):
        parts.append(f"Fixed in: {detail['fixed_version']}")
    return "\n".join(parts)
