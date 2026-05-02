"""Embed code chunks and vector-search against CVE weakness descriptions in Atlas."""
from agent.state import AgentState, CodeChunk
from agent.nodes.embed import embed_text
from agent.db import atlas

MATCH_THRESHOLD = 0.70  # minimum cosine similarity to consider a match


def code_match_node(state: AgentState) -> dict:
    chunks: list[CodeChunk] = state.get("code_chunks", [])
    if not chunks:
        return {"code_chunks": []}

    matched: list[CodeChunk] = []

    for chunk in chunks:
        # embed the code chunk
        try:
            embedding = embed_text(_chunk_embed_text(chunk))
        except Exception as e:
            print(f"[code_match] Embed failed for {chunk['file']}:{chunk['start_line']}: {e}")
            continue

        chunk = dict(chunk)
        chunk["embedding"] = embedding

        # vector search against weakness descriptions stored in cve_records
        similar = atlas.vector_search_weaknesses(embedding, limit=1)
        if similar and similar[0].get("score", 0) >= MATCH_THRESHOLD:
            top = similar[0]
            chunk["matched_cve"] = top.get("cve_id")
            chunk["match_score"] = top.get("score", 0.0)
            print(
                f"[code_match] {chunk['file']}:{chunk['start_line']} "
                f"→ {top.get('cve_id')} (score={top.get('score', 0):.2f})"
            )
            matched.append(chunk)
        else:
            # keep chunk but mark unmatched — still useful for Atlas storage
            chunk["matched_cve"] = None
            chunk["match_score"] = similar[0].get("score", 0.0) if similar else 0.0

    print(f"[code_match] {len(matched)} chunk(s) matched CVE weaknesses above threshold")
    return {"code_chunks": matched}


def _chunk_embed_text(chunk: CodeChunk) -> str:
    return f"File: {chunk['file']}\nLines: {chunk['start_line']}-{chunk['end_line']}\n\n{chunk['content']}"
