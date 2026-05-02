"""Groq reviews each matched code chunk and determines vulnerability + suggested fix."""
import os
import json
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agent.state import AgentState, CodeChunk
from agent.db import atlas

SYSTEM_PROMPT = """You are a senior security engineer reviewing JavaScript/TypeScript code for vulnerabilities.
Given a code chunk and a CVE weakness description, determine whether the code is vulnerable.

Respond with ONLY a JSON object:
{
  "verdict": "vulnerable" | "likely_vulnerable" | "not_vulnerable",
  "reasoning": "<one sentence>",
  "vulnerable_line": <line number within the chunk, or null>,
  "suggested_fix": "<brief code suggestion, or null if not_vulnerable>"
}"""


def code_review_node(state: AgentState) -> dict:
    chunks: list[CodeChunk] = state.get("code_chunks", [])
    matched = [c for c in chunks if c.get("matched_cve")]
    if not matched:
        print("[code_review] No matched chunks to review")
        return {"code_chunks": chunks}

    llm = _get_llm()
    reviewed: list[CodeChunk] = []

    for chunk in matched:
        cve_doc = atlas.cve_records().find_one(
            {"cve_id": chunk["matched_cve"]},
            {"_id": 0, "description": 1, "weakness_explanation": 1, "cwes": 1},
        ) or {}

        result = _review_chunk(llm, chunk, cve_doc)
        updated = dict(chunk)
        updated.update(result)
        reviewed.append(updated)

        if result["verdict"] != "not_vulnerable":
            print(
                f"[code_review] {chunk['file']}:{chunk['start_line']} "
                f"→ {result['verdict']} ({chunk['matched_cve']})"
            )
            if result.get("suggested_fix"):
                print(f"             Fix: {result['suggested_fix']}")

    # store matched+reviewed chunks in Atlas
    _save_code_chunks(reviewed, state)

    # replace matched chunks with reviewed versions; keep unmatched as-is
    unmatched = [c for c in chunks if not c.get("matched_cve")]
    return {"code_chunks": reviewed + unmatched}


def _review_chunk(llm: ChatGroq, chunk: CodeChunk, cve_doc: dict) -> dict:
    weakness = cve_doc.get("weakness_explanation") or cve_doc.get("description", "unknown weakness")
    cwes = ", ".join(cve_doc.get("cwes", [])) or "unknown"

    prompt = f"""CVE: {chunk['matched_cve']}
CWEs: {cwes}
Weakness: {weakness}
Match confidence: {chunk['match_score']:.2f}

Code from {chunk['file']} (lines {chunk['start_line']}–{chunk['end_line']}):
```javascript
{chunk['content']}
```

Is this code vulnerable to the described weakness?"""

    try:
        response = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
        data = json.loads(response.content.strip())
        return {
            "verdict": data.get("verdict", "not_vulnerable"),
            "reasoning": data.get("reasoning", ""),
            "suggested_fix": data.get("suggested_fix"),
        }
    except Exception as e:
        print(f"  [code_review] LLM failed for {chunk['file']}:{chunk['start_line']}: {e}")
        return {"verdict": "likely_vulnerable", "reasoning": "LLM review failed; flagged by similarity", "suggested_fix": None}


def _save_code_chunks(chunks: list[CodeChunk], state: AgentState) -> None:
    run_id = state.get("run_id", "unknown")
    repo = state.get("repo_path", ".")
    col = atlas.get_db()["code_chunks"]
    for chunk in chunks:
        doc = {**chunk, "run_id": run_id, "repo": repo}
        doc.pop("embedding", None)  # don't double-store large arrays
        col.insert_one(doc)


def _get_llm() -> ChatGroq:
    return ChatGroq(
        model=os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile"),
        temperature=0,
        max_tokens=512,
    )
