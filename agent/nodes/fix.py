"""Generate version-bump fixes using Groq (Llama 3.1 70B), informed by similar past fixes."""
import os
import json
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agent.state import AgentState, CVEDetail, Fix


SYSTEM_PROMPT = """You are a security engineer who specialises in fixing CVEs through dependency version bumps.
Given a CVE and context about the affected package, respond with a JSON object with exactly these fields:
{
  "target_version": "<minimum safe semver version>",
  "reasoning": "<one sentence explaining why this version>"
}
Respond with ONLY the JSON object, no markdown, no explanation outside the JSON."""


def fix_node(state: AgentState) -> dict:
    cve_details: list[CVEDetail] = state.get("cve_details", [])
    vulnerabilities = {v["package"]: v for v in state.get("vulnerabilities", [])}
    llm = _get_llm()
    fixes: list[Fix] = []

    for detail in cve_details:
        vuln = vulnerabilities.get(detail["package"], {})
        fix = _generate_fix(llm, detail, vuln)
        if fix:
            fixes.append(fix)
            print(f"[fix] {detail['package']}: {fix['current_version']} → {fix['target_version']}")
            print(f"      {fix['reasoning']}")

    return {"fixes": fixes}


def _generate_fix(llm: ChatGroq, detail: CVEDetail, vuln: dict) -> Fix | None:
    current_version = vuln.get("current_version", "unknown")

    similar_context = ""
    if detail.get("similar_fixes"):
        lines = []
        for s in detail["similar_fixes"]:
            lines.append(f"  - {s.get('package')}@{s.get('fixed_version', '?')} fixed {s.get('cve_id', '')}")
        similar_context = "\nSimilar past fixes for context:\n" + "\n".join(lines)

    prompt = f"""CVE: {detail['cve_id']}
Package: {detail['package']}
Currently installed version: {current_version}
Description: {detail['description']}
Known safe fixed version from OSV: {detail.get('fixed_version') or 'unknown'}{similar_context}

What is the minimum safe version to upgrade {detail['package']} to?"""

    try:
        response = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
        raw = response.content.strip()
        data = json.loads(raw)
        return Fix(
            package=detail["package"],
            current_version=current_version,
            target_version=data["target_version"],
            cve_id=detail["cve_id"],
            reasoning=data["reasoning"],
            verified=False,
        )
    except Exception as e:
        print(f"  [fix] LLM call failed for {detail['cve_id']}: {e}")
        if detail.get("fixed_version"):
            return Fix(
                package=detail["package"],
                current_version=current_version,
                target_version=detail["fixed_version"],
                cve_id=detail["cve_id"],
                reasoning="Version from OSV advisory (LLM fallback)",
                verified=False,
            )
        return None


def _get_llm() -> ChatGroq:
    return ChatGroq(
        model=os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile"),
        temperature=0,
        max_tokens=256,
    )
