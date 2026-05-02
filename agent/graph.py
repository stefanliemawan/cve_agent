"""LangChain ReAct agent for CVE auditing."""
import os

from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent

from agent.tools import make_tools

SYSTEM_PROMPT = """You are an expert security auditor. Perform a deep CVE and vulnerability audit
of the provided repository by following this exact workflow:

## Step 1 — List Dependencies
Call list_dependencies() to retrieve every package, version, and ecosystem.

## Step 2 — Parallel CVE Lookup
Call lookup_cve() for EVERY package in a single response so the calls run in parallel.
Do not wait for one result before requesting the next.

## Step 3 — Code Reachability Analysis
For each CVE returned, decide whether the vulnerable pattern is actually used:
- Identify the dangerous API from the CVE description (e.g. yaml.load, pickle.loads,
  redirect without stripping auth headers).
- Call search_code(<pattern>) to confirm the pattern appears in the source.
- A CVE is **confirmed exploitable** only when the vulnerable pattern IS found.
- A CVE is **unreached** when the pattern is NOT found (still worth noting, lower priority).
- Call search_advisories(<query>) when you need to confirm which CVE a pattern maps to.

## Step 4 — Novel Issue Detection (run alongside Step 3)
Regardless of what CVEs exist, search for these dangerous patterns:
- search_code("yaml.load(")      — unsafe YAML deserialization → RCE
- search_code("pickle.loads(")   — arbitrary code execution
- search_code("shell=True")      — command injection via subprocess
- search_code("eval(")           — dynamic code execution
- search_code("os.system(")      — OS command injection
Any result that appears to receive user-controlled input is a novel finding.

## Step 5 — Final Report
Write a structured report with exactly these three sections:

### Confirmed Exploitable CVEs
CVEs where the vulnerable pattern was found in source code.
Format per entry: CVE-XXXX-XXXXX [SEVERITY] package@version — short description — file:line

### Novel Issues (No CVE)
Dangerous patterns found in code not tied to a dependency CVE.
Format per entry: [PATTERN] file:line — risk and recommended fix

### Unreached CVEs (Lower Priority)
CVEs for packages in use whose vulnerable pattern was NOT found in source.
Format per entry: CVE-XXXX-XXXXX [SEVERITY] package@version — short description

Be concise and accurate. Only report what you actually confirmed through tool calls."""


def compile_graph(repo_path: str):
    """Build and return the compiled LangChain ReAct audit agent."""
    llm = ChatGroq(
        model=os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile"),
        temperature=0,
    )
    tools = make_tools(repo_path)
    return create_react_agent(model=llm, tools=tools, state_modifier=SYSTEM_PROMPT)
